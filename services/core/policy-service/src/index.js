'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');

const { oidcAuth } = require('./middleware/oidcAuth');
const { requirePolicyAccess } = require('./middleware/policyAccess');
const { requireLicenseIdentity, requireLicensePermission, isOwnLicenseRequest } = require('./middleware/licenseAccess');
const db = require('./db/postgres');
const { LicenseAllocator, LicenseError } = require('./licenses/LicenseAllocator');
const { LicenseLifecycleWorker } = require('./licenses/LicenseLifecycleWorker');
const { GroupSnapshotClient } = require('./licenses/GroupSnapshotClient');
const { GroupLicenseAllocator } = require('./licenses/GroupLicenseAllocator');
const { licenseBinding } = require('./middleware/licenseBinding');
const { UUID, validateRequestIdentity } = require('./licenses/LicensePrincipal');
const { RSOPEngine } = require('./engines/gpoProcessor');
const { ConflictResolver } = require('./engines/conflictResolver');
const { InheritanceEngine } = require('./engines/inheritanceEngine');
// Shared Policy Compiler package — hosts both the deployable-artifact compilers
// (used by enterprise-directory) and these RSoP-consuming compilers (used here).
// Same require-with-fallback pattern as other cross-package imports in this repo
// (see e.g. @opendirectory/driver-catalog in device-service), so the service
// still resolves the package when it isn't installed as a workspace dependency
// in a service-only Docker build context.
let WindowsPolicyCompiler, MacOSPolicyCompiler, LinuxPolicyCompiler;
try {
  ({ WindowsPolicyCompiler, MacOSPolicyCompiler, LinuxPolicyCompiler } = require('@opendirectory/policy-compilers'));
} catch (_) {
  ({ WindowsPolicyCompiler, MacOSPolicyCompiler, LinuxPolicyCompiler } = require('../../../../packages/policy-compilers/src'));
}


const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const app = express();
const PORT = process.env.PORT || 3004;

// --- Middleware ---
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 }));
app.use(oidcAuth({ skipPaths: ['/health', '/metrics'] }));
app.use('/api/company-blueprints', require('./companyBlueprintRoutes').companyBlueprintRoutes(db));
app.use('/api/company-blueprint-assignments', require('./companyBlueprintAssignmentRoutes').companyBlueprintAssignmentRoutes(db));
app.use('/api/licenses/automation/groups', require('./licenses/companyAutomationRoutes').companyAutomationRoutes(db));
app.use('/api', requirePolicyAccess);

// --- Engine singletons ---
const rsopEngine = new RSOPEngine();
const conflictResolver = new ConflictResolver();
const inheritanceEngine = new InheritanceEngine();
const compilers = {
  windows: new WindowsPolicyCompiler(),
  macos: new MacOSPolicyCompiler(),
  linux: new LinuxPolicyCompiler()
};

// --- Template cache ---
let templateCache = null;

function loadTemplates() {
  if (templateCache) return templateCache;
  const dir = path.join(__dirname, 'templates');
  if (!fs.existsSync(dir)) return [];
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
  templateCache = files.map(f => {
    const raw = fs.readFileSync(path.join(dir, f), 'utf-8');
    return JSON.parse(raw);
  });
  return templateCache;
}

// --- Event Bus ---
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();

const _bus = new EventBusClient({ source: 'policy-service' });
async function connectBus() { await _bus.connect(); }


// ============================
// Health check
// ============================
app.get('/health', async (_req, res) => {
  const dbOk = await db.testConnection();
  res.status(dbOk ? 200 : 503).json({
    status: dbOk ? 'healthy' : 'degraded',
    service: 'policy-service',
    database: dbOk ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  });
});

app.use('/api', require('./policyConfigurationRoutes').policyConfigurationRoutes(db, {
  loadTemplates, catalog: require('./policyCatalog'), rsopEngine, conflictResolver, inheritanceEngine, compilers
}));

// ============================
// License Management
// ============================

// In-memory stores for licenses (fallback when DB unavailable)
const inMemoryLicenses = new Map();
const inMemoryLicenseAssignments = new Map();
const inMemoryLicenseRequests = new Map();
const disabledLicenseSubjects = new Set();
const licenseSource = new GroupSnapshotClient();
const licenseAllocator = new LicenseAllocator(db, { source: licenseSource });
const licenseGroups = new GroupLicenseAllocator({ allocator: licenseAllocator, source: licenseSource });
const licenseGroupAuthorization = process.env.LICENSE_GROUP_READ_TOKEN ? `Bearer ${process.env.LICENSE_GROUP_READ_TOKEN}` : null;
const licenseUserAuthorization = process.env.LICENSE_USER_READ_TOKEN ? `Bearer ${process.env.LICENSE_USER_READ_TOKEN}` : null;
const automatedLicenseSources=require('./licenses/SourceCredentials').sources(process.env.LICENSE_SOURCE_CONFIG_FILE);
if(automatedLicenseSources?.groups&&licenseGroupAuthorization||automatedLicenseSources?.users&&licenseUserAuthorization)throw new Error('Choose protected workload source configuration or an explicit legacy bearer, never both');
let licenseLifecycleWorker = null;
const licenseDemoMode = process.env.LICENSE_DEMO_MODE === 'true' && process.env.NODE_ENV !== 'production';

function licenseStorageUnavailable(res) {
  if (licenseDemoMode) return false;
  res.status(503).json({ error: 'License storage unavailable' });
  return true;
}

function allocationFailure(res, error) {
  if (error instanceof LicenseError) { res.status(error.status).json({ error: error.message }); return true; }
  if(error.code==='23514'&&error.constraint==='license_group_directory_lease'){res.status(409).json({error:'Group directory proof expired; reconcile from the directory'});return true;}
  if (error.code === '23514') { res.status(409).json({ error: 'License capacity exceeded' }); return true; }
  if (error.code === '22P02') { res.status(400).json({ error: 'Invalid license or request identifier' }); return true; }
  if (error.noFallback) { res.status(503).json({ error: 'License transaction failed' }); return true; }
  return false;
}

app.use('/api/licenses/company', requireLicenseIdentity, require('./licenses/companyRoutes').companyLicenseRoutes(licenseAllocator));
app.use('/api/licenses', requireLicenseIdentity, licenseBinding(licenseSource));
app.use('/api/licenses/delegations/policies', require('./licenses/scopePolicyRoutes').scopePolicyRoutes(licenseAllocator));
app.use('/api/licenses/delegations/reviews', require('./licenses/scopeReviewRoutes').scopeReviewRoutes(licenseAllocator));
app.use('/api/licenses/delegations/pim', require('./licenses/activationRoutes').activationRoutes(licenseAllocator));
app.use('/api/licenses/delegations', require('./licenses/delegationRoutes').delegationRoutes(licenseAllocator));
app.use('/api/licenses/scoped/pools/:licenseId', require('./licenses/delegationRoutes').scopedLicenseRoutes(licenseAllocator));
app.use('/api/licenses/fulfillment', require('./licenses/fulfillment/routes').fulfillmentRoutes(licenseAllocator));
app.use('/api/licenses/reviews', require('./licenses/reviewRoutes').reviewRoutes(licenseAllocator));
app.use('/api/licenses/:licenseId/grants', require('./licenses/grantRoutes').grantRoutes(licenseAllocator));

app.post('/api/licenses/users/:id/offboard', requireLicensePermission('licenses.subjects.offboard'), async (req, res) => {
  if (!UUID.test(req.params.id)) return res.status(400).json({ error: 'A canonical directory user UUID is required' });
  try {
    res.json(await licenseAllocator.offboard(req.params.id, req.licensePrincipal.userId));
  } catch (error) {
    if (allocationFailure(res, error) || licenseStorageUnavailable(res)) return;
    if (req.licensePrincipal.userId !== req.params.id && disabledMemoryUser(res, req.licensePrincipal.userId)) return;
    disabledLicenseSubjects.add(req.params.id);
    let assignmentsRevoked = 0;
    let requestsCancelled = 0;
    for (const [assignmentId, assignment] of inMemoryLicenseAssignments) {
      if (assignment.assignee_type === 'user' && assignment.assignee_id === req.params.id) {
        inMemoryLicenseAssignments.delete(assignmentId);
        assignmentsRevoked++;
      }
    }
    for (const request of inMemoryLicenseRequests.values()) {
      if (request.status === 'pending' && (request.requester_id === req.params.id || (request.assignee_type === 'user' && request.assignee_id === req.params.id))) {
        Object.assign(request, { status: 'cancelled', decided_at: new Date().toISOString(), decided_by: req.licensePrincipal.userId });
        requestsCancelled++;
      }
    }
    activeMemoryAssignments();
    res.json({ userId: req.params.id, assignmentsRevoked, requestsCancelled, localOnly: true });
  }
});

app.get('/api/licenses/:id/audit', requireLicensePermission('licenses.assignments.read'), async (req, res) => {
  try {
    await licenseAllocator.assertPoolAccess(req.params.id, db, { legacyOnly: true });
    const result = await db.query('SELECT * FROM license_audit_events WHERE license_id = $1 ORDER BY created_at DESC, id DESC LIMIT 200', [req.params.id]);
    res.json({ events: result.rows });
  } catch (error) {
    if (allocationFailure(res, error)) return;
    res.status(503).json({ error: 'License audit storage unavailable' });
  }
});

app.post('/api/licenses/users/:id/activate', requireLicensePermission('licenses.subjects.manage'), async (req, res) => {
  if (!UUID.test(req.params.id)) return res.status(400).json({ error: 'A canonical directory user UUID is required' });
  try {
    res.json(await licenseAllocator.activate(req.params.id, req.licensePrincipal.userId, { authorization: req.headers.authorization, principal: req.licensePrincipal }));
  } catch (error) {
    if (allocationFailure(res, error) || licenseStorageUnavailable(res)) return;
    if (disabledMemoryUser(res, req.licensePrincipal.userId)) return;
    disabledLicenseSubjects.delete(req.params.id);
    res.json({ userId: req.params.id, disabled: false, localOnly: true });
  }
});

function activeMemoryAssignments(licenseId) {
  for (const [assignmentId, assignment] of inMemoryLicenseAssignments) {
    if (assignment.expires_at && Date.parse(assignment.expires_at) <= Date.now()) inMemoryLicenseAssignments.delete(assignmentId);
  }
  for (const license of inMemoryLicenses.values()) {
    license.used_seats = [...inMemoryLicenseAssignments.values()].filter(assignment => assignment.license_id === license.id).length;
  }
  return [...inMemoryLicenseAssignments.values()].filter(assignment => assignment.license_id === licenseId);
}

function disabledMemoryUser(res, actor, assigneeType, assigneeId) {
  if (disabledLicenseSubjects.has(actor) || (assigneeType === 'user' && disabledLicenseSubjects.has(assigneeId))) {
    res.status(403).json({ error: 'License access is disabled for this user' });
    return true;
  }
  return false;
}

app.get('/api/licenses/access', (req, res) => {
  res.json({ subject: req.licensePrincipal?.userId || null, tokenSubject: req.user.sub, identityState: req.licenseIdentityState,
    permissions: req.licensePrincipal ? req.licensePermissions : [], demoMode: licenseDemoMode, groupReconciliationEnabled: Boolean(automatedLicenseSources?.groups||licenseGroupAuthorization) && !licenseDemoMode,
    userReconciliationEnabled: Boolean(automatedLicenseSources?.users||licenseUserAuthorization) && !licenseDemoMode,
    groupReconciliationMode:licenseDemoMode?'disabled':automatedLicenseSources?.groups?'client-credentials':licenseGroupAuthorization?'static-bearer':'disabled' });
});

app.get('/api/licenses/users', requireLicensePermission('licenses.assignments.read'), async (_req, res) => {
  try {
    const result = await db.query(`SELECT user_id,disabled,directory_revision,directory_enabled,directory_deleted,directory_checked_at,directory_attempted_at,directory_error
      FROM license_subjects WHERE business_tenant_id IS NULL AND (directory_revision IS NOT NULL OR directory_error IS NOT NULL) ORDER BY directory_attempted_at DESC NULLS LAST,user_id LIMIT 200`);
    res.json({ users: result.rows, localOnly: true });
  } catch { res.status(503).json({ error: 'User eligibility storage unavailable' }); }
});

app.post('/api/licenses/users/:id/reconcile', requireLicensePermission('licenses.assignments.manage'), async (req, res) => {
  try { res.json(await licenseAllocator.users.reconcile(req.params.id, req.licensePrincipal.userId, { authorization: req.headers.authorization })); }
  catch (error) { if (!allocationFailure(res, error)) res.status(503).json({ error: 'User eligibility reconciliation unavailable' }); }
});

app.get('/api/licenses/groups', requireLicensePermission('licenses.assignments.read'), async (req, res) => {
  try {
    const result = await db.query(`SELECT rules.*,CASE WHEN rules.enabled AND license_source_expiry(rules.grant_id,rules.expires_at)<=license_now()
      THEN CASE WHEN rules.expires_at<=license_now() THEN 'expired' ELSE 'review-expired' END
      WHEN rules.enabled AND observation.grant_id IS NULL THEN 'directory-unobserved'
      WHEN rules.enabled AND observation.source_authorization_deadline<=license_now() THEN 'source-consent-expired'
      WHEN rules.enabled AND observation.valid_until<=license_now() THEN 'directory-stale'
      WHEN rules.enabled AND EXISTS(SELECT 1 FROM license_group_member_leases member WHERE member.grant_id=rules.grant_id AND member.observation_version=observation.version AND member.valid_until<=license_now()) THEN 'membership-expired'
      ELSE rules.status END AS status,observation.observed_at AS directory_observed_at,observation.valid_until AS directory_valid_until,observation.source_authorization_deadline AS source_authorization_valid_until,
      (SELECT min(member.valid_until) FROM license_group_member_leases member WHERE member.grant_id=rules.grant_id AND member.observation_version=observation.version) AS membership_valid_until,
      catalog.name AS license_name,(SELECT COUNT(*)::int FROM license_assignment_sources sources
      WHERE sources.license_id=rules.license_id AND sources.source_type='group' AND sources.source_id=rules.group_id
      AND (license_member_source_expiry(sources.grant_id,sources.user_id,sources.expires_at) IS NULL OR license_member_source_expiry(sources.grant_id,sources.user_id,sources.expires_at)>license_now())) AS assigned_users
      FROM license_group_rules rules JOIN license_catalog catalog ON catalog.id=rules.license_id LEFT JOIN license_group_observations observation ON observation.grant_id=rules.grant_id WHERE catalog.business_tenant_id IS NULL ORDER BY catalog.name,rules.group_id`);
    res.set('Cache-Control', 'no-store').json({ groups: result.rows, localOnly: true });
  } catch { res.status(503).json({ error: 'Group allocation storage unavailable' }); }
});

app.post('/api/licenses/:id/groups/:groupId/reconcile', requireLicensePermission('licenses.assignments.manage'), async (req, res) => {
  try {
    const result = await licenseGroups.reconcile(req.params.id, req.params.groupId, req.licensePrincipal.userId, { authorization: req.headers.authorization, principal: req.licensePrincipal });
    res.status(result.rule.status === 'capacity-blocked' ? 202 : 200).json(result);
  } catch (error) {
    if (!allocationFailure(res, error)) res.status(503).json({ error: 'Group reconciliation unavailable' });
  }
});

// Seed demo licenses
(function seedLicenses() {
  if (!licenseDemoMode) return;
  const demos = [
    {
      id: 'lic-demo-1',
      name: 'Microsoft 365 Business',
      vendor: 'Microsoft',
      category: 'Productivity',
      license_type: 'per_user',
      total_seats: 50,
      used_seats: 0,
      cost_per_seat: 12.50,
      currency: 'CHF',
      renewal_date: null,
      auto_approve: false,
      description: 'Office-Suite inkl. Exchange, Teams, SharePoint',
      icon_url: null,
      notes: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'lic-demo-2',
      name: 'Adobe Creative Cloud',
      vendor: 'Adobe',
      category: 'Design',
      license_type: 'per_user',
      total_seats: 10,
      used_seats: 0,
      cost_per_seat: 60.00,
      currency: 'CHF',
      renewal_date: null,
      auto_approve: false,
      description: 'Photoshop, Illustrator, Premiere Pro, und mehr',
      icon_url: null,
      notes: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'lic-demo-3',
      name: 'JetBrains All Products',
      vendor: 'JetBrains',
      category: 'Developer',
      license_type: 'per_user',
      total_seats: 20,
      used_seats: 0,
      cost_per_seat: 25.00,
      currency: 'CHF',
      renewal_date: null,
      auto_approve: true,
      description: 'IntelliJ, WebStorm, PyCharm, Rider und alle IDEs',
      icon_url: null,
      notes: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];
  for (const lic of demos) {
    inMemoryLicenses.set(lic.id, lic);
  }
})();


// ── Catalog (admin) ───────────────────────────────────────────────────────────

// GET /api/licenses — list all licenses with used_seats count
app.get('/api/licenses', requireLicensePermission('licenses.catalog.read'), async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT lc.*,
             COALESCE(COUNT(la.id), 0)::int AS used_seats
      FROM license_catalog lc
      LEFT JOIN license_assignments la ON la.license_id = lc.id AND (la.expires_at IS NULL OR la.expires_at > license_now())
      WHERE lc.business_tenant_id IS NULL
      GROUP BY lc.id
      ORDER BY lc.name ASC
    `);
    res.json({ licenses: result.rows, total: result.rows.length });
  } catch (err) {
    if (err.code === '23514') return res.status(409).json({ error: 'Capacity cannot be reduced below active assignments' });
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable for licenses list, using in-memory', { error: err.message });
    activeMemoryAssignments();
    const licenses = [...inMemoryLicenses.values()];
    res.json({ licenses, total: licenses.length });
  }
});

// GET /api/licenses/kiosk — public self-service catalog (hides cost/notes)
app.get('/api/licenses/kiosk', async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT lc.id, lc.name, lc.vendor, lc.category, lc.license_type,
             lc.total_seats, lc.auto_approve, lc.description, lc.icon_url,
             COALESCE(COUNT(la.id), 0)::int AS used_seats,
             (lc.total_seats - COALESCE(COUNT(la.id), 0))::int AS available_seats
      FROM license_catalog lc
      LEFT JOIN license_assignments la ON la.license_id = lc.id AND (la.expires_at IS NULL OR la.expires_at > license_now())
      WHERE lc.business_tenant_id IS NULL
      GROUP BY lc.id
      ORDER BY lc.name ASC
    `);
    res.json({ licenses: result.rows, total: result.rows.length });
  } catch (err) {
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable for kiosk, using in-memory', { error: err.message });
    activeMemoryAssignments();
    const licenses = [...inMemoryLicenses.values()].map(license => ({
      id: license.id,
      name: license.name,
      vendor: license.vendor,
      category: license.category,
      license_type: license.license_type,
      total_seats: license.total_seats,
      used_seats: license.used_seats,
      auto_approve: license.auto_approve,
      description: license.description,
      icon_url: license.icon_url,
      available_seats: license.total_seats - license.used_seats,
    }));
    res.json({ licenses, total: licenses.length });
  }
});

// GET /api/licenses/requests — list license requests (query: ?status=pending)
app.get('/api/licenses/requests', async (req, res) => {
  try {
    const { status } = req.query;
    const params = [];
    const filters = ['license_id IN (SELECT id FROM license_catalog WHERE business_tenant_id IS NULL)'];
    if (status) {
      params.push(status);
      filters.push(`status = $${params.length}`);
    }
    if (!req.licensePermissions.includes('licenses.requests.read')) {
      params.push(req.licensePrincipal.userId);
      filters.push(`identity_bound = true AND requester_id = $${params.length}`);
    }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    const result = await db.query(
      `SELECT * FROM license_requests ${where} ORDER BY requested_at DESC`,
      params
    );
    res.json({ requests: result.rows, total: result.rows.length });
  } catch (err) {
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable for license requests, using in-memory', { error: err.message });
    let requests = [...inMemoryLicenseRequests.values()];
    if (!req.licensePermissions.includes('licenses.requests.read')) {
      requests = requests.filter(request => request.identity_bound === true && request.requester_id === req.licensePrincipal.userId);
    }
    if (req.query.status) {
      requests = requests.filter(r => r.status === req.query.status);
    }
    res.json({ requests, total: requests.length });
  }
});

app.get('/api/licenses/:id', requireLicensePermission('licenses.catalog.read'), async (req, res) => {
  try {
    const result = await db.query(`SELECT catalog.*,COALESCE(COUNT(assignment.id),0)::int AS used_seats
      FROM license_catalog catalog LEFT JOIN license_assignments assignment ON assignment.license_id=catalog.id
      AND (assignment.expires_at IS NULL OR assignment.expires_at>license_now())
      WHERE catalog.id=$1 AND catalog.business_tenant_id IS NULL GROUP BY catalog.id`, [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'License not found' });
    res.json(result.rows[0]);
  } catch (error) {
    if (allocationFailure(res, error) || licenseStorageUnavailable(res)) return;
    activeMemoryAssignments();
    const license = inMemoryLicenses.get(req.params.id);
    if (!license) return res.status(404).json({ error: 'License not found' });
    res.json(license);
  }
});

// POST /api/licenses — create license
app.post('/api/licenses', requireLicensePermission('licenses.catalog.manage'), async (req, res) => {
  if (['business_tenant_id', 'business_revision', 'tenantId'].some(field => Object.hasOwn(req.body, field))) return res.status(400).json({ error: 'Legacy catalog cannot select company ownership' });
  const { name, vendor, category, license_type, total_seats, cost_per_seat, currency, renewal_date, auto_approve, description } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  if (total_seats != null && (!Number.isInteger(total_seats) || total_seats < 0 || total_seats > 2147483647)) return res.status(400).json({ error: 'total_seats must be a nonnegative integer' });

  try {
    const result = await db.query(
      `INSERT INTO license_catalog
         (name, vendor, category, license_type, total_seats, cost_per_seat, currency, renewal_date, auto_approve, description)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING *`,
      [
        name,
        vendor || null,
        category || 'Software',
        license_type || 'per_user',
        total_seats || 0,
        cost_per_seat || null,
        currency || 'CHF',
        renewal_date || null,
        auto_approve || false,
        description || null,
      ]
    );
    logger.info(`License created: ${name}`, { id: result.rows[0].id });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable, storing license in memory', { error: err.message });
    const id = `lic-${randomUUID()}`;
    const license = {
      id, name,
      vendor: vendor || null,
      category: category || 'Software',
      license_type: license_type || 'per_user',
      total_seats: total_seats || 0,
      used_seats: 0,
      cost_per_seat: cost_per_seat || null,
      currency: currency || 'CHF',
      renewal_date: renewal_date || null,
      auto_approve: auto_approve || false,
      description: description || null,
      icon_url: null,
      notes: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    inMemoryLicenses.set(id, license);
    res.status(201).json(license);
  }
});

// PUT /api/licenses/:id — update license
app.put('/api/licenses/:id', requireLicensePermission('licenses.catalog.manage'), async (req, res) => {
  if (['business_tenant_id', 'business_revision', 'tenantId'].some(field => Object.hasOwn(req.body, field))) return res.status(400).json({ error: 'Legacy catalog cannot select company ownership' });
  const { name, vendor, category, license_type, total_seats, cost_per_seat, currency, renewal_date, auto_approve, description, notes, icon_url } = req.body;
  if (total_seats != null && (!Number.isInteger(total_seats) || total_seats < 0 || total_seats > 2147483647)) return res.status(400).json({ error: 'total_seats must be a nonnegative integer' });
  try {
    const result = await db.query(
      `UPDATE license_catalog SET
         name = COALESCE($1, name),
         vendor = COALESCE($2, vendor),
         category = COALESCE($3, category),
         license_type = COALESCE($4, license_type),
         total_seats = COALESCE($5, total_seats),
         cost_per_seat = COALESCE($6, cost_per_seat),
         currency = COALESCE($7, currency),
         renewal_date = COALESCE($8, renewal_date),
         auto_approve = COALESCE($9, auto_approve),
         description = COALESCE($10, description),
         notes = COALESCE($11, notes),
         icon_url = COALESCE($12, icon_url),
         updated_at = NOW()
       WHERE id = $13 AND business_tenant_id IS NULL
       RETURNING *`,
      [
        name || null, vendor || null, category || null, license_type || null,
        total_seats != null ? total_seats : null,
        cost_per_seat != null ? cost_per_seat : null,
        currency || null, renewal_date || null,
        auto_approve != null ? auto_approve : null,
        description || null, notes || null, icon_url || null,
        req.params.id,
      ]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'License not found' });
    res.json(result.rows[0]);
  } catch (err) {
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable, updating in-memory license', { error: err.message });
    const lic = inMemoryLicenses.get(req.params.id);
    if (!lic) return res.status(404).json({ error: 'License not found' });
    if (total_seats > 0 && activeMemoryAssignments(req.params.id).length > total_seats) return res.status(409).json({ error: 'Capacity cannot be reduced below active assignments' });
    const updated = {
      ...lic,
      ...(name != null && { name }),
      ...(vendor != null && { vendor }),
      ...(category != null && { category }),
      ...(license_type != null && { license_type }),
      ...(total_seats != null && { total_seats }),
      ...(cost_per_seat != null && { cost_per_seat }),
      ...(currency != null && { currency }),
      ...(renewal_date != null && { renewal_date }),
      ...(auto_approve != null && { auto_approve }),
      ...(description != null && { description }),
      ...(notes != null && { notes }),
      ...(icon_url != null && { icon_url }),
      updated_at: new Date().toISOString(),
    };
    inMemoryLicenses.set(req.params.id, updated);
    res.json(updated);
  }
});

// DELETE /api/licenses/:id — delete license
app.delete('/api/licenses/:id', requireLicensePermission('licenses.catalog.manage'), async (req, res) => {
  try {
    const result = await db.query(
      'DELETE FROM license_catalog WHERE id = $1 AND business_tenant_id IS NULL RETURNING id',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'License not found' });
    res.status(204).send();
  } catch (err) {
    if (err.code === '23503') return res.status(409).json({ error: 'License has retained governance history' });
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable, deleting in-memory license', { error: err.message });
    if (!inMemoryLicenses.has(req.params.id)) return res.status(404).json({ error: 'License not found' });
    inMemoryLicenses.delete(req.params.id);
    // Remove associated assignments and requests
    for (const [k, v] of inMemoryLicenseAssignments.entries()) {
      if (v.license_id === req.params.id) inMemoryLicenseAssignments.delete(k);
    }
    for (const [k, v] of inMemoryLicenseRequests.entries()) {
      if (v.license_id === req.params.id) inMemoryLicenseRequests.delete(k);
    }
    res.status(204).send();
  }
});

// ── Assignments (admin) ───────────────────────────────────────────────────────

// GET /api/licenses/:id/assignments — list who has this license
app.get('/api/licenses/:id/assignments', requireLicensePermission('licenses.assignments.read'), async (req, res) => {
  try {
    await licenseAllocator.assertPoolAccess(req.params.id, db, { legacyOnly: true });
    const result = await db.query(
      `SELECT assignments.*,COALESCE((SELECT jsonb_agg(jsonb_build_object('type',sources.source_type,'id',sources.source_id,'expires_at',license_member_source_expiry(sources.grant_id,sources.user_id,sources.expires_at)))
        FROM license_assignment_sources sources WHERE assignments.assignee_type='user' AND sources.license_id=assignments.license_id
        AND sources.user_id=assignments.assignee_id AND (license_member_source_expiry(sources.grant_id,sources.user_id,sources.expires_at) IS NULL OR license_member_source_expiry(sources.grant_id,sources.user_id,sources.expires_at)>license_now())),'[]'::jsonb) AS sources
        FROM license_assignments assignments WHERE license_id=$1 AND (expires_at IS NULL OR expires_at>license_now()) ORDER BY assigned_at DESC`,
      [req.params.id]
    );
    res.json({ assignments: result.rows, total: result.rows.length });
  } catch (err) {
    if (allocationFailure(res, err)) return;
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable for assignments list, using in-memory', { error: err.message });
    const assignments = activeMemoryAssignments(req.params.id);
    res.json({ assignments, total: assignments.length });
  }
});

// POST /api/licenses/:id/assign — assign license to user/group/device
app.post('/api/licenses/:id/assign', requireLicensePermission('licenses.assignments.manage'), async (req, res) => {
  const { assignee_type, assignee_id, assignee_name, expires_at } = req.body;
  const assigned_by = req.licensePrincipal.userId;
  if (assignee_type === 'user' && (typeof assignee_id !== 'string' || !UUID.test(assignee_id))) return res.status(400).json({ error: 'A canonical directory user UUID is required' });
  if (expires_at != null && (!Number.isFinite(Date.parse(expires_at)) || Date.parse(expires_at) <= Date.now())) return res.status(400).json({ error: 'expires_at must be a future timestamp' });
  if (!assignee_type || !assignee_id) {
    return res.status(400).json({ error: 'assignee_type and assignee_id are required' });
  }
  const validTypes = ['user', 'group', 'device'];
  if (!validTypes.includes(assignee_type)) {
    return res.status(400).json({ error: `assignee_type must be one of: ${validTypes.join(', ')}` });
  }

  try {
    const assignment = await licenseAllocator.assign(req.params.id, { assignee_type, assignee_id, assignee_name, expires_at }, assigned_by, { authorization: req.headers.authorization, principal: req.licensePrincipal });
    res.status(assignment.kind === 'group' && assignment.rule.status !== 'active' ? 202 : 201).json(assignment);
  } catch (err) {
    if (allocationFailure(res, err)) return;
    if (assignee_type === 'group') return res.status(503).json({ error: 'Group allocation requires persistent source reconciliation' });
    if (err.code === '23505') {
      return res.status(409).json({ error: 'This assignee already has this license' });
    }
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable, assigning in-memory', { error: err.message });
    const lic = inMemoryLicenses.get(req.params.id);
    if (!lic) return res.status(404).json({ error: 'License not found' });

    // Check seats
    if (disabledMemoryUser(res, assigned_by, assignee_type, assignee_id)) return;
    const currentAssignments = activeMemoryAssignments(req.params.id);
    if (lic.total_seats > 0 && currentAssignments.length >= lic.total_seats) {
      return res.status(409).json({ error: 'No seats available for this license' });
    }
    // Check duplicate
    const dup = currentAssignments.find(a => a.assignee_type === assignee_type && a.assignee_id === assignee_id);
    if (dup) return res.status(409).json({ error: 'This assignee already has this license' });

    const id = `lasgn-${randomUUID()}`;
    const assignment = {
      id,
      license_id: req.params.id,
      assignee_type,
      assignee_id,
      assignee_name: assignee_name || null,
      assigned_at: new Date().toISOString(),
      assigned_by: assigned_by || null,
      expires_at: expires_at || null,
    };
    inMemoryLicenseAssignments.set(id, assignment);
    lic.used_seats = (lic.used_seats || 0) + 1;
    inMemoryLicenses.set(req.params.id, lic);
    res.status(201).json(assignment);
  }
});

// DELETE /api/licenses/:id/assignments/:assigneeId — revoke assignment
app.delete('/api/licenses/:id/assignments/:assigneeId', requireLicensePermission('licenses.assignments.manage'), async (req, res) => {
  try {
    await licenseAllocator.revoke(req.params.id, req.params.assigneeId, req.licensePrincipal.userId, req.query.assignee_type);
    res.status(204).send();
  } catch (err) {
    if (allocationFailure(res, err)) return;
    if (req.query.assignee_type === 'group') return res.status(503).json({ error: 'Group source revocation storage unavailable' });
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable, revoking in-memory assignment', { error: err.message });
    let found = false;
    for (const [k, v] of inMemoryLicenseAssignments.entries()) {
      if (v.license_id === req.params.id && v.assignee_id === req.params.assigneeId) {
        inMemoryLicenseAssignments.delete(k);
        found = true;
        break;
      }
    }
    if (!found) return res.status(404).json({ error: 'Assignment not found' });
    const lic = inMemoryLicenses.get(req.params.id);
    if (lic) {
      lic.used_seats = Math.max((lic.used_seats || 0) - 1, 0);
      inMemoryLicenses.set(req.params.id, lic);
    }
    res.status(204).send();
  }
});

// ── Kiosk / Requests ──────────────────────────────────────────────────────────

// POST /api/licenses/:id/request — user requests a license
app.post('/api/licenses/:id/request', async (req, res) => {
  const { justification, assignee_type, assignee_id, assignee_name } = req.body;
  const requester_id = req.licensePrincipal.userId;
  const requester_name = req.user.name || req.user.preferred_username || requester_id;
  const effectiveAssigneeType = assignee_type || 'user';
  const effectiveAssigneeId = assignee_id || requester_id;
  const effectiveAssigneeName = assignee_name || requester_name;
  if (!['user', 'group', 'device'].includes(effectiveAssigneeType)) {
    return res.status(400).json({ error: 'Invalid assignee_type' });
  }
  if (effectiveAssigneeType === 'user' && (typeof effectiveAssigneeId !== 'string' || !UUID.test(effectiveAssigneeId))) return res.status(400).json({ error: 'A canonical directory user UUID is required' });
  const delegated = effectiveAssigneeType !== 'user' || effectiveAssigneeId !== requester_id;
  if (delegated && !req.licensePermissions.includes('licenses.requests.delegate')) {
    return res.status(403).json({ error: 'Cannot request a license for another assignee' });
  }

  try {
    const result = await licenseAllocator.request(req.params.id, { requester_id, requester_name, justification,
      assignee_type: effectiveAssigneeType, assignee_id: effectiveAssigneeId, assignee_name: effectiveAssigneeName }, { authorization: req.headers.authorization, principal: req.licensePrincipal });
    res.status(result.created ? 201 : 200).json(result.record);
  } catch (err) {
    if (allocationFailure(res, err)) return;
    if (effectiveAssigneeType === 'group') return res.status(503).json({ error: 'Group requests require persistent source reconciliation' });
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable, processing license request in-memory', { error: err.message });
    const lic = inMemoryLicenses.get(req.params.id);
    if (!lic) return res.status(404).json({ error: 'License not found' });

    if (disabledMemoryUser(res, requester_id, effectiveAssigneeType, effectiveAssigneeId)) return;
    const assignments = activeMemoryAssignments(req.params.id);
    const assigned = assignments.some(assignment => assignment.assignee_type === effectiveAssigneeType && assignment.assignee_id === effectiveAssigneeId);
    const existing = [...inMemoryLicenseRequests.values()].find(request => request.identity_bound === true && request.license_id === req.params.id && request.requester_id === requester_id
      && request.assignee_type === effectiveAssigneeType && request.assignee_id === effectiveAssigneeId && (request.status === 'pending' || (assigned && request.status === 'approved')));
    if (existing) return res.status(200).json(existing);
    if (assigned) return res.status(409).json({ error: 'This assignee already has this license' });
    const seatsAvailable = lic.total_seats === 0 || assignments.length < lic.total_seats;
    const id = `lreq-${randomUUID()}`;
    const now = new Date().toISOString();

    if (lic.auto_approve && seatsAvailable) {
      // Create in-memory assignment
      const aId = `lasgn-${randomUUID()}`;
      inMemoryLicenseAssignments.set(aId, {
        id: aId,
        license_id: req.params.id,
        assignee_type: effectiveAssigneeType,
        assignee_id: effectiveAssigneeId,
        assignee_name: effectiveAssigneeName,
        assigned_at: now,
        assigned_by: requester_id,
        expires_at: null,
      });
      lic.used_seats = (lic.used_seats || 0) + 1;
      inMemoryLicenses.set(req.params.id, lic);

      const request = {
        id, license_id: req.params.id, license_name: lic.name,
        requester_id, requester_name: requester_name || null,
        identity_bound: true, requester_issuer: req.licensePrincipal.issuer, requester_subject: req.licensePrincipal.subject,
        assignee_type: effectiveAssigneeType, assignee_id: effectiveAssigneeId, assignee_name: effectiveAssigneeName,
        justification: justification || null,
        status: 'approved',
        requested_at: now, decided_at: now, decided_by: 'auto-approve',
      };
      inMemoryLicenseRequests.set(id, request);
      return res.status(201).json(request);
    }

    const request = {
      id, license_id: req.params.id, license_name: lic.name,
      requester_id, requester_name: requester_name || null,
      identity_bound: true, requester_issuer: req.licensePrincipal.issuer, requester_subject: req.licensePrincipal.subject,
      assignee_type: effectiveAssigneeType, assignee_id: effectiveAssigneeId, assignee_name: effectiveAssigneeName,
      justification: justification || null,
      status: 'pending',
      requested_at: now, decided_at: null, decided_by: null,
    };
    inMemoryLicenseRequests.set(id, request);
    res.status(201).json(request);
  }
});

// POST /api/licenses/requests/:id/approve — admin approves request
app.post('/api/licenses/requests/:id/approve', requireLicensePermission('licenses.requests.review'), async (req, res) => {
  const decided_by = req.licensePrincipal.userId;
  try {
    res.json(await licenseAllocator.review(req.params.id, decided_by, 'approved', { authorization: req.headers.authorization, principal: req.licensePrincipal }));
  } catch (err) {
    if (allocationFailure(res, err)) return;
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable, approving in-memory request', { error: err.message });
    const licReq = inMemoryLicenseRequests.get(req.params.id);
    if (!licReq) return res.status(404).json({ error: 'Request not found' });
    try { validateRequestIdentity(licReq); } catch (error) { return res.status(error.status).json({ error: error.message }); }
    if (disabledMemoryUser(res, decided_by, licReq.assignee_type, licReq.assignee_id) || disabledMemoryUser(res, licReq.requester_id)) return;
    if (isOwnLicenseRequest(decided_by, licReq)) {
      return res.status(403).json({ error: 'Cannot review your own license request' });
    }
    if (licReq.status !== 'pending') return res.status(409).json({ error: `Request is already ${licReq.status}` });

    const lic = inMemoryLicenses.get(licReq.license_id);
    if (!lic) return res.status(404).json({ error: 'License not found' });
    const currentAssignments = activeMemoryAssignments(licReq.license_id);
    const alreadyAssigned = currentAssignments.some(assignment => assignment.assignee_type === licReq.assignee_type && assignment.assignee_id === licReq.assignee_id);
    if (!alreadyAssigned && lic.total_seats > 0 && currentAssignments.length >= lic.total_seats) {
      return res.status(409).json({ error: 'No seats available for this license' });
    }

    const aId = `lasgn-${randomUUID()}`;
    const now = new Date().toISOString();
    if (!alreadyAssigned) inMemoryLicenseAssignments.set(aId, {
      id: aId,
      license_id: licReq.license_id,
      assignee_type: licReq.assignee_type,
      assignee_id: licReq.assignee_id,
      assignee_name: licReq.assignee_name,
      assigned_at: now,
      assigned_by: decided_by || 'admin',
      expires_at: null,
    });
    lic.used_seats = currentAssignments.length + (alreadyAssigned ? 0 : 1);
    inMemoryLicenses.set(licReq.license_id, lic);

    const updated = { ...licReq, status: 'approved', decided_at: now, decided_by: decided_by || 'admin' };
    inMemoryLicenseRequests.set(req.params.id, updated);
    res.json(updated);
  }
});

// POST /api/licenses/requests/:id/deny — admin denies request
app.post('/api/licenses/requests/:id/deny', requireLicensePermission('licenses.requests.review'), async (req, res) => {
  const decided_by = req.licensePrincipal.userId;
  try {
    res.json(await licenseAllocator.review(req.params.id, decided_by, 'denied', { authorization: req.headers.authorization, principal: req.licensePrincipal }));
  } catch (err) {
    if (allocationFailure(res, err)) return;
    if (licenseStorageUnavailable(res)) return;
    logger.warn('DB unavailable, denying in-memory request', { error: err.message });
    const licReq = inMemoryLicenseRequests.get(req.params.id);
    if (!licReq) return res.status(404).json({ error: 'Request not found' });
    try { validateRequestIdentity(licReq); } catch (error) { return res.status(error.status).json({ error: error.message }); }
    if (disabledMemoryUser(res, decided_by, licReq.assignee_type, licReq.assignee_id) || disabledMemoryUser(res, licReq.requester_id)) return;
    if (isOwnLicenseRequest(decided_by, licReq)) {
      return res.status(403).json({ error: 'Cannot review your own license request' });
    }
    if (licReq.status !== 'pending') return res.status(409).json({ error: `Request is already ${licReq.status}` });

    const now = new Date().toISOString();
    const updated = { ...licReq, status: 'denied', decided_at: now, decided_by: decided_by || 'admin' };
    inMemoryLicenseRequests.set(req.params.id, updated);
    res.json(updated);
  }
});

// ============================
// Startup
// ============================
async function start() {
  let licenseSchemaReady = false;
  try {
    // Test database connection
    const connected = await db.testConnection();
    if (!connected) {
      logger.warn('Database not available – service will start but DB features will fail');
    } else {
      // Run migrations
      await db.runMigrations();
      licenseSchemaReady = true;
      logger.info('Database migrations applied');
    }
  } catch (err) {
    logger.error('Database initialization error', { error: err.message });
    logger.warn('Starting service without database – some features will be unavailable');
  }

  if (process.env.NODE_ENV === 'production' && !licenseSchemaReady) {
    logger.error('Production policy-service requires a migrated database');
    await db.shutdown();
    process.exitCode = 1;
    return;
  }

  // Pre-load templates
  loadTemplates();

  try {
    await connectBus();
  } catch (error) { logger.warn('Event bus connection pending', { error: error.message }); }
  if (licenseSchemaReady && !licenseDemoMode) {
    try {
      licenseLifecycleWorker = new LicenseLifecycleWorker({ allocator: licenseAllocator, bus: _bus, logger, groups: licenseGroups, groupAuthorization: automatedLicenseSources?.groups||licenseGroupAuthorization,
        users: licenseAllocator.users, userAuthorization: automatedLicenseSources?.users||licenseUserAuthorization });
      await licenseLifecycleWorker.start();
    } catch (error) { logger.warn('License lifecycle worker startup failed', { error: error.message }); }
  }

  try {
    const ComplianceSaga = require('./application/ComplianceSaga');
    const PolicyApplicationService = require('./application/PolicyApplicationService');
    const PostgresPolicyRepository = require('./infrastructure/repositories/PostgresPolicyRepository');
    const policyAppService = new PolicyApplicationService({ policyRepository: new PostgresPolicyRepository(db), messageBus: _bus, logger });
    const _complianceSaga = new ComplianceSaga({ messageBus: _bus, policyApplicationService: policyAppService, logger });
    setTimeout(() => _complianceSaga.start(), 4000);
  } catch (e) { logger.warn('[saga] ComplianceSaga not available: ' + e.message); }

  app.listen(PORT, () => {
    logger.info(`Policy Service running on port ${PORT}`);
  });
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  licenseLifecycleWorker?.stop();
  logger.info('SIGTERM received – shutting down');
  await db.shutdown();
  process.exit(0);
});

process.on('SIGINT', async () => {
  licenseLifecycleWorker?.stop();
  logger.info('SIGINT received – shutting down');
  await db.shutdown();
  process.exit(0);
});

if (require.main === module) start();

module.exports = app;
