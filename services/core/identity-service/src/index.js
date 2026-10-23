const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { authorityAdmission } = require('./AuthorityAdmission');
const winston = require('winston');
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const db = require('./db');
const { oidcAuth } = require('./middleware/oidcAuth');
const { requireIdentityAccess } = require('./middleware/identityAccess');
const { GroupSnapshotStore } = require('./GroupSnapshotStore');
const { userEtag } = require('./DirectoryUsers');
const {GroupMutator,groupEtag}=require('./GroupMutator');
const groupMutator=new GroupMutator(db);
const { OuMutator, ouEtag } = require('./OuMutator');
const ouMutator = new OuMutator(db);
const directoryReader = new (require('./DirectoryReader').DirectoryReader)(db);
const directoryCreator = new (require('./DirectoryCreator').DirectoryCreator)(db);
const userMutator = new (require('./UserMutator').UserMutator)(db);
const deviceInventoryAuthority = new (require('./DeviceInventoryAuthority').DeviceInventoryAuthority)(db);
const deviceOffboardingAuthority = new (require('./DeviceOffboardingAuthority').DeviceOffboardingAuthority)(db);
const companyLicenseAuthority = new (require('./CompanyLicenseAuthority').CompanyLicenseAuthority)(db);
const companyBlueprintAuthority = new (require('./CompanyBlueprintAuthority').CompanyBlueprintAuthority)(db);
const companyBlueprintAssignmentAuthority = new (require('./CompanyBlueprintAssignmentAuthority').CompanyBlueprintAssignmentAuthority)(db);
const companyOffboarding = new (require('./CompanyOffboarding').CompanyOffboarding)(db);
const companyOffboardingGroups = new (require('./CompanyOffboardingGroups').CompanyOffboardingGroups)(db);
const companyOffboardingAccess = new (require('./CompanyOffboardingAccess').CompanyOffboardingAccess)(db);
const snapshotBoundary = new (require('./SnapshotBoundary').SnapshotBoundary)(db);
function snapshotDatabase(req,permission,{self=false,kind='user',write=false,workload=false,companyGroup=false}={}){
  if(Object.keys(req.query).length || Object.keys(req.body || {}).length || req.headers['x-api-key'])throw Object.assign(new Error('Exact snapshot request required'),{status:400});
  return snapshotBoundary.scoped({user:req.user,authorization:req.headers.authorization,id:req.params.id,kind,permission,self,write,workload,companyGroup});
}
const { AuthorizationState, authorizationRequest, authorizationTargetRequest } = require('./AuthorizationState');
const authorizationState = new AuthorizationState(db);
const subjectLinks = new (require('./SubjectLinks').SubjectLinks)(db);
const { DirectoryRoles } = require('./DirectoryRoles');
const { ROLES, PROTECTED } = require('../../../../packages/directory-role-contract');
const directoryRoles = new DirectoryRoles(db);
const { RoleAuthentication, policyEtag } = require('./RoleAuthentication');
const roleAuthentication = new RoleAuthentication(db);
const { PrivilegedAccessPolicy, activationEtag } = require('./PrivilegedAccessPolicy');
const privilegedAccessPolicy = new PrivilegedAccessPolicy(db);
const { RoleReviews } = require('./RoleReviews');
const { roleReviewRoutes } = require('./RoleReviewRoutes');
const roleReviews = new RoleReviews(db);
const { PrivilegedActivation, authority: pimAuthority, fields: pimFields } = require('./PrivilegedActivation');
const privilegedActivation = new PrivilegedActivation(db);
const organizationProfile = new (require('./OrganizationProfile').OrganizationProfile)(db);
const organizationDelegations = new (require('./OrganizationDelegations').OrganizationDelegations)(db);
const companyReviews = new (require('./CompanyRegistrationReviews').CompanyRegistrationReviews)(db);
const companyRegistrations = new (require('./CompanyRegistrations').CompanyRegistrations)(db);

// ─── Event Bus ───────────────────────────────────────────────────────────────
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();
const _bus = new EventBusClient({ source: 'identity-service' });
async function connectBus() { await _bus.connect(); }
function publish(routingKey, payload) { _bus.publish(routingKey, payload).catch(() => {}); }

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
const authorityLimits = authorityAdmission();
app.post('/internal/identity/employee-invitations/observe',authorityLimits.ingress,express.json({limit:'32kb'}),
 require('./EmployeeInvitationRequest').invitationRequest()('observe','/internal/identity/employee-invitations/observe'),
 asyncRoute(async(req,res)=>{
  try{res.set('Cache-Control','no-store').json(await new(require('./EmployeeInvitationObserver').EmployeeInvitationObserver)(db).read(req.body,req.employeeInvitationProof));}
  catch(error){res.set('Cache-Control','no-store').status(error.status||503).json({error:error.code||'employee_invitation_observation_unavailable'});}
 }));
const registrationRequest = require('./CompanyRegistrations').registrationRequest();
for (const operation of ['submit', 'status', 'activate']) app.post('/internal/identity/company-registrations/' + operation,
  authorityLimits.ingress, express.json({ limit: '32kb' }), registrationRequest(operation), authorityLimits.verified, asyncRoute(async (req, res) => {
    try {
      const receipt = await companyRegistrations.receive(operation, req.registrationInput, req.registrationProof);
      res.set('Cache-Control', 'no-store').status(operation === 'submit' && !receipt.replayed ? 201 : 200).json(receipt);
    } catch (error) {
      logger.warn('Company registration receiving failed', { error: error.cause?.message || error.message });
      res.set('Cache-Control', 'no-store').status(error.status || 503).json({ error: error.code || 'company_registration_unavailable' });
    }
  }));
app.post('/internal/identity/authorization-state', authorityLimits.ingress, express.json({ limit: '4kb' }), authorizationRequest(), authorityLimits.verified, asyncRoute(async (req, res) => {
  try { res.json(await authorizationState.state(req.authorityIssuer, req.body.subject)); }
  catch { res.status(503).json({ error: 'identity_authority_unavailable' }); }
}));
app.post('/internal/identity/company-console', authorityLimits.ingress, express.json({ limit: '4kb' }), authorizationRequest({ companyConsole: true }), authorityLimits.verified, asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store').json(await authorizationState.companyConsole(req.authorityIssuer, req.body.clientId, req.body.userId));
}));
app.post('/internal/identity/application-target', authorityLimits.ingress, express.json({ limit: '4kb' }), authorizationTargetRequest(), authorityLimits.verified, asyncRoute(async (req, res) => {
  try { res.json(await authorizationState.target(req.body.targetType, req.body.targetId, req.body.actorUserId)); }
  catch { res.status(503).json({ error: 'identity_authority_unavailable' }); }
}));
app.post('/internal/identity/company-app-tenant',authorityLimits.ingress,express.json({limit:'4kb'}),authorizationRequest({companyAppTenant:true}),authorityLimits.verified,asyncRoute(async(req,res)=>{
  res.set('Cache-Control','no-store').json(await authorizationState.companyAppTenant(req.body.clientId,req.body.tenant));
}));
const automationLimits=require('../../../../packages/company-automation-admission').automationAdmission(rateLimit,{issuer:process.env.OIDC_ISSUER||'http://localhost:3001',paths:['/api/identity/automation/run','/api/identity/automation/watch-source','/api/identity/automation/license-source']});
app.use(automationLimits.ingress);
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 1000, skip:automationLimits.matches }));
app.use(express.json({ limit: '10mb' }));

// ─── Auth ─────────────────────────────────────────────────────────────────────
//
app.use(oidcAuth({ skipPaths: ['/health'] }));
app.use(automationLimits.verified);
app.use('/api', asyncRoute(async (req, _res, next) => {
  const path = req.path.replace(/\/$/, '');
  if (req.method === 'GET' && path === '/identity/access' || /^\/identity\/organization(?:\/delegations(?:\/[a-f0-9-]{36}\/revoke)?)?$/.test(path)) {
    req.organizationPermissions = await organizationDelegations.permissions(req.user);
  }
  if (req.method === 'GET' && path === '/identity/access' || /^\/identity\/company-registrations(?:\/[a-f0-9-]{36}(?:\/review)?)?$/.test(path)) {
    req.companyRegistrationPermissions = await companyReviews.permissions(req.user);
  }
  if (req.method === 'GET' && path === '/identity/access' || /^\/(?:users(?:\/[a-f0-9-]{36})?|groups(?:\/[a-f0-9-]{36}(?:\/members(?:\/[a-f0-9-]{36})?)?)?|ous(?:\/[a-f0-9-]{36}(?:\/members(?:\/[a-f0-9-]{36})?)?)?|identity\/search)$/.test(path)) {
    req.companyDirectoryPermissions = db.isAvailable() ? await db.transaction(client => require('./CompanyOwner').companyDirectoryPermissions(client, req.user), { readOnly: true }) : [];
  }
  next();
}));
for (const method of ['get', 'post']) app[method]('/api/identity/company-blueprint-assignments', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (req.method !== method.toUpperCase()) return res.status(404).json({ error: 'Not found' });
  if (Object.keys(req.query).length || req.headers['x-api-key'] !== undefined || method === 'get' && (Array.isArray(req.body) || Object.keys(req.body || {}).length
    || Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding'] !== undefined)) return res.status(400).json({ error: 'Exact company blueprint assignment source request required' });
  if (req.user?.actor_type !== 'user') return res.status(403).json({ error: 'Canonical company blueprint assignment human required' });
  if (method === 'post') require('../../../../packages/company-blueprint-assignment-contract').exact(req.body, ['userId']);
  res.json(await companyBlueprintAssignmentAuthority.read(req.user, req.headers.authorization, ...(method === 'post' ? [req.body] : [])));
}));
app.get('/api/identity/company-license-groups/:id/snapshot', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store').set('X-OD-License-Snapshot-Protocol', '1');
  if (req.method !== 'GET') return res.status(404).json({ error: 'Not found' });
  if (Object.keys(req.query).length || req.headers['x-api-key'] !== undefined || Array.isArray(req.body) || Object.keys(req.body || {}).length
    || Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding'] !== undefined) return res.status(400).json({ error: 'Exact company group snapshot required' });
  if (req.user?.actor_type !== 'user') return res.status(403).json({ error: 'Company group human required' });
  await companyLicenseAuthority.read(req.user, req.headers.authorization);
  const snapshot = await new GroupSnapshotStore(snapshotDatabase(req, 'groups.read', { kind: 'group', write: true, companyGroup: true })).snapshot(req.params.id, { issuer: req.user.iss, subject: req.user.sub });
  await companyLicenseAuthority.read(req.user, req.headers.authorization);
  res.json(snapshot);
}));
app.get('/api/identity/company-apps',asyncRoute(async(req,res)=>{
  res.set('Cache-Control','no-store');
  if(req.method!=='GET'||Object.keys(req.query).length||req.headers['x-api-key']!==undefined||Array.isArray(req.body)||Object.keys(req.body||{}).length||Number(req.headers['content-length']||0)||req.headers['transfer-encoding'])return res.status(400).json({error:'exact_company_app_source_required'});
  res.json(await new(require('./CompanyAppAuthority').CompanyAppAuthority)(db).read(req.user,req.headers.authorization));
}));
app.post('/api/identity/employee-invitations',asyncRoute(async(req,res)=>{
 res.set('Cache-Control','no-store');
 if(Object.keys(req.query).length||req.headers['x-api-key']!==undefined)return res.status(400).json({error:'exact_employee_invitation_source_required'});
 res.json(await new(require('./EmployeeInvitationAuthority').EmployeeInvitationAuthority)(db).read(req.user,req.headers.authorization,req.body));
}));
app.use('/api/identity/automation', require('./CompanyAutomationRoutes').companyAutomationRoutes(db));
app.use('/api', requireIdentityAccess);
const demoMode = process.env.IDENTITY_DEMO_MODE === 'true' && process.env.NODE_ENV !== 'production';
const snapshots = new GroupSnapshotStore(db);
const sourceGrants=new(require('./GroupSourceGrants').GroupSourceGrants)(db);
const { UserSnapshotStore } = require('./UserSnapshotStore');
app.get('/api/identity/access', (req, res) => {
  res.set('Cache-Control', 'no-store').json({ subject: req.user.sub, permissions: req.identityPermissions, demoMode,
    userId: req.user.identity_authorization?.userId || null, directoryReadProtocol: 1, directoryCreationProtocol: 1, directoryUserMutationProtocol: 1,
    directoryGroupMutationProtocol:1,directoryOuMutationProtocol:1,directoryOuMembershipProtocol:1,licenseSnapshotProtocol:1,groupMembershipReviewProtocol:1,organizationProfileProtocol:1,organizationDelegationProtocol:1,companyRegistrationReviewProtocol:1,
    companyOwner: req.organizationPermissions?.includes('organization.delegations.manage') === true });
});
app.use('/api', (_req, res, next) => {
  if (!db.isAvailable() && !demoMode) return res.status(503).json({ error: 'Identity storage unavailable' });
  next();
});
app.get('/api/identity/device-inventory', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact inventory source request required' });
  res.set('Cache-Control', 'no-store').json(await deviceInventoryAuthority.read(req.user, req.headers.authorization));
}));
app.post('/api/identity/device-inventory', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact inventory source request required' });
  res.set('Cache-Control', 'no-store').json(await deviceInventoryAuthority.read(req.user, req.headers.authorization, req.body));
}));
app.post('/api/identity/device-offboarding', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact offboarding device source request required' });
  res.json(await deviceOffboardingAuthority.read(req.user, req.headers.authorization, req.body));
}));
app.get('/api/identity/company-licenses', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact company license source request required' });
  res.set('Cache-Control', 'no-store').json(await companyLicenseAuthority.read(req.user, req.headers.authorization));
}));
app.post('/api/identity/company-licenses', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact company license source request required' });
  res.set('Cache-Control', 'no-store').json(await companyLicenseAuthority.read(req.user, req.headers.authorization, req.body));
}));
app.get('/api/identity/company-blueprints', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length || Array.isArray(req.body) || Object.keys(req.body || {}).length || Number(req.headers['content-length'] || 0) > 0
    || req.headers['transfer-encoding'] !== undefined || req.headers['x-api-key'] !== undefined) return res.status(400).json({ error: 'Exact company blueprint source request required' });
  if (req.user?.actor_type !== 'user') return res.status(403).json({ error: 'Canonical company blueprint human required' });
  res.json(await companyBlueprintAuthority.read(req.user, req.headers.authorization));
}));
app.post('/api/users/:id/company-offboarding', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact company offboarding request required' });
  try { res.status(200).json(await companyOffboarding.receive(req.params.id, req.body, req.user, req.headers.authorization)); }
  catch (error) { storageFailure(res, error); }
}));
for (const [suffix, method] of [['', 'preview'], ['/history', 'history']]) app.get('/api/users/:id/company-offboarding-groups' + suffix, asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Array.isArray(req.body) || Object.keys(req.body || {}).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact offboarding group request required' });
  try { res.json(await companyOffboardingGroups[method](req.params.id, req.query, req.user, req.headers.authorization)); }
  catch (error) { storageFailure(res, error); }
}));
app.post('/api/users/:id/company-offboarding-groups', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact offboarding group request required' });
  try {
    const result = await companyOffboardingGroups.remove(req.params.id, req.body, req.user, req.headers.authorization);
    res.status(result.results.every(item => ['removed', 'already_removed'].includes(item.status)) ? 200 : 207).json(result);
  } catch (error) { storageFailure(res, error); }
}));

for (const [suffix, method] of [['/capabilities', 'capabilities'], ['', 'preview'], ['/history', 'history']]) app.get('/api/users/:id/company-offboarding-access' + suffix, asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Array.isArray(req.body) || Object.keys(req.body || {}).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact offboarding access request required' });
  try { res.json(await companyOffboardingAccess[method](req.params.id, req.query, req.user, req.headers.authorization)); }
  catch (error) { storageFailure(res, error); }
}));
app.post('/api/users/:id/company-offboarding-access', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length || req.headers['x-api-key']) return res.status(400).json({ error: 'Exact offboarding access request required' });
  try {
    const result = await companyOffboardingAccess.revoke(req.params.id, req.body, req.user, req.headers.authorization);
    res.status(result.results.every(item => ['revoked', 'already_revoked'].includes(item.status)) ? 200 : 207).json(result);
  } catch (error) { storageFailure(res, error); }
}));

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function storageFailure(res, error) {
  const status = error.status || ({ '22P02': 400, '23503': 400, '23505': 409, '23514': 409, '42501': 403 }[error.code]) || 503;
  return res.status(status).json({ error: status === 503 ? 'Identity storage unavailable' : 'Identity operation rejected' });
}

app.get('/api/license-groups/:id/snapshot', asyncRoute(async (req, res) => {
  res.set('Cache-Control','no-store').set('X-OD-License-Snapshot-Protocol','1');
  if(Object.keys(req.query).length || Object.keys(req.body || {}).length || req.headers['x-api-key'])return res.status(400).json({error:'Exact snapshot request required'});
  res.json(req.groupSourceWorkload?await sourceGrants.snapshot(req.params.id,req.user,req.headers.authorization):await new GroupSnapshotStore(snapshotDatabase(req,'licenses.groups.read',{kind:'group',write:true})).snapshot(req.params.id,{issuer:req.user.iss,subject:req.user.sub}));
}));
app.use('/api/identity/license-sources',require('./GroupSourceGrantRoutes').groupSourceGrantRoutes(sourceGrants));

app.get('/api/identity/subject', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store').json(await snapshots.subject({ issuer: req.user.iss, subject: req.user.sub }));
}));
app.use('/api/identity/reviews',roleReviewRoutes(roleReviews));
const membershipReviews=new (require('./ScopedGroupReviews').ScopedGroupReviews)(db);
app.use('/api/identity/membership-reviews',require('./GroupMembershipReviewRoutes').groupMembershipReviewRoutes(membershipReviews));

app.use('/api/identity/pim', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  try {
    pimAuthority(req.user);
    if (Object.keys(req.query).some(key => req.method !== 'GET' || req.path !== '/eligibilities' || key !== 'userId')) return res.status(400).json({ error: 'invalid_query' });
    if (req.method === 'DELETE' || (req.method === 'POST' && req.path.startsWith('/requests/'))) pimFields(req.body || {}, []);
    next();
  } catch (error) { res.status(error.status || 503).json({ error: error.code || 'pim_unavailable' }); }
});
app.get('/api/identity/pim/catalog', asyncRoute(async (req, res) => {
  const policies = await privilegedAccessPolicy.catalog();
  res.json({ roles: ROLES.filter(role => role !== 'user').map(role => ({ role, protected: PROTECTED.includes(role),
    activationRequired:policies.get(role).activation_required,maxDurationSeconds:policies.get(role).max_duration_seconds,
    assignable: req.identityPermissions.includes('pim.eligibilities.manage') && (!PROTECTED.includes(role) || req.user.roles?.includes('admin') === true),
    reviewable: req.identityPermissions.includes('pim.requests.review') && (!PROTECTED.includes(role) || req.user.roles?.includes('admin') === true
      || policies.get(role).activation_required && policies.get(role).reviewer_user_ids.includes(req.user.identity_authorization.userId) && req.user.roles?.includes('pim-approver')) })),
    minDurationSeconds: 60, maxDurationSeconds: 28800, maxEligibilitySeconds: 2592000, approvalWindowSeconds: 300 });
}));
app.get('/api/identity/pim/self', asyncRoute(async (req, res) => res.json(await privilegedActivation.self(req.user))));
app.get('/api/identity/pim/policies/:role', asyncRoute(async (req, res) => {
  if (Object.keys(req.body || {}).length) return res.status(400).json({ error:'invalid_fields' });
  const policy = await privilegedAccessPolicy.get(req.params.role,req.user);
  res.set('ETag',activationEtag(policy.role,policy.version)).json(policy);
}));
app.put('/api/identity/pim/policies/:role', asyncRoute(async (req, res) => {
  const policy = await privilegedAccessPolicy.change(req.params.role,req.headers['if-match'],req.body,req.user,req.headers.authorization);
  res.set('ETag',activationEtag(policy.role,policy.version)).json(policy);
}));
app.get('/api/identity/pim/eligibilities', asyncRoute(async (req, res) => res.json(await privilegedActivation.eligibilities(req.query.userId, req.user))));
app.post('/api/identity/pim/eligibilities', asyncRoute(async (req, res) => res.status(201).json(await privilegedActivation.grantEligibility(req.body, req.user, req.headers.authorization))));
app.delete('/api/identity/pim/eligibilities/:id', asyncRoute(async (req, res) => res.json(await privilegedActivation.revokeEligibility(req.params.id, req.user, req.headers.authorization))));
app.get('/api/identity/pim/requests', asyncRoute(async (req, res) => res.json(await privilegedActivation.queue(req.user))));
app.post('/api/identity/pim/requests', asyncRoute(async (req, res) => res.json(await privilegedActivation.request(req.body, req.user, req.headers.authorization))));
app.post('/api/identity/pim/requests/:id/:action', asyncRoute(async (req, res) => res.json(await privilegedActivation.change(req.params.id, req.params.action, req.user, req.headers.authorization))));
app.use('/api/identity/pim', (error, _req, res, _next) => {
  if (error.status && error.code) return res.status(error.status).json({ error: error.code });
  return storageFailure(res, error);
});

app.use('/api/identity/authentication', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.get('/api/identity/authentication/roles/:role', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'invalid_fields' });
  const policy = await roleAuthentication.get(req.params.role, req.user);
  res.set('ETag', policyEtag(policy.role, policy.version)).json(policy);
}));
app.put('/api/identity/authentication/roles/:role', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'invalid_query' });
  const policy = await roleAuthentication.change(req.params.role, req.headers['if-match'], req.body, req.user, req.headers.authorization);
  res.set('ETag', policyEtag(policy.role, policy.version)).json(policy);
}));
app.use('/api/identity/authentication', (error, _req, res, _next) => {
  if (error.status && error.code) return res.status(error.status).json({ error: error.code });
  return storageFailure(res, error);
});

app.get('/api/identity/roles/catalog', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'Unsupported role query' });
  const policies = await privilegedAccessPolicy.catalog();
  res.json({ roles: ROLES.map(role => ({ role, protected: PROTECTED.includes(role),
    assignable: !policies.get(role).activation_required && req.identityPermissions.includes('identities.roles.manage') && (!PROTECTED.includes(role) || req.user.roles?.includes('admin') === true) })), minDurationSeconds: 60, maxDurationSeconds: 28800 });
}));
app.get('/api/users/:id/roles', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'Unsupported role query' });
  res.set('Cache-Control','no-store').json(await directoryReader.roles(req.params.id,req.query,req.user,req.headers.authorization));
}));
app.post('/api/users/:id/roles', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'Unsupported role query' });
  res.status(201).json(await directoryRoles.grant(req.params.id, req.body, req.user, req.headers.authorization));
}));
app.delete('/api/users/:id/roles/:assignmentId', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'Unsupported role mutation fields' });
  res.json(await directoryRoles.revoke(req.params.id, req.params.assignmentId, req.user, req.headers.authorization));
}));

app.get('/api/policy-publication-actors/:id/snapshot', asyncRoute(async (req, res) => {
  res.set('Cache-Control','no-store').set('X-OD-License-Snapshot-Protocol','1');
  require('./PrivilegedActivation').authority(req.user);
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'Unsupported policy actor fields' });
  res.json(await new (require('./PolicyPublicationActorSnapshotStore').PolicyPublicationActorSnapshotStore)(snapshotDatabase(req,'policies.publication-actors.read')).snapshot(req.params.id, req.user.iss));
}));

app.get('/api/license-users/:id/snapshot', asyncRoute(async (req, res) => {
  res.set('Cache-Control','no-store').set('X-OD-License-Snapshot-Protocol','1').json(await new UserSnapshotStore(snapshotDatabase(req,'licenses.users.read',{self:true,workload:true})).snapshot(req.params.id,{issuer:req.user.iss,subject:req.user.sub},true));
}));

app.get('/api/license-reviewers/:id/snapshot', asyncRoute(async (req, res) => {
  res.set('Cache-Control','no-store').set('X-OD-License-Snapshot-Protocol','1');
  require('./PrivilegedActivation').authority(req.user);
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'Unsupported reviewer snapshot fields' });
  res.json(await new (require('./LicenseReviewerSnapshotStore').LicenseReviewerSnapshotStore)(snapshotDatabase(req,'licenses.reviewers.read')).snapshot(req.params.id, req.user.iss));
}));

app.get('/api/license-scope-reviewers/:id/snapshot', asyncRoute(async (req,res)=>{
  res.set('Cache-Control','no-store').set('X-OD-License-Snapshot-Protocol','1');require('./PrivilegedActivation').authority(req.user);
  if(Object.keys(req.query).length||Object.keys(req.body||{}).length)return res.status(400).json({error:'Unsupported scope reviewer fields'});
  res.json(await new (require('./LicenseReviewerSnapshotStore').LicenseReviewerSnapshotStore)(snapshotDatabase(req,'licenses.scope-reviewers.read'),['license-delegation-reviewer']).snapshot(req.params.id,req.user.iss));
}));

app.get('/api/license-activation-reviewers/:id/snapshot', asyncRoute(async (req, res) => {
  res.set('Cache-Control','no-store').set('X-OD-License-Snapshot-Protocol','1'); require('./PrivilegedActivation').authority(req.user);
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'Unsupported activation reviewer fields' });
  res.json(await new (require('./LicenseActivationReviewerSnapshotStore').LicenseActivationReviewerSnapshotStore)(snapshotDatabase(req,'licenses.activation-reviewers.read',{self:true})).snapshot(req.params.id,{issuer:req.user.iss,subject:req.user.sub},true));
}));

app.get('/api/license-delegates/:id/snapshot', asyncRoute(async (req, res) => {
  res.set('Cache-Control','no-store').set('X-OD-License-Snapshot-Protocol','1'); require('./PrivilegedActivation').authority(req.user);
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'Unsupported delegate snapshot fields' });
  res.json(await new (require('./LicenseDelegateSnapshotStore').LicenseDelegateSnapshotStore)(snapshotDatabase(req,'licenses.delegates.read',{self:true})).snapshot(req.params.id,{issuer:req.user.iss,subject:req.user.sub},true));
}));

app.post('/api/identity/links', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || req.headers['x-api-key']) return res.status(400).json({ error: 'No query or API key accepted' });
  res.set('Cache-Control','no-store').status(201).json(await subjectLinks.mutate(req.body,req.user,req.headers.authorization));
}));

app.delete('/api/identity/links', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || req.headers['x-api-key']) return res.status(400).json({ error: 'No query or API key accepted' });
  await subjectLinks.mutate(req.body,req.user,req.headers.authorization,true);
  res.set('Cache-Control','no-store').status(204).send();
}));

const users = new Map();
const groups = new Map();

// Converts a pg TIMESTAMPTZ value (a Date, via node-postgres's default
// parser) — or a plain ISO string, as produced by a mocked pg client in
// tests — into the ISO string shape the pre-existing in-memory
// implementation always returned. Returns undefined (not null) for an
// absent value so JSON.stringify drops the key entirely, matching the
// original stub's behavior of never emitting e.g. `"updatedAt": null` for a
// user that has never been updated.
function iso(value) {
  if (!value) return undefined;
  return value instanceof Date ? value.toISOString() : value;
}

function rowToGroup(row, members) {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    members: members ?? [],
    createdAt: iso(row.created_at),
    revision: row.revision == null ? undefined : String(row.revision),
  };
}

// Health check
app.get('/health', asyncRoute(async (req, res) => {
  let available = db.isAvailable();
  if (available) {
    try { await db.query('SELECT 1'); } catch { available = false; }
  }
  res.status(available ? 200 : 503).json({ status: available ? 'healthy' : 'degraded', service: 'identity-service', demoMode, timestamp: new Date().toISOString() });
}));

// ==================
// Users API
// ==================
function userResult(res, user, status = 200) {
  return res.status(status).set('Cache-Control', 'no-store').set('ETag', userEtag(user)).json(user);
}

function userFailure(res, error) {
  if ([400, 404, 409, 412, 428].includes(error.status)) return res.status(error.status).set('Cache-Control', 'no-store').json({ error: error.message });
  return storageFailure(res, error);
}

app.get('/api/users', asyncRoute(async (req, res) => {
  try { res.set('Cache-Control', 'no-store').json(await directoryReader.users(req.query,req.user,req.headers.authorization)); }
  catch (error) { return userFailure(res, error); }
}));

app.get('/api/users/:id', asyncRoute(async (req, res) => {
  try { return userResult(res, await directoryReader.user(req.params.id,req.query,req.user,req.headers.authorization)); }
  catch (error) { return userFailure(res, error); }
}));

app.post('/api/users', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({error:'No creation query selectors accepted'});
  try {
    const user = await directoryCreator.user(req.body, req.user, req.headers.authorization);
    publish('identity.user.created', { userId: user.id, username: user.username, email: user.email, enabled: user.enabled });
    return userResult(res, user, 201);
  } catch (error) { return userFailure(res, error); }
}));

app.put('/api/users/:id', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'No mutation query selectors accepted' });
  try { return userResult(res, await userMutator.update(req.params.id, req.body, req.headers['if-match'], req.user, req.headers.authorization)); }
  catch (error) { return userFailure(res, error); }
}));

app.post('/api/users/:id/authorization/invalidate', asyncRoute(async (req, res) => {
  if (Object.keys(req.body || {}).length || Object.keys(req.query).length) return res.status(400).json({ error: 'No body or query parameters are accepted' });
  try { res.set('Cache-Control', 'no-store').json(await userMutator.invalidate(req.params.id, req.user, req.headers.authorization)); }
  catch (error) { return userFailure(res, error); }
}));

app.delete('/api/users/:id', asyncRoute(async (req, res) => {
  if (Object.keys(req.body || {}).length || Object.keys(req.query).length) return res.status(400).json({ error: 'No body or query parameters are accepted' });
  try {
    await userMutator.remove(req.params.id, req.headers['if-match'], req.user, req.headers.authorization);
    publish('identity.user.deleted', { userId: req.params.id });
    res.set('Cache-Control', 'no-store').status(204).send();
  } catch (error) { return userFailure(res, error); }
}));

// ==================
// Groups: DB-first reads
// ==================
function groupResult(res,group,status=200){return res.status(status).set('Cache-Control','no-store').set('ETag',groupEtag(group)).json(group);}
function groupMutationFields(req,res,empty=false){if(Object.keys(req.query).length||empty&&(Array.isArray(req.body)||Object.keys(req.body||{}).length)){res.status(400).set('Cache-Control','no-store').json({error:'No group mutation selectors or extra body fields accepted'});return false;}return true;}

// ==================
// Groups API
// ==================
app.use('/api/groups/:id/rule', require('./CompanyGroupRuleRoutes').companyGroupRuleRoutes(db));
app.get('/api/groups', asyncRoute(async (req, res) => {
  res.set('Cache-Control','no-store').json(await directoryReader.groups(req.query,req.user,req.headers.authorization));
}));

app.get('/api/groups/:id', asyncRoute(async (req, res) => {
  try{return groupResult(res,await directoryReader.group(req.params.id,req.query,req.user,req.headers.authorization));}catch(error){return userFailure(res,error);}
}));

app.post('/api/groups', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({error:'No creation query selectors accepted'});
  try {
    const group = await directoryCreator.group(req.body,req.user,req.headers.authorization);
    groups.set(group.id,group);publish('identity.group.created',{groupId:group.id,name:group.name});
    return groupResult(res,group,201);
  } catch (error) { return userFailure(res,error); }
}));

app.post('/api/groups/:id/members', asyncRoute(async (req, res) => {
  if(!groupMutationFields(req,res))return;
  try{return groupResult(res,await groupMutator.add(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization));}catch(error){return userFailure(res,error);}
}));

app.delete('/api/groups/:id/members/:userId', asyncRoute(async (req, res) => {
  if(!groupMutationFields(req,res,true))return;
  try{return groupResult(res,await groupMutator.removeMember(req.params.id,req.params.userId,req.headers['if-match'],req.user,req.headers.authorization));}catch(error){return userFailure(res,error);}
}));

app.put('/api/groups/:id', asyncRoute(async (req, res) => {
  if(!groupMutationFields(req,res))return;
  try{return groupResult(res,await groupMutator.update(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization));}catch(error){return userFailure(res,error);}
}));

app.delete('/api/groups/:id', asyncRoute(async (req, res) => {
  if(!groupMutationFields(req,res,true))return;
  try{await groupMutator.remove(req.params.id,req.headers['if-match'],req.user,req.headers.authorization);res.set('Cache-Control','no-store').status(204).send();}catch(error){return userFailure(res,error);}
}));

// ==================
// OUs API
// ==================
app.get('/api/ous', asyncRoute(async (req, res) => {
  res.set('Cache-Control','no-store').json(await directoryReader.ous(req.query,req.user,req.headers.authorization));
}));

app.get('/api/ous/:id', asyncRoute(async (req, res) => {
  const unit = await directoryReader.ou(req.params.id,req.query,req.user,req.headers.authorization);
  res.set('Cache-Control','no-store').set('ETag',ouEtag(unit)).json(unit);
}));

app.post('/api/ous', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({error:'No creation query selectors accepted'});
  try {
    const ou = await directoryCreator.ou(req.body,req.user,req.headers.authorization);
    publish('identity.ou.created',{ouId:ou.id,name:ou.name});
    res.set('Cache-Control','no-store').set('ETag',ouEtag(ou)).status(201).json(ou);
  } catch (error) { return userFailure(res,error); }
}));

app.put('/api/ous/:id', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'No OU mutation selectors accepted' });
  try { const unit = await ouMutator.update(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization); res.set('Cache-Control','no-store').set('ETag',ouEtag(unit)).json(unit); }
  catch (error) { return userFailure(res,error); }
}));

app.delete('/api/ous/:id', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'No OU deletion selectors accepted' });
  try { await ouMutator.remove(req.params.id,req.headers['if-match'],req.user,req.headers.authorization); res.set('Cache-Control','no-store').status(204).send(); }
  catch (error) { return userFailure(res,error); }
}));

app.get('/api/ous/:id/members', asyncRoute(async (req, res) => {
  if (Object.keys(req.body || {}).length) return res.status(400).json({ error: 'No membership body selectors accepted' });
  try { const page = await directoryReader.ouMembers(req.params.id,req.query,req.user,req.headers.authorization); res.set('Cache-Control','no-store').set('ETag',ouEtag(page.unit)).json(page); }
  catch (error) { return userFailure(res,error); }
}));
app.post('/api/ous/:id/members', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'No membership mutation selectors accepted' });
  try { const result = await ouMutator.addMember(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization); res.set('Cache-Control','no-store').set('ETag',ouEtag(result.unit)).status(201).json(result); }
  catch (error) { return userFailure(res,error); }
}));
app.delete('/api/ous/:id/members/:memberId', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'No membership deletion selectors accepted' });
  try { const result = await ouMutator.removeMember(req.params.id,req.params.memberId,req.headers['if-match'],req.user,req.headers.authorization); res.set('Cache-Control','no-store').set('ETag',ouEtag(result.unit)).json(result); }
  catch (error) { return userFailure(res,error); }
}));

// ==================
// Identity (LDAP-compatible) endpoint
// ==================
app.get('/api/identity/company-registrations', asyncRoute(async (req, res) => {
  res.set('Cache-Control', 'no-store').json(await companyReviews.list(req.query, req.user));
}));
app.get('/api/identity/company-registrations/:id', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'invalid_company_review_filter' });
  const page = await companyReviews.get(req.params.id, req.user); res.set('Cache-Control', 'no-store').set('ETag', page.etag).json(page);
}));
app.post('/api/identity/company-registrations/:id/review', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'invalid_company_review_filter' });
  const page = await companyReviews.decide(req.params.id, req.body, req.headers['if-match'], req.user, req.headers.authorization);
  res.set('Cache-Control', 'no-store').set('ETag', page.etag).json(page);
}));
app.get('/api/identity/organization/delegations', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'invalid_fields' });
  res.set('Cache-Control', 'no-store').json(await organizationDelegations.list(req.user));
}));
app.post('/api/identity/organization/delegations', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'invalid_fields' });
  res.set('Cache-Control', 'no-store').status(201).json(await organizationDelegations.change('granted', req.body?.userId, req.body, req.user, req.headers.authorization));
}));
app.post('/api/identity/organization/delegations/:id/revoke', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'invalid_fields' });
  res.set('Cache-Control', 'no-store').json(await organizationDelegations.change('revoked', req.params.id, req.body, req.user, req.headers.authorization));
}));
app.get('/api/identity/organization', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length || Object.keys(req.body || {}).length) return res.status(400).json({ error: 'invalid_fields' });
  const page = await organizationProfile.get(req.user);
  res.set('Cache-Control', 'no-store').set('ETag', page.etag).json(page);
}));
app.put('/api/identity/organization', asyncRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'invalid_fields' });
  const page = await organizationProfile.save(req.body, req.headers['if-match'], req.user, req.headers.authorization);
  res.set('Cache-Control', 'no-store').set('ETag', page.etag).json(page);
}));
app.get('/api/identity/search', asyncRoute(async (req, res) => {
  res.set('Cache-Control','no-store').json(await directoryReader.search(req.query,req.user,req.headers.authorization));
}));

app.use((error, _req, res, _next) => {
  logger.error('Identity operation failed', { error: error.message });
  storageFailure(res, error);
});

let server;
async function start() {
  const ready = await db.initDb();
  if (!ready && process.env.NODE_ENV === 'production') throw new Error('Production identity-service requires a migrated database');
  await connectBus();
  server = app.listen(PORT, () => logger.info('Identity Service running on port ' + PORT));
  return server;
}

if (require.main === module) {
  start().catch(async error => {
    logger.error('Identity startup failed', { error: error.message });
    await db.pool.end();
    process.exitCode = 1;
  });
  const shutdown = () => {
    server?.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = app;
module.exports.start = start;
