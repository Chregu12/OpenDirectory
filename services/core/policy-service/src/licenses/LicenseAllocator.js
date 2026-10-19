'use strict';

const { isOwnLicenseRequest } = require('../middleware/licenseAccess');
const { LicenseError } = require('./LicenseError');
const { principalContext, requirePrincipal, validateRequestIdentity, UUID } = require('./LicensePrincipal');
const { GroupSnapshotClient } = require('./GroupSnapshotClient');
const { LicenseUserEligibility } = require('./LicenseUserEligibility');
const { scopeContext, requireScopedOperation } = require('./LicenseScopeContext');
const { companyLicenseContext } = require('./CompanyLicenseContext');

function validIdentifier(value) {
  return typeof value === 'string' && Boolean(value.trim()) && value.length <= 255;
}

function canonicalIdentifier(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value) ? value.toLowerCase() : value;
}

class LicenseAllocator {
  constructor(database, { source = new GroupSnapshotClient() } = {}) {
    this.database = database;
    this.users = new LicenseUserEligibility(this, source);
  }

  async transaction(operation) {
    const client = await this.database.getClient();
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await client.query("SET LOCAL lock_timeout = '5s'");
      await client.query("SET LOCAL statement_timeout = '15s'");
      const scope = scopeContext.getStore();
      const company = companyLicenseContext.getStore();
      if (company && (company.database !== this.database || scope)) throw new LicenseError(403, 'Company licensing cannot replace an independent delegated scope');
      if (scope) { if (scope.database !== this.database) throw new LicenseError(403, 'License scope database mismatch'); await scope.verify(client, false); }
      const principal = principalContext.getStore();
      await client.query("SELECT set_config('opendirectory.license_actor_user',$1,true),set_config('opendirectory.license_actor_issuer',$2,true),set_config('opendirectory.license_actor_subject',$3,true)",
        [principal?.userId || '', principal?.issuer || '', principal?.subject || '']);
      if (company) await company.verify(client, false);
      const result = await operation(client);
      if (scope) await scope.verify(client, true);
      if (company) { await company.verify(client, true); await company.complete(client); }
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch {}
      error.noFallback = true;
      throw error;
    } finally {
      client.release();
    }
  }

  async lockSubjects(client, actor, subjects = [], snapshots = []) {
    if (!validIdentifier(actor)) throw new LicenseError(400, 'Invalid user identifier');
    const identifiers = [...new Set([actor, ...subjects].filter(Boolean))].sort();
    if (identifiers.some(identifier => !validIdentifier(identifier))) throw new LicenseError(400, 'Invalid user identifier');
    for (const identifier of identifiers) {
      const company = companyLicenseContext.getStore();
      if (company) await client.query('INSERT INTO license_subjects (user_id,business_tenant_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [identifier, company.tenantId]);
      else await client.query('INSERT INTO license_subjects (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [identifier]);
      const result = await client.query('SELECT * FROM license_subjects WHERE user_id = $1 FOR UPDATE', [identifier]);
      if (company ? result.rows[0].business_tenant_id !== company.tenantId : result.rows[0].business_tenant_id != null) throw new LicenseError(404, 'License subject is outside this operation');
      const snapshot = snapshots.find(value => value.userId === identifier);
      const state = snapshot ? await this.users.apply(client, snapshot, result.rows[0]) : result.rows[0];
      if (state.disabled || state.directory_enabled === false) throw new LicenseError(403, 'License access is disabled for this user');
    }
  }

  async lockLicense(client, licenseId) {
    if (scopeContext.getStore() && scopeContext.getStore().licenseId !== licenseId) throw new LicenseError(403, 'License pool scope mismatch');
    const result = await client.query('SELECT * FROM license_catalog WHERE id = $1 FOR UPDATE', [licenseId]);
    if (!result.rows.length) throw new LicenseError(404, 'License not found');
    this.poolOwnership(result.rows[0]);
    return result.rows[0];
  }

  poolOwnership(row, legacyOnly = false) {
    const company = companyLicenseContext.getStore();
    if (company && legacyOnly || (row.business_tenant_id != null ? !company || company.database !== this.database || company.licenseId !== row.id || company.tenantId !== row.business_tenant_id : company)) throw new LicenseError(404, 'License not found');
  }

  async assertPoolAccess(licenseId, client = this.database, { legacyOnly = false } = {}) {
    const result = await client.query('SELECT id,business_tenant_id FROM license_catalog WHERE id=$1', [licenseId]);
    if (!result.rows.length) throw new LicenseError(404, 'License not found'); this.poolOwnership(result.rows[0], legacyOnly); return result.rows[0];
  }

  async assertLegacySubject(userId, client = this.database) {
    const row = (await client.query('SELECT business_tenant_id FROM license_subjects WHERE user_id=$1', [userId])).rows[0];
    if (row?.business_tenant_id != null) throw new LicenseError(404, 'Legacy license subject not found');
  }

  async authorizeOperation(client,licenseId,operation) {
    try { await client.query('SELECT license_scope_require_operation($1,$2)',[licenseId,operation]); }
    catch(error) { if(error.code==='42501')throw new LicenseError(403,'Approved active pool PIM scope required; use the scoped API');throw error; }
  }

  async autoApprovalAllowed(client,licenseId) {
    return (await client.query('SELECT license_scope_auto_approval_allowed($1) AS allowed',[licenseId])).rows[0]?.allowed===true;
  }

  async audit(client, licenseId, action, actor, details) {
    if (scopeContext.getStore() && licenseId === null) licenseId = scopeContext.getStore().licenseId;
    const principal = principalContext.getStore();
    await client.query('INSERT INTO license_audit_events (license_id, action, actor, details, actor_issuer, actor_subject) VALUES ($1,$2,$3,$4,$5,$6)',
      [licenseId, action, actor, JSON.stringify(details), principal?.issuer || null, principal?.subject || null]);
  }

  async expire(client, licenseId) {
    requireScopedOperation(licenseId, ['assignments.manage','requests.review']);
    const sources = await client.query('DELETE FROM license_assignment_sources WHERE license_id=$1 AND license_member_source_expiry(grant_id,user_id,expires_at)<=license_now() RETURNING *', [licenseId]);
    for (const source of sources.rows) await this.audit(client, licenseId, 'source-expired', 'system', source);
    let released = 0;
    for (const userId of [...new Set(sources.rows.map(source => source.user_id))]) {
      const result = await this.syncUser(client, licenseId, userId, 'system');
      if (result.removed) { released++; await this.audit(client, licenseId, 'expired', 'system', result.removed); }
    }
    await client.query("UPDATE license_group_rules SET enabled=false,status=CASE WHEN expires_at<=license_now() THEN 'expired' ELSE 'review-expired' END WHERE license_id=$1 AND enabled AND license_source_expiry(grant_id,expires_at)<=license_now()", [licenseId]);
    const expired = await client.query('DELETE FROM license_assignments WHERE license_id = $1 AND expires_at <= license_now() RETURNING *', [licenseId]);
    for (const assignment of expired.rows) await this.audit(client, licenseId, 'expired', 'system', assignment);
    return released + expired.rows.length;
  }

  async syncUser(client, licenseId, userId, actor, name = null) {
    requireScopedOperation(licenseId, ['assignments.manage','requests.review']);
    const sources = await client.query(`SELECT COUNT(*)::int AS count,CASE WHEN BOOL_OR(expiry IS NULL) THEN NULL ELSE MAX(expiry) END AS expires_at
      FROM (SELECT license_member_source_expiry(grant_id,user_id,expires_at) AS expiry FROM license_assignment_sources WHERE license_id=$1 AND user_id=$2) sources
      WHERE expiry IS NULL OR expiry>license_now()`, [licenseId, userId]);
    const current = await this.findAssignment(client, licenseId, { assignee_type: 'user', assignee_id: userId });
    if (!sources.rows[0].count) {
      if (current) await client.query('DELETE FROM license_assignments WHERE id=$1', [current.id]);
      return { removed: current || null, added: false, row: null };
    }
    if (current) {
      if ((current.expires_at ? new Date(current.expires_at).getTime() : null) === (sources.rows[0].expires_at ? new Date(sources.rows[0].expires_at).getTime() : null)) return { added: false, removed: null, row: current };
      const updated = await client.query('UPDATE license_assignments SET expires_at=$2 WHERE id=$1 RETURNING *', [current.id, sources.rows[0].expires_at]);
      return { added: false, removed: null, row: updated.rows[0] };
    }
    const created = await client.query(`INSERT INTO license_assignments (license_id, assignee_type, assignee_id, assignee_name, assigned_by, expires_at)
      VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`, [licenseId, 'user', userId, name, actor, sources.rows[0].expires_at]);
    return { added: true, removed: null, row: created.rows[0] };
  }

  async count(client, licenseId) {
    const result = await client.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id = $1 AND (expires_at IS NULL OR expires_at > license_now())', [licenseId]);
    return result.rows[0].count;
  }

  async syncCounter(client, licenseId) {
    await client.query('UPDATE license_catalog SET used_seats = $2, updated_at = NOW() WHERE id = $1', [licenseId, await this.count(client, licenseId)]);
  }

  validateAssignee(assignment) {
    assignment.assignee_id = canonicalIdentifier(assignment.assignee_id);
    if (!['user', 'group', 'device'].includes(assignment.assignee_type) || !validIdentifier(assignment.assignee_id)) {
      throw new LicenseError(400, 'Valid assignee_type and assignee_id are required');
    }
    if (assignment.expires_at != null && (typeof assignment.expires_at !== 'string' || !Number.isFinite(Date.parse(assignment.expires_at)) || Date.parse(assignment.expires_at) <= Date.now())) {
      throw new LicenseError(400, 'expires_at must be a future timestamp');
    }
  }

  async findAssignment(client, licenseId, assignment) {
    const result = await client.query('SELECT * FROM license_assignments WHERE license_id = $1 AND assignee_type = $2 AND assignee_id = $3',
      [licenseId, assignment.assignee_type, assignment.assignee_id]);
    return result.rows[0];
  }

  async insertAssignment(client, license, assignment, actor) {
    requireScopedOperation(license.id, ['assignments.manage','requests.review']);
    if (assignment.assignee_type === 'user') {
      const existing = await this.findAssignment(client, license.id, assignment);
      if (!existing && license.total_seats > 0 && await this.count(client, license.id) >= license.total_seats) throw new LicenseError(409, 'No seats available for this license');
      const source = await client.query("SELECT 1 FROM license_assignment_sources WHERE license_id=$1 AND user_id=$2 AND source_type='direct'", [license.id, assignment.assignee_id]);
      if (source.rows.length) throw new LicenseError(409, 'This assignee already has a direct license');
      await client.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by,expires_at) VALUES($1,$2,'direct','direct',$3,$4)", [license.id, assignment.assignee_id, actor, assignment.expires_at || null]);
      const result = await this.syncUser(client, license.id, assignment.assignee_id, actor, assignment.assignee_name || null);
      await this.syncCounter(client, license.id);
      await this.audit(client, license.id, result.added ? 'assigned' : 'direct-source-added', actor, result.row);
      return result.row;
    }
    if (await this.findAssignment(client, license.id, assignment)) throw new LicenseError(409, 'This assignee already has this license');
    if (license.total_seats > 0 && await this.count(client, license.id) >= license.total_seats) throw new LicenseError(409, 'No seats available for this license');
    const result = await client.query(`INSERT INTO license_assignments (license_id, assignee_type, assignee_id, assignee_name, assigned_by, expires_at)
      VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`, [license.id, assignment.assignee_type, assignment.assignee_id, assignment.assignee_name || null, actor, assignment.expires_at || null]);
    await this.syncCounter(client, license.id);
    await this.audit(client, license.id, 'assigned', actor, result.rows[0]);
    return result.rows[0];
  }

  async assign(licenseId, assignment, actor, context = {}) {
    requireScopedOperation(licenseId, ['assignments.manage']);
    this.validateAssignee(assignment);
    await this.assertPoolAccess(licenseId);
    if (assignment.assignee_type === 'group') return this.groups.assign(licenseId, assignment, actor, context);
    const snapshots = await this.users.active(assignment.assignee_type === 'user' ? [assignment.assignee_id] : [], context);
    return this.transaction(async client => {
      await this.lockSubjects(client, actor, assignment.assignee_type === 'user' ? [assignment.assignee_id] : [], snapshots);
      const license = await this.lockLicense(client, licenseId);
      await this.authorizeOperation(client,licenseId,'assignments.manage');
      await this.expire(client, licenseId);
      return this.insertAssignment(client, license, assignment, actor);
    });
  }

  async revoke(licenseId, assigneeId, actor, assigneeType) {
    requireScopedOperation(licenseId, ['assignments.manage']);
    assigneeId = canonicalIdentifier(assigneeId);
    if (!validIdentifier(assigneeId) || (assigneeType && !['user', 'group', 'device'].includes(assigneeType))) throw new LicenseError(400, 'Invalid assignee');
    await this.assertPoolAccess(licenseId);
    if (assigneeType === 'group') return this.groups.revoke(licenseId, assigneeId, actor);
    if (!assigneeType) {
      const group = await this.database.query('SELECT 1 FROM license_group_rules WHERE license_id=$1 AND group_id=$2 AND enabled', [licenseId, assigneeId]);
      if (group.rows.length) {
        const other = await this.database.query('SELECT 1 FROM license_assignments WHERE license_id=$1 AND assignee_id=$2', [licenseId, assigneeId]);
        if (other.rows.length) throw new LicenseError(409, 'Specify assignee_type to revoke an unambiguous source');
        return this.groups.revoke(licenseId, assigneeId, actor);
      }
    }
    return this.transaction(async client => {
      await this.lockSubjects(client, actor);
      await this.lockLicense(client, licenseId);
      await this.authorizeOperation(client,licenseId,'assignments.manage');
      if (!assigneeType && (await client.query('SELECT 1 FROM license_group_rules WHERE license_id=$1 AND group_id=$2 AND enabled', [licenseId, assigneeId])).rows.length) throw new LicenseError(409, 'Specify assignee_type to revoke an unambiguous source');
      const result = await client.query('SELECT * FROM license_assignments WHERE license_id = $1 AND assignee_id = $2 AND ($3::text IS NULL OR assignee_type = $3)', [licenseId, assigneeId, assigneeType || null]);
      if (!result.rows.length) throw new LicenseError(404, 'Assignment not found');
      if (result.rows.length > 1) throw new LicenseError(409, 'Specify assignee_type to revoke an unambiguous assignment');
      let retained = false;
      if (result.rows[0].assignee_type === 'user') {
        const removed = await client.query("DELETE FROM license_assignment_sources WHERE license_id=$1 AND user_id=$2 AND source_type='direct' RETURNING *", [licenseId, assigneeId]);
        if (!removed.rows.length) throw new LicenseError(409, 'This user is licensed only through groups; revoke the group source instead');
        retained = Boolean((await this.syncUser(client, licenseId, assigneeId, actor)).row);
      } else await client.query('DELETE FROM license_assignments WHERE id = $1', [result.rows[0].id]);
      await this.syncCounter(client, licenseId);
      await this.audit(client, licenseId, result.rows[0].assignee_type === 'user' ? 'direct-source-revoked' : 'revoked', actor, { assignment: result.rows[0], effectiveAssignmentRetained: retained });
    });
  }

  async request(licenseId, request, context = {}) {
    requireScopedOperation(licenseId, ['requests.delegate']);
    this.validateAssignee(request);
    await this.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    const principal = requirePrincipal(context.principal, request.requester_id);
    if (request.assignee_type === 'user' && !UUID.test(request.assignee_id)) throw new LicenseError(400, 'A canonical directory user UUID is required');
    if (request.assignee_type === 'group') return this.groups.request(licenseId, request, context);
    const snapshots = await this.users.active([request.requester_id, ...(request.assignee_type === 'user' ? [request.assignee_id] : [])], context);
    return this.transaction(async client => {
      await this.lockSubjects(client, request.requester_id, request.assignee_type === 'user' ? [request.assignee_id] : [], snapshots);
      const license = await this.lockLicense(client, licenseId);
      await this.expire(client, licenseId);
      const assignment = await this.findAssignment(client, licenseId, request);
      const previous = await client.query(`SELECT * FROM license_requests WHERE license_id = $1 AND requester_id = $2
        AND identity_bound = true AND assignee_type = $3 AND assignee_id = $4 AND status IN ('pending', 'approved') ORDER BY requested_at DESC, id DESC`,
      [licenseId, request.requester_id, request.assignee_type, request.assignee_id]);
      const existing = previous.rows.find(record => record.status === 'pending' || (record.status === 'approved' && assignment));
      if (existing) return { record: existing, created: false };
      if (assignment) throw new LicenseError(409, 'This assignee already has this license');
      const approved = license.auto_approve && await this.autoApprovalAllowed(client,licenseId) && (license.total_seats === 0 || await this.count(client, licenseId) < license.total_seats);
      if (approved) await this.insertAssignment(client, license, request, request.requester_id);
      const result = await client.query(`INSERT INTO license_requests
        (license_id, license_name, requester_id, requester_name, assignee_type, assignee_id, assignee_name, justification, status, decided_at, decided_by, identity_bound, requester_issuer, requester_subject)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text,CASE WHEN $9::text = 'approved' THEN NOW() END,CASE WHEN $9::text = 'approved' THEN 'auto-approve' END,true,$10,$11) RETURNING *`,
      [licenseId, license.name, request.requester_id, request.requester_name || null, request.assignee_type, request.assignee_id,
        request.assignee_name || null, request.justification || null, approved ? 'approved' : 'pending', principal.issuer, principal.subject]);
      await this.audit(client, licenseId, approved ? 'auto-approved' : 'requested', request.requester_id, result.rows[0]);
      return { record: result.rows[0], created: true };
    });
  }

  async review(requestId, actor, decision, context = {}) {
    if (!['approved', 'denied'].includes(decision)) throw new LicenseError(400, 'Invalid request decision');
    requirePrincipal(context.principal, actor);
    const snapshot = await this.database.query('SELECT requests.* FROM license_requests requests JOIN license_catalog catalog ON catalog.id=requests.license_id AND catalog.business_tenant_id IS NULL WHERE requests.id=$1', [requestId]);
    if (!snapshot.rows.length) throw new LicenseError(404, 'Request not found');
    const original = snapshot.rows[0];
    await this.assertPoolAccess(original.license_id, this.database, { legacyOnly: true });
    requireScopedOperation(original.license_id, ['requests.review']);
    validateRequestIdentity(original);
    if (original.assignee_type === 'group') return this.groups.review(original, actor, decision, context);
    if (isOwnLicenseRequest(actor, original)) throw new LicenseError(403, 'Cannot review your own license request');
    const snapshots = await this.users.active([original.requester_id, ...(original.assignee_type === 'user' ? [original.assignee_id] : [])], context);
    return this.transaction(async client => {
      await this.lockSubjects(client, actor, [original.requester_id, ...(original.assignee_type === 'user' ? [original.assignee_id] : [])], snapshots);
      const license = await this.lockLicense(client, original.license_id);
      await this.authorizeOperation(client,license.id,'requests.review');
      const result = await client.query('SELECT * FROM license_requests WHERE id = $1 FOR UPDATE', [requestId]);
      if (!result.rows.length) throw new LicenseError(404, 'Request not found');
      const request = result.rows[0];
      validateRequestIdentity(request);
      if (request.license_id !== original.license_id || request.assignee_id !== original.assignee_id || request.assignee_type !== original.assignee_type || request.requester_id !== original.requester_id) {
        throw new LicenseError(409, 'Request target changed during review');
      }
      if (isOwnLicenseRequest(actor, request)) throw new LicenseError(403, 'Cannot review your own license request');
      if (request.status !== 'pending') throw new LicenseError(409, `Request is already ${request.status}`);
      if (decision === 'approved') {
        await this.expire(client, license.id);
        const direct = request.assignee_type === 'user'
          ? (await client.query("SELECT 1 FROM license_assignment_sources WHERE license_id=$1 AND user_id=$2 AND source_type='direct'", [license.id, request.assignee_id])).rows.length > 0
          : Boolean(await this.findAssignment(client, license.id, request));
        if (!direct) await this.insertAssignment(client, license, request, actor);
      }
      const updated = await client.query('UPDATE license_requests SET status = $2, decided_at = NOW(), decided_by = $3 WHERE id = $1 RETURNING *', [requestId, decision, actor]);
      await this.audit(client, license.id, decision, actor, updated.rows[0]);
      return updated.rows[0];
    });
  }

  async offboard(userId, actor, { systemActor = false } = {}) {
    requireScopedOperation(null, []);
    userId = canonicalIdentifier(userId);
    if (!validIdentifier(userId) || !validIdentifier(actor)) throw new LicenseError(400, 'Invalid user identifier');
    await this.assertLegacySubject(userId); if (!systemActor) await this.assertLegacySubject(actor);
    return this.transaction(async client => {
      let alreadyDisabled = false;
      for (const identifier of [...new Set(systemActor ? [userId] : [userId, actor])].sort()) {
        await client.query('INSERT INTO license_subjects (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [identifier]);
        const subject = await client.query('SELECT * FROM license_subjects WHERE user_id = $1 FOR UPDATE', [identifier]);
        if (subject.rows[0].business_tenant_id != null) throw new LicenseError(404, 'Legacy lifecycle cannot change a company-owned subject');
        if (identifier === userId) alreadyDisabled = subject.rows[0].disabled;
        if (identifier === actor && actor !== userId && subject.rows[0].disabled) throw new LicenseError(403, 'License access is disabled for this user');
      }
      await client.query('UPDATE license_subjects SET disabled = true, updated_at = NOW() WHERE user_id = $1', [userId]);
      if (!alreadyDisabled) await this.audit(client, null, 'subject-disabled', actor, { userId });
      return this.releaseUser(client, userId, actor, 'offboard-revoked');
    });
  }

  async releaseUser(client, userId, actor, action) {
    if (scopeContext.getStore()) throw new LicenseError(403, 'Scoped operations cannot perform subject lifecycle changes');
    await this.assertLegacySubject(userId, client);
    const pools = await client.query(`SELECT id FROM license_catalog WHERE business_tenant_id IS NULL AND id IN (
      SELECT license_id FROM license_assignments WHERE assignee_type = 'user' AND assignee_id = $1
      UNION SELECT license_id FROM license_requests WHERE status = 'pending' AND (requester_id = $1 OR (assignee_type = 'user' AND assignee_id = $1))
      UNION SELECT license_id FROM license_assignment_sources WHERE user_id=$1
    ) ORDER BY id FOR UPDATE`, [userId]);
    const removed = await client.query("DELETE FROM license_assignments WHERE assignee_type = 'user' AND assignee_id = $1 AND license_id IN (SELECT id FROM license_catalog WHERE business_tenant_id IS NULL) RETURNING *", [userId]);
    await client.query('DELETE FROM license_assignment_sources WHERE user_id=$1 AND license_id IN (SELECT id FROM license_catalog WHERE business_tenant_id IS NULL)', [userId]);
    const cancelled = await client.query(`UPDATE license_requests SET status = 'cancelled', decided_at = NOW(), decided_by = $2
      WHERE status = 'pending' AND license_id IN (SELECT id FROM license_catalog WHERE business_tenant_id IS NULL) AND (requester_id = $1 OR (assignee_type = 'user' AND assignee_id = $1)) RETURNING *`, [userId, actor]);
    for (const license of pools.rows) await this.syncCounter(client, license.id);
    for (const assignment of removed.rows) await this.audit(client, assignment.license_id, action, actor, assignment);
    for (const request of cancelled.rows) await this.audit(client, request.license_id, 'cancelled', actor, request);
    return { userId, assignmentsRevoked: removed.rows.length, requestsCancelled: cancelled.rows.length, localOnly: true };
  }

  async expireAll() {
    requireScopedOperation(null, []);
    const pools = await this.database.query(`SELECT candidates.license_id FROM (SELECT DISTINCT license_id FROM license_assignments WHERE expires_at<=license_now()
      UNION SELECT license_id FROM license_assignment_sources WHERE license_member_source_expiry(grant_id,user_id,expires_at)<=license_now()
      UNION SELECT license_id FROM license_group_rules WHERE enabled AND license_source_expiry(grant_id,expires_at)<=license_now()) candidates JOIN license_catalog catalog ON catalog.id=candidates.license_id WHERE catalog.business_tenant_id IS NULL`);
    let expired = 0;
    for (const pool of pools.rows) {
      expired += await this.transaction(async client => {
        await this.lockLicense(client, pool.license_id);
        const count = await this.expire(client, pool.license_id);
        await this.syncCounter(client, pool.license_id);
        return count;
      });
    }
    return expired;
  }

  async activate(userId, actor, context = {}) {
    userId = canonicalIdentifier(userId);
    if (!validIdentifier(userId) || !validIdentifier(actor)) throw new LicenseError(400, 'Invalid user identifier');
    await this.assertLegacySubject(userId); await this.assertLegacySubject(actor);
    const snapshots = await this.users.active([userId], context);
    return this.transaction(async client => {
      let alreadyActive = false;
      for (const identifier of [...new Set([userId, actor])].sort()) {
        await client.query('INSERT INTO license_subjects (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [identifier]);
        const subject = await client.query('SELECT * FROM license_subjects WHERE user_id = $1 FOR UPDATE', [identifier]);
        if (subject.rows[0].business_tenant_id != null) throw new LicenseError(404, 'Legacy activation cannot change a company-owned subject');
        const snapshot = snapshots.find(value => value.userId === identifier);
        const state = snapshot ? await this.users.apply(client, snapshot, subject.rows[0]) : subject.rows[0];
        if (identifier === actor && (state.disabled || state.directory_enabled === false)) throw new LicenseError(403, 'A disabled operator cannot reactivate license eligibility');
        if (identifier === userId) alreadyActive = !subject.rows[0].disabled;
      }
      await client.query('UPDATE license_subjects SET disabled = false, updated_at = NOW() WHERE user_id = $1', [userId]);
      if (!alreadyActive) await this.audit(client, null, 'subject-reactivated', actor, { userId });
      return { userId, disabled: false, localOnly: true };
    });
  }
}

module.exports = { LicenseAllocator, LicenseError, validIdentifier, canonicalIdentifier };
