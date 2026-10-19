'use strict';

const { LicenseError, validIdentifier, canonicalIdentifier } = require('./LicenseAllocator');
const { normalizeSnapshot } = require('./GroupSnapshotClient');
const { requirePrincipal, validateRequestIdentity } = require('./LicensePrincipal');
const { requireScopedOperation } = require('./LicenseScopeContext');
const{GroupDirectoryLeases}=require('./GroupDirectoryLeases');
const{isDeepStrictEqual}=require('node:util');
const{sourceRequest}=require('./SourceCredentials');
const{SOURCE_SCOPE}=require('../../../../../packages/group-license-lease-contract');

class GroupLicenseAllocator {
  constructor({ allocator, source }) {
    this.allocator = allocator;
    this.database = allocator.database;
    this.source = source;
    this.leases=new GroupDirectoryLeases();
    allocator.groups = this;
  }

  async snapshot(groupId, context) {
    if(context.sourceCredentials&&(!context.workload||context.principal||context.sourceCredentials.purpose!==SOURCE_SCOPE))throw new LicenseError(403,'A human operator bearer cannot be replaced by workload credentials');
    const snapshot = normalizeSnapshot(await sourceRequest(context.sourceCredentials,context.authorization,authorization=>this.source.snapshot(groupId,authorization)), groupId);
    if (snapshot.viewerUserId && snapshot.viewerEnabled !== true) throw new LicenseError(403, 'The linked directory identity is disabled');
    if (context.principal && snapshot.viewerUserId !== context.principal.userId) throw new LicenseError(409, 'Directory identity binding changed; retry the operation');
    return snapshot;
  }

  async confirm(client,snapshot,context,independentActor){
    const current=await this.snapshot(snapshot.groupId,context);
    if(independentActor&&[...current.memberIds,...current.inactiveMemberIds].includes(independentActor))throw new LicenseError(403,'Cannot review a group request that benefits you');
    if(current.revision!==snapshot.revision||current.hash!==snapshot.hash||!isDeepStrictEqual(current.sourceAuthorization,snapshot.sourceAuthorization))throw new LicenseError(409,'Group or source consent changed during license operation');
    await this.leases.assertCurrent(client,snapshot,snapshot.memberIds);
  }

  async inPool(licenseId, snapshot, actor, operation, { systemActor = false, subjects = [], userSnapshots = [],context,independentActor } = {}) {
    if (!validIdentifier(actor)) throw new LicenseError(400, 'Invalid actor');
    await this.allocator.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    const previous = await this.database.query("SELECT user_id FROM license_assignment_sources WHERE license_id=$1 AND source_type='group' AND source_id=$2", [licenseId, snapshot.groupId]);
    const identifiers = [...new Set([...snapshot.memberIds, ...snapshot.inactiveMemberIds, ...previous.rows.map(row => row.user_id), ...subjects, ...(systemActor ? [] : [actor])])].sort();
    for (const identifier of identifiers) await this.allocator.assertLegacySubject(identifier);
    return this.allocator.transaction(async client => {
      await this.allocator.assertPoolAccess(licenseId, client, { legacyOnly: true });
      const disabled = new Set();
      for (const userId of identifiers) {
        await this.allocator.assertLegacySubject(userId, client);
        await client.query('INSERT INTO license_subjects(user_id) VALUES($1) ON CONFLICT DO NOTHING', [userId]);
        const subject = await client.query('SELECT * FROM license_subjects WHERE user_id=$1 AND business_tenant_id IS NULL FOR UPDATE', [userId]);
        if (!subject.rows.length) throw new LicenseError(404, 'Legacy license subject not found');
        const eligibility = userSnapshots.find(value => value.userId === userId);
        let state = eligibility ? await this.allocator.users.apply(client, eligibility, subject.rows[0]) : subject.rows[0];
        const member=snapshot.memberships?.find(value=>value.userId===userId);
        if(member&&state.directory_enabled!==false&&state.directory_deleted!==true){if(state.directory_revision!==null&&state.directory_revision!==undefined&&String(state.directory_revision)!==member.eligibilityRevision)throw new LicenseError(409,'Canonical group recipient changed; reconcile eligibility before renewing the group');
          state=await this.allocator.users.apply(client,{schemaVersion:1,userId,revision:member.eligibilityRevision,enabled:true,deleted:false},state);}
        if (state.disabled || state.directory_enabled === false) {
          if ((!systemActor && userId === actor) || subjects.includes(userId)) throw new LicenseError(403, 'License access is disabled for this user');
          disabled.add(userId);
        }
      }
      const license = await this.allocator.lockLicense(client, licenseId);
      const current = await client.query("SELECT user_id FROM license_assignment_sources WHERE license_id=$1 AND source_type='group' AND source_id=$2", [licenseId, snapshot.groupId]);
      if (current.rows.some(row => !identifiers.includes(row.user_id))) throw new LicenseError(409, 'Group sources changed; retry with a fresh snapshot');
      await this.allocator.expire(client, licenseId);
      if(context)await this.confirm(client,snapshot,context,independentActor);
      const result=await operation(client, license, disabled);
      if(context)await this.confirm(client,snapshot,context,independentActor);
      return result;
    });
  }

  async apply(client, license, snapshot, actor, disabled, { configure = false, expiresAt } = {}) {
    requireScopedOperation(license.id, ['assignments.manage','requests.review']);
    await this.allocator.assertPoolAccess(license.id, client, { legacyOnly: true });
    if(!configure)await client.query("SELECT set_config('opendirectory.group_derivation',$1,true)",[JSON.stringify({licenseId:license.id,groupId:snapshot.groupId})]);
    const stored = await client.query('SELECT * FROM license_group_rules WHERE license_id=$1 AND group_id=$2 FOR UPDATE', [license.id, snapshot.groupId]);
    const previous = stored.rows[0];
    if (!configure && (!previous || !previous.enabled)) return previous;
    if (configure && snapshot.deleted) throw new LicenseError(404, 'Group has been deleted');
    if (previous?.source_revision != null && BigInt(snapshot.revision) < BigInt(previous.source_revision)) throw new LicenseError(409, 'Stale group revision');
    if (previous?.source_revision != null && snapshot.revision === String(previous.source_revision) && previous.source_hash !== snapshot.hash) throw new LicenseError(409, 'Group revision changed content');
    const expiry = configure && expiresAt !== undefined ? expiresAt : previous?.expires_at || null;
    if (expiry && new Date(expiry).getTime() <= Date.now()) throw new LicenseError(409, 'An expired group rule needs a new expiry before reactivation');
    const desired = snapshot.deleted ? [] : snapshot.memberIds.filter(userId => !disabled.has(userId));
    const removed = await client.query("DELETE FROM license_assignment_sources WHERE license_id=$1 AND source_type='group' AND source_id=$2 AND NOT(user_id=ANY($3::text[])) RETURNING user_id", [license.id, snapshot.groupId, desired]);
    for (const row of removed.rows) await this.allocator.syncUser(client, license.id, row.user_id, actor);
    const active = await client.query("SELECT assignee_id FROM license_assignments WHERE license_id=$1 AND assignee_type='user' AND (expires_at IS NULL OR expires_at>license_now())", [license.id]);
    const existingSeats = new Set(active.rows.map(row => row.assignee_id));
    const required = desired.filter(userId => !existingSeats.has(userId)).length;
    const blocked = license.total_seats > 0 && await this.allocator.count(client, license.id) + required > license.total_seats;
    const additions = [];
    const status = snapshot.deleted ? 'deleted' : blocked ? 'capacity-blocked' : 'active';
    const rule = configure ? await client.query(`INSERT INTO license_group_rules(license_id,group_id,group_name,enabled,expires_at,source_revision,source_hash,status,last_error,last_synced_at,configured_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),$10) ON CONFLICT(license_id,group_id) DO UPDATE SET
      group_name=EXCLUDED.group_name,enabled=EXCLUDED.enabled,expires_at=EXCLUDED.expires_at,source_revision=EXCLUDED.source_revision,
      source_hash=EXCLUDED.source_hash,status=EXCLUDED.status,last_error=EXCLUDED.last_error,last_synced_at=EXCLUDED.last_synced_at,
      configured_by=CASE WHEN $11 THEN EXCLUDED.configured_by ELSE license_group_rules.configured_by END RETURNING *`,
    [license.id, snapshot.groupId, snapshot.name, !snapshot.deleted, expiry, snapshot.revision, snapshot.hash, status, blocked ? 'Insufficient seats for all eligible group members' : null, actor, configure])
      : await client.query('UPDATE license_group_rules SET group_name=$3,enabled=$4,source_revision=$5,source_hash=$6,status=$7,last_error=$8,last_synced_at=NOW() WHERE license_id=$1 AND group_id=$2 RETURNING *',
      [license.id,snapshot.groupId,snapshot.name,!snapshot.deleted,snapshot.revision,snapshot.hash,status,blocked?'Insufficient seats for all eligible group members':null]);
    await client.query('UPDATE license_group_rules SET desired_users=$3 WHERE license_id=$1 AND group_id=$2', [license.id, snapshot.groupId, desired.length]);
    rule.rows[0].desired_users = desired.length;
    if(rule.rows[0].enabled)await this.leases.observe(client,rule.rows[0],snapshot,desired);
    for (const userId of desired) {
      if (blocked && !existingSeats.has(userId)) continue;
      const assignment=await this.allocator.findAssignment(client,license.id,{assignee_type:'user',assignee_id:userId});const member=snapshot.memberships.find(value=>value.userId===userId);
      if(assignment&&String(assignment.eligibility_revision)!==member.eligibilityRevision)throw new LicenseError(409,'Existing entitlement origin requires explicit withdrawal and reissue');
      const source = await client.query(`INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by,expires_at)
        VALUES($1,$2,'group',$3,$4,$5) ON CONFLICT(license_id,user_id,source_type,source_id) DO UPDATE SET expires_at=EXCLUDED.expires_at
        WHERE license_assignment_sources.expires_at IS DISTINCT FROM EXCLUDED.expires_at RETURNING user_id`, [license.id, userId, snapshot.groupId, actor, expiry]);
      if (source.rows.length) additions.push(userId);
      await this.allocator.syncUser(client, license.id, userId, actor);
    }
    await this.allocator.syncCounter(client, license.id);
    await client.query("UPDATE license_requests SET allocation_status=$3 WHERE license_id=$1 AND assignee_type='group' AND assignee_id=$2 AND status='approved'", [license.id, snapshot.groupId, status]);
    if (!previous || String(previous.source_revision) !== snapshot.revision || previous.status !== status || configure || additions.length || removed.rows.length) {
      await this.allocator.audit(client, license.id, 'group-reconciled', actor, { groupId: snapshot.groupId, revision: snapshot.revision, status,
        expiresAt: expiry, previousExpiresAt: previous?.expires_at || null,
        sourceUsersAdded: additions, sourceUsersRemoved: removed.rows.map(row => row.user_id), disabledUsersSkipped: [...disabled] });
    }
    if(rule.rows[0].enabled)await this.leases.assertCurrent(client,snapshot,desired);
    return rule.rows[0];
  }

  async assign(licenseId, assignment, actor, context) {
    requireScopedOperation(licenseId, ['assignments.manage']);
    await this.allocator.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    await this.allocator.assertLegacySubject(actor);
    const snapshot = await this.snapshot(assignment.assignee_id, context);
    return this.inPool(licenseId, snapshot, actor, async (client, license, disabled) => {
      await this.allocator.authorizeOperation(client,licenseId,'assignments.manage');
      return {kind:'group',localOnly:true,rule:await this.apply(client,license,snapshot,actor,disabled,{configure:true,expiresAt:assignment.expires_at})};
    },{context});
  }

  async revoke(licenseId, groupId, actor) {
    requireScopedOperation(licenseId, ['assignments.manage']);
    groupId = canonicalIdentifier(groupId);
    const snapshot = { groupId, memberIds: [], inactiveMemberIds: [] };
    return this.inPool(licenseId, snapshot, actor, async client => {
      await this.allocator.authorizeOperation(client,licenseId,'assignments.manage');
      const rule = await client.query("UPDATE license_group_rules SET enabled=false,status='revoked',last_error=NULL WHERE license_id=$1 AND group_id=$2 RETURNING *", [licenseId, groupId]);
      if (!rule.rows.length) throw new LicenseError(404, 'Group rule not found');
      const removed = await client.query("DELETE FROM license_assignment_sources WHERE license_id=$1 AND source_type='group' AND source_id=$2 RETURNING user_id", [licenseId, groupId]);
      for (const row of removed.rows) await this.allocator.syncUser(client, licenseId, row.user_id, actor);
      await this.allocator.syncCounter(client, licenseId);
      await client.query("UPDATE license_requests SET allocation_status='revoked' WHERE license_id=$1 AND assignee_type='group' AND assignee_id=$2 AND status='approved'", [licenseId, groupId]);
      await this.allocator.audit(client, licenseId, 'group-revoked', actor, { groupId, userIds: removed.rows.map(row => row.user_id) });
      return { localOnly: true, groupId, sourcesRemoved: removed.rows.length };
    });
  }

  async request(licenseId, request, context) {
    requireScopedOperation(licenseId, ['requests.delegate']);
    const principal = requirePrincipal(context.principal, request.requester_id);
    await this.allocator.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    const userSnapshots = await this.allocator.users.active([request.requester_id], context);
    const snapshot = await this.snapshot(request.assignee_id, context);
    if (snapshot.deleted) throw new LicenseError(404, 'Group has been deleted');
    return this.inPool(licenseId, snapshot, request.requester_id, async (client, license, disabled) => {
      const previous = await client.query("SELECT * FROM license_requests WHERE license_id=$1 AND requester_id=$2 AND identity_bound=true AND assignee_type='group' AND assignee_id=$3 AND status IN ('pending','approved') ORDER BY requested_at DESC", [licenseId, request.requester_id, snapshot.groupId]);
      const rule = await client.query('SELECT * FROM license_group_rules WHERE license_id=$1 AND group_id=$2', [licenseId, snapshot.groupId]);
      const existing = previous.rows.find(row => row.status === 'pending' || rule.rows[0]?.enabled);
      if (existing) return { record: existing, created: false };
      const allocated = license.auto_approve && await this.allocator.autoApprovalAllowed(client,licenseId) ? await this.apply(client, license, snapshot, request.requester_id, disabled, { configure: true }) : null;
      const result = await client.query(`INSERT INTO license_requests(license_id,license_name,requester_id,requester_name,assignee_type,assignee_id,assignee_name,justification,status,decided_at,decided_by,allocation_status,identity_bound,requester_issuer,requester_subject)
        VALUES($1,$2,$3,$4,'group',$5,$6,$7,$8::text,CASE WHEN $8::text='approved' THEN NOW() END,CASE WHEN $8::text='approved' THEN 'auto-approve' END,$9,true,$10,$11) RETURNING *`,
      [licenseId, license.name, request.requester_id, request.requester_name || null, snapshot.groupId, snapshot.name, request.justification || null, allocated ? 'approved' : 'pending', allocated?.status || null, principal.issuer, principal.subject]);
      await this.allocator.audit(client, licenseId, allocated ? 'auto-approved' : 'requested', request.requester_id, result.rows[0]);
      return { record: result.rows[0], created: true };
    }, { userSnapshots,context });
  }

  async review(original, actor, decision, context) {
    requireScopedOperation(original.license_id, ['requests.review']);
    requirePrincipal(context.principal, actor);
    validateRequestIdentity(original);
    await this.allocator.assertPoolAccess(original.license_id, this.database, { legacyOnly: true });
    await this.allocator.assertLegacySubject(actor);
    const snapshot = await this.snapshot(original.assignee_id, context);
    if (original.requester_id === actor) throw new LicenseError(403, 'Cannot review your own group request');
    if (!snapshot.viewerUserId || snapshot.viewerEnabled !== true) throw new LicenseError(403, 'Group review requires a linked, enabled directory identity');
    if ([...snapshot.memberIds, ...snapshot.inactiveMemberIds].includes(snapshot.viewerUserId)) throw new LicenseError(403, 'Cannot review a group request that benefits you');
    const userSnapshots = await this.allocator.users.active([original.requester_id], context);
    return this.inPool(original.license_id, snapshot, actor, async (client, license, disabled) => {
      await this.allocator.authorizeOperation(client,license.id,'requests.review');
      const stored = await client.query('SELECT * FROM license_requests WHERE id=$1 FOR UPDATE', [original.id]);
      const request = stored.rows[0];
      if (!request) throw new LicenseError(404, 'Request not found');
      validateRequestIdentity(request);
      if (request.assignee_id !== original.assignee_id || request.license_id !== original.license_id || request.requester_id !== original.requester_id || request.assignee_type !== 'group') throw new LicenseError(409, 'Request target changed');
      if (request.status !== 'pending') throw new LicenseError(409, 'Request already decided');
      const rule = decision === 'approved' ? await this.apply(client, license, snapshot, actor, disabled, { configure: true }) : null;
      const result = await client.query('UPDATE license_requests SET status=$2,decided_at=NOW(),decided_by=$3,allocation_status=$4 WHERE id=$1 RETURNING *', [original.id, decision, actor, rule?.status || null]);
      await this.allocator.audit(client, license.id, decision, actor, result.rows[0]);
      const confirmed = await this.snapshot(original.assignee_id, context);
      if ([...confirmed.memberIds, ...confirmed.inactiveMemberIds].includes(actor)) throw new LicenseError(403, 'Cannot review a group request that benefits you');
      if (confirmed.revision !== snapshot.revision || confirmed.hash !== snapshot.hash) throw new LicenseError(409, 'Group changed during request review');
      return result.rows[0];
    }, { subjects: [original.requester_id], userSnapshots,context,independentActor:actor });
  }

  async reconcile(licenseId, groupId, actor, context) {
    requireScopedOperation(licenseId, ['assignments.manage']);
    await this.allocator.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    await this.allocator.assertLegacySubject(actor);
    const snapshot = await this.snapshot(groupId, context);
    return this.inPool(licenseId, snapshot, actor, async (client, license, disabled) => {
      await this.allocator.authorizeOperation(client,licenseId,'assignments.manage');
      const result = await this.apply(client, license, snapshot, actor, disabled);
      if (!result) throw new LicenseError(404, 'Group rule not found');
      return { rule: result, localOnly: true };
    },{context});
  }

  async reconcileAll(authorization) {
    const context=authorization&&typeof authorization==='object'?{sourceCredentials:authorization,workload:true}:{authorization};
    const rules = await this.database.query('SELECT rules.* FROM license_group_rules rules JOIN license_catalog catalog ON catalog.id=rules.license_id AND catalog.business_tenant_id IS NULL WHERE rules.enabled AND (rules.expires_at IS NULL OR rules.expires_at>license_now()) ORDER BY rules.license_id,rules.group_id');
    const results = [];
    for (const rule of rules.rows) {
      if(context.sourceCredentials?.stopped)break;
      try {
        const snapshot = await this.snapshot(rule.group_id, context);
        const updated = await this.inPool(rule.license_id, snapshot, 'system:group-reconciliation', (client, license, disabled) => this.apply(client, license, snapshot, 'system:group-reconciliation', disabled), { systemActor: true,context });
        results.push({ groupId: rule.group_id, status: updated?.status });
      } catch (error) {
        await this.database.query("UPDATE license_group_rules rules SET last_error=$3 WHERE license_id=$1 AND group_id=$2 AND enabled AND EXISTS(SELECT 1 FROM license_catalog catalog WHERE catalog.id=rules.license_id AND catalog.business_tenant_id IS NULL)", [rule.license_id, rule.group_id, error.message]);
        results.push({ groupId: rule.group_id, error: error.message });
      }
    }
    return results;
  }
}

module.exports = { GroupLicenseAllocator };
