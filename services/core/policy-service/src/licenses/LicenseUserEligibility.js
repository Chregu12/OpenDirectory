'use strict';

const { LicenseError } = require('./LicenseError');
const { UUID } = require('./LicensePrincipal');
const { normalizeUserSnapshot } = require('./GroupSnapshotClient');
const { requireScopedOperation } = require('./LicenseScopeContext');
const{sourceRequest}=require('./SourceCredentials');
const { companyLicenseContext } = require('./CompanyLicenseContext');

class LicenseUserEligibility {
  constructor(allocator, source) { this.allocator = allocator; this.source = source; }

  async read(userId, authorization) {
    if (typeof userId !== 'string' || !UUID.test(userId)) throw new LicenseError(400, 'A canonical directory user UUID is required');
    const company = companyLicenseContext.getStore();
    if (company) return normalizeUserSnapshot(await company.eligibility(userId, authorization), userId);
    await this.allocator.assertLegacySubject(userId);
    const credential=authorization&&typeof authorization==='object'?authorization:null;if(credential&&credential.purpose!=='licenses.users.read')throw new LicenseError(403,'A dedicated user-eligibility credential is required');
    try { return normalizeUserSnapshot(await sourceRequest(credential,credential?null:authorization,bearer=>this.source.user(userId,bearer)), userId); }
    catch (error) { if (error instanceof LicenseError) throw error; throw new LicenseError(503, 'Authoritative user eligibility unavailable'); }
  }

  async active(userIds, context = {}) {
    const snapshots = [];
    for (const userId of [...new Set(userIds)].sort()) {
      const snapshot = await this.read(userId, context.authorization);
      if (!snapshot.enabled || snapshot.deleted) {
        if (companyLicenseContext.getStore()) throw new LicenseError(403, 'The own company employee is disabled or deleted');
        try { await this.reconcileSnapshot(snapshot, context.principal?.userId || 'system:user-eligibility'); }
        catch (error) { if (error instanceof LicenseError) throw error; throw new LicenseError(503, 'User eligibility reconciliation failed'); }
        throw new LicenseError(403, 'The directory user is disabled or deleted');
      }
      snapshots.push(snapshot);
    }
    return snapshots;
  }

  async apply(client, snapshot, previous) {
    const company = companyLicenseContext.getStore();
    if (company ? previous.business_tenant_id !== company.tenantId || snapshot.userId !== company.targetUserId : previous.business_tenant_id != null) throw new LicenseError(404, 'License eligibility is outside this operation');
    if (previous.directory_revision != null) {
      if (BigInt(snapshot.revision) < BigInt(previous.directory_revision)) throw new LicenseError(409, 'Stale user eligibility revision');
      if (snapshot.revision === String(previous.directory_revision)
        && (snapshot.enabled !== previous.directory_enabled || snapshot.deleted !== previous.directory_deleted)) throw new LicenseError(409, 'User eligibility revision changed content');
      if (previous.directory_deleted && !snapshot.deleted) throw new LicenseError(409, 'A deleted directory identity cannot be restored');
    }
    await client.query(`UPDATE license_subjects SET directory_revision=$2,directory_enabled=$3,directory_deleted=$4,
      directory_checked_at=clock_timestamp(),directory_attempted_at=clock_timestamp(),directory_error=NULL WHERE user_id=$1`,
    [snapshot.userId, snapshot.revision, snapshot.enabled, snapshot.deleted]);
    if (previous.directory_revision == null || snapshot.revision !== String(previous.directory_revision)) {
      await this.allocator.audit(client, null, 'directory-eligibility-changed', 'system:user-eligibility', snapshot);
    }
    return { ...previous, directory_revision: snapshot.revision, directory_enabled: snapshot.enabled, directory_deleted: snapshot.deleted };
  }

  async reconcileSnapshot(snapshot, actor) {
    if (companyLicenseContext.getStore()) throw new LicenseError(403, 'Company pool operations cannot perform global eligibility reconciliation');
    requireScopedOperation(null, []);
    return this.allocator.transaction(async client => {
      await client.query('INSERT INTO license_subjects(user_id) VALUES($1) ON CONFLICT DO NOTHING', [snapshot.userId]);
      const current = (await client.query('SELECT * FROM license_subjects WHERE user_id=$1 FOR UPDATE', [snapshot.userId])).rows[0];
      await this.apply(client, snapshot, current);
      const released = !snapshot.enabled || snapshot.deleted ? await this.allocator.releaseUser(client, snapshot.userId, actor, 'directory-revoked')
        : { userId: snapshot.userId, assignmentsRevoked: 0, requestsCancelled: 0, localOnly: true };
      return { ...released, revision: snapshot.revision, enabled: snapshot.enabled, deleted: snapshot.deleted, disabled: current.disabled };
    });
  }

  async reconcile(userId, actor, context = {}) {
    return this.reconcileSnapshot(await this.read(userId, context.authorization), actor);
  }

  async reconcileAll(authorization) {
    const candidates = await this.allocator.database.query(`SELECT candidates.user_id FROM (
      SELECT user_id FROM license_subjects WHERE directory_revision IS NOT NULL AND directory_deleted IS NOT TRUE
      UNION SELECT user_id FROM license_assignment_sources
      UNION SELECT assignee_id FROM license_assignments WHERE assignee_type='user'
      UNION SELECT requester_id FROM license_requests WHERE status='pending' AND identity_bound
      UNION SELECT assignee_id FROM license_requests WHERE status='pending' AND identity_bound AND assignee_type='user'
      ) candidates LEFT JOIN license_subjects subjects ON subjects.user_id=candidates.user_id
      WHERE subjects.business_tenant_id IS NULL AND candidates.user_id ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
      ORDER BY subjects.directory_attempted_at NULLS FIRST,candidates.user_id LIMIT 50`);
    const results = [];
    for (const { user_id: userId } of candidates.rows) {
      if(authorization?.stopped)break;
      try { results.push(await this.reconcile(userId, 'system:user-reconciliation', { authorization })); }
      catch (error) {
        await this.allocator.database.query(`INSERT INTO license_subjects(user_id,directory_attempted_at,directory_error)
          SELECT $1::text,clock_timestamp(),$2::text WHERE NOT EXISTS(SELECT 1 FROM license_subjects WHERE user_id=$1::text AND business_tenant_id IS NOT NULL)
          ON CONFLICT(user_id) DO UPDATE SET directory_attempted_at=clock_timestamp(),directory_error=EXCLUDED.directory_error WHERE license_subjects.business_tenant_id IS NULL`, [userId, error.message]);
        results.push({ userId, error: error.message });
        if (error.status === 403 || error.status === 503) break;
      }
    }
    return results;
  }
}

module.exports = { LicenseUserEligibility };
