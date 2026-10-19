'use strict';

const { isDeepStrictEqual } = require('node:util');
const { validUuid } = require('../../../../../packages/identity-authorization-contract');
const { identifier, offboardingIntent, offboardingContinuation, offboardingVersion, poolEtag, pagination } = require('../../../../../packages/company-license-contract');
const { CompanyOffboardingIdentity } = require('./CompanyOffboardingIdentity');
const { CompanyLicenses, poolView } = require('./CompanyLicenses');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function sameActor(before, after) {
  if (!isDeepStrictEqual({ ...before, target: null }, { ...after, target: null })) fail(401, 'Original offboarding actor changed');
}
function summary(job) {
  return { id: job.id, userId: job.userId, createdBy: job.createdBy, revision: job.revision, reason: job.intent.reason, phase: job.state.phase,
    totalLicenses: job.state.items === null ? null : job.state.items.length, completedLicenses: job.state.items?.filter(item => item.status !== 'pending').length || 0,
    failure: job.state.failure, createdAt: job.createdAt, updatedAt: job.updatedAt };
}
function itemView(item) { return { poolId: item.poolId, assignmentId: item.assignmentId, grantId: item.grantId, poolRevision: item.poolRevision, name: item.name, vendor: item.vendor }; }
class CompanyOffboarding {
  constructor(companies, { journal, identity = new CompanyOffboardingIdentity() } = {}) {
    this.companies = companies; this.database = companies.database; this.identity = identity;
    this.journal = journal || new (require('./CompanyOffboardingJournal').CompanyOffboardingJournal)(this.database);
  }
  get v2() { if (!this.sourceAware) this.sourceAware = new (require('./CompanyOffboardingV2').CompanyOffboardingV2)(this); return this.sourceAware; }
  source(user, authorization, target = null) { return this.companies.authority.read(authorization, user, ...(target === null ? [] : [target])); }
  verify(source, user, authorization) { return () => this.companies.unchanged(source, user, authorization); }
  async own(client, source, id) {
    const job = await this.journal.load(client, source.tenant.id, id);
    if (!job) fail(404, 'Own offboarding workflow not found'); return job;
  }
  async capabilities(user, authorization) {
    const source = await this.source(user, authorization); await this.journal.ready(); await this.companies.unchanged(source, user, authorization);
    return { schemaVersion: 1, companyOffboardingProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, scope: 'account-and-local-licenses', requiresFreshMfa: true };
  }
  async preview(userId, user, authorization) {
    identifier(userId); const original = await this.source(user, authorization);
    if (userId === original.actorUserId) fail(403, 'Self offboarding requires a separate recovery procedure');
    const source = await this.source(user, authorization, userId); sameActor(original, source);
    if (source.target.deleted) fail(409, 'Use explicit license returns for a retained deleted employee');
    const person = await this.identity.user(userId, authorization, source);
    const licenseCount = await this.companies.read(user, authorization, async (client, current) => {
      if (!isDeepStrictEqual(current, source)) fail(401, 'Original employee preview changed');
      await CompanyLicenses.prototype.requireV1Sources.call(this.companies, client, null, userId, source.tenant.id);
      return (await client.query("SELECT count(*)::integer AS total FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id WHERE catalog.business_tenant_id=$1 AND assignment.assignee_type='user' AND assignment.assignee_id=$2", [source.tenant.id, userId])).rows[0].total;
    }, userId);
    return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, user: person, licenseCount };
  }
  async view(job, source, user, authorization) {
    const nextAssignments = (job.state.items || []).filter(item => item.status === 'pending').slice(0, 25).map(itemView);
    let reviewAssignments = [];
    if (job.state.phase === 'paused' && job.state.failure?.step === 'licenses' && job.state.checkpoint && !source.target.enabled && !source.target.deleted
      && source.target.eligibilityRevision === job.state.checkpoint.afterEligibilityRevision) {
      reviewAssignments = await this.companies.read(user, authorization, async (client, current) => {
        if (!isDeepStrictEqual(current, source)) fail(401, 'Original offboarding review changed');
        const rows = [];
        for (const item of nextAssignments) {
          const pool = await this.companies.ownPool(client, item.poolId, source.tenant.id);
          rows.push({ ...item, poolRevision: String(pool.business_revision) });
        }
        return rows;
      }, job.userId);
    }
    await this.companies.unchanged(source, user, authorization);
    return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id,
      workflow: { ...summary(job), requestedRevision: job.state.requestedRevision, checkpoint: job.state.checkpoint, nextAssignments, reviewAssignments },
      currentTarget: { enabled: source.target.enabled, deleted: source.target.deleted, eligibilityRevision: source.target.eligibilityRevision } };
  }
  async get(id, user, authorization) {
    identifier(id); const original = await this.source(user, authorization); const job = await this.own(this.database, original, id);
    const source = await this.source(user, authorization, job.userId); sameActor(original, source); return this.view(job, source, user, authorization);
  }
  async list(query, user, authorization) {
    const { page, limit } = pagination(query); const pages = { page, limit }; const source = await this.source(user, authorization);
    const result = await this.journal.list(this.database, source.tenant.id, pages); await this.companies.unchanged(source, user, authorization);
    return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, workflows: result.jobs.map(summary), total: result.total, page: result.page, limit: result.limit };
  }
  async history(id, query, user, authorization) {
    identifier(id); const { page, limit } = pagination(query); const pages = { page, limit }; const source = await this.source(user, authorization); await this.own(this.database, source, id);
    const result = await this.journal.history(this.database, source.tenant.id, id, pages); await this.companies.unchanged(source, user, authorization);
    return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, workflowId: id, ...result };
  }
  async create(input, user, authorization) {
    const intent = offboardingIntent(input); const original = await this.source(user, authorization);
    if (intent.userId === original.actorUserId) fail(403, 'Self offboarding requires a separate recovery procedure');
    const lock = await this.journal.lock(original.tenant.id, intent.workflowId);
    try {
      const existing = await this.journal.load(lock.client, original.tenant.id, intent.workflowId);
      if (existing) {
        if (!isDeepStrictEqual(existing.intent, intent)) fail(409, 'Workflow idempotency key already has a different intent');
        const current = await this.source(user, authorization, existing.userId); sameActor(original, current);
        return { created: false, result: await this.view(existing, current, user, authorization) };
      }
      const source = await this.source(user, authorization, intent.userId); sameActor(original, source);
      await CompanyLicenses.prototype.requireV1Sources.call(this.companies, lock.client, null, intent.userId, source.tenant.id);
      if (source.target.deleted) fail(409, 'Use explicit license returns for a retained deleted employee');
      const person = await this.identity.user(intent.userId, authorization, source);
      if (person.userRevision !== intent.userRevision || person.eligibilityRevision !== intent.eligibilityRevision) fail(412, 'Employee preview changed');
      const { job } = await this.journal.create(lock.client, source, intent, this.verify(source, user, authorization));
      return { created: true, result: await this.execute(lock.client, job, source, user, authorization, null) };
    } finally { await lock.release(); }
  }
  async continue(id, input, expected, user, authorization) {
    identifier(id); const values = offboardingContinuation(input); const version = offboardingVersion(id, expected); const original = await this.source(user, authorization);
    const lock = await this.journal.lock(original.tenant.id, id);
    try {
      let job = await this.own(lock.client, original, id);
      if (job.revision !== version) fail(412, 'Offboarding workflow changed');
      if (values.reason !== job.intent.reason) fail(409, 'Confirm the original immutable offboarding reason');
      const source = await this.source(user, authorization, job.userId); sameActor(original, source);
      if (job.userId === source.actorUserId) fail(403, 'Self offboarding requires a separate recovery procedure');
      if (job.state.phase === 'completed_local') return this.view(job, source, user, authorization);
      if (values.userRevision !== job.state.requestedRevision) {
        if (job.state.checkpoint || job.state.failure?.code !== 412 || job.state.failure?.step !== 'account' || source.target.eligibilityRevision !== job.intent.eligibilityRevision) fail(409, 'Original offboarding account request must be recovered first');
        const person = await this.identity.user(job.userId, authorization, source);
        if (person.userRevision !== values.userRevision) fail(412, 'Employee review changed');
        job = await this.journal.save(lock.client, source, job, { ...job.state, requestedRevision: values.userRevision }, this.verify(source, user, authorization));
      }
      const pending = (job.state.items || []).filter(item => item.status === 'pending').slice(0, 25);
      if (values.assignments.length !== pending.length || values.assignments.some((item, index) => item.poolId !== pending[index].poolId || item.assignmentId !== pending[index].assignmentId)) fail(409, 'Exact captured next offboarding page required');
      return this.execute(lock.client, job, source, user, authorization, values.assignments);
    } finally { await lock.release(); }
  }
  async capture(job, source, user, authorization) {
    return this.companies.read(user, authorization, async (client, current) => {
      if (!isDeepStrictEqual(source, current)) fail(401, 'Offboarding capture changed');
      await CompanyLicenses.prototype.requireV1Sources.call(this.companies, client, null, job.userId, source.tenant.id);
      const parameters = [source.tenant.id, job.userId];
      const total = (await client.query("SELECT count(*)::integer AS total FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id WHERE catalog.business_tenant_id=$1 AND assignment.assignee_type='user' AND assignment.assignee_id=$2", parameters)).rows[0].total;
      if (total > 10000) fail(409, 'Employee license capture requires a separately reviewed larger workflow');
      const rows = (await client.query(`SELECT catalog.*,catalog.used_seats AS active_seats,license_company_pool_valid(catalog.id) AS company_valid,assignment.id AS assignment_id,source.grant_id
        FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id
        JOIN license_assignment_sources source ON source.license_id=assignment.license_id AND source.user_id=assignment.assignee_id AND source.source_type='direct'
        WHERE catalog.business_tenant_id=$1 AND assignment.assignee_type='user' AND assignment.assignee_id=$2 ORDER BY catalog.name,catalog.id`, parameters)).rows;
      if (rows.length !== total) fail(503, 'Complete original license capture unavailable');
      return rows.map(row => {
        const pool = poolView(row); if (!validUuid(row.assignment_id) || !validUuid(row.grant_id)) fail(503, 'Captured license lineage unavailable');
        return { poolId: pool.id, assignmentId: row.assignment_id, grantId: row.grant_id, poolRevision: pool.revision, name: pool.name, vendor: pool.vendor, status: 'pending', eventId: null };
      });
    }, job.userId);
  }
  async observe(job, item, source, user, authorization) {
    return this.companies.read(user, authorization, async (client, current) => {
      if (!isDeepStrictEqual(source, current)) fail(401, 'Offboarding license observation changed');
      await this.companies.ownPool(client, item.poolId, source.tenant.id);
      const active = (await client.query(`SELECT assignment.id,source.grant_id FROM license_assignments assignment JOIN license_assignment_sources source
        ON source.license_id=assignment.license_id AND source.user_id=assignment.assignee_id AND source.source_type='direct'
        WHERE assignment.license_id=$1 AND assignment.assignee_type='user' AND assignment.assignee_id=$2`, [item.poolId, job.userId])).rows[0];
      if (active?.id === item.assignmentId && active.grant_id === item.grantId) return null;
      const rows = (await client.query(`SELECT events.id,events.correlation_id,events.before_revision FROM license_company_events events
        WHERE events.license_id=$1 AND events.tenant_id=$2 AND events.target_user_id=$3 AND events.type='app.license.released'
        AND events.before_state#>>'{assignment,id}'=$4 AND events.before_state#>>'{source,grant_id}'=$5 AND license_company_event_valid(events)`,
      [item.poolId, source.tenant.id, job.userId, item.assignmentId, item.grantId])).rows;
      if (rows.length !== 1) fail(409, 'Captured license changed without confirmed release evidence');
      return { ...item, status: rows[0].correlation_id === job.id ? 'released' : 'already_released', eventId: rows[0].id, poolRevision: String(rows[0].before_revision) };
    }, job.userId);
  }
  async execute(client, initial, original, user, authorization, approvals) {
    let job = initial; let source = original; let step = 'account'; const capturedApprovals = initial.state.items === null ? null : approvals;
    try {
      if (!job.state.checkpoint) {
        if (source.target.deleted || source.target.enabled && source.target.eligibilityRevision !== job.intent.eligibilityRevision) { step = 'verify'; fail(409, 'Original employee lifecycle changed'); }
        const receipt = await this.identity.disable(job, authorization, source);
        if (receipt.beforeEligibilityRevision !== job.intent.eligibilityRevision) fail(409, 'Original employee lifecycle changed');
        const after = await this.source(user, authorization, job.userId); sameActor(source, after); source = after;
        if (source.target.enabled || source.target.deleted || source.target.eligibilityRevision !== receipt.afterEligibilityRevision) fail(409, 'Original disabled employee incarnation changed');
        job = await this.journal.save(client, source, job, { ...job.state, checkpoint: receipt, phase: 'licenses', failure: null }, this.verify(source, user, authorization));
      }
      if (source.target.enabled || source.target.deleted || source.target.eligibilityRevision !== job.state.checkpoint.afterEligibilityRevision) { step = 'verify'; fail(409, 'Original disabled employee incarnation changed'); }
      if (job.state.items === null) {
        step = 'capture'; const items = await this.capture(job, source, user, authorization);
        job = await this.journal.save(client, source, job, { ...job.state, phase: 'licenses', failure: null, items }, this.verify(source, user, authorization));
      }
      step = 'licenses'; const pending = job.state.items.filter(item => item.status === 'pending').slice(0, 25);
      for (const [index, item] of pending.entries()) {
        let observed = await this.observe(job, item, source, user, authorization);
        if (!observed) {
          const version = capturedApprovals ? capturedApprovals[index].poolRevision : item.poolRevision;
          await this.companies.revoke(item.poolId, item.assignmentId, { userId: job.userId, reason: job.intent.reason, confirm: true }, poolEtag({ id: item.poolId, revision: version }), user, authorization, job.id, source);
          observed = await this.observe(job, item, source, user, authorization);
          if (!observed) fail(503, 'Original release receipt unavailable');
        }
        job = await this.journal.save(client, source, job, { ...job.state, phase: 'licenses', failure: null, items: job.state.items.map(row => row.assignmentId === item.assignmentId ? observed : row) }, this.verify(source, user, authorization));
      }
      if (job.state.items.every(item => item.status !== 'pending')) {
        step = 'verify';
        const remaining = await this.companies.read(user, authorization, async (reader, current) => {
          if (!isDeepStrictEqual(source, current)) fail(401, 'Final offboarding employee state changed');
          return (await reader.query("SELECT count(*)::integer AS total FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id WHERE catalog.business_tenant_id=$1 AND assignment.assignee_type='user' AND assignment.assignee_id=$2", [source.tenant.id, job.userId])).rows[0].total;
        }, job.userId);
        if (remaining !== 0) fail(409, 'Uncaptured assignments require a new reviewed workflow');
        job = await this.journal.save(client, source, job, { ...job.state, phase: 'completed_local', failure: null }, this.verify(source, user, authorization));
      }
    } catch (error) {
      const current = await this.source(user, authorization, job.userId); sameActor(source, current); source = current;
      const code = Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 ? error.status : 503;
      job = await this.journal.save(client, source, job, { ...job.state, phase: 'paused', failure: { code, step } }, this.verify(source, user, authorization));
    }
    return this.view(job, source, user, authorization);
  }
}
module.exports = { CompanyOffboarding, summary };
