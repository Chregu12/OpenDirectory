'use strict';

const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { identifier, exact, offboardingIntent, offboardingVersion, pagination } = require('../../../../../packages/company-license-contract');
const { operationKey, poolCapture, bindingCapture } = require('./CompanyLicenseSourcesContract');
const { envelope } = require('./CompanyLicenseSources');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function sameActor(before, after) { if (!isDeepStrictEqual({ ...before, target: null }, { ...after, target: null })) fail(401, 'Original workflow actor changed'); }
function negative(job, source) {
  if (source.target.enabled || source.target.deleted || source.target.eligibilityRevision !== job.state.checkpoint.afterEligibilityRevision) fail(409, 'Original Identity 045 negative epoch changed');
}
function summary(job) {
  const completed = job.state.phase === 'completed_local';
  return { id: job.id, userId: job.user_id, createdBy: job.created_by, revision: String(job.revision), reason: job.intent.reason, phase: job.state.phase,
    totalLicenses: job.state.items === null ? null : job.state.items.length, completedLicenses: job.state.items?.filter(item => item.status !== 'pending').length || 0,
    totalBindings: job.state.bindings === null ? null : job.state.bindings.length, completedBindings: completed ? job.state.bindings.length : 0,
    failure: job.state.failure, createdAt: new Date(job.created_at).toISOString(), updatedAt: new Date(job.updated_at).toISOString() };
}
function captured(item) { return { poolId: item.poolId, poolRevision: item.poolRevision, assignmentId: item.assignmentId, sources: item.sources }; }
function previewItem(item) { return { id: item.assignmentId, poolId: item.poolId, poolRevision: item.poolRevision, name: item.name, vendor: item.vendor, eligibilityRevision: item.eligibilityRevision, assignedAt: item.assignedAt, sources: item.sources }; }
function continuation(input) {
  exact(input, ['confirm', 'reason', 'userRevision', 'assignments', 'bindings']);
  if (input.confirm !== true || !Array.isArray(input.assignments) || input.assignments.length > 10000 || !Array.isArray(input.bindings) || input.bindings.length > 10000) fail(400, 'Complete bounded original workflow approval required');
  const assignments = input.assignments.map(poolCapture); const bindings = input.bindings.map(bindingCapture);
  if (new Set(assignments.map(item => item.poolId)).size !== assignments.length || new Set(bindings.map(item => item.id)).size !== bindings.length) fail(400, 'Duplicate workflow capture');
  return { ...input, assignments, bindings };
}

class CompanyOffboardingV2 {
  constructor(parent) { this.parent = parent; this.companies = parent.companies; this.database = parent.database; this.identity = parent.identity; }
  source(user, authorization, target = null) { return this.parent.source(user, authorization, target); }
  async transact(source, user, authorization, operation) {
    const client = await this.database.getClient();
    try {
      await client.query('BEGIN'); await client.query("SET LOCAL statement_timeout='15s';SET LOCAL lock_timeout='5s';SET LOCAL TIME ZONE 'UTC'");
      await client.query('SELECT company_blueprint_assignment_retirement_receiving()');
      await this.companies.unchanged(source, user, authorization);
      const result = await operation(client);
      await this.companies.unchanged(source, user, authorization); await client.query('COMMIT'); await this.companies.unchanged(source, user, authorization); return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
  }
  async load(id, source, client = this.database) {
    await client.query('SELECT company_blueprint_assignment_retirement_receiving()');
    const row = (await client.query('SELECT job.*,company_offboarding_v2_job_valid(job) AS valid FROM company_offboarding_v2_jobs job WHERE job.id=$1 AND job.tenant_id=$2', [id, source.tenant.id])).rows[0];
    if (!row) fail(404, 'Own source-aware offboarding workflow not found');
    if (row.valid !== true) fail(503, 'Complete original source-aware workflow evidence unavailable'); return row;
  }
  async lock(id, source) {
    const client = await this.database.getClient(); const scope = 'company-offboarding-v2:' + source.tenant.id + ':' + id;
    try {
      const locked = (await client.query('SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS locked', [scope])).rows[0]?.locked;
      if (locked !== true) fail(409, 'Original offboarding workflow is already executing');
      return { client, release: async () => { let failed; try { if ((await client.query('SELECT pg_advisory_unlock(hashtextextended($1,0)) AS unlocked', [scope])).rows[0]?.unlocked !== true) throw new Error('Workflow lock not released'); } catch (error) { failed = error; throw error; } finally { client.release(failed); } } };
    } catch (error) { client.release(); throw error; }
  }
  async save(job, source, state, user, authorization, intent = null) {
    return this.transact(source, user, authorization, async client => (await client.query('SELECT company_offboarding_v2_write($1::jsonb,$2::uuid,$3::bigint,$4::jsonb,$5::jsonb) AS job',
      [source, job.id, String(job.revision || '0'), intent, state])).rows[0].job);
  }
  async capabilities(user, authorization) {
    return this.companies.v2.observe(user, authorization, async (_client, source) => ({ ...envelope(source), companyOffboardingProtocol: 2, scope: 'account-local-licenses-and-blueprint-bindings', requiresFreshMfa: true }));
  }
  async preview(userId, user, authorization) {
    identifier(userId); const original = await this.source(user, authorization);
    if (userId === original.actorUserId) fail(403, 'Self offboarding requires a separate recovery procedure');
    const source = await this.source(user, authorization, userId); sameActor(original, source);
    if (source.target.deleted) fail(409, 'Deleted blueprint cleanup requires canonical lifecycle history support');
    const person = await this.identity.user(userId, authorization, source);
    return this.companies.v2.observe(user, authorization, async (client, current, assignmentAuthority) => {
      if (!isDeepStrictEqual(current, source)) fail(401, 'Original employee preview changed');
      const row = (await client.query("SELECT count(*)::integer AS total FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id WHERE catalog.business_tenant_id=$1 AND assignment.assignee_type='user' AND assignment.assignee_id=$2", [source.tenant.id, userId])).rows[0];
      const bindings = await this.companies.v2.bindings(client, source, userId);
      if (bindings.length) await assignmentAuthority(userId);
      return { ...envelope(source), user: person, licenseCount: row.total, bindingCount: bindings.length };
    }, userId);
  }
  async view(job, source, user, authorization) {
    const pending = (job.state.items || []).filter(item => item.status === 'pending'); let reviewAssignments = [];
    if (job.state.phase === 'paused' && job.state.checkpoint && !source.target.enabled && !source.target.deleted && source.target.eligibilityRevision === job.state.checkpoint.afterEligibilityRevision) {
      reviewAssignments = await this.companies.v2.observe(user, authorization, async (client, current) => {
        if (!isDeepStrictEqual(current, source)) fail(401, 'Original source review changed');
        const rows = [];
        for (const item of pending) {
          const pool = await this.companies.ownPool(client, item.poolId, source.tenant.id); rows.push({ ...previewItem(item), poolRevision: String(pool.business_revision) });
        }
        return rows;
      }, job.user_id);
    }
    await this.companies.unchanged(source, user, authorization);
    return { ...envelope(source), workflow: { ...summary(job), requestedRevision: job.state.requestedRevision, checkpoint: job.state.checkpoint,
      nextAssignments: pending.map(previewItem), reviewAssignments, nextBindings: job.state.phase === 'completed_local' ? [] : job.state.bindings || [] },
      currentTarget: { enabled: source.target.enabled, deleted: source.target.deleted, eligibilityRevision: source.target.eligibilityRevision } };
  }
  async get(id, user, authorization) {
    identifier(id); const original = await this.source(user, authorization); const job = await this.load(id, original);
    const source = await this.source(user, authorization, job.user_id); sameActor(original, source); return this.view(job, source, user, authorization);
  }
  async list(query, user, authorization) {
    const { page, limit } = pagination(query);
    return this.companies.v2.observe(user, authorization, async (client, source) => {
      const total = (await client.query('SELECT count(*)::integer AS total FROM company_offboarding_v2_jobs WHERE tenant_id=$1', [source.tenant.id])).rows[0].total;
      const rows = (await client.query('SELECT job.*,company_offboarding_v2_job_valid(job) AS valid FROM company_offboarding_v2_jobs job WHERE tenant_id=$1 ORDER BY created_at DESC,id LIMIT $2 OFFSET $3', [source.tenant.id, limit, (page - 1) * limit])).rows;
      if (rows.some(row => row.valid !== true)) fail(503, 'Complete retained workflow history unavailable');
      return { ...envelope(source), workflows: rows.map(summary), total, page, limit };
    });
  }
  async history(id, query, user, authorization) {
    identifier(id); const { page, limit } = pagination(query);
    return this.companies.v2.observe(user, authorization, async (client, source) => {
      await this.load(id, source, client);
      const total = (await client.query('SELECT count(*)::integer AS total FROM company_offboarding_v2_events WHERE workflow_id=$1 AND tenant_id=$2', [id, source.tenant.id])).rows[0].total;
      const rows = (await client.query('SELECT * FROM company_offboarding_v2_events WHERE workflow_id=$1 AND tenant_id=$2 ORDER BY revision DESC LIMIT $3 OFFSET $4', [id, source.tenant.id, limit, (page - 1) * limit])).rows;
      return { ...envelope(source), workflowId: id, events: rows.map(row => {
        const state = row.after_state.state; const completed = state.phase === 'completed_local';
        return { id: row.id, revision: String(row.revision), phase: state.phase, actorUserId: row.actor_user_id, createdAt: row.created_at.toISOString(), deliveryStatus: 'pending', failure: state.failure,
          completedLicenses: state.items?.filter(item => item.status !== 'pending').length || 0, totalLicenses: state.items === null ? null : state.items.length,
          completedBindings: completed ? state.bindings.length : 0, totalBindings: state.bindings === null ? null : state.bindings.length };
      }), total, page, limit };
    });
  }
  async create(input, key, user, authorization) {
    const intent = offboardingIntent(input); operationKey(key); if (key !== intent.workflowId) fail(400, 'Workflow idempotency key must equal the immutable workflow ID');
    const original = await this.source(user, authorization); if (intent.userId === original.actorUserId) fail(403, 'Self offboarding is forbidden');
    const lock = await this.lock(intent.workflowId, original);
    try {
      const rows = (await lock.client.query('SELECT id FROM company_offboarding_v2_jobs WHERE id=$1 AND tenant_id=$2', [intent.workflowId, original.tenant.id])).rows;
      if (rows.length) {
        const job = await this.load(intent.workflowId, original, lock.client); if (!isDeepStrictEqual(job.intent, intent)) fail(409, 'Workflow idempotency key already has another intent');
        const current = await this.source(user, authorization, job.user_id); sameActor(original, current); return { created: false, result: await this.view(job, current, user, authorization) };
      }
      const source = await this.source(user, authorization, intent.userId); sameActor(original, source);
      if (source.target.deleted) fail(409, 'Deleted blueprint cleanup requires canonical lifecycle history support');
      const person = await this.identity.user(intent.userId, authorization, source);
      if (person.userRevision !== intent.userRevision || person.eligibilityRevision !== intent.eligibilityRevision) fail(412, 'Original employee preview changed');
      const state = { phase: 'pending', requestedRevision: intent.userRevision, checkpoint: null, items: null, bindings: null, failure: null, retirementOperationId: null };
      const job = await this.save({ id: intent.workflowId, revision: '0' }, source, state, user, authorization, intent);
      return { created: true, result: await this.execute(job, source, key, user, authorization, null) };
    } finally { await lock.release(); }
  }
  async continue(id, input, expected, key, user, authorization) {
    identifier(id); const values = continuation(input); const revision = offboardingVersion(id, expected); operationKey(key);
    const original = await this.source(user, authorization); const lock = await this.lock(id, original);
    try {
      const job = await this.load(id, original, lock.client); const source = await this.source(user, authorization, job.user_id); sameActor(original, source);
      if (job.user_id === source.actorUserId) fail(403, 'Self offboarding is forbidden');
      if (values.reason !== job.intent.reason || values.userRevision !== job.state.requestedRevision) fail(409, 'Original workflow approval changed');
      if (job.state.phase === 'completed_local') return this.view(job, source, user, authorization);
      const fresh = await this.transact(source, user, authorization, async client => (await client.query('SELECT company_offboarding_v2_request($1::jsonb,$2::uuid,$3::uuid,$4::jsonb) AS fresh', [source, id, key, { expectedRevision: revision, body: values }])).rows[0].fresh);
      if (!fresh) return this.view(job, source, user, authorization);
      const items = job.state.items || [];
      if (!isDeepStrictEqual(values.assignments.map(item => ({ ...item, poolRevision: null })), items.map(item => ({ ...captured(item), poolRevision: null })))
        || !isDeepStrictEqual(values.bindings, (job.state.bindings || []).map(item => ({ id: item.id, revision: item.revision })))) fail(409, 'Exact complete original workflow manifest required');
      return this.execute(job, source, key, user, authorization, values.assignments);
    } finally { await lock.release(); }
  }
  async capture(job, source, user, authorization) {
    return this.companies.v2.observe(user, authorization, async (client, current, assignmentAuthority) => {
      if (!isDeepStrictEqual(current, source)) fail(401, 'Original capture authority changed');
      const capture = (await client.query('SELECT company_offboarding_v2_capture($1::uuid,$2::uuid) AS capture', [source.tenant.id, job.user_id])).rows[0].capture;
      if (capture.bindings.length) await assignmentAuthority(job.user_id); return capture;
    }, job.user_id);
  }
  async retired(job, source) {
    if (!job.state.retirementOperationId) return null;
    const rows = (await this.database.query('SELECT event.result FROM company_blueprint_assignment_operations operation JOIN company_blueprint_assignment_events event ON event.id=operation.id JOIN company_blueprint_assignment_outbox outbox ON outbox.id=event.id AND outbox.status=\'pending\' WHERE operation.id=$1 AND operation.tenant_id=$2 AND operation.user_id=$3 AND operation.action=\'retire_sources\' AND operation.command#>\'{values,checkpoint}\'=$4::jsonb',
      [job.state.retirementOperationId, source.tenant.id, job.user_id, job.state.checkpoint])).rows;
    if (!rows.length) return null; if (rows.length !== 1) fail(503, 'Exact retirement recovery receipt unavailable'); return rows[0].result;
  }
  async retireRequested(id, userId, values, key, user, authorization, correlationId) {
    identifier(id); identifier(userId); operationKey(key); const source = await this.source(user, authorization, userId); const lock = await this.lock(id, source);
    try {
      let job = await this.load(id, source, lock.client);
      if (job.user_id !== userId || !job.state.checkpoint || !job.state.items) fail(409, 'Original pending negative workflow required');
      if (!isDeepStrictEqual(values.assignments.map(value => ({ ...value, poolRevision: null })), job.state.items.map(item => ({ ...captured(item), poolRevision: null })))
        || !isDeepStrictEqual(values.bindings, job.state.bindings.map(item => ({ id: item.id, revision: item.revision })))) fail(409, 'Exact complete original retirement capture required');
      const prior = (await lock.client.query('SELECT id FROM company_blueprint_assignment_operations WHERE id=$1 AND tenant_id=$2 AND user_id=$3', [key, source.tenant.id, userId])).rows;
      if (!prior.length) {
        if (job.state.phase === 'completed_local') fail(409, 'Original workflow is already completed');
        negative(job, source);
        job = await this.save(job, source, { ...job.state, retirementOperationId: key }, user, authorization);
      }
      const result = await this.companies.v2.retire(userId, values, key, user, authorization, correlationId, job.state.checkpoint);
      if (job.state.phase !== 'completed_local') await this.execute(job, source, key, user, authorization, null);
      return result;
    } finally { await lock.release(); }
  }
  async execute(initial, original, key, user, authorization, approvals) {
    let job = initial; let source = original; let step = 'account';
    try {
      if (!job.state.checkpoint) {
        if (source.target.deleted || source.target.eligibilityRevision !== job.intent.eligibilityRevision) fail(409, 'Original employee lifecycle changed');
        const identityJob = { id: job.id, userId: job.user_id, state: job.state };
        const receipt = await this.identity.disable(identityJob, authorization, source);
        if (receipt.beforeEligibilityRevision !== job.intent.eligibilityRevision) fail(409, 'Original employee lifecycle changed');
        const current = await this.source(user, authorization, job.user_id); sameActor(source, current); source = current;
        if (source.target.enabled || source.target.deleted || source.target.eligibilityRevision !== receipt.afterEligibilityRevision) fail(409, 'Original negative account epoch changed');
        job = await this.save(job, source, { ...job.state, checkpoint: receipt, phase: 'licenses', failure: null }, user, authorization);
      }
      step = 'verify'; negative(job, source);
      if (job.state.items === null) {
        step = 'capture'; const capture = await this.capture(job, source, user, authorization);
        job = await this.save(job, source, { ...job.state, ...capture, phase: 'licenses', failure: null }, user, authorization);
      }
      if (!job.state.items.length && !job.state.bindings.length) {
        job = await this.save(job, source, { ...job.state, phase: 'completed_local', failure: null }, user, authorization);
        return this.view(job, source, user, authorization);
      }
      step = 'licenses'; let receipt = await this.retired(job, source);
      if (!receipt) {
        const values = { workflowId: job.id, eligibilityRevision: source.target.eligibilityRevision, assignments: approvals || job.state.items.map(captured),
          bindings: job.state.bindings.map(item => ({ id: item.id, revision: item.revision })), reason: job.intent.reason, confirm: true };
        job = await this.save(job, source, { ...job.state, retirementOperationId: key, phase: 'licenses', failure: null }, user, authorization);
        await this.companies.v2.retire(job.user_id, values, key, user, authorization, job.id, job.state.checkpoint);
        receipt = await this.retired(job, source); if (!receipt) fail(503, 'Actual complete retirement receipt not confirmed');
      }
      if (receipt.pools.length !== job.state.items.length) fail(503, 'Complete retirement result unavailable');
      const items = job.state.items.map(item => {
        const child = receipt.pools.find(value => value.poolId === item.poolId);
        if (!child || child.seatReleased !== true) fail(503, 'Actual seat release not confirmed'); return { ...item, status: 'released', eventId: child.eventId };
      });
      step = 'verify'; const current = await this.source(user, authorization, job.user_id); sameActor(source, current); source = current; negative(job, source);
      job = await this.save(job, source, { ...job.state, items, phase: 'completed_local', failure: null }, user, authorization);
    } catch (error) {
      const current = await this.source(user, authorization, job.user_id); sameActor(source, current); source = current;
      const code = Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 ? error.status : ({ '40001': 412, '23514': 409, '23505': 409, '55P03': 409 })[error.code] || 503;
      job = await this.save(job, source, { ...job.state, phase: 'paused', failure: { code, step } }, user, authorization);
    }
    return this.view(job, source, user, authorization);
  }
}

module.exports = { CompanyOffboardingV2, continuation, summary };
