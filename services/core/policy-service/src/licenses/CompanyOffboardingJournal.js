'use strict';

const { validContext, validRevision } = require('../../../../../packages/identity-authorization-contract');
const { validTenantContext } = require('../../../../../packages/tenant-authorization-contract');
const { COMPANY_LICENSE_PERMISSIONS, exact, identifier, text } = require('../../../../../packages/company-license-contract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function databaseError(error) {
  if (!error.status) error.status = ({ '22023': 400, '23514': 409, '23505': 409, '40001': 409, '42501': 403, P0002: 404 })[error.code] || 503;
  return error;
}
function sourceValues(source) {
  exact(source, ['schemaVersion', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil', 'target']);
  if (source.schemaVersion !== 1 || !validContext(source.context) || !validTenantContext(source.tenant)
    || source.actorUserId !== source.context.userId || JSON.stringify(source.permissions) !== JSON.stringify(COMPANY_LICENSE_PERMISSIONS)
    || !Number.isSafeInteger(source.expiresAt) || !Number.isSafeInteger(source.validUntil) || source.validUntil > source.expiresAt
    || source.validUntil > Math.floor(Date.now() / 1000) + 300) fail(403, 'Original company offboarding source required');
  identifier(source.actorUserId); identifier(source.tenant.id);
  for (const field of ['issuer', 'subject', 'tokenId']) if (text(source[field], 1, field === 'issuer' ? 2048 : 255) !== source[field]) fail(403, 'Original company offboarding source required');
  exact(source.target, ['id', 'revision', 'eligibilityRevision', 'enabled', 'deleted']); identifier(source.target.id);
  if (!validRevision(source.target.eligibilityRevision) || typeof source.target.enabled !== 'boolean' || typeof source.target.deleted !== 'boolean'
    || (source.target.deleted ? source.target.revision !== null || source.target.enabled : !validRevision(source.target.revision))) fail(403, 'Own company offboarding target required');
  deadline(source);
}
function deadline(source) { if (source.validUntil * 1000 <= Date.now()) fail(401, 'Company offboarding source expired'); }
function intentValues(intent) {
  exact(intent, ['workflowId', 'userId', 'userRevision', 'eligibilityRevision', 'reason', 'confirm']);
  identifier(intent.workflowId); identifier(intent.userId);
  if (!validRevision(intent.userRevision) || !validRevision(intent.eligibilityRevision) || intent.confirm !== true || text(intent.reason, 10, 500) !== intent.reason) fail(400, 'Exact confirmed company offboarding intent required');
}
function pages(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !['page', 'limit'].includes(key))) fail(400, 'Unsupported company offboarding selectors');
  const integer = (value, fallback, maximum) => {
    if (value === undefined) return fallback;
    if ((typeof value !== 'number' && typeof value !== 'string') || !/^[1-9][0-9]*$/u.test(String(value)) || !Number.isSafeInteger(Number(value)) || Number(value) > maximum) fail(400, 'Invalid company offboarding page');
    return Number(value);
  };
  return { page: integer(input.page, 1, 1000000), limit: integer(input.limit, 25, 100) };
}
function pooled(database) { return typeof database.getClient === 'function' || typeof database.totalCount === 'number' && typeof database.connect === 'function'; }

class CompanyOffboardingJournal {
  constructor(database) { this.database = database; }
  async connection(database = this.database) {
    if (typeof database.getClient === 'function') return database.getClient();
    if (typeof database.totalCount === 'number' && typeof database.connect === 'function') return database.connect();
    fail(503, 'Dedicated company offboarding connection unavailable');
  }
  async ready(client = this.database) {
    try { await client.query('SELECT company_offboarding_receiving()'); } catch (error) { throw Object.assign(error, { status: 503 }); }
  }
  async lock(tenantId, id) {
    identifier(tenantId); identifier(id);
    const client = await this.connection(); let released = false;
    const unlock = async () => {
      if (released) return;
      released = true; let failure;
      try {
        if ((await client.query("SELECT pg_advisory_unlock(hashtextextended('company-offboarding:'||$1::text||':'||$2::text,0)) AS unlocked", [tenantId, id])).rows[0]?.unlocked !== true) fail(503, 'Company offboarding session unlock failed');
      } catch (error) { failure = error; throw databaseError(error); }
      finally { client.release(failure); }
    };
    try {
      await this.ready(client);
      const acquired = (await client.query("SELECT pg_try_advisory_lock(hashtextextended('company-offboarding:'||$1::text||':'||$2::text,0)) AS acquired", [tenantId, id])).rows[0]?.acquired;
      if (acquired !== true) { released = true; client.release(); fail(409, 'Company offboarding workflow is busy'); }
      return { client, release: unlock };
    } catch (error) { if (!released) { released = true; client.release(error); } throw databaseError(error); }
  }
  async read(client, operation) {
    const owned = pooled(client);
    const connection = owned ? await this.connection(client) : client; let failure;
    try {
      if (owned) { await connection.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'); await connection.query("SET LOCAL statement_timeout='5s'"); }
      await this.ready(connection); const result = await operation(connection);
      if (owned) await connection.query('COMMIT');
      return result;
    } catch (error) {
      if (owned) await connection.query('ROLLBACK').catch(rollbackError => { failure = rollbackError; });
      throw databaseError(error);
    } finally { if (owned) connection.release(failure); }
  }
  async load(client, tenantId, id) {
    identifier(tenantId); identifier(id);
    return this.read(client, async connection => (await connection.query('SELECT company_offboarding_read($1::uuid,$2::uuid) AS job', [tenantId, id])).rows[0].job);
  }
  async list(client, tenantId, input = {}) {
    identifier(tenantId); const { page, limit } = pages(input);
    return this.read(client, async connection => {
      const result = (await connection.query(`WITH own AS MATERIALIZED (SELECT * FROM company_offboarding_jobs WHERE tenant_id=$1),
        selected AS (SELECT * FROM own ORDER BY created_at DESC,id LIMIT $2 OFFSET $3)
        SELECT (SELECT count(*)::integer FROM own) AS total,
        COALESCE((SELECT jsonb_agg(company_offboarding_read(tenant_id,id) ORDER BY created_at DESC,id) FROM selected),'[]'::jsonb) AS jobs`, [tenantId, limit, (page - 1) * limit])).rows[0];
      return { jobs: result.jobs, total: result.total, page, limit };
    });
  }
  async history(client, tenantId, id, input = {}) {
    identifier(tenantId); identifier(id); const { page, limit } = pages(input);
    return this.read(client, async connection => {
      const result = (await connection.query('SELECT company_offboarding_history($1::uuid,$2::uuid,$3::integer,$4::integer) AS history', [tenantId, id, page, limit])).rows[0].history;
      if (result === null) fail(404, 'Own company offboarding workflow not found');
      return result;
    });
  }
  async write(client, source, verify, operation) {
    sourceValues(source); if (typeof verify !== 'function') fail(503, 'Fresh company offboarding verification required');
    const owned = pooled(client);
    const connection = owned ? await this.connection(client) : client; let failure;
    try {
      await connection.query('BEGIN');
      await connection.query("SET LOCAL statement_timeout='5s'"); await connection.query("SET LOCAL lock_timeout='2s'");
      await connection.query("SET LOCAL idle_in_transaction_session_timeout='5s'");
      await this.ready(connection); await verify(connection); deadline(source);
      const result = await operation(connection);
      await verify(connection); deadline(source);
      await connection.query('SELECT company_offboarding_check_source($1::jsonb)', [JSON.stringify(source)]);
      await connection.query('COMMIT'); return result;
    } catch (error) {
      await connection.query('ROLLBACK').catch(rollbackError => { failure = rollbackError; });
      throw databaseError(error);
    } finally { if (owned) connection.release(failure); }
  }
  async create(client, source, intent, verify) {
    intentValues(intent);
    return this.write(client, source, verify, async connection => (await connection.query('SELECT company_offboarding_create($1::jsonb,$2::jsonb) AS result', [JSON.stringify(source), JSON.stringify(intent)])).rows[0].result);
  }
  async save(client, source, job, state, verify) {
    if (!job || !validRevision(job.revision)) fail(400, 'Exact company offboarding job revision required');
    identifier(job.id); identifier(job.tenantId); identifier(job.userId);
    if (source?.tenant?.id !== job.tenantId || source?.target?.id !== job.userId) fail(403, 'Own company offboarding source required');
    return this.write(client, source, verify, async connection => (await connection.query('SELECT company_offboarding_save($1::jsonb,$2::uuid,$3::bigint,$4::jsonb) AS job', [JSON.stringify(source), job.id, job.revision, JSON.stringify(state)])).rows[0].job);
  }
}

module.exports = { CompanyOffboardingJournal };
