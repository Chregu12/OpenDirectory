'use strict';

const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { CompanyLicenseAuthority } = require('./CompanyLicenseAuthority');
const { companyLicenseContext } = require('./CompanyLicenseContext');
const { principalContext } = require('./LicensePrincipal');
const { validRevision, validUuid } = require('../../../../../packages/identity-authorization-contract');
const { COMPANY_LICENSE_PERMISSIONS, identifier, poolValues, poolUpdateValues, assignmentValues, returnValues, poolEtag, expectedVersion, pagination } = require('../../../../../packages/company-license-contract');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
const POOL_SELECT = `SELECT catalog.*,license_company_pool_valid(catalog.id) AS company_valid, (SELECT count(*)::integer FROM license_assignments assignment WHERE assignment.license_id=catalog.id AND (assignment.expires_at IS NULL OR assignment.expires_at>license_now())) AS active_seats FROM license_catalog catalog`;
function poolView(row) {
  if (row.company_valid !== true || !validUuid(row.id) || !validUuid(row.business_tenant_id) || !validRevision(String(row.business_revision)) || row.license_type !== 'per_user'
    || !Number.isInteger(row.total_seats) || row.total_seats < 1 || row.total_seats > 10000 || !Number.isInteger(row.active_seats) || row.active_seats < 0 || row.active_seats > row.total_seats) fail(503, 'Retained company license pool unavailable');
  return { id: row.id, tenantId: row.business_tenant_id, revision: String(row.business_revision), name: row.name, vendor: row.vendor, description: row.description,
    totalSeats: row.total_seats, usedSeats: row.active_seats, availableSeats: row.total_seats - row.active_seats, licenseType: 'per_user', allocationMode: 'local-only', createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString() };
}
class CompanyLicenses {
  constructor(allocator, { authority = new CompanyLicenseAuthority(), ...options } = {}) { this.allocator = allocator; this.database = allocator.database; this.authority = authority; this.sourceOptions = options; }
  get v2() { if (!this.sourceAware) this.sourceAware = new (require('./CompanyLicenseSources').CompanyLicenseSources)(this, this.sourceOptions); return this.sourceAware; }
  async requireV1Sources(client, poolId, userId, tenantId) {
    const receiver = (await client.query("SELECT to_regprocedure('license_company_v1_sources_require(uuid,uuid,uuid)') AS receiver")).rows[0]?.receiver;
    if (receiver) await client.query('SELECT license_company_v1_sources_require($1::uuid,$2::uuid,$3::uuid)', [poolId, userId, tenantId]);
  }
  async unchanged(source, user, authorization) {
    const current = await this.authority.read(authorization, user, source.target?.id || null);
    if (!isDeepStrictEqual(current, source) || source.validUntil * 1000 <= Date.now()) fail(source.kind === 'application' ? 412 : 401, 'Original company license authority changed');
    return current;
  }
  async capabilities(user, authorization) {
    const source = await this.authority.read(authorization, user);
    await this.database.query('SELECT license_company_receiving()');
    await this.unchanged(source, user, authorization);
    return { schemaVersion: 1, companyLicenseProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, permissions: [...COMPANY_LICENSE_PERMISSIONS], allocationMode: 'local-only', supportedTargets: ['user'] };
  }
  async read(user, authorization, operation, targetUserId = null) {
    const source = await this.authority.read(authorization, user, ...(targetUserId === null ? [] : [targetUserId])); const client = await this.database.getClient();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'); await client.query("SET LOCAL statement_timeout='5s'");
      await client.query('SELECT license_company_receiving()'); const result = await operation(client, source);
      await this.unchanged(source, user, authorization); await client.query('COMMIT'); await this.unchanged(source, user, authorization); return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
  }
  async ownPool(client, id, tenantId) {
    if (client === this.database) {
      const snapshot = await this.database.getClient();
      try {
        await snapshot.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'); await snapshot.query("SET LOCAL statement_timeout='5s'");
        const row = await this.ownPool(snapshot, id, tenantId); await snapshot.query('COMMIT'); return row;
      } catch (error) { await snapshot.query('ROLLBACK').catch(() => {}); throw error; } finally { snapshot.release(); }
    }
    const row = (await client.query(POOL_SELECT + ' WHERE catalog.id=$1 AND catalog.business_tenant_id=$2', [id, tenantId])).rows[0];
    if (!row) fail(404, 'Own company license pool not found'); poolView(row); return row;
  }
  async supported(client, id) {
    const row = (await client.query('SELECT license_company_supported($1) AS supported', [id])).rows[0];
    if (row?.supported !== true) fail(409, 'This pool requires a separately supported governed allocation workflow');
  }
  async list(query, user, authorization) {
    const { page, limit, search } = pagination(query, true);
    return this.read(user, authorization, async (client, source) => {
      const parameters = [source.tenant.id, search]; const where = " WHERE catalog.business_tenant_id=$1 AND ($2='' OR strpos(lower(catalog.name),lower($2))>0 OR strpos(lower(catalog.vendor),lower($2))>0)";
      const total = (await client.query('SELECT count(*)::integer AS total FROM license_catalog catalog' + where, parameters)).rows[0].total;
      const rows = (await client.query(POOL_SELECT + where + ' ORDER BY catalog.name,catalog.id LIMIT $3 OFFSET $4', [...parameters, limit, (page - 1) * limit])).rows;
      return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, pools: rows.map(poolView), total, page, limit };
    });
  }
  async get(id, user, authorization) { identifier(id); return this.read(user, authorization, async (client, source) => poolView(await this.ownPool(client, id, source.tenant.id))); }
  async editCapabilities(id, user, authorization) {
    identifier(id);
    return this.read(user, authorization, async (client, source) => {
      const pool = poolView(await this.ownPool(client, id, source.tenant.id));
      await this.supported(client, id); await client.query('SELECT license_company_edit_receiving()');
      return { schemaVersion: 1, companyPoolEditProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, poolId: id, poolRevision: pool.revision };
    });
  }
  async assignments(id, query, user, authorization) {
    identifier(id); const { page, limit } = pagination(query);
    return this.read(user, authorization, async (client, source) => {
      await this.ownPool(client, id, source.tenant.id);
      await this.requireV1Sources(client, id, null, source.tenant.id);
      const total = (await client.query("SELECT count(*)::integer AS total FROM license_assignments WHERE license_id=$1 AND assignee_type='user' AND (expires_at IS NULL OR expires_at>license_now())", [id])).rows[0].total;
      const rows = (await client.query(`SELECT assignment.id,assignment.assignee_id AS user_id,assignment.assigned_at,assignment.assigned_by,source.grant_id FROM license_assignments assignment
        JOIN license_assignment_sources source ON source.license_id=assignment.license_id AND source.user_id=assignment.assignee_id AND source.source_type='direct'
        WHERE assignment.license_id=$1 AND assignment.assignee_type='user' AND (assignment.expires_at IS NULL OR assignment.expires_at>license_now()) ORDER BY assignment.assigned_at,assignment.id LIMIT $2 OFFSET $3`, [id, limit, (page - 1) * limit])).rows;
      if (rows.length !== Math.min(limit, Math.max(0, total - (page - 1) * limit))) fail(503, 'Complete company assignment evidence unavailable');
      return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, poolId: id, assignments: rows.map(row => ({ id: row.id, userId: row.user_id, assignedAt: row.assigned_at.toISOString(), assignedBy: row.assigned_by, grantId: row.grant_id })), total, page, limit };
    });
  }
  async history(id, query, user, authorization) {
    identifier(id); const { page, limit } = pagination(query);
    return this.read(user, authorization, async (client, source) => {
      await this.ownPool(client, id, source.tenant.id);
      const total = (await client.query('SELECT count(*)::integer AS total FROM license_company_events WHERE license_id=$1 AND tenant_id=$2', [id, source.tenant.id])).rows[0].total;
      const rows = (await client.query(`SELECT events.* FROM license_company_events events JOIN license_company_outbox outbox ON outbox.id=events.id AND outbox.status='pending'
        WHERE events.license_id=$1 AND events.tenant_id=$2 ORDER BY events.created_at DESC,events.id LIMIT $3 OFFSET $4`, [id, source.tenant.id, limit, (page - 1) * limit])).rows;
      if (rows.length !== Math.min(limit, Math.max(0, total - (page - 1) * limit))) fail(503, 'Complete company license history unavailable');
      return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, poolId: id, events: rows.map(row => ({ id: row.id, type: row.type, version: row.version, actorUserId: row.proof?.source?.kind === 'application' ? null : row.actor_user_id,
        ...(row.proof?.source?.kind === 'application' ? { actor: { kind: 'application', id: row.actor_user_id, clientId: row.proof.source.subject, clientRevision: row.proof.source.clientRevision } } : {}), userId: row.target_user_id,
        correlationId: row.correlation_id, createdAt: row.created_at.toISOString(), beforeRevision: row.before_revision === null ? null : String(row.before_revision), afterRevision: String(row.after_revision), deliveryStatus: 'pending' })), total, page, limit };
    });
  }
  async returnPreview(userId, query, user, authorization) {
    identifier(userId); const { page, limit } = pagination(query);
    if (limit > 25) fail(400, 'At most 25 captured license returns per page');
    return this.read(user, authorization, async (client, source) => {
      await this.requireV1Sources(client, null, userId, source.tenant.id);
      const parameters = [source.tenant.id, userId];
      const from = " FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id WHERE catalog.business_tenant_id=$1 AND assignment.assignee_type='user' AND assignment.assignee_id=$2 AND (assignment.expires_at IS NULL OR assignment.expires_at>license_now())";
      const total = (await client.query('SELECT count(*)::integer AS total' + from, parameters)).rows[0].total;
      const rows = (await client.query('SELECT assignment.id,assignment.license_id AS pool_id,assignment.assigned_at' + from + ' ORDER BY catalog.name,catalog.id LIMIT $3 OFFSET $4', [...parameters, limit, (page - 1) * limit])).rows;
      if (rows.length !== Math.min(limit, Math.max(0, total - (page - 1) * limit))) fail(503, 'Complete employee license return evidence unavailable');
      const assignments = [];
      for (const row of rows) {
        const pool = poolView(await this.ownPool(client, row.pool_id, source.tenant.id));
        const grant = (await client.query("SELECT grant_id FROM license_assignment_sources WHERE license_id=$1 AND user_id=$2 AND source_type='direct'", [pool.id, userId])).rows;
        if (grant.length !== 1 || !validUuid(grant[0].grant_id)) fail(503, 'Original employee license grant unavailable');
        assignments.push({ id: row.id, poolId: pool.id, poolRevision: pool.revision, name: pool.name, vendor: pool.vendor, grantId: grant[0].grant_id, assignedAt: row.assigned_at.toISOString() });
      }
      return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, userId,
        target: { enabled: source.target.enabled, deleted: source.target.deleted, eligibilityRevision: source.target.eligibilityRevision }, assignments, total, page, limit };
    }, userId);
  }
  async returnLicenses(userId, input, user, authorization, correlationId = randomUUID()) {
    identifier(userId); const values = returnValues(input); const original = await this.authority.read(authorization, user);
    for (const item of values.assignments) {
      const pool = await this.ownPool(this.database, item.poolId, original.tenant.id);
      if (String(pool.business_revision) !== item.poolRevision) fail(412, 'Company pool version changed');
      await this.supported(this.database, item.poolId);
      const row = (await this.database.query("SELECT id FROM license_assignments WHERE id=$1 AND license_id=$2 AND assignee_type='user' AND assignee_id=$3 AND (expires_at IS NULL OR expires_at>license_now())", [item.assignmentId, item.poolId, userId])).rows[0];
      if (!row) fail(404, 'Captured employee license assignment not found');
    }
    const source = await this.authority.read(authorization, user, userId);
    if (!isDeepStrictEqual({ ...source, target: null }, original)) fail(401, 'Original company license authority changed');
    if (source.target.enabled) fail(403, 'Disable the own employee before returning local licenses');
    const results = []; let stopped = false;
    for (const item of values.assignments) {
      const result = { poolId: item.poolId, assignmentId: item.assignmentId, status: 'not_attempted', code: null };
      if (!stopped) {
        try {
          await this.revoke(item.poolId, item.assignmentId, { userId, reason: values.reason, confirm: true }, poolEtag({ id: item.poolId, revision: item.poolRevision }), user, authorization, correlationId, source);
          result.status = 'released'; result.code = 200;
        } catch (error) {
          result.status = 'unconfirmed'; result.code = Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 ? error.status : 503; stopped = true;
        }
      }
      results.push(result);
    }
    await this.unchanged(source, user, authorization);
    return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, userId, correlationId, results };
  }
  async run(command, user, authorization, operation, targetUserId = null, inactiveSource = null) {
    const original = await this.authority.read(authorization, user);
    if (command.action !== 'create') {
      const pool = await this.ownPool(this.database, command.licenseId, original.tenant.id);
      if (command.action !== 'update') await this.requireV1Sources(this.database, command.licenseId, targetUserId, original.tenant.id);
      if (String(pool.business_revision) !== command.expectedVersion) fail(412, 'Company pool version changed');
      await this.supported(this.database, command.licenseId);
    }
    const source = targetUserId === null ? original : await this.authority.read(authorization, user, targetUserId);
    if (!isDeepStrictEqual({ ...source, target: null }, original)) fail(401, 'Original company license authority changed');
    if (inactiveSource && (!isDeepStrictEqual(inactiveSource, source) || source.target.enabled)) fail(401, 'Original inactive employee license source changed');
    if (command.action === 'assign' && (!source.target.enabled || source.target.deleted)) fail(403, 'Only an enabled own employee can receive a license');
    const principal = { issuer: source.issuer, subject: source.subject, userId: source.actorUserId, enabled: true }; let completed;
    const scope = { database: this.database, tenantId: source.tenant.id, licenseId: command.licenseId, actorUserId: source.actorUserId, user, authorization, action: command.action, targetUserId,
      verify: async (client, after) => {
        await this.unchanged(source, user, authorization);
        if (!after) {
          if (command.action === 'update') await client.query('SELECT license_company_edit_receiving()');
          if (command.action !== 'create') await this.supported(client, command.licenseId);
          const admitted = (await client.query('SELECT license_company_begin($1::jsonb,$2::jsonb) AS command_id', [JSON.stringify(source), JSON.stringify(command)])).rows[0]?.command_id;
          if (admitted !== command.id) fail(503, 'Original company license admission not confirmed');
        }
      },
      complete: async client => {
        const receipt = (await client.query('SELECT license_company_finish($1::uuid,$2::jsonb) AS event_id', [command.id, JSON.stringify(source)])).rows[0]?.event_id;
        if (receipt !== command.id) fail(503, 'Company license receipt not confirmed'); completed = poolView(await this.ownPool(client, command.licenseId, source.tenant.id));
      },
      eligibility: async (userId, bearer) => {
        if (bearer !== authorization || userId !== targetUserId) fail(403, 'Company license recipient exceeds the original scope');
        await this.unchanged(source, user, authorization);
        return { schemaVersion: 1, userId, revision: source.target.eligibilityRevision, enabled: source.target.enabled, deleted: source.target.deleted };
      },
    };
    await principalContext.run(principal, () => companyLicenseContext.run(scope, operation));
    if (!completed) fail(503, 'Company license transaction not confirmed'); await this.unchanged(source, user, authorization); return completed;
  }
  async create(input, user, authorization, correlationId = randomUUID()) {
    const values = poolValues(input); const { reason, ...catalog } = values;
    const command = { id: randomUUID(), correlationId, licenseId: randomUUID(), action: 'create', expectedVersion: '0', reason, values: catalog, assignmentId: null };
    return this.run(command, user, authorization, () => this.allocator.transaction(async client => {
      await client.query(`INSERT INTO license_catalog(id,name,vendor,description,category,license_type,total_seats,auto_approve,business_tenant_id,business_revision)
        VALUES($1,$2,$3,$4,'Software','per_user',$5,false,$6,1)`, [command.licenseId, values.name, values.vendor, values.description, values.totalSeats, companyLicenseContext.getStore().tenantId]);
    }));
  }
  async assign(id, input, expected, user, authorization, correlationId = randomUUID()) {
    identifier(id); const values = assignmentValues(input); const command = { id: randomUUID(), correlationId, licenseId: id, action: 'assign', expectedVersion: expectedVersion(id, expected), reason: values.reason, values: null, assignmentId: null };
    return this.run(command, user, authorization, () => this.allocator.assign(id, { assignee_type: 'user', assignee_id: values.userId }, user.identity_authorization.userId, { authorization }), values.userId);
  }
  async update(id, input, expected, user, authorization, correlationId = randomUUID()) {
    identifier(id); const { reason, confirm, ...values } = poolUpdateValues(input);
    const command = { id: randomUUID(), correlationId, licenseId: id, action: 'update', expectedVersion: expectedVersion(id, expected), reason, values, assignmentId: null };
    return this.run(command, user, authorization, () => this.allocator.transaction(async client => {
      const current = await this.ownPool(client, id, companyLicenseContext.getStore().tenantId);
      const before = { name: current.name, vendor: current.vendor, description: current.description, totalSeats: current.total_seats };
      if (values.totalSeats < current.active_seats) fail(409, 'License stock cannot be lower than current allocations');
      if (Object.keys(values).every(field => values[field] === before[field])) fail(409, 'Company catalog values have not changed');
      const result = await client.query('UPDATE license_catalog SET name=$2,vendor=$3,description=$4,total_seats=$5,updated_at=clock_timestamp() WHERE id=$1',
        [id, values.name, values.vendor, values.description, values.totalSeats]);
      if (result.rowCount !== 1) fail(503, 'Company catalog update not confirmed');
      await this.allocator.audit(client, id, 'pool-updated', user.identity_authorization.userId, { before, after: values, reason });
    }));
  }
  async revoke(id, assignmentId, input, expected, user, authorization, correlationId = randomUUID(), inactiveSource = null) {
    identifier(id); identifier(assignmentId); const values = assignmentValues(input); const command = { id: randomUUID(), correlationId, licenseId: id, action: 'revoke', expectedVersion: expectedVersion(id, expected), reason: values.reason, values: null, assignmentId };
    return this.run(command, user, authorization, () => this.allocator.revoke(id, values.userId, user.identity_authorization.userId, 'user'), values.userId, inactiveSource);
  }
}
module.exports = { CompanyLicenses, poolView };
