'use strict';

const { randomBytes } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { exact, identifier, text } = require('../../../../../packages/company-license-contract');
const { validRevision } = require('../../../../../packages/identity-authorization-contract');
const { configuration } = require('./providers/ReadConfiguration');
const { ProviderReadClient } = require('./providers/ProviderReadClient');
const { fulfillmentClient } = require('./fulfillment/RustGraphLicenseClient');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function envelope(source) { return { schemaVersion: 1, companyMicrosoftProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id }; }
function instant(value) { const parsed = new Date(value); if (!Number.isFinite(parsed.getTime())) fail(503, 'Microsoft receipt timestamp unavailable'); return parsed.toISOString(); }
function bindingView(kind, row) {
  if (!row || !validRevision(String(row.revision))) fail(503, 'Microsoft binding unavailable');
  const base = { id: identifier(row.id), tenantId: identifier(row.tenant_id), revision: String(row.revision), status: row.status, createdAt: instant(row.created_at), updatedAt: instant(row.updated_at) };
  if (kind === 'connection') return { ...base, tenantGeneration: String(row.tenant_generation), microsoftTenantId: row.microsoft_tenant_id, readClientId: row.read_client_id, writeClientId: row.write_client_id };
  if (kind === 'pool') return { ...base, connectionId: row.connection_id, poolId: row.pool_id, skuId: row.sku_id, disabledPlans: row.disabled_plans };
  return { ...base, connectionId: row.connection_id, userId: row.user_id, objectId: row.object_id };
}
function confirmation(input, extra = []) {
  exact(input, ['reason', 'confirm', ...extra]);
  if (input.confirm !== true) fail(400, 'Explicit Microsoft change confirmation required');
  return text(input.reason, 10, 500);
}
function expectedRevision(value) { if (!validRevision(value)) fail(428, 'Current Microsoft binding version required'); return value; }
function connectionRevision(expected, connection) {
  exact(expected, ['id', 'revision']); identifier(expected.id); expectedRevision(expected.revision);
  if (expected.id !== connection.id || expected.revision !== String(connection.revision)) fail(412, 'Microsoft connection version changed');
  return expected.revision;
}

class CompanyMicrosoftBridge {
  constructor(companies, {
    tenantId = process.env.LICENSE_COMPANY_PROVIDER_TENANT_ID,
    readFilename = process.env.LICENSE_COMPANY_PROVIDER_CONFIG_FILE,
    writeFilename = process.env.LICENSE_COMPANY_PROVIDER_WRITE_CONFIG_FILE,
    load = configuration,
    createReader = config => new ProviderReadClient(config),
    createGraph = config => fulfillmentClient(config, 'rust', 'rust'),
  } = {}) {
    this.companies = companies; this.database = companies.database;
    Object.assign(this, { tenantId, readFilename, writeFilename, load, createReader, createGraph });
  }

  configurations(source) {
    if (!this.tenantId || this.tenantId !== source.tenant.id) return null;
    try {
      identifier(this.tenantId);
      if (!this.readFilename || !this.writeFilename) return null;
      const read = this.load(this.readFilename), write = this.load(this.writeFilename);
      if (read.provider !== 'microsoft-365' || write.provider !== 'microsoft-365' || read.tenantId !== write.tenantId) throw new Error();
      return { read, write };
    } catch { fail(503, 'Protected company Microsoft configuration unavailable'); }
  }
  unchangedConfiguration(source, original) {
    if (!isDeepStrictEqual(original, this.configurations(source))) fail(503, 'Company Microsoft configuration changed');
  }
  requireConfiguration(source) {
    const config = this.configurations(source); if (!config) fail(503, 'Separate reviewed Microsoft read and write configurations required'); return config;
  }
  async connection(client, source, id = null) {
    const rows = (await client.query("SELECT * FROM company_microsoft_connections WHERE tenant_id=$1 AND status='active' AND ($2::uuid IS NULL OR id=$2::uuid)", [source.tenant.id, id])).rows;
    if (rows.length !== 1) fail(404, 'Own active Microsoft connection not found'); return rows[0];
  }
  matchingConnection(source, connection, config) {
    if (connection.tenant_generation.toString() !== source.tenant.generation || connection.microsoft_tenant_id !== config.read.tenantId
      || connection.read_client_id !== config.read.clientId || connection.write_client_id !== config.write.clientId) fail(409, 'Review the current Microsoft connection before using its mappings');
  }
  async state(user, authorization) {
    return this.companies.read(user, authorization, async (client, source) => {
      await client.query('SELECT company_microsoft_receiving()');
      let config = null, configurationUnavailable = false;
      try { config = this.configurations(source); } catch (error) { if (error.status !== 503) throw error; configurationUnavailable = true; }
      const row = (await client.query("SELECT * FROM company_microsoft_connections WHERE tenant_id=$1 AND status='active'", [source.tenant.id])).rows[0];
      let state = config ? 'configured' : configurationUnavailable ? 'configuration_unavailable' : 'not_configured';
      if (row && config) {
        try { this.matchingConnection(source, row, config); state = 'connected'; }
        catch { state = 'review_required'; }
      }
      if (!configurationUnavailable) this.unchangedConfiguration(source, config);
      return { ...envelope(source), state, microsoftTenantId: config?.read.tenantId || null,
        connection: row ? bindingView('connection', row) : null,
        ...(config ? { readClientId: config.read.clientId, writeClientId: config.write.clientId } : {}) };
    });
  }
  async mappings(poolId, query, user, authorization) {
    identifier(poolId); exact(query, ['page']); const page = Number(query.page);
    if (!Number.isSafeInteger(page) || page < 1 || page > 10000) fail(400, 'Exact Microsoft mapping page required');
    return this.companies.read(user, authorization, async (client, source) => {
      await client.query('SELECT company_microsoft_receiving()'); await this.companies.ownPool(client, poolId, source.tenant.id);
      const row = (await client.query("SELECT mapping.* FROM company_microsoft_pools mapping JOIN company_microsoft_connections connection ON connection.id=mapping.connection_id AND connection.status='active' WHERE mapping.tenant_id=$1 AND mapping.pool_id=$2 AND mapping.status='active'", [source.tenant.id, poolId])).rows[0];
      const users = (await client.query(`SELECT mapping.* FROM company_microsoft_users mapping JOIN company_microsoft_connections connection ON connection.id=mapping.connection_id AND connection.status='active'
        WHERE mapping.tenant_id=$1 AND mapping.status='active' ORDER BY mapping.user_id LIMIT 26 OFFSET $2`, [source.tenant.id, (page - 1) * 25])).rows;
      return { ...envelope(source), poolId, pool: row ? bindingView('pool', row) : null, users: users.slice(0, 25).map(value => bindingView('user', value)), page, hasMore: users.length > 25 };
    });
  }
  async products(user, authorization, signal) {
    return this.companies.read(user, authorization, async (client, source) => {
      await client.query('SELECT company_microsoft_receiving()');
      const config = this.requireConfiguration(source); const connection = await this.connection(client, source);
      this.matchingConnection(source, connection, config);
      const products = await this.createReader(config.read).inspect(signal);
      this.unchangedConfiguration(source, config);
      return { ...envelope(source), microsoftTenantId: config.read.tenantId, checkedAt: new Date().toISOString(), products };
    });
  }
  async recorded(source, operation, action, resource, connectionId, request) {
    const prior = (await this.database.query('SELECT * FROM company_microsoft_operations WHERE id=$1 AND tenant_id=$2', [operation, source.tenant.id])).rows[0];
    if (!prior) return null;
    const intent = value => Object.fromEntries(Object.entries(value).filter(([field]) => !['observedSku', 'accountEnabled', 'checkedAt'].includes(field)));
    if (prior.action !== action || prior.resource_id !== resource || prior.connection_id !== connectionId || prior.source.actorUserId !== source.actorUserId || !isDeepStrictEqual(intent(prior.request), intent(request))) fail(409, 'Microsoft operation key was used for another request');
    if (prior.phase !== 'finished' || prior.outcome?.kind !== 'configuration') fail(409, 'Microsoft operation needs inspection');
    await this.database.query('SELECT company_microsoft_receiving()');
    return prior.outcome.resource;
  }
  async change(source, config, operation, action, resource, connectionId, request, expected, user, authorization) {
    identifier(operation); identifier(resource); identifier(connectionId);
    request = { ...request, expectedRevision: expected === null ? null : String(expected) };
    const prior = await this.recorded(source, operation, action, resource, connectionId, request);
    if (prior) { await this.companies.unchanged(source, user, authorization); return { resource: prior, historical: true }; }
    const client = await this.database.getClient();
    try {
      await client.query('BEGIN'); await client.query("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'");
      await this.companies.unchanged(source, user, authorization); if (config) this.unchangedConfiguration(source, config);
      const result = (await client.query('SELECT company_microsoft_change($1::jsonb,$2::uuid,$3::text,$4::text,$5::uuid,$6::uuid,$7::jsonb,$8::bigint) AS result',
        [source, operation, randomBytes(32).toString('hex'), action, resource, connectionId, request, expected])).rows[0].result;
      await this.companies.unchanged(source, user, authorization); if (config) this.unchangedConfiguration(source, config);
      await client.query('COMMIT'); await this.companies.unchanged(source, user, authorization);
      return { resource: result, historical: false };
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
  }
  async connect(input, operation, user, authorization, renew = null) {
    const reason = confirmation(input, ['microsoftTenantId', 'readClientId', 'writeClientId']); identifier(operation);
    const source = await this.companies.authority.read(authorization, user); const config = this.requireConfiguration(source);
    for (const field of ['microsoftTenantId', 'readClientId', 'writeClientId']) identifier(input[field]);
    if (input.microsoftTenantId !== config.read.tenantId || input.readClientId !== config.read.clientId || input.writeClientId !== config.write.clientId) fail(412, 'Reviewed Microsoft configuration changed');
    await this.database.query('SELECT company_microsoft_receiving()');
    const resource = renew ? identifier(renew.id) : operation;
    const request = { reason, confirm: true, microsoftTenantId: config.read.tenantId, readClientId: config.read.clientId, writeClientId: config.write.clientId };
    if (!renew) { await this.createReader(config.read).inspect(); await this.companies.unchanged(source, user, authorization); this.unchangedConfiguration(source, config); }
    const changed = await this.change(source, config, operation, renew ? 'renew' : 'connect', resource, resource, request, renew ? expectedRevision(renew.revision) : null, user, authorization);
    return { ...envelope(source), connection: bindingView('connection', changed.resource), historical: changed.historical };
  }
  async bindPool(poolId, input, expected, operation, user, authorization) {
    identifier(poolId); identifier(operation); exact(expected, ['id', 'revision']); identifier(expected.id); expectedRevision(expected.revision); const reason = confirmation(input, ['skuId', 'exclusiveDirectManagement']); identifier(input.skuId);
    if (input.exclusiveDirectManagement !== true) fail(400, 'Review exclusive direct Microsoft management');
    const source = await this.companies.authority.read(authorization, user); const config = this.requireConfiguration(source);
    await this.database.query('SELECT company_microsoft_receiving()');
    const connection = await this.connection(this.database, source); this.matchingConnection(source, connection, config);
    const revision = connectionRevision(expected, connection);
    await this.companies.ownPool(this.database, poolId, source.tenant.id);
    const products = await this.createReader(config.read).inspect();
    const product = products.find(value => value.skuId === input.skuId);
    if (!product || product.appliesTo !== 'User' || product.capabilityStatus !== 'Enabled' || product.prepaidUnits.enabled < 1) fail(409, 'Current enabled Microsoft user SKU required');
    const request = { reason, confirm: true, poolId, skuId: input.skuId, disabledPlans: [], exclusiveDirectManagement: true, observedSku: product, checkedAt: new Date().toISOString() };
    const changed = await this.change(source, config, operation, 'bind_pool', operation, connection.id, request, revision, user, authorization);
    return { ...envelope(source), pool: bindingView('pool', changed.resource), historical: changed.historical };
  }
  async bindUser(userId, input, expected, operation, user, authorization) {
    identifier(userId); identifier(operation); exact(expected, ['id', 'revision']); identifier(expected.id); expectedRevision(expected.revision); const reason = confirmation(input, ['objectId', 'exclusiveDirectManagement']); identifier(input.objectId);
    if (input.exclusiveDirectManagement !== true) fail(400, 'Review exclusive direct Microsoft management');
    const source = await this.companies.authority.read(authorization, user, userId); const config = this.requireConfiguration(source);
    await this.database.query('SELECT company_microsoft_receiving()');
    const connection = await this.connection(this.database, source); this.matchingConnection(source, connection, config);
    const revision = connectionRevision(expected, connection);
    const observed = await this.createGraph(config.write).readUser(input.objectId);
    if (observed.id !== input.objectId || typeof observed.accountEnabled !== 'boolean') fail(503, 'Bound Microsoft object unavailable');
    const request = { reason, confirm: true, userId, objectId: input.objectId, exclusiveDirectManagement: true, accountEnabled: observed.accountEnabled, checkedAt: new Date().toISOString() };
    const changed = await this.change(source, config, operation, 'bind_user', operation, connection.id, request, revision, user, authorization);
    return { ...envelope(source), user: bindingView('user', changed.resource), historical: changed.historical };
  }
  async retire(kind, id, expected, operation, input, user, authorization) {
    if (!['pool', 'user', 'connection'].includes(kind)) fail(400, 'Unsupported Microsoft mapping type');
    identifier(id); identifier(operation); expectedRevision(expected); const reason = confirmation(input);
    const source = await this.companies.authority.read(authorization, user);
    await this.database.query('SELECT company_microsoft_receiving()');
    const table = { pool: 'company_microsoft_pools', user: 'company_microsoft_users', connection: 'company_microsoft_connections' }[kind];
    const mapping = (await this.database.query(`SELECT * FROM ${table} WHERE id=$1 AND tenant_id=$2`, [id, source.tenant.id])).rows[0];
    if (!mapping) fail(404, 'Own Microsoft mapping not found');
    const changed = await this.change(source, null, operation, kind === 'connection' ? 'disconnect' : 'retire_' + kind, id,
      kind === 'connection' ? id : mapping.connection_id, { reason, confirm: true }, expected, user, authorization);
    return { ...envelope(source), binding: bindingView(kind, changed.resource), historical: changed.historical };
  }
  async history(query, user, authorization) {
    exact(query, ['page']); const page = Number(query.page);
    if (!Number.isSafeInteger(page) || page < 1 || page > 10000) fail(400, 'Exact Microsoft history page required');
    return this.companies.read(user, authorization, async (client, source) => {
      await client.query('SELECT company_microsoft_receiving()');
      const rows = (await client.query(`SELECT event.*,operation.request->>'reason' AS reason FROM company_microsoft_events event
        JOIN company_microsoft_outbox box ON box.id=event.id AND box.status='pending'
        JOIN company_microsoft_operations operation ON operation.id=event.operation_id
        WHERE event.tenant_id=$1 ORDER BY event.created_at DESC,event.id LIMIT 26 OFFSET $2`, [source.tenant.id, (page - 1) * 25])).rows;
      return { ...envelope(source), events: rows.slice(0, 25).map(row => ({ id: row.id, operationId: row.operation_id, type: row.type,
        actorKind: row.actor.kind, actorUserId: row.actor.kind === 'human' ? row.actor.userId : null,
        reason: row.reason, createdAt: instant(row.created_at), resource: row.details.resource || null })), page, hasMore: rows.length > 25 };
    });
  }
}

module.exports = { CompanyMicrosoftBridge, bindingView, envelope, confirmation };
