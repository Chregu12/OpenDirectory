'use strict';

const { randomBytes, randomUUID, createHash } = require('node:crypto');
const { validUuid } = require('../../../../packages/identity-authorization-contract');
const { DeviceInventory } = require('./DeviceInventory');
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const digest = token => createHash('sha256').update(token).digest('hex');
const identifier = id => { if (!validUuid(id) || id !== id.toLowerCase()) fail(400, 'Canonical agent device required'); return id; };
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(400, 'Exact agent fields required');
}
function text(value, maximum, minimum = 0) {
  if (typeof value !== 'string' || /[\u0000-\u001f\u007f-\u009f]/u.test(value) || [...value.trim()].length < minimum || [...value.trim()].length > maximum) fail(400, 'Invalid agent text');
  return value.trim();
}
function report(input) {
  exact(input, ['hostname', 'platform', 'architecture', 'osVersion', 'agentVersion']);
  if (!['windows', 'macos', 'linux'].includes(input.platform)) fail(400, 'Unsupported agent platform');
  return { hostname: text(input.hostname, 255, 1), platform: input.platform, architecture: text(input.architecture, 40, 1), osVersion: text(input.osVersion, 120), agentVersion: text(input.agentVersion, 40, 1) };
}
const iso = value => value ? new Date(value).toISOString() : null;
const etag = (id, revision) => `"agent-${id}-${revision}"`;

class DeviceAgents {
  constructor(database, { inventory = new DeviceInventory(database), secret = () => randomBytes(32).toString('base64url') } = {}) {
    this.database = database; this.inventory = inventory; this.secret = secret;
  }
  async receiving(client) { await client.query('SELECT device_agent_receiving()'); }
  async state(client, deviceId, tenantId, actorUserId, page = 1) {
    await this.inventory.current(client, tenantId, deviceId);
    const row = (await client.query('SELECT * FROM device_agent_connections WHERE device_id=$1 AND tenant_id=$2', [deviceId, tenantId])).rows[0];
    const now = Date.now();
    const credential = row?.credential_hash && new Date(row.credential_expires_at).getTime() > now && !row.revoked_at;
    const pending = row?.bootstrap_hash && new Date(row.bootstrap_expires_at).getTime() > now;
    const status = pending ? 'pending' : credential ? (row.last_seen && now - new Date(row.last_seen).getTime() <= 180000 ? 'connected' : 'offline')
      : row?.credential_hash || row?.bootstrap_hash ? 'expired' : row?.revoked_at ? 'revoked' : 'not-enrolled';
    const total = Number((await client.query('SELECT count(*) AS total FROM device_agent_events WHERE device_id=$1 AND tenant_id=$2', [deviceId, tenantId])).rows[0].total);
    const events = (await client.query('SELECT id,action,actor_user_id,reason,correlation_id,created_at FROM device_agent_events WHERE device_id=$1 AND tenant_id=$2 ORDER BY created_at DESC,id DESC LIMIT 25 OFFSET $3', [deviceId, tenantId, (page - 1) * 25])).rows;
    return { schemaVersion: 1, agentProtocol: 1, actorUserId, tenantId, deviceId, revision: String(row?.revision || '0'), status,
      enrolledAt: iso(row?.enrolled_at), lastSeen: iso(row?.last_seen), credentialExpiresAt: iso(row?.credential_expires_at), enrollmentExpiresAt: iso(row?.bootstrap_expires_at),
      report: row?.hostname ? { hostname: row.hostname, platform: row.platform, architecture: row.architecture, osVersion: row.os_version, agentVersion: row.agent_version } : null,
      history: { total, page, limit: 25, events: events.map(event => ({ id: event.id, action: event.action, actorUserId: event.actor_user_id, reason: event.reason, correlationId: event.correlation_id, createdAt: iso(event.created_at) })) } };
  }
  async get(id, query, user, authorization) {
    identifier(id);
    if (Object.keys(query).some(key => key !== 'page') || query.page !== undefined && (typeof query.page !== 'string' || !/^[1-9][0-9]*$/.test(query.page) || Number(query.page) > 1000000)) fail(400, 'Invalid agent page');
    const source = await this.inventory.authorized(user, authorization, 'devices.inventory.read');
    const result = await this.database.transaction(async client => { await this.receiving(client); return this.state(client, id, source.tenant.id, source.actorUserId, Number(query.page || 1)); }, { readOnly: true });
    await this.inventory.checkpoint(source, user, authorization); return result;
  }
  async manage(id, action, input, expected, user, authorization, correlationId) {
    identifier(id); exact(input, ['reason', 'confirm']);
    if (!['issue', 'revoke'].includes(action) || input.confirm !== true) fail(400, 'Confirmed agent decision required');
    const reason = text(input.reason, 500, 10);
    if (!expected) fail(428, 'Agent revision required');
    const match = typeof expected === 'string' && expected.match(/^"agent-([a-f0-9-]{36})-(0|[1-9][0-9]{0,18})"$/);
    if (!match || match[1] !== id || BigInt(match[2]) > 9223372036854775807n) fail(400, 'Exact agent revision required');
    const source = await this.inventory.authorized(user, authorization, 'devices.inventory.create');
    const token = action === 'issue' ? 'odae_' + this.secret() : null;
    return this.database.transaction(async client => {
      await this.receiving(client);
      const current = await this.inventory.current(client, source.tenant.id, id, true);
      if (action === 'issue' && (!['windows', 'macos', 'linux'].includes(current.row.platform) || !['available', 'assigned'].includes(current.row.inventory_lifecycle))) fail(409, 'Restore a supported desktop device before enrollment');
      const state = await this.state(client, id, source.tenant.id, source.actorUserId);
      if (etag(id, state.revision) !== expected) fail(412, 'Agent state changed; reload before retrying');
      if (action === 'revoke' && ['not-enrolled', 'revoked'].includes(state.status)) fail(409, 'No active agent connection');
      await this.inventory.checkpoint(source, user, authorization);
      await client.query('SELECT device_agent_change($1::jsonb)', [JSON.stringify({ action, deviceId: id, expectedRevision: state.revision, reason, source,
        eventId: randomUUID(), correlationId: validUuid(correlationId) ? correlationId : randomUUID(), newHash: token ? digest(token) : null })]);
      const result = await this.state(client, id, source.tenant.id, source.actorUserId);
      return action === 'issue' ? { connection: result, enrollmentToken: token, expiresAt: result.enrollmentExpiresAt } : result;
    }, { beforeCommit: () => this.inventory.checkpoint(source, user, authorization) });
  }
  async register(input, correlationId) {
    exact(input, ['token', 'report']);
    if (typeof input.token !== 'string' || !/^odae_[A-Za-z0-9_-]{43}$/.test(input.token)) fail(401, 'Agent enrollment rejected');
    const values = report(input.report); const tokenHash = digest(input.token); const token = 'odad_' + this.secret();
    return this.database.transaction(async client => {
      await this.receiving(client);
      const row = (await client.query('SELECT device_id FROM device_agent_connections WHERE bootstrap_hash=$1 AND bootstrap_expires_at>clock_timestamp()', [tokenHash])).rows[0];
      if (!row) fail(401, 'Agent enrollment rejected');
      await client.query('SELECT device_agent_change($1::jsonb)', [JSON.stringify({ action: 'register', deviceId: row.device_id, tokenHash, newHash: digest(token), report: values, eventId: randomUUID(), correlationId: validUuid(correlationId) ? correlationId : randomUUID() })]);
      return { schemaVersion: 1, agentProtocol: 1, deviceId: row.device_id, deviceToken: token, credentialExpiresAt: iso((await client.query('SELECT credential_expires_at FROM device_agent_connections WHERE device_id=$1', [row.device_id])).rows[0].credential_expires_at) };
    });
  }
  async heartbeat(input, authorization) {
    exact(input, ['deviceId', 'report']); identifier(input.deviceId); const values = report(input.report);
    if (typeof authorization !== 'string' || !/^Bearer odad_[A-Za-z0-9_-]{43}$/.test(authorization)) fail(401, 'Device-only credential required');
    return this.database.transaction(async client => {
      await this.receiving(client);
      const tokenHash = digest(authorization.slice(7));
      const row = (await client.query('SELECT device_id FROM device_agent_connections WHERE device_id=$1 AND credential_hash=$2 AND credential_expires_at>clock_timestamp() AND revoked_at IS NULL', [input.deviceId, tokenHash])).rows[0];
      if (!row) fail(401, 'Agent credential rejected');
      await client.query('SELECT device_agent_change($1::jsonb)', [JSON.stringify({ action: 'heartbeat', deviceId: row.device_id, tokenHash, report: values })]);
      return { schemaVersion: 1, agentProtocol: 1, deviceId: row.device_id, receivedAt: iso((await client.query('SELECT last_seen FROM device_agent_connections WHERE device_id=$1', [row.device_id])).rows[0].last_seen) };
    });
  }
}
module.exports = { DeviceAgents, agentEtag: etag, report };
