'use strict';

const { randomBytes, randomUUID, createHash } = require('node:crypto');
const { validUuid } = require('../../../../packages/identity-authorization-contract');
const { DeviceInventory, pageQuery, selectionWhere, inventoryDevice } = require('./DeviceInventory');
const { DEVICE_FIELDS } = require('../../../../packages/device-inventory-contract');
const { validateInventory } = require('./AgentInventory');
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
const statuses = ['not-enrolled', 'pending', 'connected', 'offline', 'expired', 'revoked'];
// A single database clock after snapshot acquisition defines fleet filters and counts.
const statusSql = (now = 'statement_timestamp()') => `CASE WHEN connection.bootstrap_hash IS NOT NULL AND connection.bootstrap_expires_at>${now} THEN 'pending'
 WHEN connection.credential_hash IS NOT NULL AND connection.credential_expires_at>${now} AND connection.revoked_at IS NULL
 THEN CASE WHEN connection.last_seen>=${now}-interval '3 minutes' THEN 'connected' ELSE 'offline' END
 WHEN connection.credential_hash IS NOT NULL OR connection.bootstrap_hash IS NOT NULL THEN 'expired'
 WHEN connection.revoked_at IS NOT NULL THEN 'revoked' ELSE 'not-enrolled' END`;
function connectionSummary(row, status = row?.connection_status || 'not-enrolled') {
  return { status, enrolledAt: iso(row?.enrolled_at), lastSeen: iso(row?.last_seen), credentialExpiresAt: iso(row?.credential_expires_at), enrollmentExpiresAt: iso(row?.bootstrap_expires_at),
    report: row?.hostname ? { hostname: row.hostname, platform: row.platform, architecture: row.architecture, osVersion: row.os_version, agentVersion: row.agent_version } : null };
}

class DeviceAgents {
  constructor(database, { inventory = new DeviceInventory(database), secret = () => randomBytes(32).toString('base64url') } = {}) {
    this.database = database; this.inventory = inventory; this.secret = secret;
  }
  async receiving(client) { await client.query('SELECT device_agent_inventory_receiving()'); }
  async inventoryReport(id, query, user, authorization) {
    identifier(id); if (Object.keys(query).length) fail(400, 'No inventory report selectors');
    const source = await this.inventory.authorized(user, authorization, 'devices.inventory.read');
    const result = await this.database.transaction(async client => {
      await this.receiving(client); await this.inventory.current(client, source.tenant.id, id);
      const checkedAt = iso((await client.query('SELECT clock_timestamp() AS moment')).rows[0].moment);
      const row = (await client.query(`SELECT connection.*,${statusSql('$3::timestamptz')} AS connection_status,
       coalesce((inventory_report->>'enrolledAt')::timestamptz=enrolled_at,false) AS inventory_same_enrollment FROM device_agent_connections connection WHERE device_id=$1 AND tenant_id=$2`, [id, source.tenant.id, checkedAt])).rows[0];
      const stored = row?.inventory_report;
      let inventory = null, status = 'missing';
      if (stored) {
        try { validateInventory(stored.facts); } catch { fail(503, 'Stored agent inventory unavailable'); }
        inventory = { ...stored, receivedAt: iso(stored.receivedAt), enrolledAt: iso(stored.enrolledAt) };
        const same = row.inventory_same_enrollment && row.platform === stored.platform && ['connected', 'offline'].includes(row.connection_status);
        status = !same ? 'historical' : row.connection_status === 'connected' && Date.parse(checkedAt) - Date.parse(stored.receivedAt) <= 300000 ? 'current' : 'stale';
      }
      return { schemaVersion: 1, inventoryProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, deviceId: id, checkedAt, connectionStatus: row?.connection_status || 'not-enrolled', status, inventory };
    }, { readOnly: true });
    await this.inventory.checkpoint(source, user, authorization); return result;
  }
  async fleet(query, user, authorization, exportCsv = false) {
    const { connectionStatus, ...selectors } = query;
    if (connectionStatus !== undefined && !statuses.includes(connectionStatus)) fail(400, 'Invalid connection filter');
    if (exportCsv && (selectors.page !== undefined || selectors.limit !== undefined)) fail(400, 'Export uses the complete filtered fleet');
    const page = pageQuery(selectors, true);
    const source = await this.inventory.authorized(user, authorization, 'devices.inventory.read');
    const result = await this.database.transaction(async client => {
      await this.inventory.receiving(client); await this.receiving(client);
      const checkedAt = iso((await client.query('SELECT clock_timestamp() AS checked_at')).rows[0].checked_at);
      const params = [source.tenant.id, page.search, page.platform, page.lifecycle, page.ownership, page.deviceClass, checkedAt];
      const base = `WITH fleet AS (SELECT unit.id,unit.asset_id,unit.inventory_created_at,unit.inventory_updated_at,
       device_inventory_row(unit) AS inventory,(SELECT to_jsonb(link) FROM device_inventory_assignments link WHERE link.device_id=unit.id AND link.tenant_id=unit.tenant_id AND link.released_at IS NULL) AS assignment,
       to_jsonb(connection) AS agent,${statusSql('$7::timestamptz')} AS connection_status FROM (SELECT * FROM devices WHERE ${selectionWhere}) unit
       LEFT JOIN device_agent_connections connection ON connection.device_id=unit.id AND connection.tenant_id=unit.tenant_id) `;
      const counts = Object.fromEntries(statuses.map(status => [status, 0]));
      for (const row of (await client.query(base + 'SELECT connection_status,count(*) AS count FROM fleet GROUP BY connection_status', params)).rows) counts[row.connection_status] = Number(row.count);
      const column = { createdAt: 'inventory_created_at', updatedAt: 'inventory_updated_at', assetId: 'lower(asset_id)' }[page.sort];
      const rows = (await client.query(base + `SELECT * FROM fleet WHERE ($8::text IS NULL OR connection_status=$8) ORDER BY ${column} ${page.order},id LIMIT $9 OFFSET $10`, [...params, connectionStatus || null, exportCsv ? 5001 : page.limit, exportCsv ? 0 : (page.page - 1) * page.limit])).rows;
      const devices = rows.map(row => inventoryDevice(row.inventory, row.assignment));
      const connections = rows.map(row => ({ deviceId: row.id, ...connectionSummary(row.agent, row.connection_status) }));
      if (exportCsv) {
        if (rows.length > 5000) fail(413, 'Narrow the export filters; at most 5000 devices can be exported');
        const fields = [...DEVICE_FIELDS, 'lifecycle', 'assignedUserId', 'connectionStatus', 'lastSeen', 'hostname', 'agentVersion'];
        const cell = value => '"' + String(value ?? '').replace(/^([\s]*)([=+\-@])/u, "'$1$2").replace(/"/g, '""') + '"';
        const data = devices.map((device, i) => ({ ...device, connectionStatus: connections[i].status, lastSeen: connections[i].lastSeen, hostname: connections[i].report?.hostname, agentVersion: connections[i].report?.agentVersion }));
        return { tenantId: source.tenant.id, count: data.length, csv: '\uFEFF' + [fields.map(cell).join(','), ...data.map(row => fields.map(field => cell(row[field])).join(','))].join('\r\n') + '\r\n' };
      }
      const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
      return { schemaVersion: 1, actorUserId: source.actorUserId, devices, total: connectionStatus ? counts[connectionStatus] : total, page: page.page, limit: page.limit,
        fleet: { protocol: 1, tenantId: source.tenant.id, checkedAt, counts: { total, ...counts }, connections } };
    }, { readOnly: true });
    await this.inventory.checkpoint(source, user, authorization); return result;
  }
  async state(client, deviceId, tenantId, actorUserId, page = 1) {
    await this.inventory.current(client, tenantId, deviceId);
    const row = (await client.query(`SELECT connection.*,${statusSql()} AS connection_status FROM device_agent_connections connection WHERE device_id=$1 AND tenant_id=$2`, [deviceId, tenantId])).rows[0];
    const total = Number((await client.query('SELECT count(*) AS total FROM device_agent_events WHERE device_id=$1 AND tenant_id=$2', [deviceId, tenantId])).rows[0].total);
    const events = (await client.query('SELECT id,action,actor_user_id,reason,correlation_id,created_at FROM device_agent_events WHERE device_id=$1 AND tenant_id=$2 ORDER BY created_at DESC,id DESC LIMIT 25 OFFSET $3', [deviceId, tenantId, (page - 1) * 25])).rows;
    return { schemaVersion: 1, agentProtocol: 1, actorUserId, tenantId, deviceId, revision: String(row?.revision || '0'), ...connectionSummary(row),
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
    const hasInventory = input && Object.hasOwn(input, 'inventory');
    exact(input, hasInventory ? ['deviceId', 'report', 'inventory'] : ['deviceId', 'report']); identifier(input.deviceId); const values = report(input.report);
    const inventory = hasInventory ? validateInventory(input.inventory) : undefined;
    if (typeof authorization !== 'string' || !/^Bearer odad_[A-Za-z0-9_-]{43}$/.test(authorization)) fail(401, 'Device-only credential required');
    return this.database.transaction(async client => {
      await this.receiving(client);
      const tokenHash = digest(authorization.slice(7));
      const row = (await client.query('SELECT device_id FROM device_agent_connections WHERE device_id=$1 AND credential_hash=$2 AND credential_expires_at>clock_timestamp() AND revoked_at IS NULL', [input.deviceId, tokenHash])).rows[0];
      if (!row) fail(401, 'Agent credential rejected');
      await client.query('SELECT device_agent_change($1::jsonb)', [JSON.stringify({ action: 'heartbeat', deviceId: row.device_id, tokenHash, report: values, ...(hasInventory ? { inventory } : {}) })]);
      return { schemaVersion: 1, agentProtocol: 1, deviceId: row.device_id, receivedAt: iso((await client.query('SELECT last_seen FROM device_agent_connections WHERE device_id=$1', [row.device_id])).rows[0].last_seen) };
    });
  }
}
module.exports = { DeviceAgents, agentEtag: etag, report };
