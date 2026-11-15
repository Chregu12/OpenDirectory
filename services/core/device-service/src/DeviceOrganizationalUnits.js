'use strict';

const { randomUUID } = require('node:crypto');
const { validUuid } = require('../../../../packages/identity-authorization-contract');
const C = require('../../../../packages/device-ou-contract');
const { DeviceInventory } = require('./DeviceInventory');
const { DeviceOuSource } = require('./DeviceOuSource');
const iso = value => new Date(value).toISOString();
function assignment(row) {
  if (!row) return { revision: '0', ou: null, updatedAt: null, updatedBy: null };
  if (row.ou !== null && !C.validUnit(row.ou)) C.fail(503, 'Retained device OU unavailable');
  return { revision: String(row.revision), ou: row.ou, updatedAt: iso(row.updated_at), updatedBy: row.updated_by };
}

class DeviceOrganizationalUnits {
  constructor(database, { inventory = new DeviceInventory(database), authority = new DeviceOuSource() } = {}) { this.database = database; this.inventory = inventory; this.authority = authority; }
  async receiving(client) { try { await client.query('SELECT device_ou_receiving()'); } catch (cause) { throw Object.assign(new Error('Device OU receiver unavailable'), { status: 503, cause }); } }
  async current(client, tenantId, deviceId) {
    const device = await this.inventory.current(client, tenantId, deviceId);
    const row = (await client.query('SELECT * FROM device_ou_assignments WHERE device_id=$1 AND tenant_id=$2', [deviceId, tenantId])).rows[0];
    return { deviceRevision: String(device.row.inventory_revision), ...assignment(row) };
  }
  async units(query, user, authorization) {
    C.page(query, true);
    const source = await this.inventory.authorized(user, authorization, 'devices.inventory.create');
    const result = await this.authority.units(authorization, user, source.tenant.id, query);
    await this.inventory.checkpoint(source, user, authorization); return result;
  }
  async get(id, query, user, authorization) {
    C.identifier(id); if (Object.keys(query).length) C.fail(400, 'No device OU selectors');
    const source = await this.inventory.authorized(user, authorization, 'devices.inventory.read');
    const result = await this.database.transaction(async client => {
      await this.receiving(client); const value = await this.current(client, source.tenant.id, id);
      return { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, deviceId: id, ...value };
    }, { readOnly: true });
    await this.inventory.checkpoint(source, user, authorization); return result;
  }
  async write(id, body, expected, user, authorization, correlationId) {
    C.identifier(id); const values = C.input(body), versions = C.expected(expected, id);
    if (!this.database.isAvailable()) C.fail(503, 'Persistent device OU storage required');
    const ouId = values.ou?.id || null, source = await this.authority.read(authorization, user, ouId), operationId = randomUUID();
    if (values.ou !== null && (source.ou?.id !== values.ou.id || source.ou?.generation !== values.ou.generation || source.ou?.revision !== values.ou.revision)) C.fail(412, 'Selected organizational unit changed; reload');
    const checkpoint = async () => { if (JSON.stringify(source) !== JSON.stringify(await this.authority.read(authorization, user, ouId))) C.fail(401, 'Original device OU authority changed'); };
    return this.database.transaction(async client => {
      await this.receiving(client); await this.inventory.current(client, source.inventory.tenant.id, id, true);
      const current = await this.current(client, source.inventory.tenant.id, id);
      if (C.etag(id, current.deviceRevision, current.revision) !== expected) C.fail(412, 'Device or OU assignment changed; reload');
      if (JSON.stringify(current.ou) === JSON.stringify(source.ou)) C.fail(409, 'No device OU assignment changed');
      await checkpoint();
      await client.query('SELECT device_ou_change($1::jsonb)', [JSON.stringify({ id: operationId, deviceId: id, ...versions, selectedOu: values.ou, source, reason: values.reason, confirm: true, correlationId: validUuid(correlationId) ? correlationId : randomUUID() })]);
      const receipt = (await client.query("SELECT event.id FROM device_ou_events event JOIN device_ou_outbox outbox USING(id) WHERE event.id=$1 AND event.tenant_id=$2 AND event.transaction_id=txid_current() AND event.source=$3::jsonb AND outbox.tenant_id=event.tenant_id AND outbox.status='pending'", [operationId, source.inventory.tenant.id, JSON.stringify(source)])).rows;
      if (receipt.length !== 1) C.fail(503, 'Actual device OU receipt unavailable');
      return { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: source.inventory.actorUserId, tenantId: source.inventory.tenant.id, deviceId: id, ...await this.current(client, source.inventory.tenant.id, id), operationId, deliveryStatus: 'pending' };
    }, { beforeCommit: checkpoint });
  }
  async history(id, query, user, authorization) {
    C.identifier(id); const selected = C.page(query);
    const source = await this.inventory.authorized(user, authorization, 'devices.inventory.read');
    const result = await this.database.transaction(async client => {
      await this.receiving(client); await this.inventory.current(client, source.tenant.id, id);
      const total = Number((await client.query('SELECT count(*) AS count FROM device_ou_events WHERE tenant_id=$1 AND device_id=$2', [source.tenant.id, id])).rows[0].count);
      const rows = (await client.query('SELECT event.*,outbox.status AS delivery_status FROM device_ou_events event LEFT JOIN device_ou_outbox outbox ON outbox.id=event.id AND outbox.tenant_id=event.tenant_id WHERE event.tenant_id=$1 AND event.device_id=$2 ORDER BY event.created_at DESC,event.id DESC LIMIT 25 OFFSET $3', [source.tenant.id, id, (selected.page - 1) * 25])).rows;
      if (rows.some(row => row.delivery_status !== 'pending')) C.fail(503, 'Retained device OU history unavailable');
      return { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, deviceId: id, page: selected.page, limit: 25, total,
        events: rows.map(row => ({ id: row.id, actorUserId: row.actor_user_id, correlationId: row.correlation_id, reason: row.reason, createdAt: iso(row.created_at), before: row.before_state ? assignment(row.before_state) : null, after: assignment(row.after_state), deliveryStatus: 'pending' })) };
    }, { readOnly: true });
    await this.inventory.checkpoint(source, user, authorization); return result;
  }
}
module.exports = { DeviceOrganizationalUnits };
