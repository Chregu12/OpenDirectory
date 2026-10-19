'use strict';

const { randomUUID } = require('node:crypto');
const { DeviceInventory } = require('./DeviceInventory');
const { DeviceReturnAuthority } = require('./DeviceReturnAuthority');
const { returnListQuery, offboardingReturnQuery, offboardingReturnCapabilityQuery, offboardingReturnValues,
  returnDecisionValues, deviceReturnEtag, validateDeviceReturnEtag, deviceEtag } = require('../../../../packages/device-inventory-contract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function identifier(value) { if (typeof value !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value)) fail(400, 'Canonical device return UUID required'); return value; }
function iso(value) { return value === null ? null : new Date(value).toISOString(); }
function code(error) { return Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 ? error.status : ({ '23505': 409, '23514': 409, '23503': 409, '22P02': 400, '42501': 503, '55P03': 409 }[error.code] || 503); }
function envelope(source) { return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id }; }
function negativeEnvelope(source) { return { ...envelope(source), deviceOffboardingReturnsProtocol: 1, workflowId: source.parent.workflowId, userId: source.target.id,
  target: { enabled: false, eligibilityRevision: source.target.eligibilityRevision }, permissions: source.permissions, managementMode: 'inventory-only' }; }
function taskDto(row) {
  const task = row.state; const changed = task.status === 'requested' && row.assignment.released_at !== null;
  return { id: task.id, tenantId: task.tenant_id, workflowId: task.workflow_id, userId: task.user_id, deviceId: task.device_id, assignmentId: task.assignment_id,
    assetId: task.asset_id, serialNumber: task.serial_number, revision: task.revision, deviceRevision: task.device_revision, currentDeviceRevision: row.current_device_revision,
    status: changed ? 'assignment_changed' : task.status, reason: task.reason, actorUserId: task.actor_user_id, requestedAt: iso(task.requested_at), eligibilityRevision: task.eligibility_revision,
    closedAt: changed ? iso(row.assignment.released_at) : iso(task.closed_at), closedByUserId: changed ? row.release.actor_user_id : task.closed_by_user_id,
    operationId: task.operation_id, closingOperationId: task.closing_operation_id, inventoryOperationId: changed ? row.assignment.released_by_command_id : task.inventory_operation_id, deliveryStatus: 'pending' };
}

class DeviceReturns {
  constructor(database, { inventory = new DeviceInventory(database), authority, newId = randomUUID } = {}) {
    this.database = database; this.inventory = inventory; this.newId = newId;
    this.authority = authority || new DeviceReturnAuthority({ endpoint: new URL('/api/identity/device-offboarding', inventory.authority.endpoint).href });
  }
  async receiving(client) { try { await client.query('SELECT device_returns_receiving()'); } catch (error) { throw Object.assign(new Error('Device return receiver unavailable'), { status: 503, cause: error }); } }
  async initial(user, authorization, workflowId = null, userId = null) {
    if (!this.database.isAvailable()) fail(503, 'Persistent device returns storage required');
    return workflowId === null ? this.inventory.authorized(user, authorization, 'devices.inventory.read') : this.authority.read(authorization, user, workflowId, identifier(userId));
  }
  async checkpoint(source, user, authorization) {
    const current = await this.initial(user, authorization, source.parent?.workflowId || null, source.target?.id || null);
    if (JSON.stringify(source) !== JSON.stringify(current)) fail(401, 'Original device return authority changed');
  }
  async readTask(client, tenantId, requestId, lock = false) {
    if (lock) await client.query('SELECT id FROM devices WHERE tenant_id=$2 AND id=(SELECT device_id FROM device_return_requests WHERE id=$1 AND tenant_id=$2) FOR UPDATE', [requestId, tenantId]);
    const result = (await client.query('SELECT device_returns_row(task) AS state, unit.inventory_revision::text AS current_device_revision, to_jsonb(link) AS assignment, to_jsonb(release) AS release FROM device_return_requests task JOIN devices unit ON unit.id=task.device_id AND unit.tenant_id=task.tenant_id JOIN device_inventory_assignments link ON link.id=task.assignment_id LEFT JOIN device_inventory_events release ON release.id=link.released_by_command_id WHERE task.id=$1 AND task.tenant_id=$2' + (lock ? ' FOR UPDATE OF task,link' : ''), [requestId, tenantId])).rows[0];
    if (!result) fail(404, 'Device return request not found');
    await client.query('SELECT device_returns_validate($1)', [requestId]); return result;
  }
  async capabilities(user, authorization) {
    const source = await this.initial(user, authorization); await this.database.transaction(client => this.receiving(client), { readOnly: true }); await this.checkpoint(source, user, authorization);
    return { ...envelope(source), deviceReturnsProtocol: 1, permissions: source.permissions, managementMode: 'inventory-only' };
  }
  async list(query, user, authorization) {
    const page = returnListQuery(query); const source = await this.initial(user, authorization);
    const result = await this.database.transaction(async client => {
      await this.receiving(client);
      const where = "task.tenant_id=$1 AND ($2::text IS NULL OR CASE WHEN task.status='requested' AND link.released_at IS NOT NULL THEN 'assignment_changed' ELSE task.status END=$2)";
      const from = ' FROM device_return_requests task JOIN device_inventory_assignments link ON link.id=task.assignment_id WHERE ' + where;
      const total = Number((await client.query('SELECT count(*) AS count' + from, [source.tenant.id, page.status])).rows[0].count);
      const ids = (await client.query('SELECT task.id' + from + ' ORDER BY task.requested_at DESC,task.id DESC LIMIT 25 OFFSET $3', [source.tenant.id, page.status, (page.page - 1) * 25])).rows;
      const requests = []; for (const item of ids) requests.push(taskDto(await this.readTask(client, source.tenant.id, item.id)));
      return { ...envelope(source), requests, total, page: page.page, limit: 25 };
    }, { readOnly: true }); await this.checkpoint(source, user, authorization); return result;
  }
  async get(id, user, authorization) {
    identifier(id); const source = await this.initial(user, authorization);
    const result = await this.database.transaction(async client => { await this.receiving(client); return taskDto(await this.readTask(client, source.tenant.id, id)); }, { readOnly: true });
    await this.checkpoint(source, user, authorization); return result;
  }
  async history(id, query, user, authorization) {
    identifier(id); const page = returnListQuery(query); if (Object.hasOwn(query, 'status')) fail(400, 'No history status selector'); const source = await this.initial(user, authorization);
    const result = await this.database.transaction(async client => {
      await this.receiving(client); await this.readTask(client, source.tenant.id, id);
      const total = Number((await client.query('SELECT count(*) AS count FROM device_return_events WHERE request_id=$1 AND tenant_id=$2', [id, source.tenant.id])).rows[0].count);
      const rows = (await client.query("SELECT event.* FROM device_return_events event JOIN device_return_outbox outbox ON outbox.id=event.id AND outbox.tenant_id=event.tenant_id AND outbox.status='pending' WHERE event.request_id=$1 AND event.tenant_id=$2 ORDER BY event.created_at,event.id LIMIT 25 OFFSET $3", [id, source.tenant.id, (page.page - 1) * 25])).rows;
      return { ...envelope(source), requestId: id, events: rows.map(event => ({ id: event.id, tenantId: event.tenant_id, requestId: event.request_id, deviceId: event.device_id, assignmentId: event.assignment_id,
        type: event.type, version: event.version, actorUserId: event.actor_user_id, correlationId: event.correlation_id, createdAt: iso(event.created_at), before: event.before_state, after: event.after_state,
        inventoryOperationId: event.inventory_operation_id, reason: event.reason, deliveryStatus: 'pending' })), total, page: page.page, limit: 25 };
    }, { readOnly: true }); await this.checkpoint(source, user, authorization); return result;
  }
  async offboardingCapabilities(userId, query, user, authorization) {
    const { workflowId } = offboardingReturnCapabilityQuery(query); const source = await this.initial(user, authorization, workflowId, userId);
    await this.database.transaction(client => this.receiving(client), { readOnly: true }); await this.checkpoint(source, user, authorization); return negativeEnvelope(source);
  }
  async offboardingList(userId, query, user, authorization) {
    const page = offboardingReturnQuery(query); const source = await this.initial(user, authorization, page.workflowId, userId);
    const result = await this.database.transaction(async client => {
      await this.receiving(client);
      const from = ' FROM device_inventory_assignments link JOIN devices unit ON unit.id=link.device_id AND unit.tenant_id=link.tenant_id WHERE link.tenant_id=$1 AND link.user_id=$2 AND link.released_at IS NULL';
      const total = Number((await client.query('SELECT count(*) AS count' + from, [source.tenant.id, userId])).rows[0].count);
      const rows = (await client.query('SELECT unit.id,unit.asset_id,unit.serial_number,unit.inventory_revision::text AS revision,link.id AS assignment_id' + from + ' ORDER BY unit.inventory_created_at,unit.id LIMIT 25 OFFSET $3', [source.tenant.id, userId, (page.page - 1) * 25])).rows;
      const devices = [];
      for (const row of rows) {
        const current = await this.inventory.current(client, source.tenant.id, row.id);
        if (current.row.assigned_user !== userId || current.link?.id !== row.assignment_id) fail(503, 'Coherent actual original assignment required');
        const open = (await client.query("SELECT id FROM device_return_requests WHERE assignment_id=$1 AND status='requested'", [row.assignment_id])).rows[0];
        if (open) await this.readTask(client, source.tenant.id, open.id);
        devices.push({ deviceId: row.id, assetId: row.asset_id, serialNumber: row.serial_number, deviceRevision: row.revision, assignmentId: row.assignment_id, openRequestId: open?.id || null });
      }
      return { ...negativeEnvelope(source), devices, total, page: page.page, limit: 25 };
    }, { readOnly: true }); await this.checkpoint(source, user, authorization); return result;
  }
  async offboardingHistory(userId, query, user, authorization) {
    const page = offboardingReturnQuery(query); const source = await this.initial(user, authorization, page.workflowId, userId);
    const result = await this.database.transaction(async client => {
      await this.receiving(client);
      const where = 'tenant_id=$1 AND workflow_id=$2 AND user_id=$3'; const values = [source.tenant.id, page.workflowId, userId];
      const total = Number((await client.query('SELECT count(*) AS count FROM device_return_requests WHERE ' + where, values)).rows[0].count);
      const ids = (await client.query('SELECT id FROM device_return_requests WHERE ' + where + ' ORDER BY requested_at DESC,id DESC LIMIT 25 OFFSET $4', [...values, (page.page - 1) * 25])).rows;
      const requests = []; for (const item of ids) requests.push(taskDto(await this.readTask(client, source.tenant.id, item.id)));
      return { ...envelope(source), workflowId: page.workflowId, userId, target: { enabled: false, eligibilityRevision: source.target.eligibilityRevision }, requests, total, page: page.page, limit: 25 };
    }, { readOnly: true }); await this.checkpoint(source, user, authorization); return result;
  }
  async captured(client, source, item, reason, lock = false) {
    if (lock) await client.query('SELECT id FROM devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE', [item.deviceId, source.tenant.id]);
    const existing = (await client.query('SELECT tenant_id FROM device_return_requests WHERE id=$1', [item.requestId])).rows[0];
    if (existing) {
      if (existing.tenant_id !== source.tenant.id) fail(409, 'Original device return intent changed');
      const row = await this.readTask(client, source.tenant.id, item.requestId, lock); const task = row.state;
      if (task.workflow_id !== source.parent.workflowId || task.user_id !== source.target.id || task.device_id !== item.deviceId || task.assignment_id !== item.assignmentId
        || task.device_revision !== item.deviceRevision || task.eligibility_revision !== source.target.eligibilityRevision || task.reason !== reason) fail(409, 'Original device return intent changed');
      return task.operation_id;
    }
    const current = await this.inventory.current(client, source.tenant.id, item.deviceId, lock);
    if (current.row.inventory_revision !== item.deviceRevision || current.link?.id !== item.assignmentId || current.row.assigned_user !== source.target.id || current.link?.user_id !== source.target.id) fail(409, 'Captured device assignment changed');
    if ((await client.query("SELECT id FROM device_return_requests WHERE assignment_id=$1 AND status='requested'", [item.assignmentId])).rows.length) fail(409, 'Original assignment already has a return request');
    return null;
  }
  async request(userId, body, user, authorization, correlationId) {
    const values = offboardingReturnValues(body); const source = await this.initial(user, authorization, values.workflowId, userId);
    if (values.eligibilityRevision !== source.target.eligibilityRevision) fail(409, 'Original negative eligibility changed');
    await this.database.transaction(async client => { await this.receiving(client); for (const item of values.items) await this.captured(client, source, item, values.reason); }, { readOnly: true });
    await this.checkpoint(source, user, authorization); const correlation = identifier(correlationId || this.newId()); const results = []; let stopped = false;
    for (const item of values.items) {
      if (stopped) { results.push({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: 'not_attempted', code: null, operationId: null }); continue; }
      try {
        const receipt = await this.database.transaction(async client => {
          await this.receiving(client); await this.checkpoint(source, user, authorization);
          const previous = await this.captured(client, source, item, values.reason, true);
          if (previous) return { status: 'already_requested', operationId: previous };
          const operationId = identifier(this.newId());
          const proof = { id: operationId, action: 'requested', requestId: item.requestId, correlationId: correlation, source, item, reason: values.reason, eligibilityRevision: values.eligibilityRevision };
          await client.query('SELECT device_returns_change($1::jsonb)', [JSON.stringify(proof)]);
          const actual = await this.readTask(client, source.tenant.id, item.requestId);
          if (actual.state.operation_id !== operationId) fail(503, 'Actual original return receipt unavailable');
          return { status: 'requested', operationId };
        }, { beforeCommit: () => this.checkpoint(source, user, authorization) });
        results.push({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: receipt.status, code: 200, operationId: receipt.operationId });
      } catch (error) { stopped = true; results.push({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: 'unconfirmed', code: code(error), operationId: null }); }
    }
    return { ...envelope(source), workflowId: values.workflowId, userId, correlationId: correlation, results };
  }
  async decide(id, body, expected, user, authorization, correlationId) {
    identifier(id); const values = returnDecisionValues(body); const captured = validateDeviceReturnEtag(expected); if (captured.id !== id) fail(412, 'Return request changed');
    const source = await this.initial(user, authorization); const checkpoints = [];
    return this.database.transaction(async client => {
      await this.receiving(client); const current = await this.readTask(client, source.tenant.id, id, true); const task = taskDto(current);
      await this.checkpoint(source, user, authorization);
      if (current.state.status !== 'requested') {
        const decision = (await client.query('SELECT proof FROM device_return_events WHERE id=$1', [task.closingOperationId])).rows[0]?.proof;
        if (current.state.status !== values.action || decision?.expected !== expected || decision.reason !== values.reason) fail(409, 'Original return decision differs');
        return { ...envelope(source), deviceReturnsProtocol: 1, request: task, outcome: 'already_' + values.action, operationId: task.closingOperationId };
      }
      if (task.status === 'assignment_changed') fail(409, 'Original assignment was released; no decision can affect its replacement');
      if (deviceReturnEtag(task) !== expected) fail(412, 'Device or return request changed; reload before retrying');
      const correlation = identifier(correlationId || this.newId()); let inventoryOperationId = null;
      if (values.action === 'returned') {
        const bound = { isAvailable: () => true, transaction: async (operation, options = {}) => {
          const result = await operation(client); if (options.beforeCommit) { checkpoints.push(options.beforeCommit); await options.beforeCommit(client); } return result;
        } };
        await new DeviceInventory(bound, { authority: this.inventory.authority, newId: this.newId }).assign(task.deviceId, { userId: null }, deviceEtag({ id: task.deviceId, revision: task.currentDeviceRevision }), user, authorization, correlation);
        const inventory = (await client.query("SELECT id FROM device_inventory_events WHERE transaction_id=txid_current() AND tenant_id=$1 AND device_id=$2 AND action='release' AND before_assignment->>'id'=$3", [source.tenant.id, task.deviceId, task.assignmentId])).rows;
        if (inventory.length !== 1) fail(503, 'Actual original inventory release receipt unavailable'); inventoryOperationId = inventory[0].id;
      }
      const operationId = identifier(this.newId());
      await client.query('SELECT device_returns_change($1::jsonb)', [JSON.stringify({ id: operationId, action: values.action, requestId: id, correlationId: correlation, source, reason: values.reason, expected, inventoryOperationId })]);
      const actual = taskDto(await this.readTask(client, source.tenant.id, id));
      if (actual.closingOperationId !== operationId) fail(503, 'Actual return decision receipt unavailable');
      return { ...envelope(source), deviceReturnsProtocol: 1, request: actual, outcome: values.action, operationId };
    }, { beforeCommit: async client => { for (const checkpoint of checkpoints) await checkpoint(client); await this.checkpoint(source, user, authorization); } });
  }
}

module.exports = { DeviceReturns };
