'use strict';
const Scope=require('./DeviceScope');
const { actorSource } = require('../../../../packages/device-return-scope-contract');
const { isDeepStrictEqual } = require('node:util');

const { randomUUID } = require('node:crypto');
const { DeviceInventory } = require('./DeviceInventory');
const { DeviceReturnAuthority } = require('./DeviceReturnAuthority');
const { returnListQuery, offboardingReturnQuery, offboardingReturnCapabilityQuery, offboardingReturnValues,
  returnDecisionValues, deviceReturnEtag, validateDeviceReturnEtag, deviceEtag } = require('../../../../packages/device-inventory-contract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function identifier(value) { if (typeof value !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value)) fail(400, 'Canonical device return UUID required'); return value; }
function iso(value) { return value === null ? null : new Date(value).toISOString(); }
function code(error) { return Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 ? error.status : ({ '23505': 409, '23514': 409, '23503': 409, '22P02': 400, '42501': 503, '55P03': 409, 'P0412': 412 }[error.code] || 503); }
function envelope(source, manage = !!source.parent) {
  const actor = actorSource(source);
  const scoped = actor.schemaVersion === 2;
  const coverage = scoped && (Scope.limited(actor, 'devices.inventory.read') || manage && Scope.limited(actor, 'devices.inventory.assign')) ? 'scope' : 'tenant';
  return { schemaVersion: scoped ? 2 : 1, actorUserId: actor.actorUserId, tenantId: actor.tenant.id, ...(scoped ? { coverage } : {}) };
}
function negativeEnvelope(source) { return { ...envelope(source), deviceOffboardingReturnsProtocol: source.schemaVersion === 2 ? 2 : 1, workflowId: source.parent.workflowId, userId: source.target.id,
  target: { enabled: false, eligibilityRevision: source.target.eligibilityRevision }, permissions: actorSource(source).permissions, managementMode: 'inventory-only' }; }
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
    this.authority = authority || new DeviceReturnAuthority({ scoped: inventory.authority.scoped === true, endpoint: new URL('/api/identity/device-offboarding', inventory.authority.endpoint).href });
  }
  async receiving(client) { try { await client.query(this.inventory.authority?.scoped === true || this.authority.scoped === true ? 'SELECT device_returns_receiving(2)' : 'SELECT device_returns_receiving()'); } catch (error) { throw Object.assign(new Error('Device return receiver unavailable'), { status: 503, cause: error }); } }
  async initial(user, authorization, workflowId = null, userId = null) {
    if (!this.database.isAvailable()) fail(503, 'Persistent device returns storage required');
    return workflowId === null ? this.inventory.authorized(user, authorization, 'devices.inventory.read') : this.authority.read(authorization, user, workflowId, identifier(userId));
  }
  async checkpoint(source, user, authorization) {
    if (!source.parent) return this.inventory.checkpoint(source, user, authorization);
    const actor = actorSource(source);
    const current = await this.authority.read(authorization, user, source.parent.workflowId, source.target.id, actor.schemaVersion === 2 ? actor.scope.resource : null);
    if (!isDeepStrictEqual(source, current)) fail(401, 'Original device return authority changed');
  }
  async bind(client, source, user, authorization, id, revision) {
    const bound = await Scope.bind(client, this.inventory, actorSource(source), 'devices.inventory.assign', user, authorization, id, revision, source.parent ? source.target.id : null);
    return source.parent && source.schemaVersion === 2 ? { ...source, inventory: bound } : bound;
  }
  async pin(client, source, ids, manage = !!source.parent) {
    const actor = actorSource(source);
    return { read: await Scope.pin(client, actor, 'devices.inventory.read', ids), assign: manage ? await Scope.pin(client, actor, 'devices.inventory.assign', ids) : null };
  }
  async verify(source, pins) {
    await Scope.verify(this.database, actorSource(source), 'devices.inventory.read', pins.read);
    await Scope.verify(this.database, actorSource(source), 'devices.inventory.assign', pins.assign);
  }
  async visibleTask(client, source, id, lock = false, manage = false) {
    const selected = (await client.query('SELECT device_id FROM device_return_requests WHERE id=$1 AND tenant_id=$2', [id, actorSource(source).tenant.id])).rows[0];
    if (!selected) fail(404, 'Device return request not found');
    if (lock) await client.query('SELECT id FROM devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE', [selected.device_id, actorSource(source).tenant.id]);
    await Scope.requireDevice(client, actorSource(source), 'devices.inventory.read', selected.device_id);
    if (manage) await Scope.requireDevice(client, actorSource(source), 'devices.inventory.assign', selected.device_id);
    return this.readTask(client, actorSource(source).tenant.id, id, lock);
  }
  async readTask(client, tenantId, requestId, lock = false) {
    if (lock) await client.query('SELECT id FROM devices WHERE tenant_id=$2 AND id=(SELECT device_id FROM device_return_requests WHERE id=$1 AND tenant_id=$2) FOR UPDATE', [requestId, tenantId]);
    const result = (await client.query('SELECT device_returns_row(task) AS state, unit.inventory_revision::text AS current_device_revision, to_jsonb(link) AS assignment, to_jsonb(release) AS release FROM device_return_requests task JOIN devices unit ON unit.id=task.device_id AND unit.tenant_id=task.tenant_id JOIN device_inventory_assignments link ON link.id=task.assignment_id LEFT JOIN device_inventory_events release ON release.id=link.released_by_command_id WHERE task.id=$1 AND task.tenant_id=$2' + (lock ? ' FOR UPDATE OF task,link' : ''), [requestId, tenantId])).rows[0];
    if (!result) fail(404, 'Device return request not found');
    await client.query('SELECT device_returns_validate($1)', [requestId]); return result;
  }
  async capabilities(user, authorization) {
    const source = await this.initial(user, authorization); await this.database.transaction(client => this.receiving(client), { readOnly: true }); await this.checkpoint(source, user, authorization);
    return { ...envelope(source,actorSource(source).permissions.includes('devices.inventory.assign')), deviceReturnsProtocol: source.schemaVersion === 2 ? 2 : 1, permissions: actorSource(source).permissions, managementMode: 'inventory-only' };
  }
  async list(query, user, authorization) {
    const page = returnListQuery(query); const source = await this.initial(user, authorization);
    let scope;
    const result = await this.database.transaction(async client => {
      await this.receiving(client);
      const params=[actorSource(source).tenant.id,page.status];
      const where = "task.tenant_id=$1 AND ($2::text IS NULL OR CASE WHEN task.status='requested' AND link.released_at IS NOT NULL THEN 'assignment_changed' ELSE task.status END=$2)"+await Scope.predicate(client,actorSource(source),'devices.inventory.read','task.device_id',params);
      const from = ' FROM device_return_requests task JOIN device_inventory_assignments link ON link.id=task.assignment_id WHERE ' + where;
      const total = Number((await client.query('SELECT count(*) AS count' + from, params)).rows[0].count);
      const ids = (await client.query('SELECT task.id' + from + ' ORDER BY task.requested_at DESC,task.id DESC LIMIT 25 OFFSET $'+(params.length+1), [...params, (page.page - 1) * 25])).rows;
      const requests = []; for (const item of ids) requests.push(taskDto(await this.readTask(client, actorSource(source).tenant.id, item.id)));
      scope=await this.pin(client,source,requests.map(request=>request.deviceId));
      return { ...envelope(source), requests, total, page: page.page, limit: 25 };
    }, { readOnly: true }); await this.checkpoint(source, user, authorization);await this.verify(source,scope); return result;
  }
  async get(id, user, authorization) {
    identifier(id); const source = await this.initial(user, authorization);
    let scope;
    const result = await this.database.transaction(async client => { await this.receiving(client);const row=await this.visibleTask(client,source,id);scope=await this.pin(client,source,[row.state.device_id]); return taskDto(row); }, { readOnly: true });
    await this.checkpoint(source, user, authorization);await this.verify(source,scope); return result;
  }
  async history(id, query, user, authorization) {
    identifier(id); const page = returnListQuery(query); if (Object.hasOwn(query, 'status')) fail(400, 'No history status selector'); const source = await this.initial(user, authorization);
    let scope;
    const result = await this.database.transaction(async client => {
      await this.receiving(client);const task=await this.visibleTask(client,source,id);scope=await this.pin(client,source,[task.state.device_id]);
      const total = Number((await client.query('SELECT count(*) AS count FROM device_return_events WHERE request_id=$1 AND tenant_id=$2', [id, actorSource(source).tenant.id])).rows[0].count);
      const rows = (await client.query("SELECT event.* FROM device_return_events event JOIN device_return_outbox outbox ON outbox.id=event.id AND outbox.tenant_id=event.tenant_id AND outbox.status='pending' WHERE event.request_id=$1 AND event.tenant_id=$2 ORDER BY event.created_at,event.id LIMIT 25 OFFSET $3", [id, actorSource(source).tenant.id, (page.page - 1) * 25])).rows;
      return { ...envelope(source), requestId: id, events: rows.map(event => ({ id: event.id, tenantId: event.tenant_id, requestId: event.request_id, deviceId: event.device_id, assignmentId: event.assignment_id,
        type: event.type, version: event.version, actorUserId: event.actor_user_id, correlationId: event.correlation_id, createdAt: iso(event.created_at), before: event.before_state, after: event.after_state,
        inventoryOperationId: event.inventory_operation_id, reason: event.reason, deliveryStatus: 'pending' })), total, page: page.page, limit: 25 };
    }, { readOnly: true }); await this.checkpoint(source, user, authorization);await this.verify(source,scope); return result;
  }
  async offboardingCapabilities(userId, query, user, authorization) {
    const { workflowId } = offboardingReturnCapabilityQuery(query); const source = await this.initial(user, authorization, workflowId, userId);
    await this.database.transaction(client => this.receiving(client), { readOnly: true }); await this.checkpoint(source, user, authorization); return negativeEnvelope(source);
  }
  async offboardingList(userId, query, user, authorization) {
    const page = offboardingReturnQuery(query); const source = await this.initial(user, authorization, page.workflowId, userId);
    let scope;
    const result = await this.database.transaction(async client => {
      await this.receiving(client);
      const params=[actorSource(source).tenant.id,userId],from = ' FROM device_inventory_assignments link JOIN devices unit ON unit.id=link.device_id AND unit.tenant_id=link.tenant_id WHERE link.tenant_id=$1 AND link.user_id=$2 AND link.released_at IS NULL'+await Scope.predicate(client,actorSource(source),'devices.inventory.read','unit.id',params)+await Scope.predicate(client,actorSource(source),'devices.inventory.assign','unit.id',params);
      const total = Number((await client.query('SELECT count(*) AS count' + from, params)).rows[0].count);
      const rows = (await client.query('SELECT unit.id,unit.asset_id,unit.serial_number,unit.inventory_revision::text AS revision,link.id AS assignment_id' + from + ' ORDER BY unit.inventory_created_at,unit.id LIMIT 25 OFFSET $'+(params.length+1), [...params, (page.page - 1) * 25])).rows;
      const devices = [];
      for (const row of rows) {
        const current = await this.inventory.current(client, actorSource(source).tenant.id, row.id);
        if (current.row.assigned_user !== userId || current.link?.id !== row.assignment_id) fail(503, 'Coherent actual original assignment required');
        const open = (await client.query("SELECT id FROM device_return_requests WHERE assignment_id=$1 AND status='requested'", [row.assignment_id])).rows[0];
        if (open) await this.readTask(client, actorSource(source).tenant.id, open.id);
        devices.push({ deviceId: row.id, assetId: row.asset_id, serialNumber: row.serial_number, deviceRevision: row.revision, assignmentId: row.assignment_id, openRequestId: open?.id || null });
      }
      scope=await this.pin(client,source,rows.map(row=>row.id));return { ...negativeEnvelope(source), devices, total, page: page.page, limit: 25 };
    }, { readOnly: true }); await this.checkpoint(source, user, authorization);await this.verify(source,scope); return result;
  }
  async offboardingHistory(userId, query, user, authorization) {
    const page = offboardingReturnQuery(query); const source = await this.initial(user, authorization, page.workflowId, userId);
    let scope;
    const result = await this.database.transaction(async client => {
      await this.receiving(client);
      const values = [actorSource(source).tenant.id, page.workflowId, userId],where = 'tenant_id=$1 AND workflow_id=$2 AND user_id=$3'+await Scope.predicate(client,actorSource(source),'devices.inventory.read','device_return_requests.device_id',values)+await Scope.predicate(client,actorSource(source),'devices.inventory.assign','device_return_requests.device_id',values);
      const total = Number((await client.query('SELECT count(*) AS count FROM device_return_requests WHERE ' + where, values)).rows[0].count);
      const ids = (await client.query('SELECT id FROM device_return_requests WHERE ' + where + ' ORDER BY requested_at DESC,id DESC LIMIT 25 OFFSET $'+(values.length+1), [...values, (page.page - 1) * 25])).rows;
      const requests = []; for (const item of ids) requests.push(taskDto(await this.readTask(client, actorSource(source).tenant.id, item.id)));
      scope=await this.pin(client,source,requests.map(request=>request.deviceId));
      return { ...envelope(source), workflowId: page.workflowId, userId, target: { enabled: false, eligibilityRevision: source.target.eligibilityRevision }, requests, total, page: page.page, limit: 25 };
    }, { readOnly: true }); await this.checkpoint(source, user, authorization);await this.verify(source,scope); return result;
  }
  async captured(client, source, item, reason, lock = false, user, authorization) {
    const tenantId = actorSource(source).tenant.id;
    if (lock) await client.query('SELECT id FROM devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE', [item.deviceId, tenantId]);
    await Scope.requireDevice(client, actorSource(source), 'devices.inventory.read', item.deviceId);
    await Scope.requireDevice(client, actorSource(source), 'devices.inventory.assign', item.deviceId);
    const current = await this.inventory.current(client, tenantId, item.deviceId);
    const bound = lock ? await this.bind(client, source, user, authorization, item.deviceId, String(current.row.inventory_revision)) : source;
    const existing = (await client.query('SELECT tenant_id,device_id FROM device_return_requests WHERE id=$1', [item.requestId])).rows[0];
    if (existing) {
      if (existing.tenant_id !== tenantId) fail(source.schemaVersion === 2 ? 404 : 409, 'Original device return intent changed');
      await Scope.requireDevice(client, actorSource(source), 'devices.inventory.read', existing.device_id);
      await Scope.requireDevice(client, actorSource(source), 'devices.inventory.assign', existing.device_id);
      const row = await this.readTask(client, tenantId, item.requestId, lock); const task = row.state;
      if (task.workflow_id !== source.parent.workflowId || task.user_id !== source.target.id || task.device_id !== item.deviceId || task.assignment_id !== item.assignmentId
        || task.device_revision !== item.deviceRevision || task.eligibility_revision !== source.target.eligibilityRevision || task.reason !== reason) fail(409, 'Original device return intent changed');
      return { previous: task.operation_id, source: bound };
    }
    if (current.row.inventory_revision !== item.deviceRevision || current.link?.id !== item.assignmentId || current.row.assigned_user !== source.target.id || current.link?.user_id !== source.target.id) fail(409, 'Captured device assignment changed');
    if ((await client.query("SELECT id FROM device_return_requests WHERE assignment_id=$1 AND status='requested'", [item.assignmentId])).rows.length) fail(409, 'Original assignment already has a return request');
    return { previous: null, source: bound };
  }
  async request(userId, body, user, authorization, correlationId) {
    const values = offboardingReturnValues(body); const source = await this.initial(user, authorization, values.workflowId, userId);
    if (values.eligibilityRevision !== source.target.eligibilityRevision) fail(409, 'Original negative eligibility changed');
    await this.database.transaction(async client => { await this.receiving(client); for (const item of values.items) await this.captured(client, source, item, values.reason); }, { readOnly: true });
    await this.checkpoint(source, user, authorization); const correlation = identifier(correlationId || this.newId()); const results = []; let stopped = false;
    for (const item of values.items) {
      if (stopped) { results.push({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: 'not_attempted', code: null, operationId: null }); continue; }
      try {
        let bound = source, pins;
        const receipt = await this.database.transaction(async client => {
          await this.receiving(client); await this.checkpoint(source, user, authorization);
          const captured = await this.captured(client, source, item, values.reason, true, user, authorization);
          bound = captured.source; pins = await this.pin(client, bound, [item.deviceId]);
          if (captured.previous) return { status: 'already_requested', operationId: captured.previous };
          const operationId = identifier(this.newId());
          const proof = { id: operationId, action: 'requested', requestId: item.requestId, correlationId: correlation, source: bound, item, reason: values.reason, eligibilityRevision: values.eligibilityRevision };
          await client.query('SELECT device_returns_change($1::jsonb)', [JSON.stringify(proof)]);
          const actual = await this.readTask(client, actorSource(source).tenant.id, item.requestId);
          if (actual.state.operation_id !== operationId) fail(503, 'Actual original return receipt unavailable');
          return { status: 'requested', operationId };
        }, { beforeCommit: () => this.checkpoint(bound, user, authorization) });
        await this.verify(bound, pins);
        results.push({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: receipt.status, code: 200, operationId: receipt.operationId });
      } catch (error) { stopped = true; results.push({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: 'unconfirmed', code: code(error), operationId: null }); }
    }
    return { ...envelope(source), workflowId: values.workflowId, userId, correlationId: correlation, results };
  }
  async decide(id, body, expected, user, authorization, correlationId) {
    identifier(id); const values = returnDecisionValues(body); const captured = validateDeviceReturnEtag(expected); if (captured.id !== id) fail(412, 'Return request changed');
    let source = await this.initial(user, authorization); const checkpoints = []; let pins;
    if(!actorSource(source).permissions.includes('devices.inventory.assign'))fail(403,'Device assignment management required');
    const result = await this.database.transaction(async client => {
      await this.receiving(client); const current = await this.visibleTask(client, source, id, true, true); const task = taskDto(current);
      source = await this.bind(client, source, user, authorization, task.deviceId, task.currentDeviceRevision);
      pins = await this.pin(client, source, [task.deviceId], true);
      await this.checkpoint(source, user, authorization);
      if (current.state.status !== 'requested') {
        const decision = (await client.query('SELECT proof FROM device_return_events WHERE id=$1', [task.closingOperationId])).rows[0]?.proof;
        if (current.state.status !== values.action || decision?.expected !== expected || decision.reason !== values.reason) fail(409, 'Original return decision differs');
        return { ...envelope(source,true), deviceReturnsProtocol: source.schemaVersion === 2 ? 2 : 1, request: task, outcome: 'already_' + values.action, operationId: task.closingOperationId };
      }
      if (task.status === 'assignment_changed') fail(409, 'Original assignment was released; no decision can affect its replacement');
      if (deviceReturnEtag(task) !== expected) fail(412, 'Device or return request changed; reload before retrying');
      const correlation = identifier(correlationId || this.newId()); let inventoryOperationId = null;
      if (values.action === 'returned') {
        const bound = { isAvailable: () => true, transaction: async (operation, options = {}) => {
          const result = await operation(client); if (options.beforeCommit) { checkpoints.push(options.beforeCommit); await options.beforeCommit(client); } return result;
        } };
        await new DeviceInventory(bound, { authority: this.inventory.authority, newId: this.newId }).assign(task.deviceId, { userId: null }, deviceEtag({ id: task.deviceId, revision: task.currentDeviceRevision }), user, authorization, correlation);
        const inventory = (await client.query("SELECT id FROM device_inventory_events WHERE transaction_id=txid_current() AND tenant_id=$1 AND device_id=$2 AND action='release' AND before_assignment->>'id'=$3", [actorSource(source).tenant.id, task.deviceId, task.assignmentId])).rows;
        if (inventory.length !== 1) fail(503, 'Actual original inventory release receipt unavailable'); inventoryOperationId = inventory[0].id;
      }
      const operationId = identifier(this.newId());
      await client.query('SELECT device_returns_change($1::jsonb)', [JSON.stringify({ id: operationId, action: values.action, requestId: id, correlationId: correlation, source, reason: values.reason, expected, inventoryOperationId })]);
      const actual = taskDto(await this.readTask(client, actorSource(source).tenant.id, id));
      if (actual.closingOperationId !== operationId) fail(503, 'Actual return decision receipt unavailable');
      return { ...envelope(source,true), deviceReturnsProtocol: source.schemaVersion === 2 ? 2 : 1, request: actual, outcome: values.action, operationId };
    }, { beforeCommit: async client => { for (const checkpoint of checkpoints) await checkpoint(client); await this.checkpoint(source, user, authorization); } });
    await this.verify(source, pins); return result;
  }
}

module.exports = { DeviceReturns };
