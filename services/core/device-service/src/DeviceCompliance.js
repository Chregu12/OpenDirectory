'use strict';
const Scope = require('./DeviceScope');
const { randomUUID } = require('node:crypto');
const C = require('../../../../packages/device-compliance-contract');
const { validUuid } = require('../../../../packages/identity-authorization-contract');
const { InventoryAuthority } = require('./InventoryAuthority');
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const iso = value => value ? new Date(value).toISOString() : null;
function platform(value) { if (!C.PLATFORMS.includes(value)) fail(400, 'Exact compliance platform required'); return value; }
function page(query, allowed = []) {
 if (Object.keys(query).some(key => !['page', ...allowed].includes(key)) || query.page !== undefined && (typeof query.page !== 'string' || !/^[1-9][0-9]*$/.test(query.page) || Number(query.page) > 1000000)) fail(400, 'Exact compliance selectors required');
 return Number(query.page || 1);
}
function etag(tenantId, name, revision) { return `"device-compliance-${tenantId}-${name}-${revision}"`; }
function policy(row, tenantId, name) { return { tenantId, platform: name, revision: String(row?.revision || '0'), settings: row?.settings || { ...C.DEFAULTS }, createdAt: iso(row?.created_at), updatedAt: iso(row?.updated_at) }; }
class DeviceCompliance {
 constructor(database, { inventory, authority = new InventoryAuthority({ compliance: true, scoped: inventory?.authority?.scoped === true, ...(inventory?.authority?.endpoint ? { endpoint: new URL('/api/identity/device-compliance', inventory.authority.endpoint).href } : {}) }) } = {}) {
  this.database = database; this.inventory = inventory; this.authority = authority;
 }
 async source(user, authorization, manage = false) {
  if (!this.database.isAvailable()) fail(503, 'Persistent compliance storage required');
  const result = await this.authority.read(authorization, user);
  if (!result.permissions.includes(C.PERMISSIONS[manage ? 1 : 0])) fail(403, 'Actual compliance duty required'); return result;
 }
 async checkpoint(source, user, authorization) { if (JSON.stringify(await this.authority.read(authorization, user)) !== JSON.stringify(source)) fail(401, 'Original compliance authority changed'); }
 async receiving(client) { await client.query('SELECT device_compliance_receiving()'); }
 async capabilities(user, authorization) {
  const source = await this.source(user, authorization); await this.database.transaction(client => this.receiving(client), { readOnly: true }); await this.checkpoint(source, user, authorization);
  return { schemaVersion: 1, complianceProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, permissions: source.permissions };
 }
 async policyRow(client, tenant, name) { return (await client.query('SELECT * FROM device_compliance_policies WHERE tenant_id=$1 AND platform=$2', [tenant, name])).rows[0]; }
 async policies(query, user, authorization) {
  if (Object.keys(query).length) fail(400, 'No policy selectors'); const source = await this.source(user, authorization);
  if(Scope.limited(source,'devices.compliance.read'))fail(403,'Tenant compliance policy read required');
  const result = await this.database.transaction(async client => { await this.receiving(client); const rows = (await client.query('SELECT * FROM device_compliance_policies WHERE tenant_id=$1', [source.tenant.id])).rows;
   return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, permissions: source.permissions, policies: C.PLATFORMS.map(name => policy(rows.find(row => row.platform === name), source.tenant.id, name)) };
  }, { readOnly: true }); await this.checkpoint(source, user, authorization); return result;
 }
 async save(name, input, expected, user, authorization, correlationId) {
  platform(name); const values = C.change(input); const source = await this.source(user, authorization, true);
  if (!expected) fail(428, 'Current compliance policy revision required');
  const match = typeof expected === 'string' && expected.match(/^"device-compliance-([a-f0-9-]{36})-(macos|windows|linux)-(0|[1-9][0-9]{0,18})"$/);
  if (!match || match[0] !== expected || match[1] !== source.tenant.id || match[2] !== name || BigInt(match[3]).toString() !== match[3] || BigInt(match[3]) > 9223372036854775807n) fail(400, 'Exact own policy revision required');
  return this.database.transaction(async client => {
   await this.receiving(client); await client.query("SELECT pg_advisory_xact_lock(hashtextextended('device-compliance:'||$1||':'||$2,0))", [source.tenant.id, name]);
   const previous = await this.policyRow(client, source.tenant.id, name);
   if (String(previous?.revision || '0') !== match[3]) fail(412, 'Compliance policy changed; reload');
   if (previous && JSON.stringify(previous.settings) === JSON.stringify(values.settings)) fail(409, 'No compliance policy changes');
   await this.checkpoint(source, user, authorization);
   const eventId = randomUUID(); await client.query('SELECT device_compliance_policy_change($1::jsonb)', [JSON.stringify({ source, platform: name, expectedRevision: match[3], settings: values.settings, reason: values.reason, eventId, correlationId: validUuid(correlationId) ? correlationId : randomUUID() })]);
   const receipt = (await client.query("SELECT event.after_state FROM device_compliance_policy_events event JOIN device_compliance_policy_outbox outbox USING(id) WHERE event.id=$1 AND event.tenant_id=$2 AND event.source=$3::jsonb AND outbox.status='pending' AND outbox.tenant_id=event.tenant_id", [eventId, source.tenant.id, JSON.stringify(source)])).rows;
   const actual = await this.policyRow(client, source.tenant.id, name);
   if (receipt.length !== 1 || JSON.stringify(receipt[0].after_state.settings) !== JSON.stringify(actual?.settings) || String(actual.revision) !== (BigInt(match[3]) + 1n).toString()) fail(503, 'Actual policy receipt unavailable');
   return { schemaVersion: 1, actorUserId: source.actorUserId, policy: policy(actual, source.tenant.id, name), eventId, deliveryStatus: 'pending' };
  }, { beforeCommit: () => this.checkpoint(source, user, authorization) });
 }
 async current(client, source, id) {
  if (!validUuid(id)) fail(400, 'Canonical compliance device required');
  await Scope.requireDevice(client,source,'devices.compliance.read',id);
  const unit = await this.inventory.current(client, source.tenant.id, id);
  return unit.row;
 }
 async get(id, query, user, authorization) {
  if (Object.keys(query).length) fail(400, 'No assessment selectors'); const source = await this.source(user, authorization);
  let scope;
  const result = await this.database.transaction(async client => {
   await this.receiving(client); const unit = await this.current(client, source, id); const checkedAt = iso((await client.query('SELECT clock_timestamp() AS moment')).rows[0].moment);
   const read = (await client.query('SELECT device_compliance_current($1,$2,connection,$4::timestamptz) AS report FROM (SELECT 1) seed LEFT JOIN device_agent_connections connection ON connection.device_id=$3 AND connection.tenant_id=$1', [source.tenant.id, unit.platform, id, checkedAt])).rows[0].report;
   scope=await Scope.pin(client,source,'devices.compliance.read',[id]);return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, deviceId: id, assetId: unit.asset_id, platform: unit.platform, checkedAt, ...read };
  }, { readOnly: true }); await this.checkpoint(source, user, authorization);await Scope.verify(this.database,source,'devices.compliance.read',scope); return result;
 }
 async list(query, user, authorization) {
  const number = page(query, ['platform', 'status', 'search']);
  if (query.platform !== undefined) platform(query.platform);
  if (query.status !== undefined && !C.STATES.includes(query.status) || query.search !== undefined && (typeof query.search !== 'string' || query.search.length > 200 || /[\u0000-\u001f\u007f-\u009f]/u.test(query.search))) fail(400, 'Invalid compliance filter');
  const source = await this.source(user, authorization);
  let scope;
  const result = await this.database.transaction(async client => {
   await this.receiving(client); const checkedAt = iso((await client.query('SELECT clock_timestamp() AS moment')).rows[0].moment);
   const params = [source.tenant.id, query.platform || null, query.search?.trim() || '', checkedAt];
   const where=await Scope.predicate(client,source,'devices.compliance.read','unit.id',params);
   const base = `WITH fleet AS (SELECT unit.id AS device_id,unit.asset_id,unit.platform,device_compliance_current(unit.tenant_id,unit.platform,connection,$4::timestamptz) AS report FROM devices unit LEFT JOIN device_agent_connections connection ON connection.device_id=unit.id AND connection.tenant_id=unit.tenant_id WHERE unit.tenant_id=$1 AND ($2::text IS NULL OR unit.platform=$2) AND ($3='' OR strpos(lower(concat_ws(' ',unit.asset_id,unit.serial_number,unit.model,connection.hostname)),lower($3))>0)${where}) `;
   const counts = Object.fromEntries(C.STATES.map(status => [status, 0])); for (const row of (await client.query(base + "SELECT report->>'status' AS status,count(*) AS count FROM fleet GROUP BY report->>'status'", params)).rows) counts[row.status] = Number(row.count);
   const totalAll = Object.values(counts).reduce((sum, count) => sum + count, 0);
   const statusParameter='$'+(params.length+1),offsetParameter='$'+(params.length+2);
   const rows = (await client.query(base + `SELECT * FROM fleet WHERE (${statusParameter}::text IS NULL OR report->>'status'=${statusParameter}) ORDER BY lower(asset_id),device_id LIMIT 25 OFFSET ${offsetParameter}`, [...params, query.status || null, (number - 1) * 25])).rows;
   scope=await Scope.pin(client,source,'devices.compliance.read',rows.map(row=>row.device_id));
   return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, checkedAt, page: number, limit: 25, total: query.status ? counts[query.status] : totalAll, counts: { total: totalAll, ...counts }, devices: rows.map(row => ({ deviceId: row.device_id, assetId: row.asset_id, platform: row.platform, status: row.report.status, policyRevision: row.report.policyRevision, evaluatedAt: row.report.assessment?.evaluatedAt || null })) };
  }, { readOnly: true }); await this.checkpoint(source, user, authorization);await Scope.verify(this.database,source,'devices.compliance.read',scope); return result;
 }
 async history(id, query, user, authorization, policyHistory = false) {
  const number = page(query); if (policyHistory) platform(id); else if (!validUuid(id)) fail(400, 'Canonical device required'); const source = await this.source(user, authorization);
  if(policyHistory&&Scope.limited(source,'devices.compliance.read'))fail(403,'Tenant compliance policy read required');let scope=null;
  const result = await this.database.transaction(async client => {
   await this.receiving(client); if (!policyHistory){await this.current(client, source, id);scope=await Scope.pin(client,source,'devices.compliance.read',[id]);}
   const table = policyHistory ? 'device_compliance_policy_events' : 'device_compliance_events'; const key = policyHistory ? 'platform' : 'device_id';
   const total = Number((await client.query(`SELECT count(*) AS count FROM ${table} WHERE tenant_id=$1 AND ${key}=$2`, [source.tenant.id, id])).rows[0].count);
   const rows = (await client.query(`SELECT event.*${policyHistory ? ",outbox.status AS delivery_status,event.before_state->>'revision' AS before_revision,event.after_state->>'revision' AS after_revision" : ''} FROM ${table} event ${policyHistory ? 'LEFT JOIN device_compliance_policy_outbox outbox ON outbox.id=event.id AND outbox.tenant_id=event.tenant_id' : ''} WHERE event.tenant_id=$1 AND event.${key}=$2 ORDER BY event.created_at DESC,event.id DESC LIMIT 25 OFFSET $3`, [source.tenant.id, id, (number - 1) * 25])).rows;
   if (policyHistory && rows.some(row => row.delivery_status !== 'pending')) fail(503, 'Retained policy delivery evidence missing');
   return { schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, target: id, page: number, limit: 25, total, events: rows.map(row => ({ id: row.id, createdAt: iso(row.created_at), correlationId: row.correlation_id, before: policyHistory ? row.before_state && policy({ ...row.before_state, revision: row.before_revision }, source.tenant.id, id) : row.before_state, after: policyHistory ? policy({ ...row.after_state, revision: row.after_revision }, source.tenant.id, id) : row.after_state, ...(policyHistory ? { actorUserId: row.actor_user_id, reason: row.reason, deliveryStatus: row.delivery_status } : {}) })) };
  }, { readOnly: true }); await this.checkpoint(source, user, authorization);await Scope.verify(this.database,source,'devices.compliance.read',scope); return result;
 }
}
module.exports = { DeviceCompliance, compliancePolicyEtag: etag };
