'use strict';

const { randomUUID } = require('node:crypto');
const { validUuid } = require('../../../../packages/identity-authorization-contract');
const { validateDeviceValues, validateDeviceAssignment, validateDeviceEtag, deviceEtag } = require('../../../../packages/device-inventory-contract');
const { InventoryAuthority } = require('./InventoryAuthority');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function identifier(value) { if (!validUuid(value)) fail(400, 'Canonical inventory device UUID required'); return value.toLowerCase(); }
function pageQuery(query = {}, searchAllowed = false) {
  if (Object.keys(query).some(key => !['page','limit',...(searchAllowed ? ['search'] : [])].includes(key))) fail(400, 'Invalid inventory selectors');
  const number = (value, fallback, maximum) => { if (value === undefined) return fallback; if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value) || Number(value)>maximum) fail(400, 'Invalid inventory page'); return Number(value); };
  if (query.search !== undefined && (typeof query.search !== 'string' || query.search.length>255 || /[\u0000-\u001f\u007f]/.test(query.search))) fail(400, 'Invalid inventory search');
  return { page: number(query.page,1,1000000),limit:number(query.limit,25,100),search:query.search?.trim() || '' };
}
function iso(value) { return value instanceof Date ? value.toISOString() : value; }
function summary(state, assignment) { return { assignedUserId: state?.assigned_user || null, assignmentId: assignment?.id || null, revision: String(state.inventory_revision) }; }
function device(row, link) {
  if (!validUuid(row.id) || !validUuid(row.tenant_id) || (row.assigned_user === null) !== !link || link && (link.user_id !== row.assigned_user || link.tenant_id !== row.tenant_id || link.device_id !== row.id)
    || row.inventory_lifecycle !== (link ? 'assigned' : 'available') || row.status !== 'inventory-only' || row.compliance_status !== 'unknown' || row.last_seen !== null || row.enrolled_at !== null || row.is_compliant !== null) fail(503, 'Coherent inventory state unavailable');
  return { id:row.id,tenantId:row.tenant_id,assetId:row.asset_id,serialNumber:row.serial_number,manufacturer:row.manufacturer,model:row.model,deviceClass:row.device_class,platform:row.platform,osVersion:row.os_version,
    ownership:row.ownership,purchaseDate:row.purchase_date || '',warrantyEnd:row.warranty_end || '',description:row.description,revision:String(row.inventory_revision),lifecycle:row.inventory_lifecycle,
    managementMode:'inventory-only',enrollmentStatus:'not-enrolled',managementProvider:null,complianceStatus:'unknown',lastSeen:null,assignedUserId:row.assigned_user,assignmentId:link?.id || null,createdAt:iso(row.inventory_created_at),updatedAt:iso(row.inventory_updated_at) };
}
class DeviceInventory {
  constructor(database, { authority = new InventoryAuthority(), newId = randomUUID } = {}) { this.database=database;this.authority=authority;this.newId=newId; }
  async authorized(user, authorization, permission, target = null) {
    if (!this.database.isAvailable()) fail(503,'Persistent inventory storage required');
    const source=await this.authority.read(authorization,user,target);if(!source.permissions.includes(permission))fail(403,'Inventory permission required');return source;
  }
  async current(client, tenantId, id, lock = false) {
    const row=(await client.query("SELECT device_inventory_row(unit) AS state FROM devices unit WHERE id=$1 AND tenant_id=$2"+(lock?' FOR UPDATE':''),[id,tenantId])).rows[0]?.state;
    if(!row)fail(404,'Device not found');const links=(await client.query('SELECT to_jsonb(link) AS state FROM device_inventory_assignments link WHERE device_id=$1 AND released_at IS NULL',[id])).rows;
    if(links.length>1)fail(503,'Exclusive inventory assignment unavailable');return{row,link:links[0]?.state || null};
  }
  async receiving(client) { try { await client.query('SELECT device_inventory_receiving()'); } catch(error) { throw Object.assign(new Error('Inventory receiver unavailable'),{status:503,cause:error}); } }
  async checkpoint(source,user,authorization,target=null) {
    if(JSON.stringify(source)!==JSON.stringify(await this.authority.read(authorization,user,target)))fail(401,'Original inventory authority changed');
  }
  async capabilities(user, authorization) {
    const source=await this.authorized(user,authorization,'devices.inventory.read');await this.database.transaction(client=>this.receiving(client),{readOnly:true});await this.checkpoint(source,user,authorization);
    return{schemaVersion:1,inventoryProtocol:1,userId:source.actorUserId,tenantId:source.tenant.id,permissions:source.permissions,managementMode:'inventory-only',supportedActions:[]};
  }
  async list(query,user,authorization) {
    const page=pageQuery(query,true);const source=await this.authorized(user,authorization,'devices.inventory.read');
    const result=await this.database.transaction(async client=>{
      await this.receiving(client);const where="tenant_id=$1 AND ($2='' OR strpos(lower(concat_ws(' ',asset_id,serial_number,manufacturer,model)),lower($2))>0)";
      const total=Number((await client.query('SELECT count(*) AS count FROM devices WHERE '+where,[source.tenant.id,page.search])).rows[0].count);
      const rows=(await client.query('SELECT id FROM devices WHERE '+where+' ORDER BY inventory_created_at,id LIMIT $3 OFFSET $4',[source.tenant.id,page.search,page.limit,(page.page-1)*page.limit])).rows;
      const devices=[];for(const row of rows){const current=await this.current(client,source.tenant.id,row.id);devices.push(device(current.row,current.link));}
      return{schemaVersion:1,actorUserId:source.actorUserId,devices,total,page:page.page,limit:page.limit};
    },{readOnly:true});await this.checkpoint(source,user,authorization);return result;
  }
  async get(id,user,authorization) {
    const target=identifier(id);const source=await this.authorized(user,authorization,'devices.inventory.read');
    const result=await this.database.transaction(async client=>{await this.receiving(client);const current=await this.current(client,source.tenant.id,target);return device(current.row,current.link);},{readOnly:true});
    await this.checkpoint(source,user,authorization);return result;
  }
  async create(body,user,authorization,correlationId) { return this.change('create',null,validateDeviceValues(body),null,user,authorization,correlationId); }
  async assign(id,body,expected,user,authorization,correlationId) {
    const target=identifier(id);const values=validateDeviceAssignment(body);validateDeviceEtag(expected);return this.change(values.userId?'assign':'release',target,values,expected,user,authorization,correlationId);
  }
  async change(action,id,values,expected,user,authorization,correlationId) {
    const recipient=action==='assign'?values.userId:null;const source=await this.authorized(user,authorization,action==='create'?'devices.inventory.create':'devices.inventory.assign',recipient);
    const deviceId=id || this.newId();identifier(deviceId);const operationId=this.newId();identifier(operationId);const correlation=validUuid(correlationId)?correlationId.toLowerCase():this.newId();
    return this.database.transaction(async client=>{
      await this.receiving(client);let before=null;
      if(action!=='create'){
        const current=await this.current(client,source.tenant.id,deviceId,true);before=current.row;const actual=device(before,current.link);
        if(deviceEtag(actual)!==expected)fail(412,'Device changed; reload before retrying');if(actual.assignedUserId===(recipient || null))fail(409,'Assignment already has that recipient');
      }
      await this.checkpoint(source,user,authorization,recipient);
      const proof={id:operationId,deviceId,correlationId:correlation,action,source,before,values,assignmentId:action==='assign'?this.newId():null};
      await client.query('SELECT device_inventory_change($1::jsonb)',[JSON.stringify(proof)]);
      const receipt=(await client.query("SELECT event.id FROM device_inventory_events event JOIN device_inventory_outbox outbox USING(id) WHERE event.id=$1 AND event.tenant_id=$2 AND event.proof=$3::jsonb AND event.transaction_id=txid_current() AND outbox.tenant_id=event.tenant_id AND outbox.status='pending'",[operationId,source.tenant.id,JSON.stringify(proof)])).rows;
      if(receipt.length!==1)fail(503,'Actual committed inventory receipt unavailable');const actual=await this.current(client,source.tenant.id,deviceId);
      return device(actual.row,actual.link);
    },{beforeCommit:()=>this.checkpoint(source,user,authorization,recipient)});
  }
  async history(id,query,user,authorization) {
    const target=identifier(id);const page=pageQuery(query);const source=await this.authorized(user,authorization,'devices.inventory.read');
    const result=await this.database.transaction(async client=>{
      await this.receiving(client);await this.current(client,source.tenant.id,target);
      const total=Number((await client.query('SELECT count(*) AS count FROM device_inventory_events WHERE tenant_id=$1 AND device_id=$2',[source.tenant.id,target])).rows[0].count);
      const rows=(await client.query("SELECT event.*,outbox.status AS delivery_status FROM device_inventory_events event LEFT JOIN device_inventory_outbox outbox ON outbox.id=event.id AND outbox.tenant_id=event.tenant_id WHERE event.tenant_id=$1 AND event.device_id=$2 ORDER BY event.created_at DESC,event.id DESC LIMIT $3 OFFSET $4",[source.tenant.id,target,page.limit,(page.page-1)*page.limit])).rows;
      if(rows.some(row=>row.delivery_status!=='pending'))fail(503,'Retained inventory history evidence unavailable');
      return{schemaVersion:1,actorUserId:source.actorUserId,deviceId:target,total,page:page.page,limit:page.limit,events:rows.map(row=>({id:row.id,tenantId:row.tenant_id,deviceId:row.device_id,type:row.type,version:row.version,actorUserId:row.actor_user_id,correlationId:row.correlation_id,createdAt:iso(row.created_at),before:row.before_state?summary(row.before_state,row.before_assignment):null,after:summary(row.after_state,row.after_assignment),deliveryStatus:row.delivery_status}))};
    },{readOnly:true});await this.checkpoint(source,user,authorization);return result;
  }
}
module.exports={DeviceInventory,pageQuery};
