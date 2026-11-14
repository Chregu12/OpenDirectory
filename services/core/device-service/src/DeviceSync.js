'use strict';
const {randomUUID,randomBytes,createHash}=require('node:crypto');
const {validUuid}=require('../../../../packages/identity-authorization-contract');
const {DeviceInventory}=require('./DeviceInventory');
const fail=(status,message)=>{throw Object.assign(new Error(message),{status});};
const hash=value=>createHash('sha256').update(value).digest('hex');
const iso=value=>value?new Date(value).toISOString():null;
const id=value=>{if(!validUuid(value))fail(400,'Canonical sync identifier required');return value;};
function decision(input){if(!input||Array.isArray(input)||Object.keys(input).length!==2||input.confirm!==true||typeof input.reason!=='string'||/[\u0000-\u001f\u007f-\u009f]/u.test(input.reason)||[...input.reason.trim()].length<10||[...input.reason.trim()].length>500)fail(400,'Confirmed sync reason required');return input.reason.trim();}
function credential(value){if(typeof value!=='string'||!/^Bearer odad_[A-Za-z0-9_-]{43}$/.test(value))fail(401,'Current device credential required');return hash(value.slice(7));}
function syncProof(input){if(!input||Array.isArray(input)||Object.keys(input).length!==2||!validUuid(input.id)||typeof input.leaseToken!=='string'||!/^odsl_[A-Za-z0-9_-]{43}$/.test(input.leaseToken))fail(400,'Exact sync lease required');return {id:input.id,leaseHash:hash(input.leaseToken)};}
function job(row){return {id:row.id,deviceId:row.device_id,revision:String(row.revision),status:row.effective_status||row.status,attempts:row.attempts,actorUserId:row.actor_user_id,reason:row.reason,createdAt:iso(row.created_at),expiresAt:iso(row.expires_at),updatedAt:iso(row.updated_at),leaseExpiresAt:iso(row.lease_expires_at),completedAt:iso(row.completed_at),result:row.result};}
const requestEtag=row=>`"device-sync-${row.id}-${row.revision}"`;
const connectionEtag=(deviceId,generation)=>generation?`"device-sync-generation-${deviceId}-${generation}"`:null;
class DeviceSync {
 constructor(database,{inventory=new DeviceInventory(database),secret=()=>randomBytes(32).toString('base64url')}={}){this.database=database;this.inventory=inventory;this.secret=secret;}
 async receiving(client){await client.query('SELECT device_sync_receiving()');}
 async connection(client,deviceId,tenantId){return (await client.query('SELECT connection.*,device_sync_generation(connection) AS generation FROM device_agent_connections connection WHERE device_id=$1 AND tenant_id=$2',[deviceId,tenantId])).rows[0];}
 async list(deviceId,query,user,authorization){
  id(deviceId);if(Object.keys(query).some(key=>key!=='page')||query.page!==undefined&&(typeof query.page!=='string'||!/^[1-9][0-9]*$/.test(query.page)||Number(query.page)>1000000))fail(400,'Exact sync page required');
  const source=await this.inventory.authorized(user,authorization,'devices.inventory.read');const page=Number(query.page||1);
  const result=await this.database.transaction(async client=>{await this.receiving(client);await this.inventory.current(client,source.tenant.id,deviceId);const connection=await this.connection(client,deviceId,source.tenant.id);const checkedAt=iso((await client.query('SELECT clock_timestamp() AS moment')).rows[0].moment);
   const active=Boolean(connection?.credential_hash&&!connection.revoked_at&&new Date(connection.credential_expires_at).getTime()>Date.parse(checkedAt));
   const total=Number((await client.query('SELECT count(*) AS count FROM device_sync_requests WHERE device_id=$1 AND tenant_id=$2',[deviceId,source.tenant.id])).rows[0].count);
   const rows=(await client.query('SELECT request.*,device_sync_status(request,connection,$3::timestamptz) AS effective_status FROM device_sync_requests request LEFT JOIN device_agent_connections connection ON connection.device_id=request.device_id AND connection.tenant_id=request.tenant_id WHERE request.device_id=$1 AND request.tenant_id=$2 ORDER BY request.created_at DESC,request.id DESC LIMIT 10 OFFSET $4',[deviceId,source.tenant.id,checkedAt,(page-1)*10])).rows;
   return {schemaVersion:1,syncProtocol:1,actorUserId:source.actorUserId,tenantId:source.tenant.id,deviceId,checkedAt,connectionEtag:active?connectionEtag(deviceId,connection.generation):null,page,limit:10,total,requests:rows.map(job)};
  },{readOnly:true});await this.inventory.checkpoint(source,user,authorization);return result;
 }
 async write(deviceId,input,expected,user,authorization,correlationId,requestId=null){
  id(deviceId);if(requestId)id(requestId);const reason=decision(input);if(!expected)fail(428,'Current sync connection or request version required');
  const source=await this.inventory.authorized(user,authorization,'devices.inventory.create');
  return this.database.transaction(async client=>{await this.receiving(client);await this.inventory.current(client,source.tenant.id,deviceId,true);await client.query('SELECT device_id FROM device_agent_connections WHERE device_id=$1 FOR UPDATE',[deviceId]);
   let prior=null;
   if(requestId){prior=(await client.query('SELECT * FROM device_sync_requests WHERE id=$1 AND device_id=$2 AND tenant_id=$3 FOR UPDATE',[requestId,deviceId,source.tenant.id])).rows[0];if(!prior)fail(404,'Own sync request not found');if(expected!==requestEtag(prior))fail(412,'Sync request changed; reload');}
   const connection=await this.connection(client,deviceId,source.tenant.id);
   if(!requestId&&expected!==connectionEtag(deviceId,connection?.generation))fail(412,'Device registration changed; reload');
   await this.inventory.checkpoint(source,user,authorization);const request=requestId||randomUUID();
   await client.query('SELECT device_sync_change($1::jsonb)',[JSON.stringify({action:requestId?'cancelled':'queued',id:request,deviceId,generation:connection?.generation,expectedRevision:prior?.revision,reason,source,eventId:randomUUID(),correlationId:validUuid(correlationId)?correlationId:randomUUID()})]);
   const actual=(await client.query('SELECT * FROM device_sync_requests WHERE id=$1',[request])).rows[0];if(!actual||actual.status!==(requestId?'cancelled':'queued'))fail(503,'Actual sync receipt unavailable');
   return {schemaVersion:1,syncProtocol:1,actorUserId:source.actorUserId,tenantId:source.tenant.id,request:job(actual)};
  },{beforeCommit:()=>this.inventory.checkpoint(source,user,authorization)});
 }
 async history(deviceId,requestId,query,user,authorization){
  id(deviceId);id(requestId);if(Object.keys(query).length)fail(400,'No sync history selectors');const source=await this.inventory.authorized(user,authorization,'devices.inventory.read');
  const result=await this.database.transaction(async client=>{await this.receiving(client);await this.inventory.current(client,source.tenant.id,deviceId);if(!(await client.query('SELECT id FROM device_sync_requests WHERE id=$1 AND device_id=$2 AND tenant_id=$3',[requestId,deviceId,source.tenant.id])).rows.length)fail(404,'Own sync request not found');
   const rows=(await client.query('SELECT id,action,actor_user_id,reason,correlation_id,created_at FROM device_sync_events WHERE request_id=$1 AND device_id=$2 AND tenant_id=$3 ORDER BY created_at,id',[requestId,deviceId,source.tenant.id])).rows;if(rows.length>6)fail(503,'Sync transition history unavailable');
   return {schemaVersion:1,syncProtocol:1,actorUserId:source.actorUserId,tenantId:source.tenant.id,deviceId,requestId,events:rows.map(row=>({id:row.id,action:row.action,actorUserId:row.actor_user_id,reason:row.reason,correlationId:row.correlation_id,createdAt:iso(row.created_at)}))};
  },{readOnly:true});await this.inventory.checkpoint(source,user,authorization);return result;
 }
 async claim(input,authorization,correlationId){
  if(!input||Array.isArray(input)||Object.keys(input).length!==1)fail(400,'Exact sync device required');id(input.deviceId);const tokenHash=credential(authorization);const token='odsl_'+this.secret();
  return this.database.transaction(async client=>{await this.receiving(client);const requestId=(await client.query('SELECT device_sync_change($1::jsonb) AS id',[JSON.stringify({action:'claimed',deviceId:input.deviceId,tokenHash,leaseHash:hash(token),eventId:randomUUID(),correlationId:validUuid(correlationId)?correlationId:randomUUID()})])).rows[0].id;
   const row=requestId?(await client.query('SELECT id,lease_expires_at FROM device_sync_requests WHERE id=$1',[requestId])).rows[0]:null;
   return {schemaVersion:1,syncProtocol:1,deviceId:input.deviceId,command:row?{id:row.id,type:'inventory.refresh',leaseToken:token,expiresAt:iso(row.lease_expires_at)}:null};
  });
 }
 async complete(client,deviceId,proof,authorization,correlationId){const tokenHash=credential(authorization);await client.query('SELECT device_sync_change($1::jsonb)',[JSON.stringify({action:'completed',deviceId,...proof,tokenHash,eventId:randomUUID(),correlationId:validUuid(correlationId)?correlationId:randomUUID()})]);}
}
module.exports={DeviceSync,syncProof,syncRequestEtag:requestEtag};
