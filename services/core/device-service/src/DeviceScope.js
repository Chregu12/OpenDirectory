'use strict';

const C = require('../../../../packages/device-scope-contract');
const { isDeepStrictEqual } = require('node:util');
function fail(status,message) { throw Object.assign(new Error(message),{status}); }
function limited(source,permission) {
  if (!source.permissions.includes(permission)) fail(403,'Device scope permission required');
  if (source.schemaVersion === 1 && !Object.hasOwn(source,'scope')) return false;
  if (source.schemaVersion !== 2 || source.scope?.protocol !== 1) fail(503,'Versioned device scope receiver required');
  return !C.permits(source,permission,null);
}
async function receiving(client) { try { await client.query('SELECT device_ou_receiving()'); } catch(cause) { throw Object.assign(new Error('Device scope assignment receiver unavailable'),{status:503,cause}); } }
async function predicate(client,source,permission,column,params) {
  if (!limited(source,permission)) return '';
  if (!['devices.id','unit.id','task.device_id','device_return_requests.device_id'].includes(column) || params[0] !== source.tenant.id) fail(503,'Original device scope query binding required');
  await receiving(client);
  const units = source.scope.units.filter(unit => C.permits(source,permission,unit)).map(unit => ({id:unit.id,generation:unit.generation}));
  params.push(JSON.stringify(units));
  return ` AND EXISTS (SELECT 1 FROM device_ou_assignments scoped_ou JOIN jsonb_to_recordset($${params.length}::jsonb) AS permitted(id text,generation text)
    ON scoped_ou.ou->>'id'=permitted.id AND scoped_ou.ou->>'generation'=permitted.generation
    WHERE scoped_ou.device_id=${column} AND scoped_ou.tenant_id=$1)`;
}
async function requireDevice(client,source,permission,id) {
  const params=[source.tenant.id,id],where=await predicate(client,source,permission,'devices.id',params);
  if (where && !(await client.query('SELECT id FROM devices WHERE tenant_id=$1 AND id=$2'+where,params)).rows.length) fail(404,'Device not found');
}
async function pin(client,source,permission,ids) {
  if (!limited(source,permission)) return null;
  const selected=[...new Set(ids)].sort();
  if (selected.length > 5000) fail(503,'Bounded device scope result required');
  await receiving(client);
  const rows=(await client.query(`SELECT unit.id,assignment.revision::text AS revision,assignment.ou FROM devices unit
    JOIN device_ou_assignments assignment ON assignment.device_id=unit.id AND assignment.tenant_id=unit.tenant_id
    WHERE unit.tenant_id=$1 AND unit.id=ANY($2::text[]) ORDER BY unit.id`,[source.tenant.id,selected])).rows;
  if (rows.length !== selected.length || rows.some(row => !row.ou || !C.permits(source,permission,row.ou))) fail(412,'Original device scope association changed');
  return rows;
}
async function verify(database,source,permission,original) {
  if (original === null) return;
  const current=await database.transaction(client=>pin(client,source,permission,original.map(row=>row.id)),{readOnly:true});
  if (!isDeepStrictEqual(current,original)) fail(412,'Original device scope association changed');
  if (source.validUntil*1000 <= Date.now()) fail(401,'Original device scope expired');
}
async function bind(client,inventory,source,permission,user,authorization,id,revision,recipient=null) {
  if (source.schemaVersion === 1 || !limited(source,permission) && !limited(source,'devices.inventory.read')) return source;
  await requireDevice(client,source,'devices.inventory.read',id);
  await requireDevice(client,source,permission,id);
  await receiving(client);
  const assignment=(await client.query('SELECT revision::text,ou FROM device_ou_assignments WHERE device_id=$1 AND tenant_id=$2 FOR SHARE',[id,source.tenant.id])).rows[0];
  const selected={deviceId:id,deviceRevision:revision,revision:assignment?.revision || '0',ou:assignment?.ou?{id:assignment.ou.id,generation:assignment.ou.generation}:null};
  const current=await inventory.authority.read(authorization,user,recipient,selected);
  if(!isDeepStrictEqual(current,{...source,scope:{...source.scope,resource:selected}}))fail(401,'Original device write scope changed');
  return current;
}
module.exports = { limited,predicate,requireDevice,pin,verify,bind };
