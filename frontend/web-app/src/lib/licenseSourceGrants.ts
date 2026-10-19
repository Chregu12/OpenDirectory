import{api}from'./api';
export interface LicenseSourceClient{schemaVersion:1;clientId:string;revision:string;enabled:boolean;canReadGroupSources:boolean}
export interface LicenseSourceGrant{id:string;groupId:string;issuer:string;clientId:string;clientRevision:string;version:string;createdBy:string;createdAt:string;expiresAt:string;revokedAt:string|null;state:'configured'|'expired'|'revoked'}
const root='/api/identity/license-sources';const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;const CLIENT=/^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,255}$/;
const fail=():never=>{throw new Error('Keine bestätigte Service-Lesefreigabe. Neu laden, nicht blind wiederholen.');};
const revision=(value:unknown)=>typeof value==='string'&&/^[1-9]\d{0,18}$/.test(value)&&BigInt(value)<=BigInt('9223372036854775807');
const date=(value:unknown)=>typeof value==='string'&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
const tag=(row:LicenseSourceGrant)=>`"od-group-source:${row.id}:${row.version}"`;
function parse(value:unknown):LicenseSourceGrant{if(!value||typeof value!=='object'||Array.isArray(value))return fail();const row=value as LicenseSourceGrant;
 if(Object.keys(row).length!==11||!UUID.test(row.id)||!UUID.test(row.groupId)||!UUID.test(row.createdBy)||typeof row.issuer!=='string'||!row.issuer||row.issuer.length>2048||/\s/.test(row.issuer)||!CLIENT.test(row.clientId)||!revision(row.version)||!revision(row.clientRevision)||!date(row.createdAt)||!date(row.expiresAt)||Date.parse(row.expiresAt)<=Date.parse(row.createdAt)||Date.parse(row.expiresAt)-Date.parse(row.createdAt)>2592000000
  ||!['configured','expired','revoked'].includes(row.state)||(row.revokedAt===null?row.state==='revoked':!date(row.revokedAt)||row.state!=='revoked'||Date.parse(row.revokedAt)<Date.parse(row.createdAt)))return fail();return row;
}
export const licenseSourceGrants={
 async client(clientId:string):Promise<LicenseSourceClient>{if(!CLIENT.test(clientId))return fail();const result=await api.get(`${root}/clients/${encodeURIComponent(clientId)}`);const row=result.data as LicenseSourceClient;
  if(result.status!==200||!row||typeof row!=='object'||Object.keys(row).length!==5||row.schemaVersion!==1||row.clientId!==clientId||!revision(row.revision)||typeof row.enabled!=='boolean'||typeof row.canReadGroupSources!=='boolean'||row.canReadGroupSources&&!row.enabled)return fail();return row;},
 async list(groupId:string){if(!UUID.test(groupId))return fail();const result=await api.get(`${root}/groups/${groupId}`);const body=result.data;
  if(result.status!==200||!body||Object.keys(body).length!==3||body.groupId!==groupId||typeof body.truncated!=='boolean'||!Array.isArray(body.grants)||body.grants.length>100)return fail();const grants:LicenseSourceGrant[]=body.grants.map(parse);if(grants.some(row=>row.groupId!==groupId)||new Set(grants.map(row=>row.id)).size!==grants.length)return fail();return{groupId,grants,truncated:body.truncated};},
 async get(id:string){if(!UUID.test(id))return fail();const result=await api.get(`${root}/${id}`);const row=parse(result.data);if(result.status!==200||row.id!==id||result.headers?.etag!==tag(row))return fail();return row;},
 async create(body:{groupId:string;clientId:string;expiresAt:string;reason:string;acknowledgeReadScope:true},client:LicenseSourceClient,userId:string){
  if(!UUID.test(body.groupId)||!UUID.test(userId)||!CLIENT.test(body.clientId)||body.clientId!==client.clientId||!client.enabled||!client.canReadGroupSources||!date(body.expiresAt))return fail();const result=await api.post(root,{...body,expectedClientRevision:client.revision});const row=parse(result.data);
  if(result.status!==201||result.headers?.etag!==tag(row)||row.groupId!==body.groupId||row.clientId!==body.clientId||row.clientRevision!==client.revision||row.createdBy!==userId||row.expiresAt!==body.expiresAt||row.version!=='1'||row.state!=='configured'||row.revokedAt!==null)return fail();return row;},
 async revoke(current:LicenseSourceGrant,reason:string){const result=await api.post(`${root}/${current.id}/revoke`,{reason,acknowledgeReadScope:true},{headers:{'If-Match':tag(current)}});const row=parse(result.data);
  if(result.status!==200||result.headers?.etag!==tag(row)||row.id!==current.id||row.groupId!==current.groupId||row.issuer!==current.issuer||row.clientId!==current.clientId||row.clientRevision!==current.clientRevision||row.createdBy!==current.createdBy||row.createdAt!==current.createdAt||row.expiresAt!==current.expiresAt||BigInt(row.version)!==BigInt(current.version)+BigInt(1)||row.state!=='revoked'||row.revokedAt===null)return fail();return row;},
};
