import contract from '../../packages/company-app-contract.js';
import identity from '../../packages/identity-authorization-contract.js';
import tenancy from '../../packages/tenant-authorization-contract.js';
const base='/api/clients/company';
function checked(response,status=200,fields=['client']){const value=response.data;contract.exact(value,['schemaVersion','companyAppProtocol','actorUserId','tenant',...fields]);if(response.status!==status||value?.schemaVersion!==1||value.companyAppProtocol!==1||!identity.validUuid(value.actorUserId)||!tenancy.validTenantContext(value.tenant))throw new Error('Company app response unconfirmed');return value;}
function record(value,tenant){
 contract.exact(value,['clientId','name','enabled','version','purpose','tenant','createdAt','updatedAt','deletedAt']);
 if(!identity.validUuid(value.clientId)||!identity.validRevision(value.version)||value.tenant.id!==tenant||!tenancy.validTenantContext(value.tenant)||typeof value.enabled!=='boolean'||typeof value.name!=='string'||!value.name.trim()||!['none','company-automation'].includes(value.purpose)
  ||![value.createdAt,value.updatedAt].every(stamp=>typeof stamp==='string'&&Number.isFinite(Date.parse(stamp)))||value.deletedAt!==null&&(!Number.isFinite(Date.parse(value.deletedAt))||value.enabled))throw new Error('Original company app record unconfirmed');return value;
}
function id(value){return contract.identifier(value);}
function credential(value){if(typeof value!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(value))throw new Error('One-time company credential unconfirmed');}
export function createCompanyAppClient(client){
 const request=(method,path='',body,etag)=>client.request(method,base+path,body,{administrative:true,...(etag?{etag}:{})});
 const current=async identifier=>{const result=await request('GET','/'+id(identifier));const value=checked(result);record(value.client,value.tenant.id);if(value.client.clientId!==identifier||result.etag!==`"od-client:${identifier}:${value.client.version}"`)throw new Error('Original company app version unconfirmed');return{...value,etag:result.etag};};
 const mutate=async(identifier,reason,action,change={})=>{
  const before=await current(identifier);const row=before.client;const metadata=contract.metadata({name:row.name,enabled:row.enabled,purpose:row.purpose,...change,reason,confirm:true});
  const result=checked(await request(action==='updated'?'PUT':action==='deleted'?'DELETE':'POST','/'+identifier+(action==='rotated'?'/rotate-secret':''),action==='updated'?metadata:{reason:metadata.reason,confirm:true},before.etag),200,action==='rotated'?['client','clientSecret']:['client']);
  record(result.client,before.tenant.id);if(result.actorUserId!==before.actorUserId||result.client.clientId!==identifier||BigInt(result.client.version)!==BigInt(row.version)+1n)throw new Error('Changed company app generation unconfirmed');
  if(action==='updated'&&['name','enabled','purpose'].some(key=>result.client[key]!==metadata[key])||action==='deleted'&&(result.client.enabled||result.client.deletedAt===null))throw new Error('Company app transition unconfirmed');
  if(action==='rotated')credential(result.clientSecret);else if(result.clientSecret!==undefined)throw new Error('Unexpected company app credential');return result;
 };
 return{
  get:current,
  async list(page=1,status='active'){if(!['active','deleted'].includes(status))throw new Error('Supported company app status required');if(!Number.isSafeInteger(page)||page<1)throw new Error('Positive company app page required');const value=checked(await request('GET','?page='+page+'&status='+status),200,['page','status','hasMore','clients']);if(value.page!==page||value.status!==status||typeof value.hasMore!=='boolean'||!Array.isArray(value.clients)||value.clients.length>25)throw new Error('Complete company app page unconfirmed');value.clients.forEach(row=>{record(row,value.tenant.id);if((row.deletedAt!==null)!==(status==='deleted'))throw new Error('Original company app page status unconfirmed');});return value;},
  async create(requestId,name,reason,purpose='none'){const input=contract.metadata({requestId,name,purpose,reason,confirm:true},true);const value=checked(await request('POST','',input),201,['client','clientSecret','created']);record(value.client,value.tenant.id);
   if(value.client.clientId!==requestId||typeof value.created!=='boolean')throw new Error('Original company creation unconfirmed');
   if(value.created){credential(value.clientSecret);if(value.client.name!==input.name||value.client.purpose!==purpose||value.client.enabled||value.client.version!=='1')throw new Error('Disabled company app creation unconfirmed');}else if(value.clientSecret!==null)throw new Error('Replayed credentials must not be returned');return value;
  },
  update:(identifier,change,reason)=>mutate(identifier,reason,'updated',change),
  rotate:(identifier,reason)=>mutate(identifier,reason,'rotated'),
  remove:(identifier,reason)=>mutate(identifier,reason,'deleted'),
  async history(identifier,page=1){id(identifier);if(!Number.isSafeInteger(page)||page<1)throw new Error('Positive company app page required');const value=checked(await request('GET','/'+identifier+'/history?page='+page),200,['clientId','page','hasMore','events']);if(value.clientId!==identifier||value.page!==page||typeof value.hasMore!=='boolean'||!Array.isArray(value.events)||value.events.length>25||value.events.some(row=>!identity.validRevision(row.revision)||!identity.validUuid(row.actorUserId)||!['created','updated','rotated','deleted'].includes(row.action)||typeof row.reason!=='string'||row.reason.length<10||!Number.isFinite(Date.parse(row.createdAt))))throw new Error('Original company app history unconfirmed');return value;},
 };
}
