'use strict';
const {isDeepStrictEqual}=require('node:util');const {randomBytes}=require('node:crypto');
const contract=require('../../../../packages/company-app-contract');
const {validRevision}=require('../../../../packages/identity-authorization-contract');
const {etag}=require('./ClientRegistry');const {hashSecret}=require('./clientSecrets');
const view=row=>({clientId:row.clientId,name:row.name,enabled:row.enabled,version:row.version,purpose:row.scopes.length?'company-automation':'none',tenant:row.companyTenant,createdAt:row.createdAt,updatedAt:row.updatedAt,deletedAt:row.deletedAt});
const pageNumber=value=>{if(value===undefined)return 1;if(!/^[1-9][0-9]{0,5}$/.test(String(value)))contract.fail(400,'positive_company_app_page_required');return Number(value);};
class CompanyApps{
 constructor(registry,{endpoint=new URL(contract.SOURCE_PATH,process.env.OAUTH_IDENTITY_AUTHORITY_URL||'http://identity-service:3001'),fetchImpl=(...args)=>fetch(...args)}={}){
  this.registry=registry;this.endpoint=new URL(endpoint);this.fetch=fetchImpl;
  if(!['http:','https:'].includes(this.endpoint.protocol)||this.endpoint.pathname!==contract.SOURCE_PATH||this.endpoint.search||this.endpoint.hash||this.endpoint.username||this.endpoint.password)throw new Error('Pinned company app authority required');
 }
 async authority(user,authorization){
  if(user?.actor_type!=='user'||typeof authorization!=='string'||authorization.length>16384||!/^Bearer [A-Za-z0-9._~-]+$/.test(authorization))contract.fail(403,'original_company_app_human_required');
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),2500);
  try{
   const response=await this.fetch(this.endpoint,{method:'GET',headers:{Authorization:authorization,Accept:'application/json'},redirect:'error',cache:'no-store',signal:controller.signal});
   if([401,403,428].includes(response.status))contract.fail(response.status,'company_app_identity_rejected');
   if(response.status!==200||!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')||''))throw new Error('Authority unavailable');
   const chunks=[];let length=0;for await(const chunk of response.body){length+=chunk.length;if(length>8192||controller.signal.aborted)throw new Error('Authority exceeds boundary');chunks.push(Buffer.from(chunk));}
   return contract.source(JSON.parse(Buffer.concat(chunks).toString('utf8')),user);
  }catch(error){if(error.status&&error.status!==400)throw error;contract.fail(503,'company_app_identity_unavailable');}finally{clearTimeout(timer);controller.abort();}
 }
 async run(user,authorization,action,reason,operation){
  const original=await this.authority(user,authorization);
  const verify=async()=>{if(!isDeepStrictEqual(original,await this.authority(user,authorization)))contract.fail(412,'company_app_original_authority_changed');};
  const result=await this.registry.transaction(source=>operation(source,original),{companySource:original,verify,action,reason});
  await verify();return{schemaVersion:1,companyAppProtocol:1,actorUserId:original.actorUserId,tenant:original.tenant,...result};
 }
 async own(source,id,tenant,lock=false){contract.identifier(id);const row=await source.companyGet(id,tenant,lock);if(!row)contract.fail(404,'own_company_app_not_found');return row;}
 async list(query,user,authorization){
  if(Object.keys(query).some(key=>!['page','status'].includes(key)))contract.fail(400,'exact_company_app_page_required');const page=pageNumber(query.page);const status=query.status??'active';if(!['active','deleted'].includes(status))contract.fail(400,'supported_company_app_status_required');
  return this.run(user,authorization,'read','Read own company app registry',async(source,proof)=>{const rows=await source.companyList(proof.tenant.id,page,status);return{page,status,hasMore:rows.length>25,clients:rows.slice(0,25).map(view)};});
 }
 async read(id,user,authorization){return this.run(user,authorization,'read','Read own company app metadata',async(source,proof)=>({client:view(await this.own(source,id,proof.tenant.id))}));}
 async create(body,user,authorization){
  const input=contract.metadata(body,true);
  return this.run(user,authorization,'created',input.reason,async(source,proof)=>{
   await source.companyLock(proof.tenant.id);const previous=await source.companyGet(input.requestId,proof.tenant.id,true);
   if(previous){if(!isDeepStrictEqual(previous.companyRequest,input))contract.fail(409,'original_company_app_request_changed');return{client:view(previous),clientSecret:null,created:false};}
   if(await source.companyCount(proof.tenant.id)>=100)contract.fail(429,'company_app_capacity_reached');
   const client=this.registry.metadata({name:input.name,enabled:false,publicClient:false,redirectUris:[],grantTypes:['client_credentials'],scopes:input.purpose==='none'?[]:['company.automation']});
   const secret=randomBytes(32).toString('base64url');Object.assign(client,{clientId:input.requestId,clientSecretHash:hashSecret(secret),companyTenant:proof.tenant,companyRequest:input});
   await source.insert(client);return{client:view(await this.own(source,client.clientId,proof.tenant.id)),clientSecret:secret,created:true};
  });
 }
 async mutate(id,match,body,user,authorization,action='updated'){
  let input;if(action==='updated')input=contract.metadata(body);else{contract.exact(body,['reason','confirm']);input=contract.metadata({name:'credential-operation',purpose:'none',enabled:false,...body});}
  if(!['updated','rotated','deleted'].includes(action))contract.fail(400,'supported_company_app_action_required');
  if(!match)contract.fail(428,'company_app_version_required');
  return this.run(user,authorization,action,input.reason,async(source,proof)=>{
   const before=await this.own(source,id,proof.tenant.id,true);if(before.deletedAt)contract.fail(409,'company_app_already_deleted');if(match!==etag(before))contract.fail(412,'company_app_version_changed');
   const client=action==='updated'?this.registry.metadata({name:input.name,enabled:input.enabled,scopes:input.purpose==='none'?[]:['company.automation']},before):{...before};
   const secret=action==='rotated'?randomBytes(32).toString('base64url'):null;if(secret)client.clientSecretHash=hashSecret(secret);
   if(action==='deleted'){client.enabled=false;client.deletedAt=new Date().toISOString();}
   client.companyTenant=proof.tenant;client.version=String(BigInt(before.version)+1n);if(!validRevision(client.version))contract.fail(409,'company_app_generation_exhausted');
   await source.update(client);return{client:view(await this.own(source,id,proof.tenant.id)),...(action==='rotated'?{clientSecret:secret}:{})};
  });
 }
 async history(id,query,user,authorization){
  if(Object.keys(query).some(key=>key!=='page'))contract.fail(400,'exact_company_app_page_required');const page=pageNumber(query.page);
  return this.run(user,authorization,'read','Read original company app history',async(source,proof)=>{
   await this.own(source,id,proof.tenant.id);const rows=await source.companyHistory(id,page);if(rows.some(row=>!row.valid))contract.fail(503,'original_company_app_history_unavailable');
   return{clientId:id,page,hasMore:rows.length>25,events:rows.slice(0,25).map(row=>({revision:String(row.revision),action:row.action,actorUserId:row.actor_user_id,reason:row.details.reason,createdAt:new Date(row.created_at).toISOString()}))};
  });
 }
}
module.exports={CompanyApps};
