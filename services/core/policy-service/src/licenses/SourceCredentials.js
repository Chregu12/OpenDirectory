'use strict';

const fs=require('node:fs');
const {LicenseError}=require('./LicenseError');
const {ClientCredentialToken}=require('./fulfillment/transport');
const {SOURCE_SCOPE}=require('../../../../../packages/group-license-lease-contract');
const identifier=value=>typeof value==='string'&&/^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,255}$/.test(value);
const secret=value=>typeof value==='string'&&value.length>=12&&value.length<=4096&&!/[\u0000-\u0020\u007f]/.test(value);
function readConfiguration(filename,{accessStateUrl=process.env.OIDC_ACCESS_STATE_URL||'http://oauth-provider:3010/oauth/access-state'}={}){
 if(!filename)return null;if(typeof process.getuid!=='function')throw new Error('Protected license source configuration requires owner verification');
 const descriptor=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{
  const state=fs.fstatSync(descriptor);if(!state.isFile()||state.uid!==process.getuid()||(state.mode&0o077)!==0||state.size>16384)throw new Error('License source configuration must be an owner-only regular file');
  const data=JSON.parse(fs.readFileSync(descriptor,'utf8'));if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(field=>!['enabled','tokenUrl','groups','users'].includes(field))||data.enabled!==true||!data.groups&&!data.users)throw new Error('Explicit narrow license source configuration required');
  const endpoint=new URL(data.tokenUrl);const authority=new URL(accessStateUrl);if(!['https:','http:'].includes(endpoint.protocol)||endpoint.username||endpoint.password||endpoint.hash||endpoint.search||endpoint.pathname!=='/oauth/token'||endpoint.origin!==authority.origin)throw new Error('License source token endpoint must match the configured issuer authority');
  for(const kind of ['groups','users'])if(Object.hasOwn(data,kind)&&(!data[kind]||typeof data[kind]!=='object'||Array.isArray(data[kind])||Object.keys(data[kind]).length!==2||!identifier(data[kind].clientId)||!secret(data[kind].clientSecret)))throw new Error('Invalid narrow source client credential');
  if(data.groups&&data.users&&data.groups.clientId===data.users.clientId)throw new Error('Group and user sources require separate clients');
  return data;
 }finally{fs.closeSync(descriptor);}
}
function configuration(filename,options){try{return readConfiguration(filename,options);}catch{throw new Error('License source configuration rejected; an owner-only file, fixed issuer and narrow credentials are required');}}
class SourceCredential {
 constructor(config,purpose,{fetchImpl=(...args)=>fetch(...args)}={}){
  if(![SOURCE_SCOPE,'licenses.users.read'].includes(purpose))throw new Error('Fixed source purpose required');this.purpose=purpose;this.stopped=false;this.blockedUntil=0;
  this.tokens=new ClientCredentialToken({url:config.tokenUrl,clientId:config.clientId,clientSecret:config.clientSecret,scope:purpose,fetchImpl,stage:'license_source_token',requireScope:true});
 }
 stop(){this.stopped=true;this.tokens.clear();}
 rejected(error){if(error.upstreamStatus===401){this.tokens.clear();this.blockedUntil=Date.now()+30000;}else if(error.upstreamStatus===429)this.blockedUntil=Date.now()+Math.max(1,Math.min(3600,error.retryAfter||60))*1000;else if(error.sourceUnavailable)this.blockedUntil=Date.now()+30000;}
 async authorization(){if(this.stopped||Date.now()<this.blockedUntil)throw new LicenseError(503,'license_source_credentials_unavailable');
  try{if(!this.pending)this.pending=this.tokens.get().finally(()=>{this.pending=null;});const token=await this.pending;if(this.stopped){this.tokens.clear();throw new Error('Source stopped');}return'Bearer '+token;}catch(error){this.tokens.clear();this.blockedUntil=Date.now()+Math.max(30,Math.min(3600,error.retryAfter||30))*1000;throw new LicenseError(503,'license_source_credentials_unavailable');}
 }
}
function sources(filename,options={}){const data=configuration(filename,options);if(!data)return null;const result={};for(const[kind,purpose]of [['groups',SOURCE_SCOPE],['users','licenses.users.read']])if(data[kind])result[kind]=new SourceCredential({tokenUrl:data.tokenUrl,...data[kind]},purpose,options);return result;}
async function sourceRequest(credential,authorization,operation){if(!credential)return operation(authorization);try{return await operation(await credential.authorization());}catch(error){credential.rejected(error);throw error;}}
module.exports={configuration,SourceCredential,sources,sourceRequest};
