'use strict';

const { validRevision } = require('../../../../packages/identity-authorization-contract');
const CLIENT_ID=/^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,255}$/;
class LicenseSourceClients {
 constructor({url=process.env.OIDC_ACCESS_STATE_URL||'http://oauth-provider:3010/oauth/access-state',issuer=process.env.OIDC_ISSUER||'http://localhost:3001',fetchImpl=(...args)=>fetch(...args)}={}){
  this.base=new URL(url);if(!['http:','https:'].includes(this.base.protocol)||this.base.username||this.base.password||this.base.search||this.base.hash)throw new Error('Invalid canonical source-client endpoint');this.issuer=issuer;this.fetch=fetchImpl;
 }
 async get(clientId,authorization){
  if(typeof clientId!=='string'||!CLIENT_ID.test(clientId))throw Object.assign(new Error('source_client_id_required'),{status:400});
  if(typeof authorization!=='string'||!/^Bearer [^\r\n]+$/.test(authorization))throw Object.assign(new Error('original_source_administrator_required'),{status:403});
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),1500);
  try{
   const response=await this.fetch(new URL('/api/license-source-clients/'+encodeURIComponent(clientId),this.base),{headers:{Authorization:authorization},redirect:'error',cache:'no-store',signal:controller.signal});
   if(response.status!==200||!response.headers.get('content-type')?.includes('application/json'))throw new Error('Canonical source client unavailable');
   const chunks=[];let size=0;for await(const chunk of response.body){size+=chunk.length;if(size>8192)throw new Error('Oversized source-client evidence');chunks.push(Buffer.from(chunk));}
   const data=JSON.parse(Buffer.concat(chunks).toString('utf8'));
   if(!data||Object.keys(data).length!==5||data.schemaVersion!==1||data.clientId!==clientId||!validRevision(data.revision)||typeof data.enabled!=='boolean'||typeof data.canReadGroupSources!=='boolean'||data.canReadGroupSources&&!data.enabled)throw new Error('Invalid source-client evidence');
   return{schemaVersion:1,clientId:data.clientId,revision:data.revision,enabled:data.enabled,canReadGroupSources:data.canReadGroupSources};
  }catch{throw Object.assign(new Error('source_client_authority_unavailable'),{status:503});}finally{clearTimeout(timer);controller.abort();}
 }
}
module.exports={LicenseSourceClients,CLIENT_ID};
