'use strict';
const jwt=require('jsonwebtoken');const contract=require('../../../../packages/employee-invitation-contract');
class EmployeeInvitationAuthorityClient{
 constructor({endpoint=process.env.IDENTITY_SERVICE_URL||'http://identity-service:3001',fetchImpl=(...args)=>fetch(...args)}={}){
  this.endpoint=new URL(endpoint);this.fetch=fetchImpl;
  if(!['https:','http:'].includes(this.endpoint.protocol)||this.endpoint.username||this.endpoint.password||this.endpoint.search||this.endpoint.hash||this.endpoint.pathname!=='/')throw new Error('Pinned Identity origin required');
 }
 async request(path,body,authorization){
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),2500);
  try{
   const response=await this.fetch(new URL(path,this.endpoint),{method:'POST',headers:{Authorization:authorization,'Content-Type':'application/json'},body:JSON.stringify(body),redirect:'error',cache:'no-store',signal:controller.signal});
   if([400,401,403,404,409,412,428].includes(response.status))contract.fail(response.status,'employee_invitation_identity_rejected');
   if(response.status!==200||!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')||''))throw new Error('Identity unavailable');
   const chunks=[];let length=0;for await(const chunk of response.body){length+=chunk.length;if(length>32768)throw new Error('Oversized Identity proof');chunks.push(Buffer.from(chunk));}
   return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }catch(error){if(error.status)throw error;contract.fail(503,'employee_invitation_identity_unavailable');}finally{clearTimeout(timer);controller.abort();}
 }
 async owner(authorization,userId=null){
  if(typeof authorization!=='string'||authorization.length>16384||!/^Bearer [A-Za-z0-9._~-]+$/.test(authorization))contract.fail(401,'original_employee_invitation_bearer_required');
  // Identity verifies this bearer; decoding only binds its actual response to the original request.
  const user=jwt.decode(authorization.slice(7));const value=await this.request(contract.SOURCE_PATH,{userId},authorization);return contract.source(value,user);
 }
 async observe(witness,assertion){
  if(typeof assertion!=='string'||assertion.length>16377||!/^[-A-Za-z0-9._~]+$/.test(assertion))contract.fail(401,'original_employee_observation_assertion_required');
  return this.request(contract.IDENTITY_BASE+'/observe',{witness},'Bearer '+assertion);
 }
 async accepted(input,authorization){return this.request(contract.IDENTITY_BASE+'/accepted-source',input,authorization);}
}
module.exports={EmployeeInvitationAuthorityClient};
