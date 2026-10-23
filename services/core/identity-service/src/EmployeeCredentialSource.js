'use strict';
const {isDeepStrictEqual}=require('node:util');const contract=require('../../../../packages/employee-invitation-contract');
class EmployeeCredentialSource{
 constructor({endpoint=process.env.AUTH_SERVICE_URL||'http://auth-service:3002',fetchImpl=(...args)=>fetch(...args)}={}){
  this.endpoint=new URL(endpoint);this.fetch=fetchImpl;
  if(!['https:','http:'].includes(this.endpoint.protocol)||this.endpoint.username||this.endpoint.password||this.endpoint.search||this.endpoint.hash||this.endpoint.pathname!=='/')throw new Error('Pinned credential origin required');
 }
 async read(operation,input,authorization){
  if(!['complete','withdraw'].includes(operation)||typeof authorization!=='string'||authorization.length>16384||!/^Bearer [A-Za-z0-9._~-]+$/.test(authorization))contract.fail(401,'original_employee_credential_proof_required');
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),2500);
  try{
   const path=contract.AUTH_BASE+'/'+(operation==='complete'?'identity-source':'revoked-source');
   const response=await this.fetch(new URL(path,this.endpoint),{method:'POST',headers:{Authorization:authorization,'Content-Type':'application/json'},body:JSON.stringify(input),redirect:'error',cache:'no-store',signal:controller.signal});
   if([400,401,403,404,409,412].includes(response.status))contract.fail(response.status,'employee_credential_source_rejected');
   if(response.status!==200||!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')||''))throw new Error('Credential source unavailable');
   const chunks=[];let length=0;for await(const chunk of response.body){length+=chunk.length;if(length>32768)throw new Error('Oversized credential source');chunks.push(Buffer.from(chunk));}
   const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));
   if(value.schemaVersion!==1||value.employeeInvitationProtocol!==1
    ||operation==='complete'&&(typeof value.valid!=='boolean'||!['pending','credential_pending','accepted','revoked'].includes(value.status))
    ||operation==='withdraw'&&typeof value.revoked!=='boolean')throw new Error('Original credential source unconfirmed');
   if(!isDeepStrictEqual(value.witness,input.witness))contract.fail(409,'original_employee_credential_witness_changed');
   return value;
  }catch(error){if(error.status)throw error;contract.fail(503,'employee_credential_source_unavailable');}finally{clearTimeout(timer);controller.abort();}
 }
}
module.exports={EmployeeCredentialSource};
