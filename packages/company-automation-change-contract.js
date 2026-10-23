'use strict';
const {createHash}=require('node:crypto');
const {exact,identifier,workload,fail}=require('./company-automation-contract');
const {validRevision}=require('./identity-authorization-contract');
const WATCH_PATH='/api/identity/automation/watch-source';const OBSERVE_PATH='/api/licenses/automation/groups/observe';
const tokenHash=user=>createHash('sha256').update(user.jti).digest('hex');
function input(value){exact(value,['grantId','scheduleId','ruleId']);Object.values(value).forEach(identifier);return value;}
function watch(source,context,user){
 exact(source,['schemaVersion','companyAutomationChangeProtocol','grantId','scheduleId','scheduleRevision','ruleId','tenant','issuer','subject','clientRevision','tokenIdentifierHash','validUntil']);
 exact(source.tenant,['id','version','generation']);identifier(source.tenant.id);
 if(source.schemaVersion!==1||source.companyAutomationChangeProtocol!==1||['grantId','scheduleId','ruleId'].some(key=>source[key]!==context[key])
  || ![source.scheduleRevision,source.clientRevision,source.tenant.version,source.tenant.generation].every(validRevision)||source.issuer!==user.iss||source.subject!==user.client_id||source.clientRevision!==user.client_revision
  ||source.tokenIdentifierHash!==tokenHash(user)||!Number.isSafeInteger(source.validUntil)||source.validUntil*1000<=Date.now()||source.validUntil>user.exp)fail(503,'Original change subscription authority unconfirmed');return source;
}
function observation(value,plan,user){
 exact(value,['schemaVersion','companyAutomationChangeProtocol','allocationMode','grantId','scheduleId','scheduleRevision','ruleId','tenantId','groupId','poolId','ruleRevision','ruleStatus','poolRevision','availableSeats','validUntil','tokenIdentifierHash']);
 for(const field of ['groupId','poolId','tenantId'])identifier(value[field]);
 if(value.schemaVersion!==1||value.companyAutomationChangeProtocol!==1||value.allocationMode!=='local-only'||value.grantId!==plan.grant_id||value.scheduleId!==plan.id||value.scheduleRevision!==String(plan.revision)
  ||value.ruleId!==plan.rule_id||value.tenantId!==plan.tenant_id||![value.ruleRevision,value.poolRevision].every(validRevision)||!['active','unlinked'].includes(value.ruleStatus)
  ||!Number.isInteger(value.availableSeats)||value.availableSeats<0||value.availableSeats>10000||value.tokenIdentifierHash!==tokenHash(user)
  ||!Number.isSafeInteger(value.validUntil)||value.validUntil*1000<=Date.now()||value.validUntil>user.exp)fail(503,'Original local pool change observation unconfirmed');return value;
}
async function exchange(endpoint,path,body,authorization,fetchImpl){
 const address=new URL(endpoint);if(!['http:','https:'].includes(address.protocol)||address.pathname!==path||address.username||address.password||address.search||address.hash)throw new Error('Pinned change receiver required');
 const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),2500);
 try{
  const response=await fetchImpl(address,{method:'POST',headers:{Authorization:authorization,Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify(body),redirect:'error',cache:'no-store',signal:controller.signal});
  if([400,401,403,404,409,412].includes(response.status))fail(response.status,'Original change source rejected');
  if(response.status!==200||!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')||''))throw new Error('Change source unavailable');
  const chunks=[];let size=0;for await(const chunk of response.body){size+=chunk.length;if(controller.signal.aborted||size>16384)throw new Error('Change observation exceeds boundary');chunks.push(Buffer.from(chunk));}
  if(controller.signal.aborted)throw new Error('Change observation expired');return JSON.parse(Buffer.concat(chunks).toString('utf8'));
 }catch(error){if(error.status)throw error;fail(503,'Change observation unavailable');}finally{clearTimeout(timer);controller.abort();}
}
module.exports={WATCH_PATH,OBSERVE_PATH,input,watch,observation,exchange,tokenHash};
