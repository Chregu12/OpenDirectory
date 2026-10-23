'use strict';
const contract=require('./employee-invitation-contract');
const operations=['create','list','get','revoke','inspect','credential','activate','observe','complete','withdraw','state'];
const ownerOperations=['create','list','get','revoke'];
function invitationRequest({issuer,jwksUri,loadJose}){
 if(typeof loadJose!=='function')throw new Error('Service-local JOSE implementation required');
 let keys;
 return(operation,path=contract.AUTH_BASE+'/'+operation)=>{
  if(!operations.includes(operation))throw new Error('Fixed employee invitation operation required');
  return async(req,res,next)=>{
   res.set('Cache-Control','no-store');
   try{
    if(req.method!=='POST'||req.originalUrl!==path||Object.keys(req.query).length||req.headers['x-api-key']!==undefined||typeof req.headers.authorization!=='string'||req.headers.authorization.length>16384||!/^Bearer [A-Za-z0-9._~-]+$/.test(req.headers.authorization))contract.fail(401,'invalid_employee_invitation_proof');
    const {jwtVerify,createRemoteJWKSet}=await loadJose();
    if(!keys)keys=createRemoteJWKSet(new URL(jwksUri),{timeoutDuration:1500,cooldownDuration:1000,cacheMaxAge:30000});
    const claims=['iss','sub','aud','actor_type','token_use','scope','htm','htu','body_sha256','owner_sha256','jti','iat','exp'];
    const {payload,protectedHeader}=await jwtVerify(req.headers.authorization.slice(7),keys,{issuer,audience:contract.AUDIENCE,algorithms:['RS256'],requiredClaims:claims,maxTokenAge:'30s'});
    const owner=req.headers['x-opendirectory-owner-authorization'];
    if(ownerOperations.includes(operation)&&(typeof owner!=='string'||owner.length>16384||!/^Bearer [A-Za-z0-9._~-]+$/.test(owner)))contract.fail(401,'invalid_employee_invitation_proof');
    const ownerHash=ownerOperations.includes(operation)?contract.digest(owner):null;
    const originalPath=['observe','complete','withdraw'].includes(operation)?contract.IDENTITY_BASE+'/'+operation:contract.AUTH_BASE+'/'+operation;
    if(Object.keys(payload).length!==claims.length||Object.keys(protectedHeader).length!==3||protectedHeader.typ!==contract.TYPE||typeof protectedHeader.kid!=='string'||!protectedHeader.kid||protectedHeader.kid.length>128
     ||payload.sub!=='oauth-provider'||payload.aud!==contract.AUDIENCE||payload.actor_type!=='workload'||payload.token_use!==contract.PURPOSE||payload.scope!=='employees.invitations.'+operation
     ||payload.htm!=='POST'||payload.htu!==originalPath||payload.body_sha256!==contract.digest(req.body)||payload.owner_sha256!==ownerHash
     ||ownerOperations.includes(operation)&&(typeof owner!=='string'||owner.length>16384||!/^Bearer [A-Za-z0-9._~-]+$/.test(owner))||!ownerOperations.includes(operation)&&owner!==undefined
     ||!Number.isSafeInteger(payload.iat)||!Number.isSafeInteger(payload.exp)||payload.iat>Math.floor(Date.now()/1000)||payload.exp<=payload.iat||payload.exp-payload.iat>30)contract.fail(401,'invalid_employee_invitation_proof');
    contract.identifier(payload.jti);req.employeeInvitationProof=payload;next();
   }catch(error){const unavailable=['ERR_JWKS_TIMEOUT','ERR_JWKS_INVALID','ECONNREFUSED','ENOTFOUND','EAI_AGAIN'].includes(error.code)||error instanceof TypeError||/Expected 200 OK/.test(error.message);
    res.status(unavailable?503:401).json({error:unavailable?'employee_invitation_verification_unavailable':'invalid_employee_invitation_proof'});}
  };
 };
}
module.exports={invitationRequest};
