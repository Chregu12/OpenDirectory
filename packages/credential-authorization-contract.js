'use strict';
const {isDeepStrictEqual}=require('node:util');const {validUuid,validRevision}=require('./identity-authorization-contract');
const PATH='/internal/auth/credential-state';const AUDIENCE='opendirectory-credential-authorization';const PURPOSE='credential-state-read';const TYPE='od-credential-state+jwt';const SCOPE='credentials.authorization.read';
const exact=(value,keys)=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const uuid=value=>validUuid(value)&&value===value.toLowerCase();
const validSubject=value=>typeof value==='string'&&!!value.trim()&&value.length<=255&&!/[\u0000-\u001f\u007f]/.test(value);
const validSnapshot=value=>exact(value,['schemaVersion','subjectId','securityRevision'])&&value.schemaVersion===1&&uuid(value.subjectId)&&validRevision(value.securityRevision);
const validBinding=value=>exact(value,['schemaVersion','subjectId','userId','invitationId','securityRevision'])&&value.schemaVersion===1&&uuid(value.subjectId)&&uuid(value.userId)&&(value.invitationId===null||uuid(value.invitationId))&&validRevision(value.securityRevision);
const sameBinding=(first,second)=>first==null||second==null?first==null&&second==null:validBinding(first)&&validBinding(second)&&isDeepStrictEqual(first,second);
function matchesPasswordAuthentication(state,snapshot,subject){
 const binding=state.credentialAuthorization;
 return binding==null?snapshot==null:validBinding(binding)&&validSnapshot(snapshot)&&binding.subjectId===subject&&snapshot.subjectId===subject&&binding.securityRevision===snapshot.securityRevision;
}
function credentialStateRequest({issuer,jwksUri,loadJose}){
 let keys;return async(req,res,next)=>{
  res.set('Cache-Control','no-store');
  try{
   if(req.method!=='POST'||req.originalUrl!==PATH||Object.keys(req.query).length||!exact(req.body,['subject'])||!validSubject(req.body.subject)||req.headers['x-api-key']!==undefined
    ||req.headers['x-opendirectory-owner-authorization']!==undefined||typeof req.headers.authorization!=='string'||req.headers.authorization.length>16384||!/^Bearer [A-Za-z0-9._~-]+$/.test(req.headers.authorization))throw new Error('Invalid request');
   const {jwtVerify,createRemoteJWKSet}=await loadJose();if(!keys)keys=createRemoteJWKSet(new URL(jwksUri),{timeoutDuration:1500,cooldownDuration:1000,cacheMaxAge:30000});
   const required=['iss','sub','aud','actor_type','token_use','scope','htm','htu','request_subject','jti','iat','exp'];
   const {payload,protectedHeader}=await jwtVerify(req.headers.authorization.slice(7),keys,{issuer,audience:AUDIENCE,algorithms:['RS256'],requiredClaims:required,maxTokenAge:'30s'});const now=Math.floor(Date.now()/1000);
   if(Object.keys(payload).length!==required.length||Object.keys(protectedHeader).length!==3||protectedHeader.typ!==TYPE||typeof protectedHeader.kid!=='string'||!protectedHeader.kid||protectedHeader.kid.length>128
    ||payload.sub!=='oauth-provider'||payload.actor_type!=='workload'||payload.aud!==AUDIENCE||payload.token_use!==PURPOSE||payload.scope!==SCOPE||payload.htm!=='POST'||payload.htu!==PATH||payload.request_subject!==req.body.subject
    ||!uuid(payload.jti)||!Number.isSafeInteger(payload.iat)||!Number.isSafeInteger(payload.exp)||payload.iat>now||payload.exp<=now||payload.exp<=payload.iat||payload.exp-payload.iat>30)throw new Error('Invalid proof');
   req.credentialStateProof=payload;next();
  }catch(error){const unavailable=['ERR_JWKS_TIMEOUT','ERR_JWKS_INVALID','ECONNREFUSED','ENOTFOUND','EAI_AGAIN'].includes(error.code)||error instanceof TypeError||/Expected 200 OK/.test(error.message);
   res.status(unavailable?503:401).json({error:unavailable?'credential_state_verification_unavailable':'invalid_credential_state_proof'});}
 };
}
module.exports={PATH,AUDIENCE,PURPOSE,TYPE,SCOPE,exact,uuid,validRevision,validSubject,validSnapshot,validBinding,sameBinding,matchesPasswordAuthentication,credentialStateRequest};
