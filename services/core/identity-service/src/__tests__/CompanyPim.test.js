'use strict';
const {randomUUID}=require('node:crypto');const C=require('../CompanyRoleContract');const A=require('../CompanyRoleAuthority');
const actor=randomUUID(),id=randomUUID(),now=Math.floor(Date.now()/1000);const user={actor_type:'user',iss:'https://pim.test',sub:'actual-user',auth_time:now-600,exp:now+3600,amr:['pwd','otp'],identity_authorization:{userId:actor,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64)},mfa_authorization:{schemaVersion:1,userId:actor,revision:'1',authTime:now-600,methods:['pwd','otp']}};
const source={id,activationId:randomUUID(),actorContext:user.identity_authorization,issuer:user.iss,subject:user.sub,authTime:String(user.auth_time),mfaRevision:'1',validUntil:String(now+3600)};
test('only a matching live original PIM source can extend custom use beyond direct MFA freshness',()=>{
 expect(A.accepted(user,source)).toBe(true);expect(A.accepted(user,{id,validUntil:source.validUntil})).toBe(false);
 expect(A.accepted(user,{...source,mfaRevision:'2'})).toBe(false);expect(A.accepted(user,{...source,actorContext:{...user.identity_authorization,revision:'2'}})).toBe(false);expect(A.accepted(user,{...source,subject:'someone-else'})).toBe(false);
 expect(A.deadline(user,{grants:[{source}]})).toBe(now+3600);expect(A.deadline(user,{grants:[{source},{source:{id,validUntil:String(now+7200)}}]})).toBe(user.auth_time+300);
});
test('PIM eligibility has an exact independently assigned target, scope and bounded validity',()=>{
 const body={targetType:'user',targetId:id,scopeType:'tenant',ouId:null,validForSeconds:30*86400,reason:'Actual independent PIM eligibility decision',confirm:true};expect(C.eligibility(body)).toEqual(body);
 for(const changed of [{validForSeconds:31536001},{validForSeconds:59},{tenantId:randomUUID()},{scopeType:'ou',ouId:null},{confirm:false}])expect(()=>C.eligibility({...body,...changed})).toThrow();
});
test('PIM activation accepts only a bounded duration and explicit reason/confirmation with a separate exact ETag',()=>{
 const body={durationSeconds:36000,reason:'Original own ten-hour PIM activation',confirm:true};expect(C.activation(body)).toEqual(body);
 for(const changed of [{durationSeconds:36001},{durationSeconds:0},{userId:actor},{confirm:false}])expect(()=>C.activation({...body,...changed})).toThrow();
 const current={id,revision:'9223372036854775807'};expect(C.expected('eligibility',C.etag('eligibility',current),id)).toBe(current.revision);expect(()=>C.expected('activation',C.etag('eligibility',current),id)).toThrow();
});
