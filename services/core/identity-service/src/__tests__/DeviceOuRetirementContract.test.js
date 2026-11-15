'use strict';
const {randomUUID}=require('node:crypto');
const C=require('../../../../../packages/device-ou-retirement-contract');
let user,selected,source;
beforeEach(()=>{
 const now=Math.floor(Date.now()/1000),id=randomUUID();user={actor_type:'user',iss:'https://retirement.test',sub:'original',jti:randomUUID(),exp:now+900,auth_time:now,identity_authorization:{userId:id,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64)},amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId:id,revision:'1',authTime:now,methods:['pwd','otp']}};
 selected={action:'prepare',ouId:randomUUID(),generation:'9007199254740993',revision:'9007199254740994',fenceRevision:'0'};
 source={schemaVersion:1,deviceOuRetirementProtocol:1,issuer:user.iss,subject:user.sub,tokenId:user.jti,expiresAt:user.exp,context:{...user.identity_authorization},tenant:{id:randomUUID(),version:'1',generation:'1'},actorUserId:id,permissions:['ous.delete'],validUntil:now+90,action:selected.action,target:{id:selected.ouId,generation:selected.generation,revision:selected.revision},fenceRevision:'0',protected:false,delegation:null};
});
test('the retirement source has its own purpose and preserves exact BIGINT namespace and request bindings',()=>{
 expect(C.validSource(source,user,selected)).toBe(true);expect(C.validSource(source,user,{...selected,fenceRevision:'1'})).toBe(false);
 expect(require('../../../device-service/src/InventoryAuthority').inventorySourceMatches(source,user)).toBe(false);
});
test.each(['purpose','version','issuer','subject','token','expiry','actor','context','tenant','permission','grant','target','generation','OU revision','fence revision','extra','MFA age','MFA factor'])('retirement source refuses substituted %s',change=>{
 if(change==='purpose')delete source.deviceOuRetirementProtocol;if(change==='version')source.schemaVersion=2;if(change==='issuer')source.issuer='https://other.test';if(change==='subject')source.subject='other';if(change==='token')source.tokenId=randomUUID();if(change==='expiry')source.validUntil=user.exp+1;if(change==='actor')source.actorUserId=randomUUID();if(change==='context')source.context.revision='2';if(change==='tenant')source.tenant.generation='0';if(change==='permission')source.permissions=['devices.inventory.create'];if(change==='grant')source.delegation={grants:[]};if(change==='target')source.target.id=randomUUID();if(change==='generation')source.target.generation='9007199254740992';if(change==='OU revision')source.target.revision='1';if(change==='fence revision')source.fenceRevision='1';if(change==='extra')source.inventory={};if(change==='MFA age'){user.auth_time-=301;user.mfa_authorization.authTime=user.auth_time;}if(change==='MFA factor')user.mfa_authorization.userId=randomUUID();
 expect(C.validSource(source,user,selected)).toBe(false);
});
test('a deletion PIM source retains the original activation factor and canonical membership incarnation',()=>{
 source.delegation={grants:[{permission:'ous.delete',source:{id:randomUUID(),roleId:randomUUID(),roleRevision:'1',scopeType:'tenant',ouId:null,targetType:'group',targetId:randomUUID(),membershipId:randomUUID(),validUntil:String(source.validUntil),activationId:randomUUID(),mfaRevision:'1',authTime:String(user.auth_time),issuer:user.iss,subject:user.sub,actorContext:{...user.identity_authorization}}}]};
 expect(C.validSource(source,user,selected)).toBe(true);source.delegation.grants[0].source.mfaRevision='2';expect(C.validSource(source,user,selected)).toBe(false);
});
test('cancel requires a positive original fence revision and never permits free tenant or source fields',()=>{
 for(const bad of [{...selected,action:'cancel'},{...selected,fenceRevision:0},{...selected,tenantId:source.tenant.id},{...selected,source},{...selected,revision:'9223372036854775808'}])expect(()=>C.input(bad)).toThrow();
 selected.action='cancel';selected.fenceRevision='2';source.action='cancel';source.fenceRevision='2';expect(C.validSource(source,user,selected)).toBe(true);
});
test('the canonical API documents source purpose and separate initial/final routes without claiming a deletion receiver',()=>{
 const api=JSON.parse(require('node:fs').readFileSync(require('node:path').resolve(__dirname,'../../../../../docs/api/openapi.yaml'),'utf8')),generated=require('../../scripts/device-ou-retirement-openapi').deviceOuRetirementOpenApi();
 for(const name of ['DeviceOuRetirementSourceRequest','DeviceOuRetirementSource'])expect(api.components.schemas[name]).toEqual(generated.components.schemas[name]);
 for(const path of ['/api/identity/device-ou-retirement','/api/identity/device-ou-retirement/check']){expect(api.paths[path]).toEqual(generated.paths[path]);expect(api.paths[path].post.parameters).toContainEqual(expect.objectContaining({name:'X-OD-Device-Ou-Retirement-Protocol',required:true,schema:{const:'1'}}));}
 expect(api.components.schemas.DeviceOuRetirementSource.required).toHaveLength(16);expect(api.components.schemas.DeviceOuRetirementSource.properties.permissions).toEqual({const:['ous.delete']});expect(api.components.schemas.DeviceOuRetirementSource.properties.inventory).toBeUndefined();
});
