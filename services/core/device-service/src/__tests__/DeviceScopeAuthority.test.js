'use strict';
const { randomUUID } = require('node:crypto');
const C = require('../../../../../packages/device-scope-contract');
const { InventoryAuthority,inventorySourceMatches } = require('../InventoryAuthority');
let user,source,root,child,fetchImpl,authority;
beforeEach(()=>{
 const now=Math.floor(Date.now()/1000),actor=randomUUID();root='11111111-1111-4111-8111-111111111111';child='22222222-2222-4222-8222-222222222222';
 user={actor_type:'user',iss:'https://scoped.test',sub:'original',jti:randomUUID(),exp:now+600,auth_time:now,identity_authorization:{userId:actor,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64)},amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId:actor,revision:'1',authTime:now,methods:['pwd','otp']}};
 const permission='devices.inventory.read';source={schemaVersion:2,issuer:user.iss,subject:user.sub,tokenId:user.jti,expiresAt:user.exp,context:{...user.identity_authorization},tenant:{id:randomUUID(),version:'1',generation:'1'},actorUserId:actor,permissions:[permission],validUntil:now+90,target:null,
  scope:{protocol:1,inherent:[],grants:[{permission,source:{id:randomUUID(),roleId:randomUUID(),roleRevision:'1',scopeType:'device-ou',ouId:root,ouGeneration:'9007199254740993',targetType:'user',targetId:actor,membershipId:null,validUntil:String(now+90)}}],units:[{id:root,generation:'9007199254740993',roots:[root]},{id:child,generation:'4',roots:[root]}],resource:null}};
 fetchImpl=jest.fn(async()=>Response.json(source));authority=new InventoryAuthority({scoped:true,endpoint:'https://identity.test/api/identity/device-inventory',fetchImpl});
});
afterEach(()=>jest.useRealTimers());
test('the canonical private API preserves legacy sources and requires an explicit scoped receiver version',()=>{
 const api=JSON.parse(require('node:fs').readFileSync(require('node:path').resolve(__dirname,'../../../../../docs/api/openapi.yaml'),'utf8'));
 const generated=require('../../scripts/inventory-openapi').deviceInventoryOpenApi();
 for(const name of ['DeviceScopeResource','DeviceScopeDescriptor','InventoryScopedAuthoritySource','DeviceComplianceScopedAuthoritySource'])expect(api.components.schemas[name]).toEqual(generated.components.schemas[name]);
 expect(api.paths['/api/identity/device-inventory']).toEqual(generated.paths['/api/identity/device-inventory']);
 for(const path of ['/api/identity/device-inventory','/api/identity/device-compliance','/api/identity/device-organizational-units/status'])for(const operation of Object.values(api.paths[path]))expect(operation.parameters).toContainEqual(expect.objectContaining({name:'X-OD-Device-Scope-Protocol',in:'header',required:false,schema:{const:'1'}}));
 const schemas=api.components.schemas;expect(schemas.InventoryAuthoritySource.properties.schemaVersion).toEqual({const:1});expect(schemas.InventoryScopedAuthoritySource.required).toHaveLength(12);expect(schemas.InventoryScopedAuthoritySource.additionalProperties).toBe(false);expect(schemas.InventoryScopedAuthoritySource.properties.delegation).toBeUndefined();
 expect(schemas.DeviceScopeDescriptor.properties.units.maxItems).toBe(C.MAX_UNITS);expect(schemas.DeviceScopeDescriptor.properties.grants.maxItems).toBe(C.MAX_GRANTS);
 expect(schemas.InventoryCapabilities.properties.inventoryProtocol).toEqual({const:2});expect(schemas.InventoryCapabilities.properties.scope).toBeUndefined();
});
test('only an explicitly upgraded receiver accepts the original source and its exact OU generations',async()=>{
 expect(inventorySourceMatches(source,user)).toBe(false);expect(C.validEnvelope(source,user)).toBe(true);
 await expect(authority.read('Bearer original',user)).resolves.toEqual(source);
 expect(fetchImpl).toHaveBeenCalledWith(expect.any(URL),expect.objectContaining({method:'GET',headers:{Authorization:'Bearer original',Accept:'application/json','X-OD-Device-Scope-Protocol':'1'},redirect:'error',cache:'no-store'}));
 expect(fetchImpl.mock.calls[0][1].signal.aborted).toBe(true);
});
test('inherent and independent tenant rights remain separate from scoped rights and unassigned devices',()=>{
 expect(C.permits(source,'devices.inventory.read',{id:child,generation:'4'})).toBe(true);expect(C.permits(source,'devices.inventory.read',{id:child,generation:'5'})).toBe(false);expect(C.permits(source,'devices.inventory.read',null)).toBe(false);expect(C.permits(source,'devices.inventory.assign',{id:child,generation:'4'})).toBe(false);
 source.scope.inherent=['devices.inventory.read'];expect(C.validEnvelope(source,user)).toBe(true);expect(C.permits(source,'devices.inventory.read',null)).toBe(true);
 expect(C.permits({...source,schemaVersion:3},'devices.inventory.read',null)).toBe(false);
});
test('a scoped endpoint can retain a complete legacy tenant source without inventing scoped authority',async()=>{
 delete source.scope;source.schemaVersion=1;source.permissions=['devices.inventory.read','devices.inventory.create','devices.inventory.assign'];await expect(authority.read('Bearer original',user)).resolves.toEqual(source);
});
test.each(['issuer','subject','tokenId','expiresAt','actorUserId','context','tenant','target'])('a different original %s cannot substitute scope authority',async field=>{
 source[field]=field==='expiresAt'?source.expiresAt+1:field==='context'?{...source.context,revision:'2'}:field==='tenant'?{...source.tenant,generation:'0'}:field==='target'?{}:'foreign';
 await expect(authority.read('Bearer original',user)).rejects.toMatchObject({status:503});
});
test.each(['no factor','old MFA','future MFA','unbound factor'])('original human MFA remains independently mandatory: %s',async mode=>{
 if(mode==='no factor')user.amr=['pwd'];if(mode==='old MFA'){user.auth_time-=301;user.mfa_authorization.authTime=user.auth_time;}if(mode==='future MFA'){user.auth_time+=6;user.mfa_authorization.authTime=user.auth_time;}if(mode==='unbound factor')user.mfa_authorization.userId=randomUUID();
 await expect(authority.read('Bearer original',user)).rejects.toMatchObject({status:503});
});
test.each(['root generation','missing root','foreign root','duplicate units','duplicate roots','unordered units','unknown unit field','unknown scope field','unknown source field','user OU','empty grants','duplicate grant','unknown permission'])('scope receiving refuses %s',async mode=>{
 if(mode==='root generation')source.scope.units[0].generation='9007199254740992';if(mode==='missing root')source.scope.units.shift();if(mode==='foreign root')source.scope.units[1].roots=[randomUUID()];if(mode==='duplicate units')source.scope.units.push({...source.scope.units[1]});if(mode==='duplicate roots')source.scope.units[1].roots.push(root);if(mode==='unordered units')source.scope.units.reverse();if(mode==='unknown unit field')source.scope.units[0].revision='9';if(mode==='unknown scope field')source.scope.tenantId=randomUUID();if(mode==='unknown source field')source.override=true;if(mode==='user OU')source.scope.grants[0].source.scopeType='ou';if(mode==='empty grants')source.scope.grants=[];if(mode==='duplicate grant')source.scope.grants.push(structuredClone(source.scope.grants[0]));if(mode==='unknown permission')source.permissions=['admin'];
 await expect(authority.read('Bearer original',user)).rejects.toMatchObject({status:503});
});
test('a real PIM source keeps the same original actor MFA and membership incarnation',async()=>{
 Object.assign(source.scope.grants[0].source,{activationId:randomUUID(),mfaRevision:'1',authTime:String(user.auth_time),issuer:user.iss,subject:user.sub,actorContext:{...user.identity_authorization},targetType:'group',targetId:randomUUID(),membershipId:randomUUID()});
 await expect(authority.read('Bearer original',user)).resolves.toEqual(source);source.scope.grants[0].source.mfaRevision='2';await expect(authority.read('Bearer original',user)).rejects.toMatchObject({status:503});
});
test('recipient and local device association versions are bound without accepting browser scope overrides',async()=>{
 const recipient=randomUUID(),selected={deviceId:randomUUID(),deviceRevision:'9007199254740993',revision:'5',ou:{id:child,generation:'4'}};source.target={id:recipient,revision:'6',enabled:false};source.scope.resource=selected;
 await expect(authority.read('Bearer original',user,recipient,selected)).resolves.toEqual(source);expect(JSON.parse(fetchImpl.mock.calls[0][1].body)).toEqual({userId:recipient,device:selected});
 await expect(authority.read('Bearer original',user,recipient,{...selected,revision:'6'})).rejects.toMatchObject({status:503});
 await expect(authority.read('Bearer original',user,recipient,{...selected,tenantId:source.tenant.id})).rejects.toMatchObject({status:400});
});
test('read proofs cannot be reused as a bound device proof or for another recipient',async()=>{
 await expect(authority.read('Bearer original',user,null,{deviceId:randomUUID(),deviceRevision:'1',revision:'0',ou:null})).rejects.toMatchObject({status:503});await expect(authority.read('Bearer original',user,randomUUID())).rejects.toMatchObject({status:503});
});
test('scoped compliance is independently bound and cannot grant tenant policy management',async()=>{
 source.permissions=['devices.compliance.read'];source.scope.grants[0].permission='devices.compliance.read';const compliance=new InventoryAuthority({scoped:true,compliance:true,endpoint:'https://identity.test/api/identity/device-compliance',fetchImpl});
 await expect(compliance.read('Bearer original',user)).resolves.toEqual(source);expect(inventorySourceMatches(source,user,null,false,true)).toBe(false);
 source.permissions.push('devices.compliance.manage');source.scope.grants.push({permission:'devices.compliance.manage',source:{...source.scope.grants[0].source,id:randomUUID()}});await expect(compliance.read('Bearer original',user)).rejects.toMatchObject({status:503});
});
test('bounded grants units and complete response bodies fail without a wider fallback',async()=>{
 source.scope.units=Array.from({length:C.MAX_UNITS+1},()=>source.scope.units[0]);await expect(authority.read('Bearer original',user)).rejects.toMatchObject({status:503});
 source.scope.units=[{id:root,generation:'9007199254740993',roots:[root]}];source.scope.grants=Array.from({length:C.MAX_GRANTS+1},()=>source.scope.grants[0]);await expect(authority.read('Bearer original',user)).rejects.toMatchObject({status:503});
 fetchImpl.mockResolvedValue(Response.json({payload:'x'.repeat(262144)}));await expect(authority.read('Bearer original',user)).rejects.toMatchObject({status:503});expect(fetchImpl).toHaveBeenCalledTimes(3);
});
test('the original deadline cannot expire while a successful response is being read',async()=>{
 jest.useFakeTimers().setSystemTime(user.auth_time*1000);source.validUntil=user.auth_time+1;
 fetchImpl.mockImplementation(async()=>({status:200,headers:new Headers({'Content-Type':'application/json'}),body:(async function*(){jest.setSystemTime((user.auth_time+2)*1000);yield Buffer.from(JSON.stringify(source));})()}));
 await expect(authority.read('Bearer original',user)).rejects.toMatchObject({status:503});
});
