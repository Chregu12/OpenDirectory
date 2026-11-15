'use strict';
const { randomUUID } = require('node:crypto');
const { DeviceOuSource } = require('../DeviceOuSource');
const C = require('../../../../../packages/device-ou-contract');
let user,inventory,ou,resource,proof,fetchImpl,client;
beforeEach(()=>{
 const now=Math.floor(Date.now()/1000),actor=randomUUID(),root='11111111-1111-4111-8111-111111111111';
 user={actor_type:'user',iss:'https://ou-scopes.test',sub:'original',jti:randomUUID(),exp:now+600,auth_time:now,identity_authorization:{userId:actor,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64)},amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId:actor,revision:'1',authTime:now,methods:['pwd','otp']}};
 ou={id:root,generation:'9007199254740993',revision:'9007199254740994',name:'Original scoped unit',parentId:null};
 resource={deviceId:randomUUID(),deviceRevision:'9007199254740995',revision:'4',ou:{id:root,generation:ou.generation}};
 inventory={schemaVersion:2,issuer:user.iss,subject:user.sub,tokenId:user.jti,expiresAt:user.exp,context:{...user.identity_authorization},tenant:{id:randomUUID(),version:'1',generation:'1'},actorUserId:actor,permissions:['devices.inventory.read','devices.inventory.create'],validUntil:now+90,target:null,
  scope:{protocol:1,inherent:[],grants:['devices.inventory.read','devices.inventory.create'].map(permission=>({permission,source:{id:randomUUID(),roleId:randomUUID(),roleRevision:'1',scopeType:'device-ou',ouId:root,ouGeneration:ou.generation,targetType:'user',targetId:actor,membershipId:null,validUntil:String(now+90)}})),units:[{id:root,generation:ou.generation,roots:[root]}],resource}};
 proof={schemaVersion:2,deviceOuProtocol:2,inventory,ou,directoryGrant:null,validUntil:inventory.validUntil};
 fetchImpl=jest.fn(async()=>Response.json(proof));client=new DeviceOuSource({scoped:true,endpoint:'https://identity.test/api/identity/device-organizational-units',fetchImpl});
});
test('a scoped OU proof retains the exact normal inventory resource and genuine protocol without coercion',async()=>{
 await expect(client.read('Bearer original',user,ou.id,resource)).resolves.toEqual(proof);
 expect(fetchImpl.mock.calls[0][1]).toMatchObject({body:JSON.stringify({ouId:ou.id,device:resource}),headers:{Authorization:'Bearer original','X-OD-Device-Scope-Protocol':'1'},redirect:'error',cache:'no-store'});
 await expect(new DeviceOuSource({endpoint:'https://identity.test/api/identity/device-organizational-units',fetchImpl}).read('Bearer original',user,ou.id)).rejects.toMatchObject({status:503});
});
test.each(['legacy wrapper','protocol','different resource','targeted core','outside OU','generation','no read','no stock','expired','unknown field','source identity'])('scoped OU source refuses %s',async change=>{
 if(change==='legacy wrapper'){proof.schemaVersion=1;proof.deviceOuProtocol=1;}
 if(change==='protocol')proof.deviceOuProtocol=1;
 if(change==='different resource')inventory.scope.resource={...resource,revision:'5'};
 if(change==='targeted core')inventory.target={id:randomUUID(),revision:'1',enabled:true};
 if(change==='outside OU')ou.id=randomUUID();
 if(change==='generation')ou.generation='9007199254740992';
 if(change==='no read'){inventory.permissions.shift();inventory.scope.grants.shift();}
 if(change==='no stock'){inventory.permissions.pop();inventory.scope.grants.pop();}
 if(change==='expired')proof.validUntil=user.auth_time-1;
 if(change==='unknown field')proof.override=true;
 if(change==='source identity')inventory.tokenId=randomUUID();
 await expect(client.read('Bearer original',user,ou.id,resource)).rejects.toMatchObject({status:503});
});
test('clearing a scoped source requires independent read and stock duties over unassigned resources',async()=>{
 proof.ou=null;await expect(client.read('Bearer original',user,null,resource)).rejects.toMatchObject({status:503});
 inventory.scope.inherent=['devices.inventory.read','devices.inventory.create'];await expect(client.read('Bearer original',user,null,resource)).resolves.toEqual(proof);
});
function choices(){inventory.scope.resource=null;return{schemaVersion:2,deviceOuProtocol:2,inventory,directoryGrant:null,validUntil:inventory.validUntil,coverage:'scope',units:[ou],total:1,page:1,limit:25};}
test('scoped candidate transport retains the original private source for the final Device checkpoint',async()=>{
 const value=choices();fetchImpl.mockImplementation(async()=>Response.json(value));
 const result=await client.units('Bearer original',user,inventory.tenant.id,{},inventory);
 expect(result).toEqual(value);expect(C.validChoices(value,user)).toBe(true);
});
test.each(['coverage','hidden unit','total','page','actor','directory','original source','unknown private field'])('scoped candidate transport refuses %s',async change=>{
 const value=choices(),original=structuredClone(inventory);fetchImpl.mockImplementation(async()=>Response.json(value));
 if(change==='coverage')value.coverage='tenant';
 if(change==='hidden unit')value.units=[{...ou,id:randomUUID()}];
 if(change==='total')value.total=2;
 if(change==='page')value.page=2;
 if(change==='actor')value.inventory.actorUserId=randomUUID();
 if(change==='directory')value.directoryGrant={};
 if(change==='original source')value.inventory.tokenId=randomUUID();
 if(change==='unknown private field')value.tenantOverride=randomUUID();
 await expect(client.units('Bearer original',user,original.tenant.id,{},original)).rejects.toMatchObject({status:503});
});
test('the canonical API distinguishes public scoped choices from original private sources and preserves legacy schemas',()=>{
 const api=JSON.parse(require('node:fs').readFileSync(require('node:path').resolve(__dirname,'../../../../../docs/api/openapi.yaml'),'utf8'));
 const generated=require('../../scripts/device-ou-openapi').deviceOuOpenApi();
 for(const name of ['DeviceOuScopedAuthority','DeviceOuScopedReceipt','DeviceOuScopedChoices','DeviceOuScopedChoicesAuthority'])expect(api.components.schemas[name]).toEqual(generated.components.schemas[name]);
 const schemas=api.components.schemas;expect(schemas.DeviceOuAuthority.properties.inventory).toEqual({$ref:'#/components/schemas/InventoryAuthoritySource'});expect(schemas.DeviceOuReceipt.properties.schemaVersion).toEqual({const:1});
 expect(schemas.DeviceOuScopedChoices.required).toHaveLength(10);expect(schemas.DeviceOuScopedChoices.properties.inventory).toBeUndefined();expect(schemas.DeviceOuScopedChoices.properties.directoryGrant).toBeUndefined();expect(schemas.DeviceOuScopedChoicesAuthority.required).toHaveLength(10);
 for(const operation of Object.values(api.paths['/api/identity/device-organizational-units']))expect(operation.parameters).toContainEqual(expect.objectContaining({name:'X-OD-Device-Scope-Protocol',schema:{const:'1'}}));
});
test('an upgraded OU receiver requires actual SQL protocol two and cannot fall back to the old database probe',async()=>{
 const {DeviceOrganizationalUnits}=require('../DeviceOrganizationalUnits');
 const service=new DeviceOrganizationalUnits({}, {inventory:{authority:{scoped:true}},authority:{scoped:true}}),database={query:jest.fn().mockRejectedValue(Object.assign(new Error('Previous database has no protocol two receiver'),{code:'42883'}))};
 await expect(service.receiving(database)).rejects.toMatchObject({status:503});expect(database.query).toHaveBeenCalledTimes(1);expect(database.query).toHaveBeenCalledWith('SELECT device_ou_receiving(2)');
});
