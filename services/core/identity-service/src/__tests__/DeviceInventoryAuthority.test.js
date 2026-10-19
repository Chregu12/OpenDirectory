'use strict';
const {randomUUID}=require('node:crypto');
jest.mock('../AuthorizationState',()=>({AuthorizationState:jest.fn()}));jest.mock('../CompanyOwner',()=>({companyOwner:jest.fn()}));
const {AuthorizationState}=require('../AuthorizationState');const {companyOwner}=require('../CompanyOwner');const {DeviceInventoryAuthority}=require('../DeviceInventoryAuthority');
const {INVENTORY_PERMISSIONS}=require('../../../../../packages/device-inventory-contract');
const userId=randomUUID();const tenant={id:randomUUID(),version:'1',generation:'1'};const context={userId,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64)};
let user;let state;let query;let revalidate;let database;let authority;
beforeEach(()=>{
  jest.clearAllMocks();
  const now=Math.floor(Date.now()/1000);user={iss:'https://inventory.test',sub:'original-owner',jti:randomUUID(),actor_type:'user',exp:now+600,auth_time:now,amr:['pwd','otp'],identity_authorization:context,mfa_authorization:{schemaVersion:1,userId,revision:'1',authTime:now,methods:['pwd','otp']},roles:['admin'],permissions:['devices.inventory.assign']};
  state={active:true,context,tenant,roles:[],authentication:{required:true,maxAgeSeconds:300}};AuthorizationState.mockImplementation(()=>({state:jest.fn(async()=>state)}));companyOwner.mockResolvedValue({tenant_id:tenant.id});
  query=jest.fn(async()=>({rows:[]}));database={isAvailable:()=>true,transaction:async callback=>callback({query})};revalidate=jest.fn(async()=>tenant);authority=new DeviceInventoryAuthority(database,{issuer:user.iss,revalidate});
});
test('actual roleless company ownership supplies only three own-inventory duties and original MFA deadline',async()=>{
  const source=await authority.read(user,'Bearer original');expect(source.permissions).toEqual(INVENTORY_PERMISSIONS);expect(source.actorUserId).toBe(userId);expect(source.validUntil).toBe(user.auth_time+300);expect(source.target).toBeNull();expect(source.tenant).toEqual(tenant);expect(companyOwner).toHaveBeenCalled();expect(revalidate).toHaveBeenCalledTimes(2);
});
test('claimed admin or permissions cannot replace actual canonical owner or administrative source',async()=>{companyOwner.mockResolvedValue(null);await expect(authority.read(user,'Bearer original')).rejects.toMatchObject({status:403});expect(query).not.toHaveBeenCalled();});
test('actual canonical administrative source is still restricted to its actual home tenant',async()=>{state.roles=['admin'];const source=await authority.read(user,'Bearer original');expect(source.tenant).toEqual(tenant);expect(companyOwner).not.toHaveBeenCalled();});
test('recipient projection is exact current own canonical identity, including disabled records',async()=>{const target=randomUUID();query.mockResolvedValue({rows:[{id:target,authorization_revision:'9007199254740993',enabled:false}]});const source=await authority.read(user,'Bearer original',{userId:target});expect(source.target).toEqual({id:target,revision:'9007199254740993',enabled:false});expect(query).toHaveBeenCalledWith(expect.stringContaining("identity_tenant_id('user',id)=$2"),[target,tenant.id]);});
test('foreign or missing canonical recipient is not found',async()=>{await expect(authority.read(user,'Bearer original',{userId:randomUUID()})).rejects.toMatchObject({status:404});});
test.each([{},[],{userId:'name'},{userId,tenantId:tenant.id}])('recipient selector rejects unsupported shape %j',async body=>{await expect(authority.read(user,'Bearer original',body)).rejects.toMatchObject({status:400});expect(revalidate).not.toHaveBeenCalled();});
test('independently bound fresh MFA is mandatory even for reads and claimed admins',async()=>{user.auth_time-=301;await expect(authority.read(user,'Bearer original')).rejects.toMatchObject({status:428});expect(query).not.toHaveBeenCalled();});
test('an actual canonical source change invalidates a previously valid original bearer',async()=>{state.context={...context,revision:'2'};await expect(authority.read(user,'Bearer original')).rejects.toMatchObject({status:401});});
test('a longer canonical MFA policy cannot extend the inventory deadline and malformed policies fail closed',async()=>{state.authentication.maxAgeSeconds=86400;expect((await authority.read(user,'Bearer original')).validUntil).toBe(user.auth_time+300);state.authentication.maxAgeSeconds=0;await expect(authority.read(user,'Bearer original')).rejects.toMatchObject({status:401});});
test('a changed tenant after canonical SQL prevents releasing an authority response',async()=>{revalidate.mockResolvedValueOnce(tenant).mockResolvedValueOnce({...tenant,generation:'2'});await expect(authority.read(user,'Bearer original')).rejects.toMatchObject({status:401});});
test('workload or unconfirmed storage never acquires inventory authority',async()=>{await expect(authority.read({...user,actor_type:'application'},'Bearer original')).rejects.toMatchObject({status:403});database.isAvailable=()=>false;await expect(authority.read(user,'Bearer original')).rejects.toMatchObject({status:503});});
