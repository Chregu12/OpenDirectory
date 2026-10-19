'use strict';

jest.mock('../AuthorityTenant',()=>({authorityTenant:jest.fn()}));
const {randomUUID}=require('node:crypto');
const express=require('express');
const request=require('supertest');
const {authorityTenant}=require('../AuthorityTenant');
const {GroupSourceGrants}=require('../GroupSourceGrants');
const {groupSourceGrantRoutes}=require('../GroupSourceGrantRoutes');
const {SOURCE_SCOPE}=require('../../../../../packages/group-license-lease-contract');
const tenantId=randomUUID();const groupId=randomUUID();const grantId=randomUUID();const authorization='Bearer original-consent-operator';
let user;let grant;let client;let database;let store;let revalidate;
beforeEach(()=>{
 jest.clearAllMocks();const userId=randomUUID();const authTime=Math.floor(Date.now()/1000);
 user={actor_type:'user',iss:'https://source.test',sub:'original-human',client_id:'human-console',roles:['license-scope-administrator'],identity_authorization:{userId,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64)},auth_time:authTime,amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId,revision:'1',authTime,methods:['pwd','otp']}};
 grant={id:grantId,group_id:groupId,issuer:user.iss,client_id:'exact-source',client_revision:'2',version:'1',created_by:userId,created_at:new Date(),expires_at:new Date(Date.now()+3600000),revoked_at:null,observed_at:new Date(),target_tenant_id:tenantId,target_tenant_version:'3',target_tenant_generation:'7',target_tenant_enabled:true};
 client={query:jest.fn(async sql=>({rows:sql.startsWith('SELECT 1 WHERE')?[{allowed:true}]:[grant]}))};database={transaction:jest.fn(operation=>operation(client))};
 revalidate=jest.fn(async(_user,bearer)=>{if(bearer!==authorization)throw Object.assign(new Error('Original bearer required'),{status:401});});
 store=new GroupSourceGrants(database,{revalidate,clients:{issuer:user.iss}});store.identity.currentActor=jest.fn();authorityTenant.mockResolvedValue(tenantId);
});
test.each(['list','get'])('human %s revalidates the original bearer and actual read permission before and after SQL',async method=>{
 const result=await store[method](method==='list'?groupId:grantId,user,authorization);expect(result).toBeDefined();
 expect(store.identity.currentActor).toHaveBeenCalledTimes(2);expect(store.identity.currentActor).toHaveBeenCalledWith(client,user,'licenses.sources.read');
 expect(revalidate.mock.calls).toEqual([[user,authorization],[user,authorization]]);expect(authorityTenant).toHaveBeenCalledWith(client,{...user.identity_authorization,issuer:user.iss,subject:user.sub},{write:false});
 expect(database.transaction).toHaveBeenCalledWith(expect.any(Function),{readOnly:true});
});
test('foreign group list is rejected before reading any consent rows',async()=>{
 client.query.mockResolvedValueOnce({rows:[]});await expect(store.list(groupId,user,authorization)).rejects.toMatchObject({status:404});
 expect(client.query).toHaveBeenCalledTimes(1);expect(client.query.mock.calls[0][1]).toEqual([groupId,tenantId]);
});
test('known consent lookup includes retained group ownership in its initial SQL',async()=>{
 await store.get(grantId,user,authorization);const [sql,values]=client.query.mock.calls[0];
 expect(sql).toContain('JOIN identity_tenant_ownership ownership');expect(sql).toContain("ownership.resource_kind='group'");expect(sql).toContain('ownership.tenant_id=$3');expect(values).toEqual([grantId,user.iss,tenantId]);
});
test.each(['list','get'])('human %s cannot fall back when the original bearer is missing',async method=>{
 await expect(store[method](method==='list'?groupId:grantId,user)).rejects.toMatchObject({status:401});expect(client.query).not.toHaveBeenCalled();
});
test('claimed source permissions cannot replace a failed current-actor check',async()=>{
 store.identity.currentActor.mockRejectedValue(Object.assign(new Error('Actual source duty withdrawn'),{status:401}));
 await expect(store.list(groupId,{...user,permissions:['licenses.sources.read']},authorization)).rejects.toMatchObject({status:401});expect(client.query).not.toHaveBeenCalled();expect(authorityTenant).not.toHaveBeenCalled();
});
test.each(['list','get'])('human %s discards rows when final original-token verification fails',async method=>{
 revalidate.mockResolvedValueOnce().mockRejectedValueOnce(Object.assign(new Error('Original token revoked'),{status:401}));
 await expect(store[method](method==='list'?groupId:grantId,user,authorization)).rejects.toMatchObject({status:401});
});
function workload(){return{actor_type:'application',token_use:'access',iss:user.iss,sub:grant.client_id,client_id:grant.client_id,client_revision:'2',scope:SOURCE_SCOPE,permissions:[SOURCE_SCOPE]};}
function sourceSnapshots(between=()=>{}){store.snapshots={snapshot:jest.fn(async(_groupId,viewer,{authorize})=>{expect(viewer).toBeNull();const first=await authorize(client);await between();const second=await authorize(client);expect(second).toEqual(first);return{sourceAuthorization:second};})};}
test('explicit workload consent uses retained creator/group ownership without requiring a human home or widening its DTO',async()=>{
 sourceSnapshots();const result=await store.snapshot(groupId,workload(),authorization);expect(Object.keys(result.sourceAuthorization)).toHaveLength(6);
 expect(result.sourceAuthorization).toEqual({grantId,version:'1',issuer:user.iss,clientId:grant.client_id,clientRevision:'2',expiresAt:grant.expires_at.toISOString()});
 expect(authorityTenant).not.toHaveBeenCalled();expect(store.identity.currentActor).not.toHaveBeenCalled();expect(client.query.mock.calls[0][0]).toContain("tenant.id=identity_tenant_id('user',grants.created_by)");expect(client.query.mock.calls[0][0]).toContain("tenant.id=identity_tenant_id('group',grants.group_id)");
});
test.each([{target_tenant_version:'4'},{target_tenant_generation:'8'},{target_tenant_enabled:false}])('a target tenant change between consent authorizations discards the frame: %j',async change=>{
 sourceSnapshots(()=>Object.assign(grant,change));await expect(store.snapshot(groupId,workload(),authorization)).rejects.toMatchObject({status:409,code:'source_target_tenant_changed'});
});
test('an initially disabled target tenant remains authorized for negative hygiene',async()=>{
 grant.target_tenant_enabled=false;sourceSnapshots();await expect(store.snapshot(groupId,workload(),authorization)).resolves.toHaveProperty('sourceAuthorization.grantId',grantId);
});
test('missing historical creator/group ownership denies workload consent before another snapshot authorization',async()=>{
 client.query.mockResolvedValue({rows:[]});sourceSnapshots();await expect(store.snapshot(groupId,workload(),authorization)).rejects.toMatchObject({status:403});expect(client.query).toHaveBeenCalledTimes(1);
});
test('current source API forwards the original authorization argument to human list and get',async()=>{
 const apiStore={list:jest.fn(async()=>({grants:[]})),get:jest.fn(async()=>({id:grantId,version:'1'}))};const app=express();
 app.use((req,_res,next)=>{req.user=user;next();});app.use('/sources',groupSourceGrantRoutes(apiStore));
 expect((await request(app).get('/sources/groups/'+groupId).set('Authorization',authorization)).status).toBe(200);expect(apiStore.list).toHaveBeenCalledWith(groupId,user,authorization);
 expect((await request(app).get('/sources/'+grantId).set('Authorization',authorization)).status).toBe(200);expect(apiStore.get).toHaveBeenCalledWith(grantId,user,authorization);
});
