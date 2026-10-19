'use strict';

const crypto = require('crypto');
const { createTenantStateClient } = require('../../../../../packages/oidc-tenant-state');
const { validTenantContext, sameTenantContext } = require('../../../../../packages/tenant-authorization-contract');
const context = { userId:crypto.randomUUID(),revision:'1',linkRevision:'2',rolesRevision:'a'.repeat(64) };
const tenant = { id:crypto.randomUUID(),version:'2',generation:'7' };
const expected = { iss:'https://issuer.test',sub:'original',jti:crypto.randomUUID(),exp:Math.floor(Date.now()/1000)+300,actor_type:'user',identity_authorization:context };
const state = () => ({ schemaVersion:1,active:true,issuer:expected.iss,subject:expected.sub,tokenId:expected.jti,expiresAt:expected.exp,context,tenant });
let fetchImpl; let verify;
beforeEach(() => { fetchImpl=jest.fn(async()=>Response.json(state()));verify=createTenantStateClient({ fetchImpl }); });

test('only the original human token determines tenant ownership and no profile, role or bearer is returned',async()=>{
  expect(await verify('Bearer original.token',expected)).toEqual(tenant);
  const [url,options]=fetchImpl.mock.calls[0];expect(url.pathname).toBe('/oauth/tenant-state');expect(options).toMatchObject({ method:'GET',redirect:'error',cache:'no-store',headers:{ Authorization:'Bearer original.token' } });
  expect(options.body).toBeUndefined();expect(validTenantContext(tenant)).toBe(true);expect(sameTenantContext(tenant,{...tenant,generation:'8'})).toBe(false);
});
test.each([{ issuer:'https://foreign.test' },{ subject:'foreign' },{ tokenId:crypto.randomUUID() },{ expiresAt:expected.exp+1 },
  { context:{...context,userId:crypto.randomUUID()} },{ context:{...context,revision:'2'} },{ schemaVersion:0 },{ active:'true' },
  { tenant:undefined },{ tenant:{...tenant,version:0} },{ tenant:{...tenant,generation:'0'} },{ tenant:{...tenant,ignored:true} },{ profile:{email:'private'} }])('rejects a mismatched, down-level or overbroad proof: %j',async change=>{
  fetchImpl.mockImplementation(async()=>Response.json({...state(),...change}));await expect(verify('Bearer original.token',expected)).rejects.toMatchObject({status:503});
});
test.each([{ actor_type:'application' },{ identity_authorization:undefined },{ jti:'' },{ iss:'' }])('a workload or unbound legacy token cannot invent a tenant: %j',async change=>{
  await expect(verify('Bearer original.token',{...expected,...change})).rejects.toMatchObject({status:401});expect(fetchImpl).not.toHaveBeenCalled();
});
test.each(['https://authority.test/oauth/tenant-state?tenant=other','https://user:secret@authority.test/oauth/tenant-state','file:///tmp/proof','https://authority.test/oauth/access-state'])('configuration cannot redirect the proof to another path or caller-selected tenant: %s',endpoint=>{
  expect(()=>createTenantStateClient({endpoint})).toThrow();
});
test('negative authority and unavailable authority stay distinct and neither has a cache or fallback',async()=>{
  fetchImpl.mockResolvedValueOnce(Response.json({schemaVersion:1,active:false}));await expect(verify('Bearer original.token',expected)).rejects.toMatchObject({status:401});
  fetchImpl.mockResolvedValueOnce(Response.json({}, {status:403}));await expect(verify('Bearer original.token',expected)).rejects.toMatchObject({status:401});
  fetchImpl.mockRejectedValueOnce(new Error('offline'));await expect(verify('Bearer original.token',expected)).rejects.toMatchObject({status:503});
  expect(await verify('Bearer original.token',expected)).toEqual(tenant);expect(fetchImpl).toHaveBeenCalledTimes(4);
});
test('oversized bodies, wrong media types, physical expiry and stalled authorities fail closed',async()=>{
  for(const response of [Response.json({...state(),padding:'x'.repeat(4096)}),new Response('not json')]){fetchImpl.mockResolvedValueOnce(response);await expect(verify('Bearer original.token',expected)).rejects.toMatchObject({status:503});}
  const expired={...expected,exp:Math.floor(Date.now()/1000)-1};fetchImpl.mockResolvedValueOnce(Response.json({...state(),expiresAt:expired.exp}));await expect(verify('Bearer original.token',expired)).rejects.toMatchObject({status:503});
  const stalled=createTenantStateClient({timeoutMs:10,fetchImpl:(_url,options)=>new Promise((_resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))))});
  await expect(stalled('Bearer original.token',expected)).rejects.toMatchObject({status:503});
});
