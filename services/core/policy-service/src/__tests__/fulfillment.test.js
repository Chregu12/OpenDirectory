'use strict';

const fs=require('fs'); const os=require('os'); const path=require('path'); const crypto=require('crypto');
const { GraphLicenseClient,observation }=require('../licenses/fulfillment/GraphLicenseClient');
const { configuration,WorkerIdentity }=require('../licenses/fulfillment/WorkerConfiguration');
const { ProviderStore }=require('../licenses/fulfillment/ProviderStore');
const { getLicensePermissions }=require('../middleware/licenseAccess');
const { plans }=require('../licenses/fulfillment/contracts');
const objectId=crypto.randomUUID(); const skuId=crypto.randomUUID();
const record=extra=>({ id:objectId,accountEnabled:true,assignedLicenses:[],licenseAssignmentStates:[],...extra });
function client(fetchImpl) { return new GraphLicenseClient({ tenantId:crypto.randomUUID(),clientId:crypto.randomUUID(),clientSecret:'private-owned-test-secret',fetchImpl }); }
test('provider administration, local seat management, adoption and retry are separate duties',()=>{
  expect(getLicensePermissions({ roles:['license-administrator'] }).some(permission=>permission.startsWith('licenses.fulfillment.'))).toBe(false);
  expect(getLicensePermissions({ roles:['license-provider-administrator'] })).toEqual(['licenses.fulfillment.read','licenses.fulfillment.configure','licenses.fulfillment.adopt']);
  expect(getLicensePermissions({ roles:['license-fulfillment-operator'] })).toEqual(['licenses.fulfillment.read','licenses.fulfillment.retry']);
  expect(getLicensePermissions({ roles:['license-administrator','license-provider-administrator'] })).toContain('licenses.fulfillment.configure');
  expect(getLicensePermissions({ scope:'licenses.fulfillment.configure',roles:['user'] })).toEqual([]);
});
test.each([{ actor_type:'application' },{ identity_authorization:undefined },{ roles:['license-administrator'] },{ amr:['pwd'] }])('provider configuration requires canonical human duty and real fresh MFA, not %j',patch=>{
  const userId=crypto.randomUUID(); const authTime=Math.floor(Date.now()/1000); const principal={ issuer:'https://issuer.test',subject:'human',userId,enabled:true };
  const user={ iss:principal.issuer,sub:principal.subject,actor_type:'user',roles:['license-provider-administrator'],identity_authorization:{ userId,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64) },
    auth_time:authTime,amr:['pwd','otp'],mfa_authorization:{ schemaVersion:1,userId,revision:'1',authTime,methods:['pwd','otp'] },...patch };
  expect(()=>new ProviderStore({}).actor(user,principal,'licenses.fulfillment.configure',true)).toThrow();
});
test('Graph transport uses only fixed tenant OAuth and one GUID user/SKU body, never caller-selected URLs or a human bearer',async()=>{
  const calls=[]; const graph=client(async(url,options)=>{
    calls.push({ url,options }); return Response.json(String(url).includes('/token')?{ token_type:'Bearer',access_token:'private-graph-access',expires_in:3600 }:options.method==='GET'?record():{ id:objectId });
  });
  const observed=await graph.inspect(objectId,skuId,[]); expect(observed.present).toBe(false);
  await graph.mutate(objectId,skuId,[],true,await graph.tokens.get(),crypto.randomUUID());
  expect(calls[0].url).toBe(`https://login.microsoftonline.com/${graph.tenantId}/oauth2/v2.0/token`);
  expect(new URLSearchParams(calls[0].options.body).get('scope')).toBe('https://graph.microsoft.com/.default');
  expect(calls[2].url).toBe(`https://graph.microsoft.com/v1.0/users/${objectId}/assignLicense`);
  expect(calls[2].options.redirect).toBe('manual'); expect(calls[2].options.headers.Authorization).toBe('Bearer private-graph-access');
  expect(JSON.parse(calls[2].options.body)).toEqual({ addLicenses:[{ skuId,disabledPlans:[] }],removeLicenses:[] });
});
test.each([{ assignedLicenses:undefined },{ licenseAssignmentStates:undefined },{ id:crypto.randomUUID() },{ accountEnabled:'true' },{ licenseAssignmentStates:[{ skuId,disabledPlans:[],state:'Active',error:null }] },{ assignedLicenses:[{ skuId,disabledPlans:[] },{ skuId,disabledPlans:[] }] }])('partial or mismatched Graph state cannot be interpreted as absence: %j',extra=>{
  expect(()=>observation(record(extra),objectId,skuId,[])).toThrow('graph_read_invalid_response');
});
test('direct and inherited state is explicit and errors never count as active provisioning',()=>{
  const data=record({ assignedLicenses:[{ skuId,disabledPlans:[] }],licenseAssignmentStates:[{ skuId,disabledPlans:[],assignedByGroup:null,state:'ActiveWithError',error:'CountViolation' }] });
  expect(observation(data,objectId,skuId,[])).toMatchObject({ present:true,direct:true,active:false,plansMatch:true,inherited:false });
  data.licenseAssignmentStates[0].assignedByGroup=crypto.randomUUID(); expect(observation(data,objectId,skuId,[])).toMatchObject({ direct:false,inherited:true,active:false });
});
test.each([202,207,302,408,409,500])('write HTTP %i is uncertain, not a completed license or an automatic retry',async status=>{
  const graph=client(async()=>Response.json({ id:objectId },{ status }));
  await expect(graph.mutate(objectId,skuId,[],true,'private-token',crypto.randomUUID())).rejects.toMatchObject({ uncertain:true });
});
test('invalid successful write JSON and another user id stay uncertain after dispatch',async()=>{
  const graph=client(async()=>Response.json({ id:crypto.randomUUID() })); await expect(graph.mutate(objectId,skuId,[],false,'private-token',crypto.randomUUID())).rejects.toMatchObject({ uncertain:true });
});
test('a real Graph assignment error is reported as failure with bounded observation, not endless successful provisioning',async()=>{
  const graph=client(async url=>Response.json(String(url).includes('/token')?{ access_token:'private-token',token_type:'Bearer',expires_in:3600 }:record({ assignedLicenses:[{ skuId,disabledPlans:[] }],licenseAssignmentStates:[{ skuId,disabledPlans:[],assignedByGroup:null,state:'Error',error:'CountViolation' }] })));
  await expect(graph.inspect(objectId,skuId,[])).rejects.toMatchObject({ code:'graph_assignment_error',observation:{ active:false,direct:true,present:true } });
});
test.each([['https://evil.test',skuId],['../users',skuId],[objectId,'anything-not-a-uuid']])('identifiers cannot choose an egress URL: %s %s',async(user,sku)=>{
  const fetchImpl=jest.fn(); await expect(client(fetchImpl).inspect(user,sku,[])).rejects.toThrow(); expect(fetchImpl).not.toHaveBeenCalled();
});
test('local workload tokens have only the fixed eligibility scope and never reach Graph',async()=>{
  const calls=[]; const identity=new WorkerIdentity({ sourceTokenUrl:'http://issuer.internal/oauth/token',sourceClientId:'owned-worker',sourceClientSecret:'private-local-credential',identityUrl:'http://identity.internal' },{ fetchImpl:async(url,options)=>{
    calls.push({ url:String(url),options }); return Response.json(String(url).endsWith('/oauth/token')?{ token_type:'Bearer',access_token:'private-local-access',expires_in:3600 }:{ schemaVersion:1,userId:objectId,revision:'1',enabled:true,deleted:false },String(url).endsWith('/oauth/token')?undefined:{headers:{'X-OD-License-Snapshot-Protocol':'1'}});
  } });
  expect((await identity.user(objectId)).enabled).toBe(true); expect(calls).toHaveLength(2);
  expect(new URLSearchParams(calls[0].options.body).get('scope')).toBe('licenses.users.read'); expect(calls[1].options.headers.Authorization).toBe('Bearer private-local-access');
  expect(calls.every(call=>!call.url.includes('graph.microsoft.com'))).toBe(true);
});
test('worker secrets are file-only, owner protected, nonsymlinked and explicit; no file contains a browser bearer',()=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'od-fulfillment-config-')); const filename=path.join(directory,'worker.json');
  const data={ enabled:true,connectorId:crypto.randomUUID(),tenantId:crypto.randomUUID(),graphClientId:crypto.randomUUID(),graphClientSecret:'private-graph-secret',sourceClientId:'owned-worker',sourceClientSecret:'private-local-secret',sourceTokenUrl:'http://issuer.internal/oauth/token',identityUrl:'http://identity.internal/' };
  try {
    fs.writeFileSync(filename,JSON.stringify(data),{ mode:0o600 }); expect(configuration(filename).tenantId).toBe(data.tenantId);
    fs.chmodSync(filename,0o640); expect(()=>configuration(filename)).toThrow(); fs.chmodSync(filename,0o600);
    const alias=path.join(directory,'alias'); fs.symlinkSync(filename,alias); expect(()=>configuration(alias)).toThrow();
    fs.writeFileSync(filename,JSON.stringify({ ...data,enabled:false })); expect(()=>configuration(filename)).toThrow();
    fs.writeFileSync(filename,JSON.stringify({ ...data,graphApiUrl:'https://evil.test' })); expect(()=>configuration(filename)).toThrow();
  } finally { fs.rmSync(directory,{ recursive:true,force:true }); }
});
test.each([[['bad']],[[skuId,skuId]],[['ffffffff-ffff-ffff-ffff-ffffffffffff','00000000-0000-0000-0000-000000000000']]])('plan identifiers must be bounded canonical sorted unique values: %j',value=>expect(()=>plans(value)).toThrow());
