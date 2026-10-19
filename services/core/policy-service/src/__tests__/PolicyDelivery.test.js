'use strict';

const { EventEmitter } = require('node:events');
const { randomUUID } = require('node:crypto');
const { PolicyDelivery } = require('../PolicyDelivery');
const userId = randomUUID();
function fixture(options = {}) {
  const authTime = Math.floor(Date.now() / 1000);
  const claims = { actor_type: 'user', sub: 'operator', jti: randomUUID(), exp: authTime + 3600, roles: ['policy-deployment-operator'],
    identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', methods: ['pwd', 'otp'], authTime } };
  const req = { verifiedAccess: { authorization: 'Bearer original.actor.signature', claims }, headers: { authorization: 'Bearer untrusted.changed.header', 'x-oauth-internal-token': 'must-not-be-used' } };
  req.policyDeliverySource={resourceKind:'policy',resourceId:randomUUID(),resourceVersion:2,publicationId:randomUUID()};
  req.policyPublicationBinding={configurationVersion:1,configurationHash:'a'.repeat(64),version:2};
  req.policyCommandPayloads={gpo:{gpoId:req.policyDeliverySource.resourceId,gpoName:'Owned GPO',configurationVersion:2,settings:{firewall:true}}};
  const res = new EventEmitter(); const authority = jest.fn().mockResolvedValue(undefined);
  const fetchImpl = jest.fn().mockImplementation(async () => Response.json([]));
  const transport = new PolicyDelivery({ authority, fetchImpl, deviceUrl: 'http://devices.test:3010', certificateUrl: 'http://certificates.test', ...options });
  const protocol={schemaVersion:1,commandContract:'approved-content-v1',receiptContract:'postgres-evidence-v1',admissionMaxSeconds:30,deliveryMaxSeconds:300,subject:claims.sub,userId,freshMfa:true};
  const handshake=async()=>{fetchImpl.mockResolvedValueOnce(Response.json(protocol));return transport.request(req,res,'devices','/api/devices/policy-command-access');};
  return { req, res, authority, fetchImpl, transport, protocol, handshake, reference:{...req.policyDeliverySource,configurationId:null}, read: () => transport.request(req, res, 'devices', '/api/devices/registry') };
}
function accepted(current,deviceId='known-device'){
 const id=randomUUID();return{id,command:'update_policy',status:'pending',payload:current.req.policyCommandPayloads.gpo,enforcementConfirmed:false,
  policyReceipt:{schemaVersion:1,commandId:id,operationId:current.transport.context(current.req,current.res).operationId,deviceId,deviceGeneration:'1',operatorUserId:userId,
   reference:current.reference,configurationVersion:1,configurationHash:'a'.repeat(64),publicationVersion:2,payloadHash:'b'.repeat(64),expiresAt:new Date(Date.now()+30000).toISOString(),persistence:'committed'}};
}

test('forwards only the original verified operator and checks live authority around a bounded receiver call', async () => {
  const current = fixture(); await current.read();
  expect(current.authority).toHaveBeenCalledTimes(2); expect(current.authority).toHaveBeenNthCalledWith(1, 'Bearer original.actor.signature', current.req.verifiedAccess.claims);
  expect(current.fetchImpl).toHaveBeenCalledWith('http://devices.test:3010/api/devices/registry', expect.objectContaining({ redirect: 'error', cache: 'no-store', headers: expect.objectContaining({ Authorization: 'Bearer original.actor.signature' }) }));
  expect(current.fetchImpl.mock.calls[0][1].headers).not.toHaveProperty('x-oauth-internal-token');
});
test.each([401, 403, 428, 503])('authority status %s stops before the next HTTP side effect', async status => {
  const current = fixture(); current.authority.mockRejectedValue(Object.assign(new Error('Owned authority denial'), { status }));
  await expect(current.read()).rejects.toMatchObject({ status, deliveryMayHaveOccurred: false }); expect(current.fetchImpl).not.toHaveBeenCalled();
});
test('a post-response revocation reports uncertainty and cannot send a subsequent command', async () => {
  const current = fixture(); current.authority.mockResolvedValueOnce(undefined).mockRejectedValueOnce(Object.assign(new Error('Revoked'), { status: 401 }));
  await expect(current.read()).rejects.toMatchObject({ status: 401, deliveryMayHaveOccurred: true });
  await expect(current.read()).rejects.toMatchObject({ status: 503, deliveryMayHaveOccurred: false }); expect(current.fetchImpl).toHaveBeenCalledTimes(1);
});
test.each([401, 403, 429, 503])('receiver rejection %s has no ambient-token fallback or write retry', async status => {
  const current = fixture(); current.fetchImpl.mockResolvedValue(Response.json({}, { status }));
  await expect(current.read()).rejects.toMatchObject({ status: [401, 403].includes(status) ? status : 502 }); expect(current.fetchImpl).toHaveBeenCalledTimes(1);
});
test.each(['/api/devices/../commands', '/api/devices/%2e%2e/commands', '/api/devices/a%2fb/commands', '/api/devices/id/commands?admin=true', '//other.test/api/devices/registry'])('rejects a path-changing delivery target: %s', async pathname => {
  const current = fixture(); await expect(current.transport.request(current.req, current.res, 'devices', pathname, { method: 'POST', body: {} })).rejects.toMatchObject({ status: 403 }); expect(current.fetchImpl).not.toHaveBeenCalled();
});
test('a late response after the actual request closes cannot continue delivery', async () => {
  const current = fixture(); let release; current.fetchImpl.mockImplementation(() => new Promise(resolve => { release = resolve; }));
  const pending = current.read(); while (!release) await new Promise(resolve => setImmediate(resolve));
  current.res.emit('close'); release(Response.json([])); await expect(pending).rejects.toMatchObject({ deliveryMayHaveOccurred: true });
  await expect(current.read()).rejects.toMatchObject({ deliveryMayHaveOccurred: false }); expect(current.fetchImpl).toHaveBeenCalledTimes(1);
});
test.each([Response.json({ devices: [] }), new Response('<html>bad</html>', { headers: { 'Content-Type': 'text/html' } }), Response.json([{ id: '../escape' }])])('rejects malformed inventory rather than treating an outage as an empty fleet', async response => {
  const current = fixture(); current.fetchImpl.mockResolvedValue(response); await expect(current.read()).rejects.toMatchObject({ status: 503 });
});
test('only a genuine pending command receipt confirms queuing, not device enforcement', async () => {
  const current = fixture();await current.handshake(); const receipt = accepted(current);
  current.fetchImpl.mockResolvedValueOnce(Response.json(receipt, { status: 201 }));
  expect((await current.transport.request(current.req, current.res, 'devices', '/api/devices/known-device/commands', { method: 'POST', body: { command: 'update_policy', reference:current.reference } })).body).toEqual(receipt);
  current.fetchImpl.mockResolvedValueOnce(Response.json({ success: true }));
  await expect(current.transport.request(current.req, current.res, 'devices', '/api/devices/known-device/commands', { method: 'POST', body: { command: 'update_policy',reference:current.reference } })).rejects.toMatchObject({ deliveryMayHaveOccurred: true });
});
test('an oversized response is uncertain and closes the operation without reading or replaying another target', async () => {
  const current = fixture(); current.fetchImpl.mockResolvedValue(Response.json({ oversized: 'x'.repeat(2 * 1024 * 1024) }));
  await expect(current.read()).rejects.toMatchObject({ status: 503, deliveryMayHaveOccurred: true });
  await expect(current.read()).rejects.toMatchObject({ deliveryMayHaveOccurred: false }); expect(current.fetchImpl).toHaveBeenCalledTimes(1);
});
test('the bounded fetch timeout aborts the actual request signal and latches delivery failure', async () => {
  const current = fixture({ timeoutMs: 10 }); let signal;
  current.fetchImpl.mockImplementation((url, options) => new Promise((resolve, reject) => { signal = options.signal; signal.addEventListener('abort', () => reject(new Error('Owned HTTP timeout')), { once: true }); }));
  await expect(current.read()).rejects.toMatchObject({ status: 503, deliveryMayHaveOccurred: true }); expect(signal.aborted).toBe(true);
  await expect(current.read()).rejects.toMatchObject({ deliveryMayHaveOccurred: false }); expect(current.fetchImpl).toHaveBeenCalledTimes(1);
});
test('an accepted earlier write remains explicit uncertainty when the next captured configuration check fails before HTTP',async()=>{
 const current=fixture();current.req.policyConfigurationCheck=jest.fn().mockResolvedValue(undefined);await current.handshake();current.fetchImpl.mockResolvedValue(Response.json(accepted(current,'owned-device'),{status:201}));
 await current.transport.request(current.req,current.res,'devices','/api/devices/owned-device/commands',{method:'POST',body:{command:'update_policy',reference:current.reference}});current.req.policyConfigurationCheck.mockRejectedValue(Object.assign(new Error('Owned changed version'),{status:412}));
 await expect(current.transport.request(current.req,current.res,'devices','/api/devices/owned-device/commands',{method:'POST',body:{command:'update_policy',reference:current.reference}})).rejects.toMatchObject({status:412,deliveryMayHaveOccurred:true});expect(current.fetchImpl).toHaveBeenCalledTimes(2);
});
test('an older receiver is rejected during read-only preflight and never receives a privileged command to discover incompatibility afterwards',async()=>{
 const current=fixture();current.fetchImpl.mockResolvedValue(Response.json({...current.protocol,commandContract:'legacy-payload'}));await expect(current.transport.request(current.req,current.res,'devices','/api/devices/policy-command-access')).rejects.toMatchObject({status:503});
 await expect(current.transport.request(current.req,current.res,'devices','/api/devices/known-device/commands',{method:'POST',body:{command:'update_policy',reference:current.reference}})).rejects.toThrow();expect(current.fetchImpl).toHaveBeenCalledTimes(1);expect(current.fetchImpl.mock.calls[0][1].method).toBe('GET');
});
test.each(['operatorUserId','configurationHash','operationId','deviceId'])('a misbound %s receipt cannot acknowledge a durable command',async field=>{
 const current=fixture();await current.handshake();const row=accepted(current);row.policyReceipt[field]=field==='configurationHash'?'c'.repeat(64):field==='deviceId'?'other-device':randomUUID();current.fetchImpl.mockResolvedValue(Response.json(row,{status:201}));
 await expect(current.transport.request(current.req,current.res,'devices','/api/devices/known-device/commands',{method:'POST',body:{command:'update_policy',reference:current.reference}})).rejects.toMatchObject({deliveryMayHaveOccurred:true});expect(current.fetchImpl).toHaveBeenCalledTimes(2);
});
test('free-form payloads are refused before HTTP and retain uncertainty from an earlier accepted command',async()=>{
 const current=fixture();await current.handshake();current.fetchImpl.mockResolvedValue(Response.json(accepted(current),{status:201}));await current.transport.request(current.req,current.res,'devices','/api/devices/known-device/commands',{method:'POST',body:{command:'update_policy',reference:current.reference}});
 await expect(current.transport.request(current.req,current.res,'devices','/api/devices/known-device/commands',{method:'POST',body:{command:'update_policy',reference:current.reference,payload:{arbitrary:true}}})).rejects.toMatchObject({status:400,deliveryMayHaveOccurred:true});expect(current.fetchImpl).toHaveBeenCalledTimes(2);
});
