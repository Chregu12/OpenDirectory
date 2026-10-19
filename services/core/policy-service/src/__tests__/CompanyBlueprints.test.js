'use strict';

const { randomUUID } = require('node:crypto');
const express = require('express');
const request = require('supertest');
const { CompanyBlueprintAuthority } = require('../CompanyBlueprintAuthority');
const { CompanyBlueprints } = require('../CompanyBlueprints');
const { companyBlueprintRoutes } = require('../companyBlueprintRoutes');
const { COMPANY_BLUEPRINT_PERMISSIONS, etag } = require('../../../../../packages/company-blueprint-contract');
let user; let source; let app; let store;
const bearer = 'Bearer original.company.blueprint';
const response = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const reason = 'Explicitly reviewed local desired blueprint';
const draft = () => ({ name: 'Local draft', description: '', platform: 'all', configurations: [], appPoolIds: [] });
beforeEach(() => {
  const now = Math.floor(Date.now() / 1000); const actorUserId = randomUUID();
  user = { actor_type: 'user', token_use: 'access', iss: 'https://blueprint.test', sub: 'owner', jti: randomUUID(), exp: now + 3600, auth_time: now,
    identity_authorization: { userId: actorUserId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, amr: ['pwd', 'otp'],
    mfa_authorization: { schemaVersion: 1, userId: actorUserId, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
  source = { schemaVersion: 1, companyBlueprintProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization,
    tenant: { id: randomUUID(), version: '1', generation: '1' }, actorUserId, permissions: [...COMPANY_BLUEPRINT_PERMISSIONS], validUntil: now + 300 };
  store = Object.fromEntries(['capabilities', 'list', 'get', 'versions', 'version', 'history', 'change'].map(method => [method, jest.fn(async () => ({ schemaVersion: 1, outcome: 'applied' }))]));
  app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); }); app.use('/api/company-blueprints', companyBlueprintRoutes({}, { store }));
});
test('the original human bearer reads the exact independent source with no API key or machine fallback', async () => {
  const fetchImpl = jest.fn(async () => response(source)); const authority = new CompanyBlueprintAuthority({ fetchImpl });
  expect(await authority.read(bearer, user)).toEqual(source); const [endpoint, options] = fetchImpl.mock.calls[0];
  expect(endpoint.pathname).toBe('/api/identity/company-blueprints'); expect(options).toMatchObject({ method: 'GET', headers: { Authorization: bearer, Accept: 'application/json' }, redirect: 'error', cache: 'no-store' }); expect(options.body).toBeUndefined(); expect(options.signal.aborted).toBe(true);
});
test.each([401, 403, 428, 400, 404, 429, 500, 302])('source HTTP %s is denied once without retry or alternate authority', async status => {
  const fetchImpl = jest.fn(async () => ({ status })); await expect(new CompanyBlueprintAuthority({ fetchImpl }).read(bearer, user)).rejects.toMatchObject({ status: [401, 403, 428].includes(status) ? status : 503 }); expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test.each([
  value => ({ ...value, extra: true }), value => ({ ...value, permissions: ['company.blueprints.read'] }), value => ({ ...value, companyBlueprintProtocol: 2 }),
  value => ({ ...value, schemaVersion: 2 }), value => ({ ...value, actorUserId: randomUUID() }), value => ({ ...value, tenant: { ...value.tenant, generation: '0' } }),
  value => ({ ...value, context: { ...value.context, revision: '2' } }), value => ({ ...value, issuer: 'other' }), value => ({ ...value, subject: 'other' }),
  value => ({ ...value, tokenId: 'other' }), value => ({ ...value, expiresAt: value.expiresAt - 1 }), value => ({ ...value, validUntil: 1 }),
  value => ({ ...value, validUntil: Math.floor(Date.now() / 1000) + 301 }), value => ({ ...value, validUntil: String(value.validUntil) }),
])('malformed, expired or broadened source is unavailable (%#)', async transform => {
  await expect(new CompanyBlueprintAuthority({ fetchImpl: async () => response(transform(source)) }).read(bearer, user)).rejects.toMatchObject({ status: 503 });
});
test.each([
  ['missing bearer', null, {}], ['machine', bearer, { actor_type: 'application' }], ['missing context', bearer, { identity_authorization: null }],
])('%s is rejected before source transport', async (_label, authorization, patch) => {
  const fetchImpl = jest.fn(); await expect(new CompanyBlueprintAuthority({ fetchImpl }).read(authorization, { ...user, ...patch })).rejects.toMatchObject({ status: 401 }); expect(fetchImpl).not.toHaveBeenCalled();
});
test.each([
  { amr: ['pwd'], mfa_authorization: undefined }, { auth_time: 1 }, { token_use: 'refresh' },
])('a valid-looking source cannot substitute missing original fresh MFA: %j', async patch => {
  await expect(new CompanyBlueprintAuthority({ fetchImpl: async () => response(source) }).read(bearer, { ...user, ...patch })).rejects.toMatchObject({ status: 503 });
});
test.each(['file:///tmp/source', 'https://user:secret@identity.test/api/identity/company-blueprints', 'https://identity.test/api/other', 'https://identity.test/api/identity/company-blueprints?tenant=other', 'https://identity.test/api/identity/company-blueprints#fallback'])('unsupported source URL %s never starts a request', endpoint => { expect(() => new CompanyBlueprintAuthority({ endpoint })).toThrow(); });
test('source streaming enforces the 8KiB ceiling before parsing', async () => {
  const fetchImpl = async () => ({ status: 200, headers: new Headers({ 'Content-Type': 'application/json' }), body: (async function* () { yield Buffer.alloc(4096); yield Buffer.alloc(4097); })() });
  await expect(new CompanyBlueprintAuthority({ fetchImpl }).read(bearer, user)).rejects.toMatchObject({ status: 503 });
});
test('the source request actually aborts after 2.5 seconds', async () => {
  jest.useFakeTimers(); let started; const ready = new Promise(resolve => { started = resolve; });
  const authority = new CompanyBlueprintAuthority({ fetchImpl: async (_endpoint, { signal }) => { started(); return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('Aborted')))); } });
  const operation = expect(authority.read(bearer, user)).rejects.toMatchObject({ status: 503 }); await ready; await jest.advanceTimersByTimeAsync(2500); await operation; jest.useRealTimers();
});
test('a fetch implementation ignoring abort cannot return a successful late source', async () => {
  jest.useFakeTimers(); let complete; const fetchImpl = () => new Promise(resolve => { complete = resolve; });
  const authority = new CompanyBlueprintAuthority({ fetchImpl }); const operation = expect(authority.read(bearer, user)).rejects.toMatchObject({ status: 503 });
  await jest.advanceTimersByTimeAsync(2500); complete(response(source)); await operation; jest.useRealTimers();
});
test('a streamed source arriving only after abort is not accepted', async () => {
  jest.useFakeTimers(); let complete; let started; const reading = new Promise(resolve => { started = resolve; });
  const fetchImpl = async () => ({ status: 200, headers: new Headers({ 'Content-Type': 'application/json' }), body: (async function* () { started(); await new Promise(resolve => { complete = resolve; }); yield Buffer.from(JSON.stringify(source)); })() });
  const authority = new CompanyBlueprintAuthority({ fetchImpl }); const operation = expect(authority.read(bearer, user)).rejects.toMatchObject({ status: 503 }); await reading;
  await jest.advanceTimersByTimeAsync(2500); complete(); await operation; jest.useRealTimers();
});
test.each([
  ['/capabilities', 'capabilities'], ['', 'list'], ['/ID/versions', 'versions'], ['/ID/versions/1', 'version'], ['/ID/history', 'history'],
])('public GET %s calls only the own store method', async (suffix, method) => {
  const id = randomUUID(); const result = await request(app).get('/api/company-blueprints' + suffix.replace('ID', id)).set('Authorization', bearer); expect(result.status).toBe(200); expect(result.headers['cache-control']).toBe('no-store'); expect(result.headers['x-correlation-id']).toMatch(/^[a-f0-9-]{36}$/); expect(store[method]).toHaveBeenCalledTimes(1); expect(store[method].mock.calls[0]).toContain(user); expect(store[method].mock.calls[0]).toContain(bearer);
});
test('detail returns only the actual current captured parent ETag', async () => {
  const id = randomUUID(); store.get.mockResolvedValue({ blueprint: { id, revision: '9007199254740993' } });
  const result = await request(app).get('/api/company-blueprints/' + id).set('Authorization', bearer); expect(result.status).toBe(200); expect(result.headers.etag).toBe(etag({ id, revision: '9007199254740993' }));
});
test.each([{}, [], { tenantId: 'other' }])('an explicitly supplied GET body %j is rejected before the store', async body => {
  const result = await request(app).get('/api/company-blueprints/capabilities').send(body); expect(result.status).toBe(400); expect(store.capabilities).not.toHaveBeenCalled();
});
test.each(['HEAD', 'DELETE', 'PATCH'])('%s is not an implicit own-blueprint operation', async method => {
  const result = await request(app)[method.toLowerCase()]('/api/company-blueprints'); expect(result.status).toBe(404); expect(Object.values(store).every(operation => operation.mock.calls.length === 0)).toBe(true);
});
test('an API key never substitutes or supplements the original human route', async () => {
  const result = await request(app).get('/api/company-blueprints/capabilities').set('Authorization', bearer).set('X-API-Key', 'unused'); expect(result.status).toBe(400); expect(store.capabilities).not.toHaveBeenCalled();
});
test.each(['created', 'updated', 'published', 'restored'])('%s passes the exact captured operation UUID, ETag, user and bearer', async action => {
  const id = randomUUID(); const operation = randomUUID(); const tag = etag({ id, revision: '9007199254740993' });
  const suffix = action === 'created' ? '' : '/' + id + (action === 'published' ? '/publish' : action === 'restored' ? '/restore' : '');
  const body = { ...(action === 'created' ? { id, draft: draft() } : action === 'updated' ? { draft: draft() } : action === 'restored' ? { version: 1 } : {}), reason, confirm: true };
  const result = await request(app)[action === 'updated' ? 'put' : 'post']('/api/company-blueprints' + suffix).set('Authorization', bearer).set('If-Match', tag).set('Idempotency-Key', operation).send(body);
  expect(result.status).toBe(action === 'created' ? 201 : 200); expect(store.change).toHaveBeenCalledWith(action, action === 'created' ? undefined : id, body, tag, operation, user, bearer, expect.any(String));
});
test('a recovered create is a historical 200 receipt, not a new 201 resource', async () => {
  store.change.mockResolvedValue({ outcome: 'already_applied' }); const result = await request(app).post('/api/company-blueprints').set('Idempotency-Key', randomUUID()).send({}); expect(result.status).toBe(200);
});
test.each([undefined, 'alias', 'A'.repeat(36), '*'])('missing or noncanonical Idempotency-Key %s is 400 before any mutation', async operation => {
  let pending = request(app).post('/api/company-blueprints').send({}); if (operation !== undefined) pending = pending.set('Idempotency-Key', operation);
  const result = await pending; expect({ status: result.status, body: result.body }).toMatchObject({ status: 400 }); expect(store.change).not.toHaveBeenCalled();
});
test('write query selectors and capability selectors are not accepted', async () => {
  expect((await request(app).post('/api/company-blueprints?tenant=other').send({})).status).toBe(400); expect((await request(app).get('/api/company-blueprints/capabilities?tenant=other')).status).toBe(400); expect(store.change).not.toHaveBeenCalled(); expect(store.capabilities).not.toHaveBeenCalled();
});
test('error bodies do not expose internal storage errors or proofs', async () => {
  store.list.mockRejectedValue(new Error('SQL payload secret internal')); const result = await request(app).get('/api/company-blueprints'); expect(result.status).toBe(503); expect(JSON.stringify(result.body)).not.toContain('secret'); expect(result.body.correlationId).toBe(result.headers['x-correlation-id']);
});
test.each([400, 401, 403, 404, 409, 412, 428])('actual store denial %s preserves its public status', async status => {
  store.list.mockRejectedValue(Object.assign(new Error('Explicit domain denial'), { status })); expect((await request(app).get('/api/company-blueprints')).status).toBe(status);
});
test('invalid writes are rejected by the shared contract before reading any live source', async () => {
  const authority = { read: jest.fn() }; const database = { getClient: jest.fn() }; const real = new CompanyBlueprints(database, { authority });
  await expect(real.change('created', undefined, { id: randomUUID(), draft: { ...draft(), arbitrary: true }, reason, confirm: true }, undefined, randomUUID(), user, bearer)).rejects.toMatchObject({ status: 400 }); expect(authority.read).not.toHaveBeenCalled(); expect(database.getClient).not.toHaveBeenCalled();
});
test('a missing current ETag fails before live sources or storage', async () => {
  const authority = { read: jest.fn() }; const database = { getClient: jest.fn() }; const real = new CompanyBlueprints(database, { authority });
  await expect(real.change('published', randomUUID(), { reason, confirm: true }, undefined, randomUUID(), user, bearer)).rejects.toMatchObject({ status: 428 }); expect(authority.read).not.toHaveBeenCalled();
});
