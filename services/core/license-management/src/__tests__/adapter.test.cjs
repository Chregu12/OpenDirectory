'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { randomBytes } = require('node:crypto');
const { createService } = require('../index');
const { PolicyLicenseClient } = require('../PolicyLicenseClient');
const { operations } = require('../routes/licenseRoutes');

const subject = '11111111-1111-4111-8111-111111111111';
const permissions = ['licenses.catalog.read', 'licenses.catalog.manage', 'licenses.assignments.read', 'licenses.assignments.manage',
  'licenses.requests.read', 'licenses.requests.review', 'licenses.subjects.offboard', 'licenses.subjects.manage'];
let authority; let adapter; let base; let mode; let calls;

function capabilities(token) {
  const identityState = ['unlinked', 'disabled', 'unavailable'].includes(token) ? token : 'active';
  return { subject: identityState === 'active' ? subject : null, tokenSubject: token, identityState,
    permissions: identityState === 'active' && token === 'operator' ? permissions : [], demoMode: false };
}

before(async () => {
  authority = http.createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : undefined;
    calls.push({ method: request.method, path: request.url, headers: request.headers, body });
    response.setHeader('Content-Type', 'application/json');
    const token = request.headers.authorization?.slice(7);
    if (!['operator', 'ordinary', 'unlinked', 'disabled', 'unavailable'].includes(token)) { response.statusCode = 403; return response.end('{"error":"invalid token"}'); }
    if (request.url === '/api/licenses/access') {
      if (mode === 'offline') { response.statusCode = 503; return response.end('{"error":"storage unavailable"}'); }
      const result = capabilities(token);
      return response.end(JSON.stringify(typeof mode === 'function' ? mode(result) : result));
    }
    if (mode === 'conflict') { response.statusCode = 409; return response.end('{"error":"No seats available"}'); }
    if (mode === 'revoked') { response.statusCode = 403; return response.end('{"error":"identity revoked during operation"}'); }
    if (mode === 'throttled') { response.statusCode = 429; response.setHeader('Retry-After', '20'); return response.end('{"error":"rate limited"}'); }
    if (request.method === 'DELETE') { response.statusCode = 204; return response.end(); }
    response.setHeader('Set-Cookie', 'upstream-secret=not-forwarded');
    response.statusCode = request.method === 'POST' ? 201 : 200;
    response.end(JSON.stringify({ source: 'canonical', path: request.url, body }));
  });
  await new Promise(resolve => authority.listen(0, '127.0.0.1', resolve));
  adapter = createService({ client: new PolicyLicenseClient({ baseUrl: `http://127.0.0.1:${authority.address().port}` }) });
  await new Promise(resolve => adapter.server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${adapter.server.address().port}`;
});

beforeEach(() => { mode = null; calls = []; });
after(async () => {
  for (const server of [adapter?.server, authority]) if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

async function api(method, path, token = 'operator', body, headers = {}) {
  const response = await fetch(`${base}${path}`, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: response.status, headers: response.headers, body: response.status === 204 ? null : await response.json() };
}

test('health is liveness only and never reaches a license store or exposes process/license statistics', async () => {
  const result = await api('GET', '/health', null);
  assert.equal(result.status, 200); assert.deepEqual(Object.keys(result.body).sort(), ['canonicalApi', 'mode', 'service', 'status']);
  assert.equal(result.body.mode, 'canonical-adapter'); assert.equal(calls.length, 0);
});

for (const [method, path, permission, destination] of operations) {
  test(`registered ${method} ${path} preserves the canonical permission/path`, async () => {
    const source = path.replace(/:[A-Za-z]+/g, subject);
    const target = destination.replace(/:[A-Za-z]+/g, subject);
    const result = await api(method, `/api/license${source}`, 'operator', method === 'GET' ? undefined : {});
    assert.equal(result.status, method === 'DELETE' ? 204 : method === 'POST' ? 201 : 200);
    assert.equal(calls[0].path, '/api/licenses/access'); assert.equal(calls.at(-1).path, `/api/licenses${target}`);
    assert.equal(calls.at(-1).headers.authorization, 'Bearer operator'); assert.equal(result.headers.get('cache-control'), 'no-store');
    assert.equal(result.headers.get('set-cookie'), null);
    if (permission) {
      calls = [];
      assert.equal((await api(method, `/api/license${source}`, 'ordinary', method === 'GET' ? undefined : { permissions, roles: ['admin'] }, { 'X-User-Roles': 'admin' })).status, 403);
      assert.equal(calls.length, 1);
    }
  });
}

test('missing/forged credentials and dependency outages never activate old prototype maps', async () => {
  assert.equal((await api('GET', '/api/license/licenses', null, undefined, { Cookie: 'token=operator', 'X-API-Key': 'operator' })).status, 401);
  assert.equal(calls.length, 0);
  assert.equal((await api('GET', '/api/license/licenses', 'forged')).status, 403);
  mode = 'offline';
  assert.equal((await api('POST', '/api/license/licenses', 'operator', { name: 'Office' })).status, 503);
  assert.ok(calls.every(call => call.path === '/api/licenses/access'));
});

test('inactive identity states retain safe capability/kiosk reads but block private reads and mutations', async () => {
  for (const state of ['unlinked', 'disabled', 'unavailable']) {
    const access = await api('GET', '/api/license/access', state);
    assert.equal(access.status, 200); assert.deepEqual(access.body.permissions, []);
    assert.equal((await api('GET', '/api/license/kiosk', state)).status, 200);
    assert.equal((await api('POST', '/api/license/licenses', state, { name: 'Office' })).status, state === 'unavailable' ? 503 : 403);
  }
});

test('body-supplied actor and authority claims are discarded, never turned into credentials', async () => {
  const result = await api('POST', `/api/license/licenses/${subject}/assign`, 'operator', { assignee_type: 'user', assignee_id: subject,
    assignedBy: 'forged', assigned_by: 'forged', authorization: 'Bearer administrator', roles: ['admin'], directory_user_id: 'forged' },
  { 'X-User-Roles': 'admin', 'X-Service-Token': 'forged', Cookie: 'token=forged' });
  assert.equal(result.status, 201); assert.deepEqual(calls.at(-1).body, { assignee_type: 'user', assignee_id: subject });
  assert.equal(calls.at(-1).headers.authorization, 'Bearer operator');
  for (const header of ['x-user-roles', 'x-service-token', 'cookie']) assert.equal(calls.at(-1).headers[header], undefined);
});

test('request ownership filters cannot be replaced by a caller-provided requester', async () => {
  const result = await api('GET', '/api/license/requests?status=pending&requester_id=someone-else', 'ordinary');
  assert.equal(result.status, 200); assert.equal(calls.at(-1).path, '/api/licenses/requests?status=pending');
});

test('unsupported license keys, embedded assignments and procurement semantics are not silently acknowledged', async () => {
  for (const field of ['licenseKey', 'assignments', 'quantity', 'vendorId', 'softwareId', 'terms', 'cost']) {
    calls = [];
    assert.equal((await api('POST', '/api/license/licenses', 'operator', { name: 'Office', [field]: 'secret-not-echoed' })).status, 422);
    assert.equal(calls.length, 1);
  }
});

test('prototype analytics, mobile writes-on-GET, renewals and unknown paths cannot reach stateful handlers', async () => {
  for (const path of ['/types', '/software', '/vendors', '/usage/track', '/compliance/scan', '/optimization/analyze', '/assets/discovery', '/mobile/sync', '/reports', '/dashboard', '/audit/export', `/licenses/${subject}/renew`, `/licenses/${subject}/revoke`]) {
    calls = [];
    assert.equal((await api('GET', `/api/license${path}`)).status, 410);
    assert.equal(calls.length, 1);
  }
  assert.equal((await api('PATCH', '/api/license/licenses', 'operator', {})).status, 404);
  assert.equal((await api('POST', '/api/license/unregistered', 'operator', {})).status, 404);
});

test('path/query injection, repeated filters and malformed bodies cannot change the fixed target', async () => {
  assert.equal((await api('GET', '/api/license/licenses/user%2F..%2Fsecrets')).status, 400);
  assert.equal((await api('GET', '/api/license/requests?status=pending&status=approved')).status, 400);
  assert.equal((await api('GET', '/api/license/licenses?target=http://elsewhere.invalid')).status, 422);
  const malformed = await fetch(`${base}/api/license/licenses`, { method: 'POST', headers: { Authorization: 'Bearer operator', 'Content-Type': 'application/json' }, body: '{broken' });
  assert.equal(malformed.status, 400);
  assert.ok(calls.every(call => call.path === '/api/licenses/access'));
});

test('operation-time denial/capacity/rate-limit outcomes pass through without retry or a local success', async () => {
  for (const [value, status] of [['conflict', 409], ['revoked', 403], ['throttled', 429]]) {
    mode = value; calls = [];
    const result = await api('POST', `/api/license/licenses/${subject}/assign`, 'operator', { assignee_type: 'user', assignee_id: subject });
    assert.equal(result.status, status); assert.equal(calls.length, 2);
    if (status === 429) assert.equal(result.headers.get('retry-after'), '20');
  }
});

test('demo or malformed upstream capabilities do not establish persistent authorization', async () => {
  for (const corrupt of [value => ({ ...value, demoMode: true }), value => ({ ...value, subject: 'alias' }), value => ({ ...value, permissions: 'admin' }), value => ({ ...value, identityState: 'unknown' })]) {
    mode = corrupt;
    assert.equal((await api('POST', '/api/license/licenses', 'operator', { name: 'Office' })).status, 503);
  }
});

async function upgrade(path, authorization) {
  return new Promise((resolve, reject) => {
    const request = http.request(`${base}${path}`, { headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Key': randomBytes(16).toString('base64'), 'Sec-WebSocket-Version': '13', ...(authorization ? { Authorization: authorization } : {}) } });
    request.on('response', response => { response.resume(); response.on('end', () => resolve(response.statusCode)); });
    request.on('upgrade', (_response, socket) => { socket.destroy(); reject(new Error('An obsolete event feed accepted a connection')); });
    request.on('error', reject); request.end();
  });
}

test('real WebSocket upgrades cannot authenticate via query strings or receive raw license broadcasts', async () => {
  assert.equal(await upgrade('/ws/license'), 401);
  assert.equal(await upgrade('/ws/license?token=operator'), 404);
  assert.equal(await upgrade('/ws/license', 'Bearer forged'), 403);
  assert.equal(await upgrade('/ws/license', 'Bearer unlinked'), 403);
  assert.equal(await upgrade('/ws/license', 'Bearer operator'), 410);
  mode = 'offline'; assert.equal(await upgrade('/ws/license', 'Bearer operator'), 503);
});

test('the bounded transport rejects unsafe URLs, redirects, HTML, oversized bodies and timeouts', async () => {
  for (const baseUrl of ['file:///tmp/licenses', 'https://user:secret@policy.test', 'https://policy.test/prefix', 'https://policy.test/?target=elsewhere']) assert.throws(() => new PolicyLicenseClient({ baseUrl }));
  const responses = [new Response('{}', { status: 302 }), new Response('<secret>', { headers: { 'Content-Type': 'text/html' } }),
    new Response(JSON.stringify({ data: 'x'.repeat(2048) }), { headers: { 'Content-Type': 'application/json' } })];
  for (const response of responses) {
    const client = new PolicyLicenseClient({ fetchImpl: async () => response, maxBytes: 1024 });
    await assert.rejects(client.request('GET', '/api/licenses', 'Bearer operator'), { status: 503 });
  }
  let attempts = 0;
  const client = new PolicyLicenseClient({ timeoutMs: 10, fetchImpl: (_url, options) => new Promise((_resolve, reject) => {
    attempts++; assert.equal(options.redirect, 'error'); assert.equal(options.cache, 'no-store');
    options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  }) });
  await assert.rejects(client.request('POST', '/api/licenses', 'Bearer operator', { body: { name: 'Office' } }), { status: 503 });
  assert.equal(attempts, 1);
});
