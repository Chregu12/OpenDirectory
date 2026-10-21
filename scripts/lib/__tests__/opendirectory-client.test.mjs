import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createClient } from '../opendirectory-client.mjs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

let server; let origin; let calls; let mode; let app;
const secret = 's'.repeat(43);
const fixture = () => ({ clientId: 'app-1', name: 'Nightly job', publicClient: false, enabled: false, version: '1', redirectUris: [], grantTypes: ['client_credentials'], scopes: [] });
before(async () => {
  server = http.createServer(async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    calls.push({ url: req.url, method: req.method, auth: req.headers.authorization, match: req.headers['if-match'], body });
    res.setHeader('Content-Type', 'application/json');
    const send = (status, data) => { res.statusCode = status; res.end(JSON.stringify(data)); };
    if (req.url === '/oauth/token') {
      if (mode === 'redirect') { res.writeHead(307, { Location: origin + '/stolen' }); return res.end(); }
      if (mode === 'token-error') return send(401, { error: 'invalid_client', secret: 'must-not-be-logged' });
      const fields = new URLSearchParams(body);
      assert.equal(fields.get('grant_type'), 'client_credentials'); assert.equal(fields.get('client_id'), 'app-1'); assert.equal(fields.get('client_secret'), secret);
      return send(200, { access_token: 'verified-app-token', token_type: 'Bearer', expires_in: 60 });
    }
    if (req.url === '/oauth/introspect') return send(200, { active: mode !== 'inactive', client_id: mode === 'substituted' ? 'other-app' : 'app-1', actor_type: 'application', scope: '' });
    if (req.url === '/api/status') {
      if (mode === 'unavailable') return send(503, { error: 'unavailable' });
      return send(200, { received: body ? JSON.parse(body) : null });
    }
    if (req.url === '/api/clients' && req.method === 'POST') {
      app = { ...fixture(), ...JSON.parse(body) };
      return send(mode === 'uncertain-create' ? 202 : 201, { ...app, clientSecret: secret });
    }
    if (req.url === '/api/clients/app-1' && req.method === 'GET') {
      res.setHeader('ETag', mode === 'wrong-etag' ? '"wrong"' : `"od-client:app-1:${app.version}"`);
      return send(200, app);
    }
    if (req.url === '/api/clients/app-1' && req.method === 'PUT') {
      if (mode === 'stale') return send(412, { error: 'client_version_conflict' });
      app = { ...app, ...JSON.parse(body), version: String(BigInt(app.version) + 1n) };
      return send(200, app);
    }
    if (req.url === '/api/clients/app-1/rotate-secret') return send(200, { ...app, version: String(BigInt(app.version) + 1n), clientSecret: secret });
    send(404, { error: 'not_found' });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); origin = 'http://127.0.0.1:' + server.address().port;
});
after(async () => { await new Promise(resolve => server.close(resolve)); });
beforeEach(() => { calls = []; mode = ''; app = fixture(); });
const client = (extra = {}) => createClient({ issuer: origin, apiUrl: origin, clientId: 'app-1', clientSecret: secret, adminToken: 'original-admin-user', ...extra });

test('app creation uses the original user token, no redirect and a separate disabled state', async () => {
  const created = await client().createApp('Nightly job');
  assert.equal(created.clientSecret, secret); assert.equal(created.enabled, false);
  assert.equal(calls.length, 1); assert.equal(calls[0].auth, 'Bearer original-admin-user');
  assert.deepEqual(JSON.parse(calls[0].body).grantTypes, ['client_credentials']);
});
test('activation, disablement and rotation retain the observed version and never use app credentials for administration', async () => {
  assert.equal((await client().enableApp('app-1', true)).enabled, true);
  assert.equal(calls[1].match, '"od-client:app-1:1"');
  assert.equal((await client().enableApp('app-1', false)).enabled, false);
  assert.equal(calls[3].match, '"od-client:app-1:2"');
  assert.equal((await client().rotateApp('app-1')).clientSecret, secret);
  assert.equal(calls[5].match, '"od-client:app-1:3"');
  assert.ok(calls.every(call => call.auth === 'Bearer original-admin-user'));
});
test('workload requests acquire a fresh token and preserve body and conditional header', async () => {
  const result = await client().request('POST', '/api/status', { operation: 'example' }, { etag: '"revision:1"' });
  assert.deepEqual(result.data, { received: { operation: 'example' } });
  assert.equal(calls.length, 2); assert.equal(calls[1].auth, 'Bearer verified-app-token'); assert.equal(calls[1].match, '"revision:1"');
  assert.equal(new URLSearchParams(calls[0].body).get('scope'), '');
});
test('check confirms the active identity of this app', async () => {
  assert.equal((await client().check()).actor_type, 'application');
  for (mode of ['inactive', 'substituted']) await assert.rejects(client().check(), /inactive or unconfirmed/);
});
test('API origins, traversal and admin identity cannot be substituted before authentication', async () => {
  for (const value of ['http://untrusted.test', 'https://user:password@example.com', 'https://example.com/path', 'https://example.com?token=secret']) assert.throws(() => client({ issuer: value }));
  for (const path of ['https://attacker.test/api/data', '//attacker.test/api/data', '/api/../../oauth/token', '/api/data#token', '/api/\\evil']) await assert.rejects(client().request('POST', path, {}));
  await assert.rejects(client({ adminToken: '' }).createApp('Job'), /administrator user/);
  assert.equal(calls.length, 0);
});
test('redirects never receive credentials and write or token failures are not retried', async () => {
  mode = 'redirect'; await assert.rejects(client().request('POST', '/api/status', {}));
  assert.equal(calls.length, 1); assert.equal(calls.some(call => call.url === '/stolen'), false);
  calls = []; mode = 'unavailable'; await assert.rejects(client().request('POST', '/api/status', {}), { status: 503 });
  assert.equal(calls.filter(call => call.url === '/api/status').length, 1);
  calls = []; mode = 'token-error'; await assert.rejects(client().check(), error => error.status === 401 && !error.message.includes('must-not-be-logged'));
  assert.equal(calls.length, 1);
});
test('uncertain creation, substituted versions and stale writes never confirm success', async () => {
  mode = 'uncertain-create'; await assert.rejects(client().createApp('Nightly job'), /not confirmed/);
  mode = 'wrong-etag'; await assert.rejects(client().enableApp('app-1', true), /version was not confirmed/);
  assert.equal(calls.filter(call => call.method === 'PUT').length, 0);
  mode = 'stale'; await assert.rejects(client().enableApp('app-1', true), { status: 412 });
  assert.equal(calls.filter(call => call.method === 'PUT').length, 1);
});
test('the CLI preserves a quoted conditional version and rejects incomplete options without a request', async () => {
  const cli = fileURLToPath(new URL('../../od.mjs', import.meta.url));
  const env = { ...process.env, OPENDIRECTORY_ISSUER: origin, OPENDIRECTORY_API_URL: origin, OPENDIRECTORY_CLIENT_ID: 'app-1', OPENDIRECTORY_CLIENT_SECRET: secret, OPENDIRECTORY_SCOPES: '' };
  const run = promisify(execFile);
  const response = await run(process.execPath, [cli, 'request', 'GET', '/api/status', '--if-match', '"version:3"'], { env });
  assert.equal(JSON.parse(response.stdout).status, 200); assert.equal(calls[1].match, '"version:3"');
  calls = [];
  await assert.rejects(run(process.execPath, [cli, 'request', 'GET', '/api/status', '--if-match'], { env }), { code: 1 });
  assert.equal(calls.length, 0);
});
