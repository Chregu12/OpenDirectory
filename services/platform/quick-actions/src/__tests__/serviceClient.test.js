'use strict';

jest.mock('../../../../../packages/oidc-access-state', () => ({ createAccessStateClient: jest.fn(() => jest.fn(async () => {})) }));
const nock = require('nock');
const { runWithOperator, currentOperator, validate } = require('../utils/delegation');
const { call, ping, SERVICES, getServiceToken, createServiceClient } = require('../utils/serviceClient');
const { accessClaims } = require('./fixtures/claims');
const authorization = 'Bearer header.payload.signature';
const delegated = operation => runWithOperator(authorization, accessClaims(), operation);
beforeEach(() => { jest.clearAllMocks(); validate.mockResolvedValue(undefined); });
afterEach(() => nock.cleanAll());

test.each(['auth', 'directory', 'kerberos', 'samba', 'device', 'policy', 'pim', 'mdm', 'appStore'])('the fixed %s service has a configured root URL', key => {
  expect(new URL(SERVICES[key]).pathname).toBe('/'); expect(Object.keys(SERVICES)).toHaveLength(9);
});
test('a protected call without a verified operation cannot fetch a service credential', async () => {
  process.env.QA_CLIENT_SECRET = 'must-not-be-used';
  await expect(call('auth', 'POST', '/api/service-accounts', {})).rejects.toMatchObject({ status: 401 });
  await expect(getServiceToken()).rejects.toMatchObject({ status: 401 });
  expect(validate).not.toHaveBeenCalled(); delete process.env.QA_CLIENT_SECRET;
});
test.each(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])('%s forwards only the verified operator, a fixed operation ID and a bounded JSON receipt', async method => {
  let operationId;
  await delegated(async context => {
    operationId = context.operationId;
    const scope = nock(SERVICES.auth, { reqheaders: { authorization, 'x-od-operation-id': operationId } })
      .intercept('/api/test', method).reply(200, { success: true }, { 'Content-Type': 'application/json' });
    expect(await call('auth', method, '/api/test', { marker: true })).toEqual({ success: true }); expect(scope.isDone()).toBe(true);
  });
  expect(validate).toHaveBeenCalledWith(authorization, expect.objectContaining({ sub: 'operator' })); expect(operationId).toHaveLength(36);
});
test('a redundant explicit operator header is accepted but cannot replace the verified identity', async () => {
  await delegated(async () => {
    await expect(call('policy', 'POST', '/api/licenses/users/known/offboard', {}, { authorization: 'Bearer other.payload.signature' })).rejects.toMatchObject({ status: 403 });
    const scope = nock(SERVICES.policy, { reqheaders: { authorization } }).post('/api/licenses/users/known/offboard', {}).reply(200, { assignmentsRevoked: 1 });
    expect((await call('policy', 'POST', '/api/licenses/users/known/offboard', {}, { authorization })).assignmentsRevoked).toBe(1); expect(scope.isDone()).toBe(true);
  });
});
test('each step freshly checks authority and a source failure latches the operation without subsequent calls or fallback', async () => {
  await delegated(async () => {
    nock(SERVICES.auth).get('/api/first').reply(200, {}); await call('auth', 'GET', '/api/first');
    validate.mockRejectedValueOnce(Object.assign(new Error('source offline'), { status: 503 }));
    await expect(call('auth', 'POST', '/api/second', {})).rejects.toMatchObject({ status: 503 });
    validate.mockResolvedValue(undefined);
    await expect(call('samba', 'POST', '/api/third', {})).rejects.toMatchObject({ status: 503 });
    expect(validate).toHaveBeenCalledTimes(2);
  });
});
test.each([401, 403])('a downstream HTTP %s cannot trigger a retry as a privileged service actor', async status => {
  await delegated(async () => {
    nock(SERVICES.auth).post('/api/denied').once().reply(status, { privateError: 'must not escape' });
    await expect(call('auth', 'POST', '/api/denied', {})).rejects.toMatchObject({ status });
    await expect(call('samba', 'POST', '/api/not-attempted', {})).rejects.toMatchObject({ status }); expect(validate).toHaveBeenCalledTimes(1);
  });
});
test('client completion/cancellation ends the captured operation and prevents detached work', async () => {
  let captured;
  await delegated(async context => { captured = context; context.close(); await expect(call('auth', 'GET', '/api/private')).rejects.toMatchObject({ status: 401 }); });
  expect(captured.signal.aborted).toBe(true); expect(() => currentOperator()).toThrow(); expect(validate).not.toHaveBeenCalled();
});
test('parallel asynchronous operations do not borrow another request identity', async () => {
  const credentials = ['Bearer first.payload.signature', 'Bearer second.payload.signature'];
  await Promise.all(credentials.map((credential, index) => runWithOperator(credential, accessClaims({ sub: 'operator-' + index, jti: 'token-' + index }), async () => {
    await new Promise(resolve => setTimeout(resolve, index ? 5 : 15));
    const scope = nock(SERVICES.auth, { reqheaders: { authorization: credential } }).get('/api/parallel/' + index).reply(200, { index });
    expect(await call('auth', 'GET', '/api/parallel/' + index)).toEqual({ index }); expect(scope.isDone()).toBe(true);
  })));
});
test('principal metadata is immutable and nested credential substitution is rejected', async () => {
  await delegated(async context => {
    expect(() => { context.claims.sub = 'forged'; }).toThrow(); expect(() => { context.claims.identity_authorization.revision = '9'; }).toThrow();
    expect(() => runWithOperator('Bearer other.payload.signature', accessClaims(), () => {})).toThrow();
  });
});
test.each(['//evil.test/path', 'https://evil.test', '/api/with space', '/api/with\\escape', '/api/path#fragment'])('a downstream target cannot redirect credentials through %s', async path => {
  await delegated(async () => expect(call('auth', 'GET', path)).rejects.toMatchObject({ status: 400 })); expect(validate).not.toHaveBeenCalled();
});
test.each(['https://user:secret@host/', 'file:///tmp/socket', 'https://host/base', 'https://host/?token=x'])('unsafe configured destination %s is rejected', url => {
  expect(() => createServiceClient({ services: { auth: url } })).toThrow();
});
test('redirects are never followed with a delegated bearer', async () => {
  await delegated(async () => {
    const redirected = nock('http://should-not-receive.test').post('/private').reply(200, {});
    nock(SERVICES.auth).post('/api/redirect').reply(302, '', { Location: 'http://should-not-receive.test/private' });
    await expect(call('auth', 'POST', '/api/redirect', {})).rejects.toMatchObject({ status: 502 }); expect(redirected.isDone()).toBe(false);
  });
});
test('body bounds, malformed JSON and explicit business failures cannot confirm an operation', async () => {
  const bounded = createServiceClient({ maxResponseBytes: 1024 });
  await delegated(async () => {
    nock(SERVICES.auth).get('/large').reply(200, { data: 'x'.repeat(2048) }); await expect(bounded.call('auth', 'GET', '/large')).rejects.toMatchObject({ status: 502 });
    nock(SERVICES.auth).get('/malformed').reply(200, '{not-json', { 'Content-Type': 'application/json' }); await expect(call('auth', 'GET', '/malformed')).rejects.toMatchObject({ status: 502 });
    nock(SERVICES.auth).post('/failed').reply(200, { success: false }); await expect(call('auth', 'POST', '/failed', {})).rejects.toMatchObject({ status: 502 });
  });
});
test('the deadline includes waiting for a response body, not just headers', async () => {
  const bounded = createServiceClient({ timeoutMs: 100 });
  await delegated(async () => {
    nock(SERVICES.auth).get('/slow').delayBody(300).reply(200, { success: true });
    await expect(bounded.call('auth', 'GET', '/slow')).rejects.toMatchObject({ status: 504, code: 'ETIMEOUT' });
  });
});
test('a confirmed no-content delete is handled without inventing a JSON object from an error', async () => {
  await delegated(async () => { nock(SERVICES.auth).delete('/api/record').reply(204); expect(await call('auth', 'DELETE', '/api/record')).toEqual({}); });
});
test('public health probes never obtain or send a privileged credential', async () => {
  const scope = nock(SERVICES.auth, { badheaders: ['authorization'] }).get('/health').reply(200, { status: 'healthy' });
  expect((await ping('auth')).healthy).toBe(true); expect(scope.isDone()).toBe(true); expect(validate).not.toHaveBeenCalled();
});
test('public health failures are explicit and do not leak internal responses', async () => {
  nock(SERVICES.auth).get('/health').reply(500, { secret: 'private' }); const result = await ping('auth'); expect(result.healthy).toBe(false); expect(JSON.stringify(result)).not.toContain('private');
});
test('a denied receiver latches authorization failure at the headers, without waiting for an untrusted body', async () => {
  const server = require('node:http').createServer((_request, response) => {
    response.writeHead(403, { 'Content-Type': 'application/json' }); response.flushHeaders();
    const timer = setTimeout(() => response.end('{"secret":"private"}'), 2000); response.once('close', () => clearTimeout(timer));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await delegated(async () => {
      const bounded = createServiceClient({ services: { auth: 'http://127.0.0.1:' + server.address().port }, timeoutMs: 500 });
      await expect(bounded.call('auth', 'GET', '/denied-slow-body')).rejects.toMatchObject({ status: 403 });
      await expect(call('auth', 'POST', '/not-dispatched', {})).rejects.toMatchObject({ status: 403 }); expect(validate).toHaveBeenCalledTimes(1);
    });
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
