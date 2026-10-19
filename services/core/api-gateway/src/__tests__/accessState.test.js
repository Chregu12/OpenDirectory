'use strict';

const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
const claims = { iss: 'https://issuer.test', sub: 'operator', jti: 'token-id', exp: Math.floor(Date.now() / 1000) + 300 };
const state = { schemaVersion: 1, active: true, issuer: claims.iss, subject: claims.sub, tokenId: claims.jti, expiresAt: claims.exp };
const json = (body = state, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

test.each(['file:///oauth/access-state', 'https://user:secret@issuer.test/oauth/access-state', 'https://issuer.test/other',
  'https://issuer.test/oauth/access-state?token=secret', 'https://issuer.test/oauth/access-state#fragment'])('rejects unsafe access-state authority configuration %s', endpoint => {
  expect(() => createAccessStateClient({ endpoint })).toThrow();
});

test('forwards only the original bearer to a fixed authority without redirects, retries, cookies, or an auth cache', async () => {
  const fetchImpl = jest.fn(async () => json());
  const verify = createAccessStateClient({ endpoint: 'https://issuer.test/oauth/access-state', fetchImpl });
  await verify('Bearer signed.token.value', claims);
  await verify('Bearer signed.token.value', claims);
  expect(fetchImpl).toHaveBeenCalledTimes(2);
  expect(String(fetchImpl.mock.calls[0][0])).toBe('https://issuer.test/oauth/access-state');
  expect(fetchImpl.mock.calls[0][1]).toMatchObject({ method: 'GET', redirect: 'error', cache: 'no-store', headers: { Authorization: 'Bearer signed.token.value', Accept: 'application/json' } });
  expect(Object.keys(fetchImpl.mock.calls[0][1].headers)).toEqual(['Authorization', 'Accept']);
});

test.each([401, 403])('returns an authentication denial, not a fallback, for authority status %s', async status => {
  const verify = createAccessStateClient({ fetchImpl: async () => json({}, status) });
  await expect(verify('Bearer signed', claims)).rejects.toMatchObject({ status: 401 });
});

test.each([302, 404, 429, 500, 503])('fails closed on unavailable or unexpected authority status %s', async status => {
  await expect(createAccessStateClient({ fetchImpl: async () => json({}, status) })('Bearer signed', claims)).rejects.toMatchObject({ status: 503 });
});

test('does not mistake a revoked token response for a verified principal', async () => {
  await expect(createAccessStateClient({ fetchImpl: async () => json({ schemaVersion: 1, active: false }) })('Bearer signed', claims)).rejects.toMatchObject({ status: 401 });
});

test.each([{ active: 'true' }, { schemaVersion: 2 }, { subject: 'other' }, { issuer: 'https://other.test' }, { tokenId: 'other' }, { expiresAt: claims.exp + 1 }])('rejects malformed or mismatched authority responses %j', async override => {
  await expect(createAccessStateClient({ fetchImpl: async () => json({ ...state, ...override }) })('Bearer signed', claims)).rejects.toMatchObject({ status: 503 });
});

test('requires a signed-token identifier and never contacts a source for malformed credential inputs', async () => {
  const fetchImpl = jest.fn(); const verify = createAccessStateClient({ fetchImpl });
  await expect(verify('Bearer signed', { ...claims, jti: undefined })).rejects.toMatchObject({ status: 401 });
  await expect(verify('Bearer secret\r\nCookie: secret', claims)).rejects.toMatchObject({ status: 401 });
  expect(fetchImpl).not.toHaveBeenCalled();
});

test.each([new Response('html', { headers: { 'Content-Type': 'text/html' } }), new Response('a'.repeat(5000), { headers: { 'Content-Type': 'application/json' } }), json(null)])('bounds response type, size and structure', async response => {
  await expect(createAccessStateClient({ fetchImpl: async () => response })('Bearer signed', claims)).rejects.toMatchObject({ status: 503 });
});

test('a transport deadline denies access rather than using a prior positive result', async () => {
  const fetchImpl = jest.fn().mockImplementationOnce(async () => json()).mockImplementationOnce((_url, options) => new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('timeout')), { once: true })));
  const verify = createAccessStateClient({ fetchImpl, timeoutMs: 20 });
  await verify('Bearer signed', claims);
  await expect(verify('Bearer signed', claims)).rejects.toMatchObject({ status: 503 });
  expect(fetchImpl).toHaveBeenCalledTimes(2);
});
