'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { configuredWebClient, assertWebClient } = require('../webClient');
const { hashSecret } = require('../clientSecrets');

let directory; let env;
beforeEach(() => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-web-client-'));
  const filename = path.join(directory, 'client.secret');
  fs.writeFileSync(filename, 'disposable-confidential-web-secret-123456789', { mode: 0o600 });
  env = { OAUTH_WEB_CLIENT_SECRET_FILE: filename, OAUTH_WEB_REDIRECT_URIS: '["https://web.test/auth/callback"]' };
});
afterEach(() => fs.rmSync(directory, { recursive: true, force: true }));

test('there is no implicit public browser client', () => { expect(configuredWebClient({})).toBeNull(); });
test('the explicit confidential client has only authorization-code, refresh and self-session scopes', () => {
  const client = configuredWebClient(env);
  expect(client.clientId).toBe('web-app');
  expect(client.grantTypes).toEqual(['authorization_code', 'refresh_token']);
  expect(client.scopes).toEqual(['openid', 'profile', 'email', 'roles', 'sessions.self.read', 'sessions.self.revoke']);
  expect(client.clientSecret).toBeUndefined();
  expect(client.clientSecretHash).toBe(hashSecret('disposable-confidential-web-secret-123456789'));
});
test.each([
  {}, { OAUTH_WEB_CLIENT_ID: 'invalid client' }, { OAUTH_WEB_REDIRECT_URIS: '[]' },
  { OAUTH_WEB_REDIRECT_URIS: '["http://web.test/auth/callback"]' },
  { OAUTH_WEB_REDIRECT_URIS: '["https://web.test/auth/callback?redirect=evil"]' },
  { OAUTH_WEB_REDIRECT_URIS: '["https://web.test/other"]' },
  { OAUTH_WEB_CLIENT_ID: 'grafana-od-client' },
])('partial or unsafe registration fails closed: %j', override => {
  const value = Object.keys(override).length ? { ...env, ...override } : { ...env, OAUTH_WEB_CLIENT_SECRET_FILE: undefined };
  expect(() => configuredWebClient(value)).toThrow();
});
test('world-readable secrets are refused', () => {
  fs.chmodSync(env.OAUTH_WEB_CLIENT_SECRET_FILE, 0o644);
  expect(() => configuredWebClient(env)).toThrow();
});
test('HTTP callbacks require explicit loopback-only development opt-in', () => {
  env.OAUTH_WEB_REDIRECT_URIS = '["http://127.0.0.1:3000/auth/callback"]';
  expect(() => configuredWebClient(env)).toThrow();
  expect(configuredWebClient({ ...env, OAUTH_WEB_ALLOW_HTTP_LOOPBACK: 'true' }).redirectUris).toHaveLength(1);
});
test('startup never recreates deleted clients or overwrites changed grants, secrets, redirects or scopes', () => {
  const client = { ...configuredWebClient(env), enabled: true, deletedAt: null };
  expect(() => assertWebClient(client, client)).not.toThrow();
  for (const stored of [undefined, { ...client, clientSecretHash: hashSecret('other') }, { ...client, grantTypes: [...client.grantTypes, 'client_credentials'] },
    { ...client, scopes: ['openid'] }, { ...client, redirectUris: ['https://evil.test/auth/callback'] }]) {
    expect(() => assertWebClient(stored, client)).toThrow(/authorized client administration/);
  }
});
