'use strict';

const { hashSecret } = require('./clientSecrets');
const { readKeyFile } = require('./SigningKeys');

function configuredWebClient(env = process.env) {
  if (!env.OAUTH_WEB_CLIENT_SECRET_FILE && !env.OAUTH_WEB_REDIRECT_URIS && !env.OAUTH_WEB_CLIENT_ID) return null;
  let redirects; let secret;
  try {
    redirects = JSON.parse(env.OAUTH_WEB_REDIRECT_URIS);
    secret = readKeyFile(env.OAUTH_WEB_CLIENT_SECRET_FILE, true).trim();
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(secret) || !Array.isArray(redirects) || !redirects.length || redirects.length > 8
      || new Set(redirects).size !== redirects.length) throw new Error('Invalid web client');
    for (const redirect of redirects) {
      const url = new URL(redirect);
      if (url.username || url.password || url.hash || url.search || url.pathname !== '/auth/callback'
        || (url.protocol !== 'https:' && !(env.OAUTH_WEB_ALLOW_HTTP_LOOPBACK === 'true' && url.protocol === 'http:'
          && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) throw new Error('Invalid redirect');
    }
  } catch { throw new Error('Protected web client secret and explicit HTTPS callback URIs are required'); }
  const clientId = env.OAUTH_WEB_CLIENT_ID || 'web-app';
  if (!/^[A-Za-z0-9._~-]{1,255}$/.test(clientId) || ['grafana-od-client', 'devportal-od-client'].includes(clientId)) throw new Error('Invalid first-party web client ID');
  return { clientId, clientSecretHash: hashSecret(secret), publicClient: false, name: 'OpenDirectory Web', redirectUris: redirects,
    scopes: ['openid', 'profile', 'email', 'roles', 'sessions.self.read', 'sessions.self.revoke'],
    grantTypes: ['authorization_code', 'refresh_token'] };
}

function assertWebClient(stored, configured) {
  if (!configured) return;
  const sameSet = (first, second) => Array.isArray(first) && first.length === second.length
    && new Set(first).size === first.length && first.every(value => second.includes(value));
  if (!stored || stored.clientId !== configured.clientId || stored.clientSecretHash !== configured.clientSecretHash || stored.publicClient || !stored.enabled || stored.deletedAt
    || !sameSet(stored.redirectUris, configured.redirectUris) || !sameSet(stored.scopes, configured.scopes)
    || !sameSet(stored.grantTypes, configured.grantTypes)) throw new Error('Stored web client differs from configuration; reconcile through authorized client administration');
}

module.exports = { configuredWebClient, assertWebClient };
