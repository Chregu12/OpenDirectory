'use strict';

const crypto = require('crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const { readKeyFile } = require('./SigningKeys');

function trustedUrl(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' && !(process.env.NODE_ENV !== 'production' && url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw new Error('HTTPS required');
  if (url.username || url.password || url.hash) throw new Error('Invalid provider URL');
  return url.toString();
}

class OidcAdapter {
  constructor({ issuer, clientId, clientSecret, subjects }, callbackUrl) {
    trustedUrl(issuer);
    if (new URL(issuer).search) throw new Error('Invalid OIDC issuer');
    this.issuer = issuer;
    this.callbackUrl = trustedUrl(callbackUrl);
    if (typeof clientId !== 'string' || !clientId || typeof clientSecret !== 'string' || !clientSecret
      || !subjects || typeof subjects !== 'object' || Array.isArray(subjects)
      || Object.values(subjects).some(subject => typeof subject !== 'string' || !subject || subject.length > 255)) throw new Error('Invalid OIDC configuration');
    this.clientId = clientId; this.clientSecret = clientSecret; this.subjects = subjects;
  }

  async json(url, options) {
    const response = await fetch(url, { ...options, signal: AbortSignal.timeout(5000), redirect: 'error', cache: 'no-store' });
    if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error('OIDC provider unavailable');
    let length = 0; const chunks = [];
    for await (const chunk of response.body) {
      length += chunk.length; if (length > 65536) throw new Error('Oversized OIDC response'); chunks.push(Buffer.from(chunk));
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }

  async discovery() {
    if (this.metadata) return this.metadata;
    const metadata = await this.json(this.issuer.replace(/\/$/, '') + '/.well-known/openid-configuration');
    if (metadata.issuer !== this.issuer || !Array.isArray(metadata.response_types_supported) || !metadata.response_types_supported.includes('code')
      || !Array.isArray(metadata.id_token_signing_alg_values_supported) || !metadata.id_token_signing_alg_values_supported.includes('RS256')
      || !Array.isArray(metadata.code_challenge_methods_supported) || !metadata.code_challenge_methods_supported.includes('S256')) throw new Error('Unsupported OIDC provider');
    for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) trustedUrl(metadata[key]);
    if (metadata.token_endpoint_auth_methods_supported && !metadata.token_endpoint_auth_methods_supported.includes('client_secret_basic')) throw new Error('client_secret_basic required');
    this.jwks = createRemoteJWKSet(new URL(metadata.jwks_uri), { timeoutDuration: 5000 });
    this.metadata = metadata;
    return metadata;
  }

  async begin() {
    const metadata = await this.discovery();
    const transaction = { state: crypto.randomBytes(32).toString('base64url'), nonce: crypto.randomBytes(32).toString('base64url'), verifier: crypto.randomBytes(32).toString('base64url') };
    const url = new URL(metadata.authorization_endpoint);
    url.search = new URLSearchParams({ client_id: this.clientId, redirect_uri: this.callbackUrl, response_type: 'code', scope: 'openid email profile',
      state: transaction.state, nonce: transaction.nonce, code_challenge: crypto.createHash('sha256').update(transaction.verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
    return { url: url.toString(), transaction };
  }

  async complete(query, transaction) {
    if (query.error || typeof query.code !== 'string' || !query.code || query.code.length > 4096 || query.state !== transaction.state) throw new Error('Invalid OIDC callback');
    const metadata = await this.discovery();
    const credentials = [this.clientId, this.clientSecret].map(value => new URLSearchParams({ v: value }).toString().slice(2)).join(':');
    const tokens = await this.json(metadata.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: 'Basic ' + Buffer.from(credentials).toString('base64') },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: query.code, redirect_uri: this.callbackUrl, code_verifier: transaction.verifier }).toString() });
    if (typeof tokens.id_token !== 'string') throw new Error('Missing ID token');
    const { payload } = await jwtVerify(tokens.id_token, this.jwks, { issuer: this.issuer, audience: this.clientId, algorithms: ['RS256'], requiredClaims: ['sub', 'iat', 'exp', 'nonce'], maxTokenAge: '10m' });
    if (typeof payload.sub !== 'string' || !payload.sub || payload.nonce !== transaction.nonce
      || (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== this.clientId)
      || (payload.azp !== undefined && payload.azp !== this.clientId)
      || !Object.hasOwn(this.subjects, payload.sub)) throw new Error('Unbound OIDC identity');
    // Only explicit issuer/subject bindings identify local users; email and IdP roles grant no authority.
    return { id: this.subjects[payload.sub], username: this.subjects[payload.sub], roles: [], permissions: [] };
  }
}

function loadOidcAdapters(issuer, filename = process.env.OAUTH_OIDC_CONFIG_FILE) {
  if (!filename) return new Map();
  const config = JSON.parse(readKeyFile(filename, true));
  if (!config || typeof config !== 'object' || Array.isArray(config) || Object.keys(config).length > 20) throw new Error('Invalid OIDC adapters');
  return new Map(Object.entries(config).map(([id, settings]) => {
    if (!/^[a-z][a-z0-9-]{0,31}$/.test(id)) throw new Error('Invalid OIDC provider ID');
    return [id, new OidcAdapter(settings, `${issuer}/oauth/federation/${id}/callback`)];
  }));
}

module.exports = { OidcAdapter, loadOidcAdapters, trustedUrl };
