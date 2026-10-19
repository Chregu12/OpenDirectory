'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const express = require('express');
async function listen(server) { await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); return `http://127.0.0.1:${server.address().port}`; }
async function close(server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
async function main() {
  const { SignJWT, jwtVerify, generateKeyPair, exportJWK } = await import('jose');
  const { privateKey, publicKey } = await generateKeyPair('RS256'); const wrongKey = (await generateKeyPair('RS256')).privateKey;
  const key = { ...await exportJWK(publicKey), kid: 'quick-actions-test', alg: 'RS256', use: 'sig' }; const issuer = 'https://issuer.quick-actions.test';
  let active = true; let unavailable = false; let mismatch = false;
  const jwks = http.createServer(async (request, response) => {
    response.setHeader('Content-Type', 'application/json');
    if (request.url !== '/oauth/access-state') return response.end(JSON.stringify({ keys: [key] }));
    if (unavailable) { response.statusCode = 503; return response.end('{}'); }
    try {
      const { payload } = await jwtVerify(request.headers.authorization.slice(7), publicKey, { issuer, audience: 'opendirectory-api' });
      response.end(JSON.stringify(active ? { schemaVersion: 1, active: true, issuer: payload.iss, subject: mismatch ? 'wrong-subject' : payload.sub, tokenId: payload.jti, expiresAt: payload.exp } : { schemaVersion: 1, active: false }));
    } catch { response.statusCode = 401; response.end('{}'); }
  });
  const authority = await listen(jwks); Object.assign(process.env, { JWKS_URI: authority + '/jwks', OIDC_ISSUER: issuer, OIDC_ACCESS_STATE_URL: authority + '/oauth/access-state', SERVICE_TOKEN: 'test-legacy-credential' });
  const authenticate = require('../../middleware/auth'); const { requireQuickActionAccess } = require('../../middleware/quickActionsAccess');
  const app = express(); app.use(express.json()); app.use(authenticate); app.use('/api/quick', requireQuickActionAccess);
  app.get('/api/quick/service-principals', (request, response) => response.json({ subject: request.user.sub }));
  app.post('/api/quick/service-principals', (request, response) => response.status(201).json({ subject: request.user.sub }));
  const server = http.createServer(app); const base = await listen(server); let checks = 0;
  async function token(claims = {}, options = {}) {
    const now = Math.floor(Date.now() / 1000);
    const jwt = new SignJWT({ sub: 'verified-actor', jti: crypto.randomUUID(), token_use: 'access', actor_type: 'user', sid: crypto.randomUUID(), auth_time: now, client_id: 'fixture-client',
      identity_authorization: { userId: crypto.randomUUID(), revision: '1', linkRevision: '2', rolesRevision: 'a'.repeat(64) }, ...claims })
      .setProtectedHeader({ alg: 'RS256', kid: key.kid }).setIssuer(options.issuer || issuer).setIssuedAt().setExpirationTime(options.expired ? now - 1 : '5m');
    if (options.audience !== null) jwt.setAudience(options.audience || 'opendirectory-api'); return jwt.sign(options.privateKey || privateKey);
  }
  async function check(credential, method, status, body = {}, suffix = '', headers = {}) {
    const response = await fetch(base + '/api/quick/service-principals' + suffix, { method, headers: { 'Content-Type': 'application/json', ...(credential ? { Authorization: 'Bearer ' + credential } : {}), ...headers }, ...(method === 'POST' ? { body: JSON.stringify(body) } : {}) });
    assert.equal(response.status, status, `${method} must return ${status}`); checks++; return response.json();
  }
  try {
    await check(null, 'GET', 401); await check('not-a-signed-token', 'GET', 401);
    await check(await token({ permissions: ['applications.read'] }), 'GET', 200);
    await check(await token({ roles: ['application-reader'] }), 'POST', 403);
    assert.equal((await check(await token({ permissions: ['applications.create'] }), 'POST', 201, { createdBy: 'forged' })).subject, 'verified-actor');
    await check(await token({ scope: 'applications.read' }), 'GET', 403);
    for (const token_use of ['id', 'refresh', undefined]) await check(await token({ roles: ['admin'], token_use }), 'GET', 401);
    await check(await token({ roles: ['admin'] }, { issuer: 'https://untrusted.test' }), 'GET', 401);
    await check(await token({ roles: ['admin'] }, { privateKey: wrongKey }), 'GET', 401);
    await check(await token({ roles: ['admin'] }, { expired: true }), 'GET', 401);
    await check(await token({ sub: '', roles: ['admin'] }), 'GET', 401);
    await check(await token({ roles: 'admin' }), 'GET', 403); await check('svc-test-legacy-credential', 'GET', 401);
    await check(await token({ realm_access: { roles: ['application-reader'] } }), 'GET', 200);
    await check(await token({ roles: ['admin'] }), 'GET', 200);
    await check(await token({ roles: ['admin'] }, { audience: 'another-resource' }), 'GET', 401);
    await check(await token({ roles: ['admin'] }, { audience: null }), 'GET', 401);
    await check(await token({ roles: ['admin'], identity_authorization: undefined }), 'GET', 401);
    await check(await token({ roles: ['admin'], actor_type: 'device' }), 'GET', 401);
    const credential = await token({ roles: ['admin'] });
    await check(credential, 'GET', 401, {}, '?access_token=ignored'); await check(credential, 'GET', 401, {}, '', { 'X-API-Key': 'ignored' });
    active = false; await check(credential, 'GET', 401); active = true;
    unavailable = true; await check(credential, 'GET', 503); unavailable = false;
    mismatch = true; await check(credential, 'GET', 503); mismatch = false;
    await check(credential, 'GET', 200);
    await check(await token({ actor_type: 'application', roles: ['admin'], identity_authorization: undefined }), 'POST', 403);
    await check(await token({ actor_type: 'application', permissions: ['applications.read'], identity_authorization: undefined }), 'GET', 200);
    process.stdout.write(`Signed authorization: ${checks} checks passed\n`);
  } finally { await close(server); await close(jwks); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
