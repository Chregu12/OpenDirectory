'use strict';

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const request = require('supertest');
const rateLimit = require('express-rate-limit');
const { SignJWT, generateKeyPair, exportJWK } = require('jose');
const { authorityAdmission } = require('../AuthorityAdmission');
const { authorizationRequest, authorizationTargetRequest } = require('../AuthorizationState');
const { PATH, TARGET_PATH, AUDIENCE, PURPOSE, TARGET_PURPOSE, TYPE } = require('../../../../../packages/identity-authorization-contract');
const issuer = 'https://authority-admission.test'; const body = { subject: 'owner' };
let server; let jwks; let privateKey; let app; let sourceCalls; let sourceStatus;
beforeAll(async () => {
  const keys = await generateKeyPair('RS256'); privateKey = keys.privateKey;
  const key = { ...await exportJWK(keys.publicKey), kid: 'admission-test', alg: 'RS256', use: 'sig' };
  jwks = http.createServer((_req, res) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ keys: [key] })); });
  await new Promise(resolve => jwks.listen(0, '127.0.0.1', resolve));
  server = http.createServer((req, res) => app(req, res)); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
});
afterAll(async () => { for (const listener of [server, jwks]) { listener.closeAllConnections(); await new Promise(resolve => listener.close(resolve)); } });
function configure(ingressMax = 20) {
  sourceCalls = 0; sourceStatus = 200; app = express();
  const limits = authorityAdmission({ ingressMax, verifiedMax: 3 }); const verification = { issuer, jwksUri: `http://127.0.0.1:${jwks.address().port}/jwks` };
  const respond = (_req, res) => { sourceCalls++; res.status(sourceStatus).json({ active: true }); };
  app.post(PATH, limits.ingress, express.json({ limit: '4kb' }), authorizationRequest(verification), limits.verified, respond);
  app.post(TARGET_PATH, limits.ingress, express.json({ limit: '4kb' }), authorizationTargetRequest(verification), limits.verified, respond);
  app.use(rateLimit({ windowMs: 60000, max: 2 })); app.get('/resource', (_req, res) => res.json({ ok: true }));
}
beforeEach(() => configure());
function proof(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: issuer, sub: 'oauth-provider', aud: AUDIENCE, jti: crypto.randomUUID(), iat: now, exp: now + 30,
    actor_type: 'workload', token_use: PURPOSE, scope: 'identity.authorization.read', request_subject: body.subject, htm: 'POST', htu: PATH, ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: 'admission-test', typ: TYPE }).sign(privateKey);
}
test('a saturated public API budget cannot deny an independently authenticated live authority checkpoint', async () => {
  for (let count = 0; count < 2; count++) expect((await request(server).get('/resource')).status).toBe(200);
  expect((await request(server).get('/resource')).status).toBe(429);
  expect((await request(server).post(PATH).set('Authorization', 'Bearer ' + await proof()).send(body)).status).toBe(200); expect(sourceCalls).toBe(1);
});
test('live source reads cannot consume the public resource budget', async () => {
  for (let count = 0; count < 3; count++) expect((await request(server).post(PATH).set('Authorization', 'Bearer ' + await proof()).send(body)).status).toBe(200);
  for (let count = 0; count < 2; count++) expect((await request(server).get('/resource')).status).toBe(200);
});
test('both signed authority purposes share a bounded issuer budget rather than opening an unmetered internal bypass', async () => {
  for (let count = 0; count < 3; count++) expect((await request(server).post(PATH).set('Authorization', 'Bearer ' + await proof()).send(body)).status).toBe(200);
  const target = { targetType: 'user', targetId: crypto.randomUUID(), actorUserId: crypto.randomUUID() };
  const token = await proof({ htu: TARGET_PATH, token_use: TARGET_PURPOSE, scope: 'identity.application-target.read', target_type: target.targetType, target_id: target.targetId, actor_user_id: target.actorUserId });
  expect((await request(server).post(TARGET_PATH).set('Authorization', 'Bearer ' + token).send(target)).status).toBe(429); expect(sourceCalls).toBe(3);
});
test('forged issuer fields, invalid proofs and ordinary bearer purposes never reach the source and are ingress-limited', async () => {
  configure(2);
  expect((await request(server).post(PATH).send({ ...body, authorityIssuer: issuer })).status).toBe(401);
  expect((await request(server).post(PATH).set('Authorization', 'Bearer ' + await proof({ token_use: 'access' })).send(body)).status).toBe(401);
  expect((await request(server).post(PATH).set('Authorization', 'Bearer invalid').send(body)).status).toBe(429); expect(sourceCalls).toBe(0);
});
test('a failing signed source remains bounded independently from public request accounting', async () => {
  sourceStatus = 503;
  for (let count = 0; count < 3; count++) expect((await request(server).post(PATH).set('Authorization', 'Bearer ' + await proof()).send(body)).status).toBe(503);
  expect((await request(server).post(PATH).set('Authorization', 'Bearer ' + await proof()).send(body)).status).toBe(429);
  expect((await request(server).get('/resource')).status).toBe(200);
});
