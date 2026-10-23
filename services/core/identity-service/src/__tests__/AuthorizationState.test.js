'use strict';

const crypto = require('crypto');
const http = require('http');
const express = require('express');
const request = require('supertest');
const { SignJWT, generateKeyPair, exportJWK } = require('jose');
const { AuthorizationState, authorizationRequest, authorizationTargetRequest } = require('../AuthorizationState');
const { PATH, TYPE, PURPOSE, AUDIENCE, TARGET_PATH, TARGET_PURPOSE, COMPANY_CONSOLE_PATH, COMPANY_CONSOLE_PURPOSE } = require('../../../../../packages/identity-authorization-contract');

const issuer = 'https://authority.test'; const subject = 'selected-subject';
let privateKey; let jwks; let server;
beforeAll(async () => {
  const keys = await generateKeyPair('RS256'); privateKey = keys.privateKey;
  const key = { ...await exportJWK(keys.publicKey), kid: 'authority-tests', alg: 'RS256', use: 'sig' };
  jwks = http.createServer((incoming, response) => {
    response.setHeader('Content-Type', 'application/json');
    if (incoming.url === '/unavailable') { response.statusCode = 503; return response.end('{}'); }
    response.end(JSON.stringify({ keys: [key] }));
  });
  await new Promise(resolve => jwks.listen(0, '127.0.0.1', resolve));
  const app = express(); app.use(express.json({ limit: '4kb' }));
  app.post(PATH, authorizationRequest({ issuer, jwksUri: `http://127.0.0.1:${jwks.address().port}/jwks` }), (req, res) => res.json({ issuer: req.authorityIssuer, subject: req.body.subject }));
  app.post(TARGET_PATH, authorizationTargetRequest({ issuer,jwksUri: `http://127.0.0.1:${jwks.address().port}/jwks` }), (req,res) => res.json({ issuer: req.authorityIssuer,targetId: req.body.targetId }));
  app.post(COMPANY_CONSOLE_PATH, authorizationRequest({ issuer, jwksUri: `http://127.0.0.1:${jwks.address().port}/jwks`, companyConsole: true }), (req, res) => res.json(req.body));
  server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
});
afterAll(async () => { for (const listener of [server, jwks]) { listener.closeAllConnections(); await new Promise(resolve => listener.close(resolve)); } });

function token(overrides = {}, headers = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: issuer, sub: 'oauth-provider', aud: AUDIENCE, jti: crypto.randomUUID(), iat: now, exp: now + 30,
    actor_type: 'workload', token_use: PURPOSE, scope: 'identity.authorization.read', request_subject: subject, htm: 'POST', htu: PATH, ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: 'authority-tests', typ: TYPE, ...headers }).sign(privateKey);
}
test('company console proof is separately purpose-, client- and user-bound and cannot borrow state-read or human access authority', async () => {
  const body = { clientId: 'web-app', userId: crypto.randomUUID() }; const claims = { token_use: COMPANY_CONSOLE_PURPOSE, scope: 'identity.company-console.read', htu: COMPANY_CONSOLE_PATH, console_client_id: body.clientId, console_user_id: body.userId };
  const bearer = await token(claims); expect((await request(server).post(COMPANY_CONSOLE_PATH).set('Authorization', 'Bearer ' + bearer).send(body)).status).toBe(200);
  for (const changed of [{ ...body, clientId: 'another-client' }, { ...body, userId: crypto.randomUUID() }, { ...body, tenantId: crypto.randomUUID() }]) expect((await request(server).post(COMPANY_CONSOLE_PATH).set('Authorization', 'Bearer ' + bearer).send(changed)).status).toBe(401);
  expect((await request(server).post(COMPANY_CONSOLE_PATH).set('Authorization', 'Bearer ' + await token()).send(body)).status).toBe(401);
});

test('valid workload proof grants only the selected issuer/subject read, without token-state introspection', async () => {
  const response = await request(server).post(PATH).set('Authorization', 'Bearer ' + await token()).send({ subject });
  expect(response.status).toBe(200); expect(response.body).toEqual({ issuer, subject }); expect(response.headers['cache-control']).toBe('no-store');
});
test.each([
  { token_use: 'access', actor_type: 'user', roles: ['admin'] }, { aud: 'opendirectory-api' }, { iss: 'https://other.test' },
  { sub: 'other-service' }, { scope: 'identity.authorization.read users.write' }, { request_subject: 'other' }, { htm: 'GET' }, { htu: '/api/users' },
  { actor_type: 'application' }, { jti: '' }, { exp: Math.floor(Date.now() / 1000) + 3600 }, { iat: Math.floor(Date.now() / 1000) + 100 },
])('rejects signed but wrong-purpose, overbroad or misbound assertions: %j', async override => {
  expect((await request(server).post(PATH).set('Authorization', 'Bearer ' + await token(override)).send({ subject })).status).toBe(401);
});
test.each([{ typ: 'JWT' }, { jku: 'https://attacker.test/jwks' }, { kid: '' }])('token headers cannot choose another trust source or token type: %j', async headers => {
  expect((await request(server).post(PATH).set('Authorization', 'Bearer ' + await token({}, headers)).send({ subject })).status).toBe(401);
});
test('query aliases, extra selectors and API keys never widen the authority endpoint', async () => {
  const bearer = 'Bearer ' + await token();
  for (const [route, body] of [[PATH + '?subject=other', { subject }], [PATH + '/', { subject }], [PATH, { subject, issuer: 'https://other.test' }]]) {
    expect((await request(server).post(route).set('Authorization', bearer).send(body)).status).toBe(401);
  }
  expect((await request(server).post(PATH).set('Authorization', bearer).set('X-API-Key', 'anything').send({ subject })).status).toBe(401);
});
test('an unavailable verifier source fails closed with 503 rather than accepting an unverified assertion', async () => {
  const verify = authorizationRequest({ issuer, jwksUri: `http://127.0.0.1:${jwks.address().port}/unavailable` });
  const response = { set: jest.fn(), status: jest.fn(), json: jest.fn() }; response.status.mockReturnValue(response);
  const next = jest.fn();
  await verify({ method: 'POST', originalUrl: PATH, body: { subject }, headers: { authorization: 'Bearer ' + await token() } }, response, next);
  expect(response.status).toHaveBeenCalledWith(503); expect(next).not.toHaveBeenCalled();
});
test('unknown, unlinked and disabled users are inactive and never mapped by subject guesses', async () => {
  const database = { query: jest.fn(async () => ({ rows: [] })), transaction: jest.fn() }; database.transaction.mockImplementation(operation => operation(database));
  const state = new AuthorizationState(database);
  expect(await state.state(issuer, subject)).toEqual({ schemaVersion: 1, issuer, subject, active: false });
  database.query.mockResolvedValue({ rows: [{ id: crypto.randomUUID(), enabled: false }] }); expect((await state.state(issuer, subject)).active).toBe(false);
  expect(database.query).toHaveBeenCalledWith(expect.stringContaining('JOIN users'), [issuer, subject]);
  expect(database.transaction).toHaveBeenCalledWith(expect.any(Function), { readOnly: true });
  expect(database.query).toHaveBeenCalledWith("SET LOCAL statement_timeout = '1000ms'");
});
test('state exposes only minimal canonical identity/revisions, and storage failures have no memory fallback', async () => {
  const userId = crypto.randomUUID(); const database = { query: jest.fn(async sql => ({ rows: sql.includes('FROM identity_role_assignments') || sql.includes('FROM identity_role_authentication') || (sql.includes('FROM identity_company_activations') || sql.includes('FROM identity_employee_enrollments')) || sql.includes('FROM group_members') ? [] : [{ id: userId, enabled: true, revision: '10', link_revision: '11', tenant_id: crypto.randomUUID(), tenant_version: '1', tenant_generation: '2', password: 'must-not-leak' }] })), transaction: jest.fn() };
  database.transaction.mockImplementation(operation => operation(database));
  const state = new AuthorizationState(database); expect((await state.state(issuer, subject)).context).toEqual({ userId, revision: '10', linkRevision: '11', rolesRevision: crypto.createHash('sha256').update('[[],[]]').digest('hex') });
  database.query.mockRejectedValue(new Error('offline')); await expect(state.state(issuer, subject)).rejects.toThrow('offline');
});
test('manual invalidation records the verified actor, rejects guessed identifiers and returns no profile or credentials', async () => {
  const userId = crypto.randomUUID(); const database = { write: jest.fn(async () => ({ rows: [{ authorization_revision: '12' }] })) }; const state = new AuthorizationState(database);
  expect(await state.invalidate(userId, 'verified-operator')).toEqual({ userId, revision: '12' });
  expect(database.write).toHaveBeenCalledWith(expect.stringContaining('authorization_revision+1'), [userId], 'verified-operator');
  await expect(state.invalidate('guessed-subject', 'operator')).rejects.toMatchObject({ status: 400 });
  database.write.mockResolvedValue({ rows: [] }); await expect(state.invalidate(userId, 'operator')).rejects.toMatchObject({ status: 404 });
});
test('target metadata proof is fixed-purpose and cannot be borrowed for another actor, target, path or ordinary authorization read', async () => {
  const targetId = crypto.randomUUID(); const actorUserId = crypto.randomUUID(); const body = { targetType: 'group',targetId,actorUserId };
  const proof = await token({ token_use: TARGET_PURPOSE,scope: 'identity.application-target.read',htu: TARGET_PATH,target_type: 'group',target_id: targetId,actor_user_id: actorUserId });
  expect((await request(server).post(TARGET_PATH).set('Authorization','Bearer '+proof).send(body)).status).toBe(200);
  for (const changed of [{ ...body,targetId: crypto.randomUUID() },{ ...body,actorUserId: crypto.randomUUID() },{ ...body,targetType: 'user' },{ ...body,approved: true }]) expect((await request(server).post(TARGET_PATH).set('Authorization','Bearer '+proof).send(changed)).status).toBe(401);
  expect((await request(server).post(PATH).set('Authorization','Bearer '+proof).send({ subject })).status).toBe(401);
  expect((await request(server).post(TARGET_PATH).set('Authorization','Bearer '+await token()).send(body)).status).toBe(401);
});
test('minimal target eligibility does not reveal profile or credentials and identifies current canonical self/group membership', async () => {
  const targetId = crypto.randomUUID(); const actorId = crypto.randomUUID();
  const database = { query: jest.fn(async sql => ({ rows: sql.includes('FROM users WHERE id=$1') ? [{ id: targetId,enabled: true,revision: '3',password: 'private' }] : sql.includes('actor_member') ? [{ id: targetId,revision: '4',actor_member: true }] : [] })),transaction: jest.fn() };
  database.transaction.mockImplementation(operation => operation(database)); const state = new AuthorizationState(database);
  expect(await state.target('user',targetId,actorId)).toEqual({ schemaVersion: 1,targetType: 'user',targetId,active: true,revision: '3',actorIsMember: false });
  expect(database.query).toHaveBeenLastCalledWith(expect.stringContaining("identity_tenant_id('user',id)=identity_tenant_id('user',$2::uuid)"),[targetId,actorId]);
  expect((await state.target('group',targetId,actorId)).actorIsMember).toBe(true);
});
