import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomUUID, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, writeFile, stat, unlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createClient } from '../opendirectory-client.mjs';
import { createEmployeeInvitationClient, createEmployeeInvitationFile } from '../employee-invitations.mjs';

const run = promisify(execFile);
const id = randomUUID(), userId = randomUUID(), tenantId = randomUUID();
const secret = id + '.' + randomBytes(32).toString('base64url');
const input = { id, userId, userRevision: '1', loginName: 'employee.test', durationHours: 72, reason: 'Explicit ordinary employee invitation', confirm: true };
const original = { id, tenantId, userId, loginName: input.loginName, organizationName: 'Own company', status: 'pending', revision: '1',
  createdAt: '2026-11-14T00:00:00.000Z', expiresAt: '2026-11-17T00:00:00.000Z', credentialCreated: false, identityConfirmed: false };
const envelope = { schemaVersion: 1, employeeInvitationProtocol: 1 };
let server, origin, directory, calls, mode, stored;

before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'od-invitation-cli-'));
  server = http.createServer(async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : null;
    calls.push({ path: req.url, authorization: req.headers.authorization, method: req.method, body });
    const send = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    if (mode === 'redirect') { res.writeHead(307, { Location: origin + '/stolen' }); return res.end(); }
    if (mode === 'forbidden' || req.headers.authorization !== 'Bearer original-owner-token') return send(403, { error: 'employee_invitation_owner_required', secret: 'must-not-be-logged' });
    if (req.method !== 'POST') return send(405, { error: 'method_not_allowed' });
    if (req.url === '/oauth/employee-invitations/owner/create') {
      if (mode === 'uncertain') { stored = { ...original }; return send(503, { error: 'employee_invitation_unavailable' }); }
      const created = !stored; stored ||= { ...original };
      const value = { ...envelope, invitation: { ...stored }, created, invitationToken: created ? secret : null, mailStatus: created ? 'sent' : 'not_sent' };
      if (mode === 'wrong-target') value.invitation.userId = randomUUID();
      if (mode === 'wrong-token') value.invitationToken = randomUUID() + secret.slice(36);
      if (mode === 'extra-secret') value.password = 'must-not-be-logged';
      if (mode === 'replayed-secret') { value.created = false; value.invitationToken = secret; }
      if (mode === 'wrong-lease') value.invitation.expiresAt = '2026-11-18T00:00:00.000Z';
      return send(mode === 'wrong-status' || !value.created ? 200 : 201, value);
    }
    if (req.url === '/oauth/employee-invitations/owner/list') {
      const invitations = mode === 'mixed-tenant' ? [{ ...original }, { ...original, id: randomUUID(), tenantId: randomUUID() }] : [{ ...original }];
      return send(200, { ...envelope, page: mode === 'wrong-page' ? body.page + 1 : body.page, hasMore: false, invitations });
    }
    if (req.url === '/oauth/employee-invitations/owner/get') return send(200, { ...envelope, invitation: { ...(stored || original), ...(mode === 'wrong-id' ? { id: randomUUID() } : {}) } });
    if (req.url === '/oauth/employee-invitations/owner/revoke') return send(200, { ...envelope, invitation: { ...original, status: 'revoked', revision: mode === 'wrong-revision' ? '3' : '2' }, partialEnrollmentWithdrawn: mode !== 'missing-withdrawal' });
    send(404, { error: 'not_found' });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); origin = 'http://127.0.0.1:' + server.address().port;
});
beforeEach(() => { calls = []; mode = ''; stored = null; });
after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
const client = (token = 'original-owner-token') => createEmployeeInvitationClient(createClient({ issuer: origin, apiUrl: 'https://unrelated-api.invalid',
  adminToken: token, clientId: 'must-not-be-used', clientSecret: 'must-not-be-used' }));

test('management stays on the issuer with the original human bearer and preserves explicit create intent', async () => {
  const created = await client().create(input);
  assert.equal(created.invitationToken, secret); assert.equal(created.created, true);
  assert.deepEqual(calls, [{ path: '/oauth/employee-invitations/owner/create', method: 'POST', authorization: 'Bearer original-owner-token', body: input }]);
  assert.equal((await client().get(id)).invitation.id, id);
  assert.equal((await client().list(2)).page, 2);
  const revoke = { id, revision: '1', reason: 'Withdraw this original pending invitation', confirm: true };
  assert.equal((await client().revoke(revoke)).partialEnrollmentWithdrawn, true);
  assert.deepEqual(calls[3].body, revoke);
  assert.ok(calls.every(call => call.authorization === 'Bearer original-owner-token'));
});

test('invalid IDs, bodies, confirmations, versions and pages fail before any request', async () => {
  for (const page of [0, -1, 1.5, 1000001, '1']) await assert.rejects(client().list(page));
  await assert.rejects(client().get('../other'));
  for (const body of [{ ...input, confirm: false }, { ...input, userRevision: '0' }, { ...input, durationHours: 73 }, { ...input, reason: 'short' }, { ...input, roles: ['admin'] }]) await assert.rejects(client().create(body));
  for (const body of [{ id, revision: '01', reason: input.reason, confirm: true }, { id, revision: '1', reason: input.reason, confirm: false }]) await assert.rejects(client().revoke(body));
  await assert.rejects(client('').list());
  assert.deepEqual(calls, []);
});

test('creation refuses substituted recipients, secrets, leases, response status and extra private fields', async () => {
  for (mode of ['wrong-target', 'wrong-token', 'wrong-lease', 'wrong-status', 'extra-secret', 'replayed-secret']) {
    stored = null; await assert.rejects(client().create(input));
  }
});

test('read and revoke reject wrong pages, mixed tenants, changed IDs and incomplete partial-enrollment withdrawal', async () => {
  for (mode of ['wrong-page', 'mixed-tenant']) await assert.rejects(client().list());
  mode = 'wrong-id'; await assert.rejects(client().get(id));
  for (mode of ['wrong-revision', 'missing-withdrawal']) await assert.rejects(client().revoke({ id, revision: '1', reason: input.reason, confirm: true }));
});

test('the same create UUID returns metadata without another one-time token', async () => {
  await client().create(input);
  const replay = await client().create(input);
  assert.equal(replay.created, false); assert.equal(replay.invitationToken, null); assert.equal(replay.mailStatus, 'not_sent');
});

test('existing result files are refused before creating an invitation', async () => {
  const filename = join(directory, 'existing.json'); await writeFile(filename, 'retained personal data');
  await assert.rejects(createEmployeeInvitationFile(client(), input, filename), { code: 'EEXIST' });
  assert.equal(await readFile(filename, 'utf8'), 'retained personal data'); assert.deepEqual(calls, []);
});

test('a replaced result destination is never overwritten or removed', async () => {
  const filename = join(directory, 'replaced.json');
  const replacing = { create: async () => { await unlink(filename); await writeFile(filename, 'unrelated replacement'); return { ...envelope, invitation: original, created: true, invitationToken: secret, mailStatus: 'sent' }; } };
  await assert.rejects(createEmployeeInvitationFile(replacing, input, filename), /destination changed/);
  assert.equal(await readFile(filename, 'utf8'), 'unrelated replacement');
});

async function cli(args, token = 'original-owner-token') {
  return run(process.execPath, [fileURLToPath(new URL('../../od.mjs', import.meta.url)), 'employee-invitation', ...args], {
    env: { ...process.env, OPENDIRECTORY_ISSUER: origin, OPENDIRECTORY_API_URL: 'https://unrelated-api.invalid', OPENDIRECTORY_ADMIN_ACCESS_TOKEN: token,
      OPENDIRECTORY_CLIENT_ID: 'must-not-be-used', OPENDIRECTORY_CLIENT_SECRET: 'must-not-be-used' }, timeout: 10000,
  });
}

test('actual CLI create stores its one-time secret privately and reports Graph acceptance separately from delivery', async () => {
  const request = join(directory, 'create.json'), result = join(directory, 'result.json'); await writeFile(request, JSON.stringify(input));
  const { stdout, stderr } = await cli(['create', request, '--result-file', result]);
  const summary = JSON.parse(stdout), saved = JSON.parse(await readFile(result, 'utf8'));
  assert.equal(summary.created, true); assert.equal(summary.mailRequestStatus, 'provider_accepted'); assert.equal(summary.deliveryConfirmed, false);
  assert.equal(summary.invitationToken, undefined); assert.equal(saved.invitationToken, secret); assert.equal((await stat(result)).mode & 0o777, 0o600);
  assert.ok(!stdout.includes(secret) && !stderr.includes(secret));
  const again = join(directory, 'replay.json'); const replay = JSON.parse((await cli(['create', request, '--result-file', again])).stdout);
  assert.equal(replay.created, false); assert.equal(JSON.parse(await readFile(again, 'utf8')).invitationToken, null);
  assert.deepEqual(JSON.parse((await cli(['get', id])).stdout).invitation.id, id);
  assert.equal(JSON.parse((await cli(['list', '2'])).stdout).page, 2);
  const revocation = join(directory, 'revoke.json'); await writeFile(revocation, JSON.stringify({ id, revision: '1', reason: 'Explicit original CLI invitation revocation', confirm: true }));
  assert.equal(JSON.parse((await cli(['revoke', revocation])).stdout).invitation.status, 'revoked');
});

test('actual CLI denies missing/insufficient Owner authority and never echoes private error bodies', async () => {
  mode = 'forbidden';
  for (const token of ['', 'ordinary-user', 'application-token']) {
    await assert.rejects(cli(['list'], token), error => error.code === 1 && !error.stderr.includes('must-not-be-logged') && !error.stdout);
  }
  assert.equal(calls.length, 2); assert.ok(calls.every(call => call.path === '/oauth/employee-invitations/owner/list'));
});

test('a lost create result is read back by original ID without automatic retry or a replacement credential', async () => {
  const request = join(directory, 'uncertain-create.json'), result = join(directory, 'uncertain-result.json'); await writeFile(request, JSON.stringify(input));
  mode = 'uncertain'; await assert.rejects(cli(['create', request, '--result-file', result]), error => error.code === 1);
  assert.equal(calls.length, 1); assert.equal(await readFile(result, 'utf8'), ''); assert.equal((await stat(result)).mode & 0o777, 0o600);
  mode = ''; const observed = JSON.parse((await cli(['get', id])).stdout);
  assert.equal(observed.invitation.id, id); assert.equal(observed.invitation.status, 'pending'); assert.equal(observed.invitationToken, undefined);
});

test('Owner tokens are never forwarded across an issuer redirect', async () => {
  mode = 'redirect'; await assert.rejects(client().list());
  assert.equal(calls.length, 1); assert.notEqual(calls[0].path, '/stolen');
});
