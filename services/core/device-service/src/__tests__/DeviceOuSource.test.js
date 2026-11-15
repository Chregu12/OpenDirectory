'use strict';
const { randomUUID } = require('node:crypto');
const { DeviceOuSource } = require('../DeviceOuSource');
const C = require('../../../../../packages/device-ou-contract');
let user, proof, authority, fetchImpl, ou;
beforeEach(() => {
  const now = Math.floor(Date.now() / 1000), id = randomUUID();
  user = { actor_type: 'user', iss: 'https://device-ou.test', sub: 'original', jti: randomUUID(), exp: now + 3600, auth_time: now, identity_authorization: { userId: id, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } };
  ou = { id: randomUUID(), generation: '2', revision: '3', name: 'Own engineering', parentId: null };
  proof = { schemaVersion: 1, deviceOuProtocol: 1, inventory: { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization,
    actorUserId: id, tenant: { id: randomUUID(), version: '1', generation: '1' }, permissions: ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign'], validUntil: now + 300, target: null }, ou, directoryGrant: null, validUntil: now + 300 };
  fetchImpl = jest.fn(async () => Response.json(proof)); authority = new DeviceOuSource({ endpoint: 'https://identity.test/api/identity/device-organizational-units', fetchImpl });
});
test('only the selected original OU and human bearer reach the private source', async () => {
  await expect(authority.read('Bearer original', user, ou.id)).resolves.toEqual(proof);
  expect(fetchImpl).toHaveBeenCalledWith(expect.any(URL), expect.objectContaining({ method: 'POST', body: JSON.stringify({ ouId: ou.id }), headers: { Authorization: 'Bearer original', Accept: 'application/json', 'Content-Type': 'application/json' }, redirect: 'error', cache: 'no-store' }));
});
test.each(['extra', 'actor', 'ou', 'revision', 'expiry', 'inventory', 'directory'])('substituted %s source cannot authorize an OU change', async variant => {
  if (variant === 'extra') proof.admin = true;
  if (variant === 'actor') proof.inventory.actorUserId = randomUUID();
  if (variant === 'ou') proof.ou = { ...ou, id: randomUUID() };
  if (variant === 'revision') proof.ou.revision = '0';
  if (variant === 'expiry') proof.validUntil = proof.inventory.validUntil + 1;
  if (variant === 'inventory') proof.inventory.permissions = ['devices.inventory.read'];
  if (variant === 'directory') proof.directoryGrant = { id: randomUUID() };
  await expect(authority.read('Bearer original', user, ou.id)).rejects.toMatchObject({ status: 503 });
});
test('purpose, credentials, tenant overrides and nonhuman actors fail before HTTP', async () => {
  for (const endpoint of ['https://identity.test/api/identity/device-inventory', 'https://user:password@identity.test/api/identity/device-organizational-units', 'https://identity.test/api/identity/device-organizational-units?tenant=other']) expect(() => new DeviceOuSource({ endpoint })).toThrow();
  await expect(authority.read('Bearer original', { ...user, actor_type: 'application' }, ou.id)).rejects.toMatchObject({ status: 401 }); expect(fetchImpl).not.toHaveBeenCalled();
  expect(() => C.input({ ou: null, reason: 'Explicit decision', confirm: true, tenantId: randomUUID() })).toThrow();
});
test('a selected directory grant retains its original actor, deadline and exact source fields', async () => {
  proof.directoryGrant = { id: randomUUID(), roleId: randomUUID(), roleRevision: '1', scopeType: 'tenant', ouId: null, targetType: 'user', targetId: user.identity_authorization.userId, membershipId: null, validUntil: String(proof.validUntil) };
  await expect(authority.read('Bearer original', user, ou.id)).resolves.toEqual(proof);
  proof.directoryGrant.targetId = randomUUID(); await expect(authority.read('Bearer original', user, ou.id)).rejects.toMatchObject({ status: 503 });
});
test('removal requires an actual untargeted source and cannot retain a directory grant', async () => {
  proof.ou = null; await expect(authority.read('Bearer original', user, null)).resolves.toEqual(proof);
  proof.directoryGrant = {}; await expect(authority.read('Bearer original', user, null)).rejects.toMatchObject({ status: 503 });
});
test('catalog pages are bound to the requested actor, tenant, count and exact unit metadata', async () => {
  const page = { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: proof.inventory.actorUserId, tenantId: proof.inventory.tenant.id, units: [ou], total: 1, page: 1, limit: 25 };
  fetchImpl.mockImplementation(async () => Response.json(page)); await expect(authority.units('Bearer original', user, page.tenantId, {})).resolves.toEqual(page);
  page.tenantId = randomUUID(); await expect(authority.units('Bearer original', user, proof.inventory.tenant.id, {})).rejects.toMatchObject({ status: 503 });
});
test('malformed bodies and excess or unconfirmed authority responses fail closed', async () => {
  for (const response of [new Response('not JSON', { headers: { 'Content-Type': 'application/json' } }), Response.json({ data: 'x'.repeat(32769) }), new Response('{}', { status: 200, headers: { 'Content-Type': 'text/html' } })]) {
    fetchImpl.mockResolvedValueOnce(response); await expect(authority.read('Bearer original', user, ou.id)).rejects.toMatchObject({ status: 503 });
  }
});
test.each([401, 403, 404, 428, 503])('actual source denial %i preserves failure without fallback', async status => {
  fetchImpl.mockResolvedValueOnce(Response.json({}, { status })); await expect(authority.read('Bearer original', user, ou.id)).rejects.toMatchObject({ status });
});
function statusProof() { return { schemaVersion: 1, deviceOuStatusProtocol: 1, inventory: proof.inventory, selection: { id: ou.id, generation: ou.generation }, currentOu: ou, directoryGrant: null, validUntil: proof.validUntil }; }
test('current status uses its own private purpose and original OU generation without write authority', async () => {
  const value = statusProof(); fetchImpl.mockResolvedValueOnce(Response.json(value));
  await expect(authority.status('Bearer original', user, value.selection)).resolves.toEqual(value);
  expect(String(fetchImpl.mock.calls[0][0])).toBe('https://identity.test/api/identity/device-organizational-units/status');
  expect(fetchImpl.mock.calls[0][1]).toMatchObject({ method: 'POST', body: JSON.stringify({ selection: value.selection }), headers: { Authorization: 'Bearer original' }, redirect: 'error' });
});
test.each(['purpose', 'actor', 'tenant', 'generation', 'selection', 'expiry', 'directory', 'extra'])('unconfirmed status %s cannot populate current OU metadata', async variant => {
  const value = statusProof();
  if (variant === 'purpose') { delete value.deviceOuStatusProtocol; value.deviceOuProtocol = 1; }
  if (variant === 'actor') value.inventory.actorUserId = randomUUID();
  if (variant === 'tenant') value.inventory.tenant = { id: randomUUID(), generation: '0', version: '1' };
  if (variant === 'generation') value.currentOu = { ...ou, generation: '99' };
  if (variant === 'selection') value.selection = { ...value.selection, id: randomUUID() };
  if (variant === 'expiry') value.validUntil++;
  if (variant === 'directory') value.directoryGrant = {};
  if (variant === 'extra') value.source = {};
  fetchImpl.mockResolvedValueOnce(Response.json(value)); await expect(authority.status('Bearer original', user, { id: ou.id, generation: ou.generation })).rejects.toMatchObject({ status: 503 });
});
test('status cannot be mistaken for a write proof, and an unassigned status needs no directory grant', async () => {
  const value = statusProof(); fetchImpl.mockResolvedValueOnce(Response.json(value)); await expect(authority.read('Bearer original', user, ou.id)).rejects.toMatchObject({ status: 503 });
  value.selection = null; value.currentOu = null; fetchImpl.mockResolvedValueOnce(Response.json(value)); await expect(authority.status('Bearer original', user, null)).resolves.toEqual(value);
});
