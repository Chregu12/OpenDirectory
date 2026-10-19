'use strict';

const { randomUUID } = require('node:crypto');
const { LicenseAllocator, LicenseError } = require('../LicenseAllocator');
const { GroupLicenseAllocator } = require('../GroupLicenseAllocator');
const { LicenseDelegations } = require('../LicenseDelegations');
const { LicenseGrants } = require('../LicenseGrants');
const { LicenseReviews } = require('../LicenseReviews');
const { LicenseScopeActivations } = require('../LicenseScopeActivations');
const { LicenseScopePolicies } = require('../LicenseScopePolicies');
const { LicenseScopeReviews } = require('../LicenseScopeReviews');
const { withdrawSource, syncRecipients } = require('../LicenseSourceMutation');
const { ProviderStore } = require('../fulfillment/ProviderStore');
const { FulfillmentWorker } = require('../fulfillment/FulfillmentWorker');
const { companyLicenseContext } = require('../CompanyLicenseContext');

function fixture() {
  const licenseId = randomUUID(); const targetId = randomUUID(); const reviewerId = randomUUID(); const userId = randomUUID();
  const principal = { issuer: 'https://legacy-isolation.test', subject: userId, userId, enabled: true };
  const authTime = Math.floor(Date.now() / 1000);
  const user = { actor_type: 'user', iss: principal.issuer, sub: userId,
    roles: ['license-manager', 'license-scope-administrator', 'license-delegate', 'license-review-administrator', 'license-reviewer', 'license-scope-policy-administrator', 'license-scope-activation-reviewer', 'license-delegation-review-administrator', 'license-delegation-reviewer', 'license-provider-administrator'],
    identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, auth_time: authTime, amr: ['pwd', 'otp'],
    mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime, methods: ['pwd', 'otp'] } };
  const database = { query: jest.fn().mockResolvedValue({ rows: [] }) };
  const source = Object.fromEntries(['user', 'snapshot', 'delegate', 'reviewer', 'activationReviewer', 'scopeReviewer'].map(name => [name, jest.fn()]));
  const allocator = { database, users: { source, active: jest.fn(), read: jest.fn() }, transaction: jest.fn(), lockSubjects: jest.fn(),
    assertLegacySubject: jest.fn().mockResolvedValue(undefined), assertPoolAccess: jest.fn().mockRejectedValue(new LicenseError(404, 'License not found')) };
  const delegations = new LicenseDelegations(allocator, { source, revalidate: jest.fn() });
  const groups = new GroupLicenseAllocator({ allocator, source });
  return { allocator, database, source, delegations, groups, user, principal, licenseId, targetId, reviewerId, authorization: 'Bearer original-human',
    confirmed: { reason: 'Explicit independent legacy operation review', confirm: true } };
}

const poolOperations = [
  ['group assignment', frame => frame.groups.assign(frame.licenseId, { assignee_id: frame.targetId }, frame.principal.userId, frame)],
  ['group reconciliation', frame => frame.groups.reconcile(frame.licenseId, frame.targetId, frame.principal.userId, frame)],
  ['group request', frame => frame.groups.request(frame.licenseId, { requester_id: frame.principal.userId }, frame)],
  ['group transaction', frame => frame.groups.inPool(frame.licenseId, { groupId: frame.targetId }, frame.principal.userId, jest.fn())],
  ['grant get', frame => new LicenseGrants(frame.allocator).get(frame.licenseId, frame.targetId)],
  ['grant list', frame => new LicenseGrants(frame.allocator).list(frame.licenseId)],
  ['delegation list', frame => frame.delegations.list(frame.licenseId, undefined, frame.user, frame.principal)],
  ['delegation create', frame => frame.delegations.create({ ...frame.confirmed, licenseId: frame.licenseId, userId: frame.targetId, duty: 'allocator', durationSeconds: 60 }, frame.user, frame.principal, frame.authorization)],
  ['delegated execution', frame => frame.delegations.run(frame.licenseId, 'pool.read', null, frame.user, frame.principal, frame.authorization, jest.fn())],
  ['delegated read', frame => frame.delegations.read(frame.licenseId, jest.fn(), frame.principal.userId)],
  ['review policy get', frame => new LicenseReviews(frame.allocator).policy(frame.licenseId, frame.user, frame.principal)],
  ['review policy create', frame => new LicenseReviews(frame.allocator).create({ licenseId: frame.licenseId, intervalSeconds: 3600, windowSeconds: 60, reviewerUserIds: [frame.reviewerId], reason: frame.confirmed.reason, acknowledgeDeadlines: true }, frame.user, frame.principal, frame.authorization)],
  ['review inventory', frame => new LicenseReviews(frame.allocator).inventory(frame.database, frame.licenseId)],
  ['review transaction', frame => new LicenseReviews(frame.allocator).inPool(frame.licenseId, frame.principal.userId, null, jest.fn())],
  ['PIM eligibility create', frame => new LicenseScopeActivations(frame.allocator, { delegations: frame.delegations }).create({ ...frame.confirmed, licenseId: frame.licenseId, userId: frame.targetId, duty: 'allocator', durationSeconds: 3600, maxDurationSeconds: 60, reviewerUserIds: [frame.reviewerId] }, frame.user, frame.principal, frame.authorization)],
  ['PIM list', frame => new LicenseScopeActivations(frame.allocator, { delegations: frame.delegations }).list(frame.licenseId, undefined, frame.user, frame.principal)],
  ['activation policy get', frame => new LicenseScopePolicies(frame.allocator, { delegations: frame.delegations }).get(frame.licenseId, 'allocator', frame.user, frame.principal)],
  ['activation policy prepare', frame => new LicenseScopePolicies(frame.allocator, { delegations: frame.delegations }).prepare(frame.database, frame.licenseId, 'allocator', [], frame.principal.userId, frame.principal.issuer, frame.authorization, 60)],
  ['delegation review policy get', frame => new LicenseScopeReviews(frame.allocator, { delegations: frame.delegations }).policy(frame.licenseId, 'allocator', 'grant', frame.user, frame.principal)],
  ['delegation review inventory', frame => new LicenseScopeReviews(frame.allocator, { delegations: frame.delegations }).inventory(frame.licenseId, 'allocator', 'grant', frame.principal.issuer)],
  ['delegation review create', frame => new LicenseScopeReviews(frame.allocator, { delegations: frame.delegations }).create({ ...frame.confirmed, licenseId: frame.licenseId, duty: 'allocator', targetKind: 'grant', intervalSeconds: 60, windowSeconds: 60, reviewerUserIds: [frame.reviewerId], acknowledgeCutoffs: true }, frame.user, frame.principal, frame.authorization)],
  ['source withdrawal', frame => withdrawSource(frame.allocator, frame.database, { id: frame.targetId, licenseId: frame.licenseId }, frame.principal.userId)],
  ['recipient synchronization', frame => syncRecipients(frame.allocator, frame.database, frame.licenseId, [], frame.principal.userId)],
  ['provider product create', frame => new ProviderStore(frame.allocator).create('products', { licenseId: frame.licenseId, connectorId: frame.targetId, skuId: frame.reviewerId, disabledPlans: [], exclusiveDirectManagement: true, reason: frame.confirmed.reason }, frame.user, frame.principal, frame.authorization)],
  ['provider target lookup', frame => new ProviderStore(frame.allocator).lookup(frame.licenseId, frame.targetId, frame.user)],
];

test.each(poolOperations)('%s rejects company pools before directory calls, transaction or child access', async (_name, operation) => {
  const frame = fixture();
  await expect(operation(frame)).rejects.toMatchObject({ status: 404 });
  expect(frame.allocator.assertPoolAccess).toHaveBeenCalledWith(frame.licenseId, frame.database, { legacyOnly: true });
  expect(frame.database.query).not.toHaveBeenCalled();
  expect(frame.allocator.transaction).not.toHaveBeenCalled();
  expect(frame.allocator.users.active).not.toHaveBeenCalled();
  for (const source of Object.values(frame.source)) expect(source).not.toHaveBeenCalled();
});

test.each([false, true])('actual pool ownership rejects legacy access even with company context=%s', async captured => {
  const frame = fixture(); const tenantId = randomUUID();
  frame.database.query.mockResolvedValue({ rows: [{ id: frame.licenseId, business_tenant_id: tenantId }] });
  const allocator = new LicenseAllocator(frame.database, { source: frame.source });
  const operation = () => new LicenseGrants(allocator).list(frame.licenseId);
  if (captured) await expect(companyLicenseContext.run({ database: frame.database, tenantId, licenseId: frame.licenseId }, operation)).rejects.toMatchObject({ status: 404 });
  else await expect(operation()).rejects.toMatchObject({ status: 404 });
  expect(frame.database.query).toHaveBeenCalledTimes(1);
});

const childOperations = [
  ['license request', frame => new LicenseAllocator(frame.database, { source: frame.source }).review(frame.targetId, frame.principal.userId, 'approved', { principal: frame.principal })],
  ['delegation', frame => frame.delegations.revoke(frame.targetId, 'expected-version', frame.confirmed, frame.user, frame.principal, frame.authorization)],
  ['PIM eligibility', frame => new LicenseScopeActivations(frame.allocator).peek(frame.targetId)],
  ['PIM request', frame => new LicenseScopeActivations(frame.allocator).peek(frame.targetId, true)],
  ['review policy', frame => new LicenseReviews(frame.allocator).retire(frame.targetId, 'expected-version', { reason: frame.confirmed.reason, acknowledgeDeadlines: true }, frame.user, frame.principal, frame.authorization)],
  ['review lease', frame => new LicenseReviews(frame.allocator).get(frame.targetId, frame.user, frame.principal)],
  ['delegation review policy', frame => new LicenseScopeReviews(frame.allocator).retire(frame.targetId, 'expected-version', frame.confirmed, frame.user, frame.principal, frame.authorization)],
  ['delegation review lease', frame => new LicenseScopeReviews(frame.allocator).get(frame.targetId, frame.user, frame.principal)],
  ['provider product', frame => new ProviderStore(frame.allocator).get('products', frame.targetId)],
  ['provider target', frame => new ProviderStore(frame.allocator).row(frame.targetId).then(row => { if (row !== undefined) throw new Error('Unexpected target'); })],
];

test.each(childOperations)('arbitrary %s UUID first resolves through a null-owned catalog parent', async (_name, operation) => {
  const frame = fixture();
  try { await operation(frame); } catch (error) { expect(error.status).toBe(404); }
  expect(frame.database.query).toHaveBeenCalledTimes(1);
  expect(frame.database.query.mock.calls[0][0]).toMatch(/JOIN license_catalog [a-z_]+ ON/);
  expect(frame.database.query.mock.calls[0][0]).toContain('business_tenant_id IS NULL');
  expect(frame.allocator.transaction).not.toHaveBeenCalled();
  for (const source of Object.values(frame.source)) expect(source).not.toHaveBeenCalled();
});

test('company-owned delegate mirror is rejected before the authoritative role lookup', async () => {
  const frame = fixture(); frame.allocator.assertLegacySubject.mockRejectedValue(new LicenseError(404, 'Legacy license subject not found'));
  await expect(frame.delegations.subject(frame.targetId, frame.authorization)).rejects.toMatchObject({ status: 404 });
  expect(frame.source.delegate).not.toHaveBeenCalled();
});

test('group worker inventories and error writes both exclude company pools', async () => {
  const frame = fixture(); frame.database.query.mockResolvedValueOnce({ rows: [{ license_id: frame.licenseId, group_id: frame.targetId }] }).mockResolvedValue({ rows: [] });
  frame.source.snapshot.mockRejectedValue(new LicenseError(503, 'Source unavailable'));
  await frame.groups.reconcileAll(frame.authorization);
  expect(frame.database.query).toHaveBeenCalledTimes(2);
  for (const [query] of frame.database.query.mock.calls) expect(query).toContain('business_tenant_id IS NULL');
  expect(frame.allocator.transaction).not.toHaveBeenCalled();
});

test.each([
  ['delegations', frame => frame.delegations.self(frame.user, frame.principal, frame.authorization)],
  ['PIM', frame => new LicenseScopeActivations(frame.allocator).self(frame.user, frame.principal, frame.authorization)],
  ['assigned PIM', frame => new LicenseScopeActivations(frame.allocator).assigned(frame.user, frame.principal)],
  ['allocation reviews', frame => new LicenseReviews(frame.allocator).self(frame.user, frame.principal)],
  ['own delegation reviews', frame => new LicenseScopeReviews(frame.allocator).list(true, frame.user, frame.principal)],
  ['assigned delegation reviews', frame => new LicenseScopeReviews(frame.allocator).list(false, frame.user, frame.principal)],
])('%s self/assigned inventories retain a null-owned parent join', async (_name, operation) => {
  const frame = fixture();
  frame.source.delegate.mockResolvedValue({ enabled: true, linked: true, revision: '1', delegationRevision: 'a'.repeat(64) });
  await operation(frame);
  expect(frame.database.query.mock.calls.length).toBeGreaterThan(0);
  for (const [query] of frame.database.query.mock.calls) expect(query).toContain('business_tenant_id IS NULL');
});

test('provider candidate inventory excludes both company pools and company-owned subjects', async () => {
  const frame = fixture();
  await new ProviderStore(frame.allocator).candidates(frame.targetId);
  const query = frame.database.query.mock.calls[0][0];
  expect(query).toContain('catalog.business_tenant_id IS NULL');
  expect(query).toContain('owned_subject.business_tenant_id IS NOT NULL');
});

test.each([
  ['refresh', (store, row) => store.refresh(row)],
  ['checkpoint', (store, row) => store.checkpoint(row, { schemaVersion: 1, userId: row.user_id, revision: '1', enabled: false, deleted: true }, {})],
  ['write intent', (store, row) => store.writeIntent(row, {})],
  ['negative dispatch', (store, row) => store.dispatch(row, randomUUID())],
])('provider %s cannot mutate or refresh an inaccessible target, even with a stale caller row', async (_name, operation) => {
  const frame = fixture(); frame.allocator.transaction.mockImplementation(callback => callback(frame.database));
  const row = { id: frame.targetId, license_id: frame.licenseId, user_id: frame.reviewerId, desired: false };
  await expect(operation(new ProviderStore(frame.allocator), row)).rejects.toMatchObject({ status: 404 });
  expect(frame.database.query).toHaveBeenCalledTimes(1);
  expect(frame.database.query.mock.calls[0][0]).toContain('catalog.business_tenant_id IS NULL');
  expect(frame.database.query.mock.calls[0][0]).not.toMatch(/^(?:UPDATE|INSERT|DELETE|SELECT license_fulfillment_refresh)/);
});

test('provider settlement cannot write an inaccessible target or create an error receipt', async () => {
  const frame = fixture(); frame.allocator.transaction.mockImplementation(callback => callback(frame.database));
  await new ProviderStore(frame.allocator).settle({ id: frame.targetId }, {}, { status: 'failed', error: 'source_unavailable' });
  expect(frame.database.query).toHaveBeenCalledTimes(1);
  expect(frame.database.query.mock.calls[0][0]).toContain('catalog.business_tenant_id IS NULL');
});

test('fulfillment independently rejects an owned target before eligibility or Graph requests', async () => {
  const connectorId = randomUUID(); const tenantId = randomUUID();
  const connection = { query: jest.fn().mockResolvedValue({ rows: [{ locked: true }] }), release: jest.fn() };
  const store = { database: { getClient: jest.fn().mockResolvedValue(connection) }, row: jest.fn().mockResolvedValue({ enabled: true, connector_id: connectorId, tenant_id: tenantId, business_tenant_id: randomUUID() }), checkpoint: jest.fn() };
  const identity = { user: jest.fn() }; const graph = { tenantId, inspect: jest.fn(), mutate: jest.fn() };
  await new FulfillmentWorker({ store, identity, graph, connectorId, tenantId, sourceClientId: 'legacy-worker' }).target(randomUUID());
  expect(identity.user).not.toHaveBeenCalled(); expect(graph.inspect).not.toHaveBeenCalled(); expect(graph.mutate).not.toHaveBeenCalled(); expect(store.checkpoint).not.toHaveBeenCalled(); expect(connection.release).toHaveBeenCalledTimes(1);
});

test.each(['actor', 'target'])('activation rejects an %s adopted after preflight when its actual row is locked', async adopted => {
  const actorId = '11111111-1111-4111-8111-111111111111'; const targetId = '22222222-2222-4222-8222-222222222222';
  const adoptedId = adopted === 'actor' ? actorId : targetId;
  const database = { query: jest.fn().mockResolvedValue({ rows: [{ business_tenant_id: null }] }) };
  const client = { release: jest.fn(), query: jest.fn(async (query, parameters) => {
    if (query.startsWith('SELECT * FROM license_subjects')) return { rows: [{ user_id: parameters[0], business_tenant_id: parameters[0] === adoptedId ? randomUUID() : null,
      disabled: parameters[0] === targetId, directory_enabled: true, directory_deleted: false, directory_revision: '1' }] };
    return { rows: [] };
  }) };
  database.getClient = jest.fn().mockResolvedValue(client);
  const allocator = new LicenseAllocator(database);
  jest.spyOn(allocator.users, 'active').mockResolvedValue([{ schemaVersion: 1, userId: targetId, revision: '1', enabled: true, deleted: false }]);
  const apply = jest.spyOn(allocator.users, 'apply');
  await expect(allocator.activate(targetId, actorId)).rejects.toMatchObject({ status: 404, message: 'Legacy activation cannot change a company-owned subject' });
  expect(database.query).toHaveBeenCalledTimes(2);
  expect(client.query).toHaveBeenCalledWith('SELECT * FROM license_subjects WHERE user_id = $1 FOR UPDATE', [adoptedId]);
  expect(apply).not.toHaveBeenCalled();
  expect(client.query).toHaveBeenCalledWith('ROLLBACK');
  expect(client.query.mock.calls.some(([query]) => query === 'COMMIT' || query.includes('SET disabled = false') || query.startsWith('INSERT INTO license_audit_events'))).toBe(false);
  expect(client.release).toHaveBeenCalledTimes(1);
});

test('reconciliation error recording fences both insert and conflict-update after a selected user becomes company-owned', async () => {
  const frame = fixture(); const tenantId = randomUUID(); let errorStatements = 0;
  frame.database.query.mockImplementation(async query => {
    if (query.includes('SELECT candidates.user_id')) return { rows: [{ user_id: frame.targetId }] };
    if (query.startsWith('SELECT business_tenant_id')) return { rows: [{ business_tenant_id: tenantId }] };
    if (query.startsWith('INSERT INTO license_subjects')) {
      errorStatements++;
      expect(query).toContain('WHERE NOT EXISTS(SELECT 1 FROM license_subjects WHERE user_id=');
      expect(query).toContain('AND business_tenant_id IS NOT NULL)');
      expect(query).toMatch(/ON CONFLICT\(user_id\) DO UPDATE[\s\S]+WHERE license_subjects.business_tenant_id IS NULL/);
      return { rows: [], rowCount: 0 };
    }
    throw new Error('Unexpected query');
  });
  const allocator = new LicenseAllocator(frame.database, { source: frame.source });
  await expect(allocator.users.reconcileAll(frame.authorization)).resolves.toEqual([{ userId: frame.targetId, error: 'Legacy license subject not found' }]);
  expect(frame.source.user).not.toHaveBeenCalled();
  expect(errorStatements).toBe(1);
});
