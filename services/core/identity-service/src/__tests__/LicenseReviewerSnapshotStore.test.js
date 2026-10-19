'use strict';

jest.mock('../RoleState', () => ({ readRoleState: jest.fn() }));
const { readRoleState } = require('../RoleState');
const { LicenseReviewerSnapshotStore } = require('../LicenseReviewerSnapshotStore');
const userId = '11111111-1111-4111-8111-111111111111';
let client; let database; let store;
beforeEach(() => {
  jest.clearAllMocks(); client = { query: jest.fn(async () => ({ rows: [{ enabled: true, linked: true }] })) };
  database = { transaction: jest.fn(async operation => operation(client)) }; store = new LicenseReviewerSnapshotStore(database);
  readRoleState.mockResolvedValue({ roles: ['license-reviewer'] });
});
test('availability is read-only, issuer-linked and does not disclose profile or role inventories', async () => {
  expect(await store.snapshot(userId, 'https://issuer.test')).toEqual({ schemaVersion: 1, userId, enabled: true, linked: true, canReview: true });
  expect(database.transaction).toHaveBeenCalledWith(expect.any(Function), { readOnly: true });
  expect(client.query).toHaveBeenCalledWith(expect.any(String), [userId, 'https://issuer.test']);
});
test.each(['license-manager', 'access-reviewer', 'license-review-administrator', 'license-review-reader'])('the unrelated role %s is not a named license voter duty', async role => {
  readRoleState.mockResolvedValue({ roles: [role] }); expect((await store.snapshot(userId, 'https://issuer.test')).canReview).toBe(false);
});
test.each([{ enabled: false, linked: true }, { enabled: true, linked: false }])('disabled or unlinked recipients are not available: %j', async state => {
  client.query.mockResolvedValue({ rows: [state] }); expect((await store.snapshot(userId, 'https://issuer.test')).canReview).toBe(false);
});
test('unknown and noncanonical reviewer identifiers are not guessed from aliases', async () => {
  await expect(store.snapshot('alias', 'https://issuer.test')).rejects.toMatchObject({ status: 400 });
  client.query.mockResolvedValue({ rows: [] }); await expect(store.snapshot(userId, 'https://issuer.test')).rejects.toMatchObject({ status: 404 });
});
test.each(['admin','license-reviewer','license-scope-activation-reviewer','license-delegation-review-administrator','license-delegation-reviewer'])('administrative-review availability uses only its separate explicit duty: %s',async role=>{
  readRoleState.mockResolvedValue({roles:[role]});const administrative=new LicenseReviewerSnapshotStore(database,['license-delegation-reviewer']);
  expect((await administrative.snapshot(userId,'https://issuer.test')).canReview).toBe(role==='license-delegation-reviewer');
});
