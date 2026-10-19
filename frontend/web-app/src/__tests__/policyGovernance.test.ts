jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
import { api } from '@/lib/api';
import { policyGovernance, policyTag } from '@/lib/policyGovernance';
const mock = api as jest.Mocked<typeof api>;
const userId = '11111111-1111-4111-8111-111111111111';
const id = '22222222-2222-4222-8222-222222222222';
const access = { schemaVersion: 4, subject: 'operator', userId, permissions: ['policies.read', 'policies.manage', 'policies.deploy'], freshMfa: true, writeAuthenticationMaxAgeSeconds: 300 };
const row = { id, name: 'Owned policy', type: 'security', platform: 'all', status: 'draft', version: 1, settings: { firewall: true, screenLock: 5 }, created_by: userId };
const reason = 'Owned exact policy change confirmation';
beforeEach(() => jest.resetAllMocks());
test('accepts only actual receiver capabilities and canonical pagination, never a demo policy list', async () => {
  mock.get.mockResolvedValueOnce({ status: 200, data: access }).mockResolvedValueOnce({ status: 200, data: { policies: [row], total: 1, page: 1, limit: 50 } });
  expect(await policyGovernance.access()).toEqual(access); expect((await policyGovernance.list()).policies).toEqual([row]);
});
test.each([{ ...access, schemaVersion: 1 }, { ...access, schemaVersion: 2 }, { ...access, schemaVersion: 3 }, { ...access, permissions: ['policies.unknown'] }, { ...access, userId: 'alias' }, { ...access, writeAuthenticationMaxAgeSeconds: 3600 }, { ...access, freshMfa: 'true' }, { ...access, subject: '' }, { ...access, demo: true }])('rejects malformed or wider access metadata: %j', async value => {
  mock.get.mockResolvedValue({ status: 200, data: value }); await expect(policyGovernance.access()).rejects.toThrow();
});
test.each([{ policies: [row, row], total: 2, page: 1, limit: 50 }, { policies: [], total: 0, page: 2, limit: 50 }, { policies: [{ ...row, id: 'demo-policy' }], total: 1, page: 1, limit: 50 }])('rejects fabricated, duplicated or wrong-page policy data: %j', async value => {
  mock.get.mockResolvedValue({ status: 200, data: value }); await expect(policyGovernance.list()).rejects.toThrow();
});
test('confirms an actual canonical draft and compares JSON content independently of PostgreSQL key order', async () => {
  mock.post.mockResolvedValue({ status: 201, data: row, headers: { etag: policyTag(row) } });
  expect((await policyGovernance.create({ name: row.name, type: row.type, platform: row.platform, settings: { screenLock: 5, firewall: true } }, userId, reason)).id).toBe(id);
  expect(mock.post).toHaveBeenCalledTimes(1);
});
test.each([{ ...row, created_by: id }, { ...row, status: 'active' }, { ...row, name: 'Another policy' }, { ...row, settings: {} }])('a mismatched creation receipt cannot produce success: %j', async value => {
  mock.post.mockResolvedValue({ status: 201, data: value, headers: { etag: policyTag(value) } }); await expect(policyGovernance.create({ name: row.name, type: row.type, platform: row.platform, settings: row.settings }, userId, reason)).rejects.toThrow(); expect(mock.post).toHaveBeenCalledTimes(1);
});
test('a transition confirms the captured canonical policy and actual state, not a local optimistic toggle', async () => {
  const next = { ...row, version: 2, status: 'active' }; mock.post.mockResolvedValueOnce({ status: 200, data: next, headers: { etag: policyTag(next) } }); expect((await policyGovernance.transition(row, 'activate', reason, id)).status).toBe('active');
  expect(mock.post).toHaveBeenLastCalledWith('/api/policies/' + id + '/activate', { reason, acknowledgeScope: true, publicationId: id }, { headers: { 'If-Match': policyTag(row) } });
  mock.post.mockResolvedValueOnce({ status: 200, data: row }); await expect(policyGovernance.transition(row, 'activate', reason, id)).rejects.toThrow();
});
test('does not even send activation without an explicit captured publication', async () => { await expect(policyGovernance.transition(row,'activate',reason)).rejects.toThrow(); expect(mock.post).not.toHaveBeenCalled(); });
