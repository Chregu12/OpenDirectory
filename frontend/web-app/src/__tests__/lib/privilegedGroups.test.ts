import { api } from '@/lib/api';
import { privilegedGroups } from '@/lib/privilegedGroups';
import { privilegedActivation } from '@/lib/privilegedActivation';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
jest.mock('@/lib/privilegedActivation', () => ({ ...jest.requireActual('@/lib/privilegedActivation'), privilegedActivation: { self: jest.fn(), catalog: jest.fn(), queue: jest.fn() } }));
const userId = '11111111-1111-4111-8111-111111111111'; const groupId = '22222222-2222-4222-8222-222222222222'; const eligibilityId = '33333333-3333-4333-8333-333333333333';
const group = { id: groupId, name: 'Lizenzen', description: 'License inventory only', role: 'license-reader', maxDurationSeconds: 3600, configuredMaxDurationSeconds: 36000, enabled: true, protected: false, createdAt: '2026-11-08T12:00:00Z', canManage: false };
const catalog = { schemaVersion: 1, userId, groups: [group], bindings: [{ groupId, eligibilityId, userId }], standingRoles: [], canCreate: false, canReview: false, truncated: false };
beforeEach(() => {
  jest.clearAllMocks(); (api.get as jest.Mock).mockResolvedValue({ data: catalog });
  (privilegedActivation.self as jest.Mock).mockResolvedValue({ userId, eligibilities: [{ id: eligibilityId, userId, role: 'license-reader' }], requests: [], truncated: false });
  (privilegedActivation.catalog as jest.Mock).mockResolvedValue([{ role: 'license-reader', reviewable: false }]);
});
test('group eligibility remains separate from runtime roles and no review queue is read without its capability', async () => {
  const result = await privilegedGroups.load(); expect(result.groups).toEqual([group]); expect(result.standingRoles).toEqual([]);
  expect(privilegedActivation.queue).not.toHaveBeenCalled(); expect(api.get).toHaveBeenCalledWith('/api/identity/pim/groups', { signal: undefined });
});
test.each([{ ...catalog, userId: groupId }, { ...catalog, groups: [group, group] }, { ...catalog, groups: [{ ...group, maxDurationSeconds: 36001 }] }, { ...catalog, groups: [{ ...group, configuredMaxDurationSeconds: 60 }] }, { ...catalog, extraAuthority: true }])('rejects unbound or malformed group source %j', async data => {
  (api.get as jest.Mock).mockResolvedValue({ data }); await expect(privilegedGroups.load()).rejects.toThrow();
});
test('a group-role mismatch cannot be presented as a confirmed assignment', async () => {
  (api.get as jest.Mock).mockResolvedValue({ data: { ...catalog, groups: [{ ...group, role: 'admin' }] } });
  await expect(privilegedGroups.load()).rejects.toThrow('nicht bestätigt');
});
test('unconfirmed assignment responses are consumed without retrying the POST', async () => {
  (api.post as jest.Mock).mockResolvedValue({ status: 201, data: { schemaVersion: 1, groupId, eligibility: { id: eligibilityId, userId, role: 'license-reader', reason: 'Explicit independent eligibility', maxDurationSeconds: 3600, createdAt: '2026-11-08T12:00:00Z', expiresAt: '2026-11-09T12:00:00Z', revokedAt: null, status: 'eligible' } } });
  await expect(privilegedGroups.assign(groupId, { userId: groupId, maxDurationSeconds: 3600, validForSeconds: 86400, reason: 'Explicit independent eligibility', confirm: true })).rejects.toThrow('nicht bestätigt');
  expect(api.post).toHaveBeenCalledTimes(1);
});
test('history is bound to the requested group and page', async () => {
  (api.get as jest.Mock).mockResolvedValue({ data: { schemaVersion: 1, groupId: userId, page: 1, limit: 25, total: 0, events: [] } });
  await expect(privilegedGroups.history(groupId)).rejects.toThrow(); expect(api.get).toHaveBeenCalledWith('/api/identity/pim/groups/' + groupId + '/history', { params: { page: 1 }, signal: undefined });
});
