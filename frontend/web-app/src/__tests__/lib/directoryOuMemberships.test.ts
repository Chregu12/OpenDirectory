import { api } from '@/lib/api';
import { directoryUsers } from '@/lib/directoryUsers';
import { directoryOuMemberships } from '@/lib/directoryOuMemberships';
import { ouEtag } from '@/lib/directoryOus';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn(), delete: jest.fn() } }));
jest.mock('@/lib/directoryUsers', () => ({ ...jest.requireActual('@/lib/directoryUsers'), directoryUsers: { access: jest.fn() } }));
const unit = { id: '11111111-1111-4111-8111-111111111111', name: 'Engineering', revision: '9007199254740993', memberCount: 0, createdAt: '2026-10-19T00:00:00Z' };
const userId = '22222222-2222-4222-8222-222222222222'; const member = { id: '33333333-3333-4333-8333-333333333333', ouId: unit.id, userId, createdAt: '2026-10-19T01:00:00Z' };
const access = { userId, permissions: ['ous.read', 'ous.members.manage'], demoMode: false, directoryOuMembershipProtocol: 1 };
const page = { schemaVersion: 1, actorUserId: userId, unit, members: [], total: 0, page: 1, limit: 25, profileAccess: false };
beforeEach(() => { jest.clearAllMocks(); (directoryUsers.access as jest.Mock).mockResolvedValue(access); (api.get as jest.Mock).mockResolvedValue({ data: page }); });
test('membership counts and current OU revision come from the exact own list response', async () => {
  expect((await directoryOuMemberships.list(unit.id)).total).toBe(0); expect(api.get).toHaveBeenCalledWith('/api/ous/' + unit.id + '/members', { params: { page: 1, limit: 25 }, signal: undefined });
});
test.each([{ actorUserId: unit.id }, { total: 1 }, { profileAccess: true }, { members: [member] }])('inconsistent actor, profile authority or pagination cannot be treated as a complete list: %j', async changed => {
  (api.get as jest.Mock).mockResolvedValue({ data: { ...page, ...changed } }); await expect(directoryOuMemberships.list(unit.id)).rejects.toThrow();
});
test('user profiles cannot leak through an OU-only read response', async () => {
  (api.get as jest.Mock).mockResolvedValue({ data: { ...page, total: 1, unit: { ...unit, memberCount: 1 }, members: [{ ...member, profile: { username: 'private', email: 'private@example.invalid' } }] } }); await expect(directoryOuMemberships.list(unit.id)).rejects.toThrow();
});
test('a profile-capable read requires actual profile fields and never infers them from a user ID', async () => {
  (directoryUsers.access as jest.Mock).mockResolvedValue({ ...access, permissions: [...access.permissions, 'users.read'] }); (api.get as jest.Mock).mockResolvedValue({ data: { ...page, profileAccess: true, total: 1, unit: { ...unit, memberCount: 1 }, members: [member] } });
  await expect(directoryOuMemberships.list(unit.id)).rejects.toThrow();
});
test('additions send only a canonical user ID with the exact BIGINT OU version', async () => {
  (api.post as jest.Mock).mockResolvedValue({ data: { unit: { ...unit, revision: '9007199254740994', memberCount: 1 }, membership: member, action: 'member-add' } }); expect((await directoryOuMemberships.add(unit, userId)).membership.id).toBe(member.id);
  expect(api.post).toHaveBeenCalledWith('/api/ous/' + unit.id + '/members', { userId }, { headers: { 'If-Match': ouEtag(unit) } });
});
test('removal binds the exact membership incarnation and verifies the new OU count/version', async () => {
  const previous = { ...unit, memberCount: 1 }; (api.delete as jest.Mock).mockResolvedValue({ data: { unit: { ...unit, revision: '9007199254740994' }, membership: member, action: 'member-remove' } });
  expect((await directoryOuMemberships.remove(previous, member)).action).toBe('member-remove'); expect(api.delete).toHaveBeenCalledWith('/api/ous/' + unit.id + '/members/' + member.id, { headers: { 'If-Match': ouEtag(previous) } });
});
test.each([{ revision: unit.revision, memberCount: 1 }, { revision: '9007199254740995', memberCount: 1 }, { revision: '9007199254740994', memberCount: 2 }, { revision: '9007199254740994', memberCount: 1, name: 'Unrequested rename' }])('an unexpected command effect cannot confirm an assignment: %j', async changed => {
  (api.post as jest.Mock).mockResolvedValue({ data: { unit: { ...unit, ...changed }, membership: member, action: 'member-add' } }); await expect(directoryOuMemberships.add(unit, userId)).rejects.toThrow('nicht bestätigt');
});
test('old protocols or missing record counts cannot reach any legacy membership write', async () => {
  (directoryUsers.access as jest.Mock).mockResolvedValue({ ...access, directoryOuMembershipProtocol: undefined }); await expect(directoryOuMemberships.add(unit, userId)).rejects.toThrow();
  await expect(directoryOuMemberships.add({ ...unit, memberCount: undefined }, userId)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
