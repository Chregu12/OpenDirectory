import { directoryGroups, DirectoryGroup } from '../../lib/directoryGroups';
import { employeeInvitationManagement, EmployeeInvitationInput } from '../../lib/employeeInvitationManagement';
import { createEmployeeInvitationWithGroups, EmployeeInvitationActionError } from '../../lib/employeeOnboarding';

jest.mock('../../lib/directoryGroups', () => ({ directoryGroups: { get: jest.fn(), add: jest.fn(), removeMember: jest.fn() } }));
jest.mock('../../lib/employeeInvitationManagement', () => ({ ...jest.requireActual('../../lib/employeeInvitationManagement'), employeeInvitationManagement: { create: jest.fn() } }));

const userId = '22222222-2222-4222-8222-222222222222';
const first: DirectoryGroup = { id: '33333333-3333-4333-8333-333333333333', name: 'Engineering', members: [], revision: '1', createdAt: '2026-01-01T00:00:00.000Z' };
const second: DirectoryGroup = { ...first, id: '44444444-4444-4444-8444-444444444444', name: 'Apps' };
const input: EmployeeInvitationInput = { id: '55555555-5555-4555-8555-555555555555', userId, userRevision: '1', loginName: 'ada', durationHours: 72, reason: 'Mitarbeiteraufnahme für Ada', confirm: true };
beforeEach(() => {
  jest.clearAllMocks();
  (directoryGroups.get as jest.Mock).mockImplementation(async id => [first, second].find(group => group.id === id));
  (directoryGroups.add as jest.Mock).mockImplementation(async group => ({ ...group, revision: '2', members: [userId] }));
  (directoryGroups.removeMember as jest.Mock).mockResolvedValue({ ...first, revision: '3' });
  (employeeInvitationManagement.create as jest.Mock).mockResolvedValue({ created: true, mailStatus: 'not_configured' });
});

test('confirmed groups precede the one original invitation and independent membership reviews stay pending', async () => {
  (directoryGroups.add as jest.Mock).mockResolvedValueOnce({ ...first, revision: '2', members: [userId], membershipReview: { required: true, membershipId: input.id, effective: false } });
  const result = await createEmployeeInvitationWithGroups(input, [first, second]);
  expect(result).toMatchObject({ groupsAdded: 2, pendingReviews: 1 });
  expect(employeeInvitationManagement.create).toHaveBeenCalledTimes(1); expect(employeeInvitationManagement.create).toHaveBeenCalledWith(input);
  expect((directoryGroups.add as jest.Mock).mock.invocationCallOrder[1]).toBeLessThan((employeeInvitationManagement.create as jest.Mock).mock.invocationCallOrder[0]);
  expect(directoryGroups.removeMember).not.toHaveBeenCalled();
});
test('a changed reviewed group is not silently refreshed into a new write', async () => {
  (directoryGroups.get as jest.Mock).mockResolvedValue({ ...first, revision: '2' });
  await expect(createEmployeeInvitationWithGroups(input, [first])).rejects.toMatchObject({ uncertain: false, rollbackComplete: true });
  expect(directoryGroups.add).not.toHaveBeenCalled(); expect(employeeInvitationManagement.create).not.toHaveBeenCalled();
});
test('existing membership is preserved without creating or removing another link', async () => {
  const existing = { ...first, members: [userId] }; (directoryGroups.get as jest.Mock).mockResolvedValue(existing);
  expect(await createEmployeeInvitationWithGroups(input, [existing])).toMatchObject({ groupsAdded: 0, pendingReviews: 0 });
  expect(directoryGroups.add).not.toHaveBeenCalled(); expect(directoryGroups.removeMember).not.toHaveBeenCalled();
});
test('a definite invitation rejection compensates only our acknowledged group versions in reverse order', async () => {
  (employeeInvitationManagement.create as jest.Mock).mockRejectedValue({ response: { status: 403 } });
  await expect(createEmployeeInvitationWithGroups(input, [first, second])).rejects.toMatchObject({ uncertain: false, rollbackComplete: true });
  expect(directoryGroups.removeMember).toHaveBeenNthCalledWith(1, { ...second, revision: '2', members: [userId] }, userId);
  expect(directoryGroups.removeMember).toHaveBeenNthCalledWith(2, { ...first, revision: '2', members: [userId] }, userId);
  expect(directoryGroups.get).toHaveBeenCalledTimes(2);
});
test('a later independent group edit cannot be removed by refreshing its version during compensation', async () => {
  (employeeInvitationManagement.create as jest.Mock).mockRejectedValue({ response: { status: 409 } });
  (directoryGroups.removeMember as jest.Mock).mockRejectedValue({ response: { status: 412 } });
  await expect(createEmployeeInvitationWithGroups(input, [first])).rejects.toMatchObject({ uncertain: false, rollbackComplete: false });
  expect(directoryGroups.removeMember).toHaveBeenCalledWith(expect.objectContaining({ revision: '2' }), userId);
  expect(directoryGroups.get).toHaveBeenCalledTimes(1);
});
test('an unconfirmed invitation response neither resends nor removes the selected groups', async () => {
  (employeeInvitationManagement.create as jest.Mock).mockRejectedValue(new Error('Connection reset'));
  await expect(createEmployeeInvitationWithGroups(input, [first])).rejects.toMatchObject({ uncertain: true });
  expect(employeeInvitationManagement.create).toHaveBeenCalledTimes(1); expect(directoryGroups.removeMember).not.toHaveBeenCalled();
});
test('an ambiguous group write stops all later actions and does not compensate across uncertainty', async () => {
  (directoryGroups.add as jest.Mock).mockRejectedValue(new Error('Response lost'));
  await expect(createEmployeeInvitationWithGroups(input, [first, second])).rejects.toBeInstanceOf(EmployeeInvitationActionError);
  expect(directoryGroups.add).toHaveBeenCalledTimes(1); expect(employeeInvitationManagement.create).not.toHaveBeenCalled(); expect(directoryGroups.removeMember).not.toHaveBeenCalled();
});
test('an already cancelled flow has no network effects', async () => {
  const controller = new AbortController(); controller.abort();
  await expect(createEmployeeInvitationWithGroups(input, [first], controller.signal)).rejects.toThrow('unterbrochen');
  expect(directoryGroups.get).not.toHaveBeenCalled(); expect(employeeInvitationManagement.create).not.toHaveBeenCalled();
});
test('session invalidation after a confirmed group write prevents invitation and all further writes', async () => {
  const controller = new AbortController();
  (directoryGroups.add as jest.Mock).mockImplementation(async group => { controller.abort(); return { ...group, revision: '2', members: [userId] }; });
  await expect(createEmployeeInvitationWithGroups(input, [first, second], controller.signal)).rejects.toMatchObject({ uncertain: true, rollbackComplete: false });
  expect(directoryGroups.add).toHaveBeenCalledTimes(1); expect(directoryGroups.removeMember).not.toHaveBeenCalled(); expect(employeeInvitationManagement.create).not.toHaveBeenCalled();
});
test('duplicate group selections fail before a mutation', async () => {
  await expect(createEmployeeInvitationWithGroups(input, [first, first])).rejects.toMatchObject({ uncertain: false });
  expect(directoryGroups.get).not.toHaveBeenCalled(); expect(employeeInvitationManagement.create).not.toHaveBeenCalled();
});
