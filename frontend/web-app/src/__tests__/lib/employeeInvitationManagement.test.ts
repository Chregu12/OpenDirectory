import { api } from '../../lib/api';
import { employeeInvitationManagement, EmployeeInvitationInput } from '../../lib/employeeInvitationManagement';

const id = '11111111-1111-4111-8111-111111111111';
const userId = '22222222-2222-4222-8222-222222222222';
const other = '33333333-3333-4333-8333-333333333333';
const request: EmployeeInvitationInput = { id, userId, userRevision: '1', loginName: 'ada', durationHours: 72, reason: 'Mitarbeiteraufnahme Ada', confirm: true };
const record = { id, userId, tenantId: other, loginName: 'ada', organizationName: 'Example', status: 'pending', revision: '1', createdAt: '2026-01-01T00:00:00.000Z', expiresAt: '2099-01-01T00:00:00.000Z', credentialCreated: false, identityConfirmed: false };
beforeEach(() => jest.clearAllMocks());
test.each([{ ...record, id: other }, { ...record, userId: other }])('an acknowledged invitation must belong to the exact requested operation and person', async invitation => {
  (api.post as jest.Mock).mockResolvedValue({ data: { schemaVersion: 1, employeeInvitationProtocol: 1, invitation, created: true, invitationToken: id + '.' + 'a'.repeat(43), mailStatus: 'not_configured' } });
  await expect(employeeInvitationManagement.create(request)).rejects.toThrow('nicht bestätigt');
});
test('original-status recovery cannot return a different invitation', async () => {
  (api.post as jest.Mock).mockResolvedValue({ data: { schemaVersion: 1, employeeInvitationProtocol: 1, invitation: { ...record, id: other } } });
  await expect(employeeInvitationManagement.get(id)).rejects.toThrow('nicht bestätigt');
});
test('original-status recovery is a read of the exact original ID and exposes no invitation token', async () => {
  (api.post as jest.Mock).mockResolvedValue({ data: { schemaVersion: 1, employeeInvitationProtocol: 1, invitation: record } });
  expect(await employeeInvitationManagement.get(id)).toEqual(record);
  expect(api.post).toHaveBeenCalledWith('/api/employee-invitations/manage/get', { id }, { headers: { 'X-OD-Employee-Invitation-Owner': '1' } });
});
