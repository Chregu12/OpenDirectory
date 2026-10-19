import { api } from '@/lib/api';
import { getAccessToken } from '@/lib/auth';
import { organizationDelegations } from '@/lib/organizationDelegations';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
jest.mock('@/lib/auth', () => ({ getAccessToken: jest.fn(() => 'original') }));
const actor = '11111111-1111-4111-8111-111111111111'; const tenant = '22222222-2222-4222-8222-222222222222'; const recipient = '33333333-3333-4333-8333-333333333333'; const grantId = '44444444-4444-4444-8444-444444444444';
const grant = { id: grantId, userId: recipient, username: 'actual-person', name: 'Actual Person', expiresAt: '2026-10-19T13:00:00Z', createdAt: '2026-10-19T12:00:00Z', status: 'active' as const };
const page = { schemaVersion: 1 as const, actorUserId: actor, tenantId: tenant, permissions: ['organization.read', 'organization.manage'], canManage: true, truncated: false, grants: [] as typeof grant[] };
const result = { schemaVersion: 1, actorUserId: actor, tenantId: tenant, eventId: grantId, grantId, userId: recipient, action: 'granted', expiresAt: grant.expiresAt };
beforeEach(() => { jest.clearAllMocks(); (getAccessToken as jest.Mock).mockReturnValue('original'); (api.get as jest.Mock).mockResolvedValue({ data: page }); });
test('confirms only a matching real command and a subsequent actual current grant, sending no arbitrary scope or role', async () => {
  (api.get as jest.Mock).mockResolvedValueOnce({ data: page }).mockResolvedValueOnce({ data: { ...page, grants: [grant] } }); (api.post as jest.Mock).mockResolvedValue({ data: result });
  expect((await organizationDelegations.change(page, { userId: recipient, durationSeconds: 3600 }, 'Reviewed actual profile delegation')).grants).toEqual([grant]);
  expect(api.post).toHaveBeenCalledWith('/api/identity/organization/delegations', { userId: recipient, durationSeconds: 3600, reason: 'Reviewed actual profile delegation' });
});
test('revocation uses the selected immutable grant and requires actual revoked state', async () => {
  const before = { ...page, grants: [grant] }; (api.get as jest.Mock).mockResolvedValueOnce({ data: before }).mockResolvedValueOnce({ data: { ...before, grants: [{ ...grant, status: 'revoked' }] } });
  (api.post as jest.Mock).mockResolvedValue({ data: { ...result, eventId: recipient, action: 'revoked' } });
  const actual = await organizationDelegations.change(before, { grantId }, 'Reviewed actual profile revocation'); expect(actual.grants[0].status).toBe('revoked');
  expect(api.post).toHaveBeenCalledWith(`/api/identity/organization/delegations/${grantId}/revoke`, { reason: 'Reviewed actual profile revocation' });
});
test.each([{ ...page, tenantId: recipient }, { ...page, actorUserId: recipient }, { ...page, permissions: ['admin'] }, { ...page, grants: [grant, grant] }, { ...page, canManage: 'true' }])('rejects foreign or malformed actual receiving data %#', async value => {
  (api.get as jest.Mock).mockResolvedValue({ data: value }); await expect(organizationDelegations.load(actor, tenant)).rejects.toThrow('nicht bestätigt');
});
test.each([{ userId: actor, durationSeconds: 3600 }, { userId: recipient, durationSeconds: 59 }, { userId: recipient, durationSeconds: 28801 }, { grantId }])('does not send unsafe, self or unknown-target operations %#', async operation => {
  await expect(organizationDelegations.change(page, operation, 'Reviewed actual profile delegation')).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('changed MFA, session or permissions before a write do not become a positive command', async () => {
  (api.get as jest.Mock).mockResolvedValue({ data: { ...page, canManage: false } }); await expect(organizationDelegations.change(page, { userId: recipient, durationSeconds: 3600 }, 'Reviewed actual profile delegation')).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
  (api.get as jest.Mock).mockImplementation(async () => { (getAccessToken as jest.Mock).mockReturnValue('replacement'); return { data: page }; });
  await expect(organizationDelegations.load(actor, tenant)).rejects.toThrow();
});
test('lost, substituted or unconfirmed responses never report success or automatically retry a write', async () => {
  (api.post as jest.Mock).mockResolvedValue({ data: result }); await expect(organizationDelegations.change(page, { userId: recipient, durationSeconds: 3600 }, 'Reviewed actual profile delegation')).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
  (api.post as jest.Mock).mockResolvedValue({ data: { ...result, userId: actor } }); await expect(organizationDelegations.change(page, { userId: recipient, durationSeconds: 3600 }, 'Reviewed actual profile delegation')).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(2);
});
test('a plausible active grant with a longer lifetime than explicitly requested is unconfirmed', async () => {
  const longer = { ...grant, expiresAt: '2026-10-19T14:00:00Z' };
  (api.get as jest.Mock).mockResolvedValueOnce({ data: page }).mockResolvedValueOnce({ data: { ...page, grants: [longer] } }); (api.post as jest.Mock).mockResolvedValue({ data: { ...result, expiresAt: longer.expiresAt } });
  await expect(organizationDelegations.change(page, { userId: recipient, durationSeconds: 3600 }, 'Reviewed actual profile delegation')).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
