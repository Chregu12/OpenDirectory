import { api } from '@/lib/api';
import { getAccessToken } from '@/lib/auth';
import { organizationProfile } from '@/lib/organizationProfile';
import { organizationEtag } from '../../../../packages/organization-profile-contract';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), put: jest.fn() } }));
jest.mock('@/lib/auth', () => ({ getAccessToken: jest.fn(() => 'original') }));
const actor = '11111111-1111-4111-8111-111111111111'; const tenant = { id: '22222222-2222-4222-8222-222222222222', name: 'Actual company', version: '1', generation: '2' };
const profile = { name: 'Actual company', legalForm: '', registrationNumber: '', taxId: '', addressLine1: 'Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
const page = { schemaVersion: 1, actorUserId: actor, tenant, organization: null, etag: organizationEtag(tenant, '0'), canManage: true, requiresFreshMfa: false, verificationSupported: false };
const record = { ...profile, id: '33333333-3333-4333-8333-333333333333', version: '1', createdAt: '2026-10-19T00:00:00.000Z', updatedAt: '2026-10-19T00:00:00.000Z' };
const response = (data: any) => ({ data, headers: { etag: data.etag } });
beforeEach(() => { jest.clearAllMocks(); (getAccessToken as jest.Mock).mockReturnValue('original'); (api.get as jest.Mock).mockResolvedValue(response(page)); });
test('loads a confirmed tenant-bound empty profile rather than inventing an organization', async () => {
  expect(await organizationProfile.load()).toEqual(page);
});
test.each([{ ...page, schemaVersion: 2 }, { ...page, verificationSupported: true }, { ...page, etag: 'invented' }, { ...page, tenant: { ...tenant, generation: 2 } }, { ...page, organization: { ...record, version: 1 } }])('rejects an incompatible or unconfirmed response', async value => {
  (api.get as jest.Mock).mockResolvedValue(response(value)); await expect(organizationProfile.load()).rejects.toThrow();
});
test('requires a matching real ETag header', async () => {
  (api.get as jest.Mock).mockResolvedValue({ data: page, headers: {} }); await expect(organizationProfile.load()).rejects.toThrow();
});
test('revalidates actor/tenant and sends the original version with exact profile fields', async () => {
  const previous = await organizationProfile.load(); const updated = { ...page, organization: record, etag: organizationEtag(tenant, '1') }; (api.put as jest.Mock).mockResolvedValue(response(updated));
  expect(await organizationProfile.save(previous, profile, 'Actual requested company update')).toEqual(updated);
  expect(api.put).toHaveBeenCalledWith('/api/identity/organization', { profile, reason: 'Actual requested company update' }, { headers: { 'If-Match': page.etag } });
});
test.each([{ ...page, actorUserId: '44444444-4444-4444-8444-444444444444' }, { ...page, canManage: false }, { ...page, tenant: { ...tenant, generation: '3' }, etag: organizationEtag({ ...tenant, generation: '3' }, '0') }])('a changed actor or authority cannot submit the captured profile', async current => {
  const previous = await organizationProfile.load(); (api.get as jest.Mock).mockResolvedValue(response(current)); await expect(organizationProfile.save(previous, profile, 'Actual requested company update')).rejects.toThrow(); expect(api.put).not.toHaveBeenCalled();
});
test('a changed browser session discards a late response', async () => {
  (api.get as jest.Mock).mockImplementation(async () => { (getAccessToken as jest.Mock).mockReturnValue('different'); return response(page); }); await expect(organizationProfile.load()).rejects.toThrow();
});
test('a lost write receipt is not retried or optimistically accepted', async () => {
  const previous = await organizationProfile.load(); (api.put as jest.Mock).mockRejectedValue(new Error('lost response'));
  await expect(organizationProfile.save(previous, profile, 'Actual requested company update')).rejects.toThrow(); expect(api.put).toHaveBeenCalledTimes(1);
});
test('a plausible write response with the wrong content or revision is not a confirmation', async () => {
  const previous = await organizationProfile.load(); (api.put as jest.Mock).mockResolvedValue(response({ ...page, organization: { ...record, city: 'Different City' }, etag: organizationEtag(tenant, '1') }));
  await expect(organizationProfile.save(previous, profile, 'Actual requested company update')).rejects.toThrow();
});
