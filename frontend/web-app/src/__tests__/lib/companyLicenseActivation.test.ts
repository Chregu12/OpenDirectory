import { api } from '@/lib/api';
import { companyLicenseActivation } from '@/lib/companyLicenseActivation';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const tenant = { id: '11111111-1111-4111-8111-111111111111', version: '1', generation: '1' };
const status = { schemaVersion: 1, scope: 'company-licenses', tenant, durations: [900, 3600, 36000], requiresFreshMfa: false, activation: null };
test.each([{ ...status, durations: [36001] }, { ...status, durations: [3600, 900] }, { ...status, durations: [] }, { ...status, tenant: { ...tenant, generation: '0' } }, { ...status, extra: true }, { ...status, activation: {} }])('rejects malformed activation status %j', async data => {
  (api.get as jest.Mock).mockResolvedValue({ data }); await expect(companyLicenseActivation.status()).rejects.toThrow('nicht bestätigt');
});
test('valid status and explicit activation use only fixed same-origin routes', async () => {
  (api.get as jest.Mock).mockResolvedValue({ data: status }); expect(await companyLicenseActivation.status()).toEqual(status);
  expect(api.get).toHaveBeenLastCalledWith('/api/mfa/company-license-activation', { signal: undefined });
  (api.post as jest.Mock).mockResolvedValue({ data: { schemaVersion: 1, activation: null } });
  await expect(companyLicenseActivation.change({ durationSeconds: 36000, reason: 'Actual change', confirm: true })).rejects.toThrow('Nicht erneut');
});
