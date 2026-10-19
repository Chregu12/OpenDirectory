import { companyRegistration } from '@/lib/companyRegistration';
const registrationId = '11111111-1111-4111-8111-111111111111'; const tenantId = '22222222-2222-4222-8222-222222222222';
const receipt = { schemaVersion: 1, registrationId, tenantId, administratorId: '33333333-3333-4333-8333-333333333333', createdAt: '2026-10-19T00:00:00Z', status: 'pending-verification', tenantEnabled: false, administratorEnabled: false, profileSaved: false, activationSupported: false, replayed: false };
const credentials = { registrationId, username: 'verified', password: 'disposable-provider-password', mfaCode: '' };
const profile = { name: 'Actual Company', legalForm: '', registrationNumber: '', taxId: '', addressLine1: 'Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
const response = (data: any, status = 200) => ({ ok: status >= 200 && status < 300, status, headers: { get: () => 'application/json' }, json: async () => data });
beforeEach(() => { global.fetch = jest.fn(); Object.defineProperty(AbortSignal, 'timeout', { configurable: true, value: () => new AbortController().signal }); });
test('an explicit same-origin pending request is confirmed only by the exact persisted disabled receipt', async () => {
  (fetch as jest.Mock).mockResolvedValue(response(receipt, 201)); expect(await companyRegistration.submit({ ...credentials, profile, confirm: true })).toEqual(receipt);
  const [url, options] = (fetch as jest.Mock).mock.calls[0]; expect(url).toBe('/api/company-registration/submit'); expect(options.redirect).toBe('error'); expect(options.headers['X-OD-Company-Registration']).toBe('1'); expect(options.headers.Authorization).toBeUndefined();
});
test.each([{ ...receipt, registrationId: tenantId }, { ...receipt, tenantEnabled: true }, { ...receipt, administratorEnabled: true }, { ...receipt, access_token: 'invalid' }, { ...receipt, profileSaved: true }])('foreign, activated or token-bearing plausible acknowledgements are not registration success %#', async value => {
  (fetch as jest.Mock).mockResolvedValue(response(value, 201)); await expect(companyRegistration.submit({ ...credentials, profile, confirm: true })).rejects.toThrow('nicht bestätigt');
});
test('status is a separate authenticated read; a lost write response never automatically sends another submit', async () => {
  (fetch as jest.Mock).mockRejectedValueOnce(new Error('response lost')); await expect(companyRegistration.submit({ ...credentials, profile, confirm: true })).rejects.toThrow(); expect(fetch).toHaveBeenCalledTimes(1);
  (fetch as jest.Mock).mockResolvedValueOnce(response({ ...receipt, replayed: true })); expect((await companyRegistration.status(credentials)).replayed).toBe(true); expect((fetch as jest.Mock).mock.calls[1][0]).toBe('/api/company-registration/status');
});
test('capabilities are actual disabled/pending-only metadata, never an assumed activation path', async () => {
  const capabilities = { schemaVersion: 1, enabled: false, requiresExistingAccount: true, activationSupported: false, status: 'pending-verification' }; (fetch as jest.Mock).mockResolvedValue(response(capabilities)); expect((await companyRegistration.capabilities()).enabled).toBe(false);
  (fetch as jest.Mock).mockResolvedValue(response({ ...capabilities, activationSupported: true })); await expect(companyRegistration.capabilities()).rejects.toThrow();
});
test('activation needs explicit confirmation and an exact activated receipt, never a plausible still-pending acknowledgement', async () => {
  const activated = { ...receipt, schemaVersion: 3, status: 'active', tenantEnabled: true, administratorEnabled: true, profileSaved: true, activationSupported: true, reviewedAt: '2026-10-19T01:00:00Z', activatedAt: '2026-10-19T02:00:00Z', consoleClientId: 'web-app', mfaRequired: true };
  (fetch as jest.Mock).mockResolvedValueOnce(response(activated)); expect((await companyRegistration.activate({ ...credentials, confirm: true })).schemaVersion).toBe(3);
  expect((fetch as jest.Mock).mock.calls[0][0]).toBe('/api/company-registration/activate'); (fetch as jest.Mock).mockResolvedValueOnce(response(receipt)); await expect(companyRegistration.activate({ ...credentials, confirm: true })).rejects.toThrow('nicht bestätigt');
});
