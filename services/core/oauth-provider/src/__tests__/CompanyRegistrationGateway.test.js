const { generateKeyPairSync, randomUUID } = require('node:crypto');
const jwt = require('jsonwebtoken');
const { CompanyRegistrationGateway } = require('../CompanyRegistrationGateway');
const { TYPE, PURPOSE, AUDIENCE } = require('../../../../../packages/company-registration-contract');
const { requestDigest } = require('../../../../../packages/company-registration-contract/digest');
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 }); const issuer = 'https://registration.test'; const registrationId = randomUUID();
const profile = { name: 'Company AG', legalForm: '', registrationNumber: '', taxId: '', addressLine1: 'Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
const body = { registrationId, username: 'verified', password: 'disposable-provider-password', mfaCode: '', profile, confirm: true };
const principal = { id: 'credential-subject', username: 'verified', email: 'verified@example.invalid', displayName: 'Verified Person', roles: ['admin'] };
const receipt = { schemaVersion: 1, registrationId, tenantId: randomUUID(), administratorId: randomUUID(), createdAt: '2026-10-19T00:00:00Z', status: 'pending-verification', tenantEnabled: false, administratorEnabled: false, profileSaved: false, activationSupported: false, replayed: false };
function fixture() {
  const authenticate = jest.fn(async () => ({ user: principal })); const fetchImpl = jest.fn(async () => new Response(JSON.stringify(receipt), { status: 201, headers: { 'Content-Type': 'application/json' } }));
  const service = new CompanyRegistrationGateway({ signingKeys: { privateKey: keys.privateKey, kid: 'registration-unit-key' }, issuer, endpoint: 'https://identity.test/internal/identity/authorization-state', authenticate, fetchImpl });
  return { service, authenticate, fetchImpl };
}
test('only a verified provider principal is signed into a bounded purpose/method/body-bound internal workload; credentials and global roles are not forwarded', async () => {
  const { service, authenticate, fetchImpl } = fixture(); expect(await service.execute('submit', body)).toEqual(receipt); expect(authenticate).toHaveBeenCalledWith({ username: body.username, password: body.password });
  const [url, options] = fetchImpl.mock.calls[0]; expect(url.pathname).toBe('/internal/identity/company-registrations/submit'); expect(options.redirect).toBe('error');
  const token = options.headers.Authorization.slice(7); const verified = jwt.verify(token, keys.publicKey, { issuer, audience: AUDIENCE, algorithms: ['RS256'], complete: true });
  expect(verified.header.typ).toBe(TYPE); expect(verified.payload.token_use).toBe(PURPOSE); expect(verified.payload.actor_type).toBe('workload'); expect(verified.payload.exp - verified.payload.iat).toBe(30);
  const actual = JSON.parse(options.body); expect(actual.subject).toBe(principal.id); expect(actual.principal).toEqual({ username: principal.username, email: principal.email, displayName: principal.displayName });
  expect(verified.payload.body_sha256).toBe(requestDigest('submit', actual)); expect(options.body.includes(body.password)).toBe(false); expect(options.body.includes('admin')).toBe(false);
});
test('failed credentials or incomplete verified identity metadata cannot reach registration storage', async () => {
  const { service, authenticate, fetchImpl } = fixture(); authenticate.mockResolvedValueOnce({ status: 401, error: 'invalid_credentials' });
  await expect(service.execute('submit', body)).rejects.toMatchObject({ status: 401 }); expect(fetchImpl).not.toHaveBeenCalled();
  authenticate.mockResolvedValueOnce({ user: { id: 'credential-subject' } }); await expect(service.execute('submit', body)).rejects.toMatchObject({ status: 503 }); expect(fetchImpl).not.toHaveBeenCalled();
});
test.each([{ ...receipt, tenantEnabled: true }, { ...receipt, registrationId: randomUUID() }, { ...receipt, access_token: 'invalid-purpose' }])('plausible activated, foreign or token-bearing responses are never accepted %#', async value => {
  const { service, fetchImpl } = fixture(); fetchImpl.mockResolvedValueOnce(new Response(JSON.stringify(value), { status: 201, headers: { 'Content-Type': 'application/json' } })); await expect(service.execute('submit', body)).rejects.toMatchObject({ status: 503 });
});
test('lost acknowledgements are unconfirmed, not automatically retried, and status requests cannot become a second write', async () => {
  const { service, fetchImpl } = fixture(); fetchImpl.mockRejectedValueOnce(new Error('response lost')); await expect(service.execute('submit', body)).rejects.toMatchObject({ status: 503 }); expect(fetchImpl).toHaveBeenCalledTimes(1);
  fetchImpl.mockResolvedValueOnce(new Response(JSON.stringify({ ...receipt, replayed: true }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  const { profile: ignoredProfile, confirm: ignoredConfirm, ...credentials } = body; expect((await service.execute('status', credentials)).replayed).toBe(true); expect(fetchImpl.mock.calls[1][0].pathname).toBe('/internal/identity/company-registrations/status');
});
test.each(['pending-activation', 'rejected'])('credential-bound reviewed status %s passes only with the exact versioned disabled receipt', async status => {
  const { service, fetchImpl } = fixture(); const observed = { ...receipt, schemaVersion: 2, replayed: true, status, reviewedAt: '2026-10-19T01:00:00Z' };
  fetchImpl.mockResolvedValueOnce(new Response(JSON.stringify(observed), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  expect(await service.execute('status', { registrationId, username: body.username, password: body.password, mfaCode: '' })).toEqual(observed);
});
test('activation binds only the operator-configured existing protected console and never forwards browser-selected scopes', async () => {
  const authenticate = jest.fn(async () => ({ user: principal })); const fetchImpl = jest.fn(async () => new Response(JSON.stringify({ ...receipt, schemaVersion: 3, status: 'active', reviewedAt: '2026-10-19T01:00:00Z', activatedAt: '2026-10-19T02:00:00Z', tenantEnabled: true, administratorEnabled: true, profileSaved: true, activationSupported: true, consoleClientId: 'web-app', mfaRequired: true }), { headers: { 'Content-Type': 'application/json' } }));
  const client = jest.fn(async () => ({ enabled: true, publicClient: false, grantTypes: ['authorization_code'], scopes: ['openid', 'roles'] }));
  const service = new CompanyRegistrationGateway({ signingKeys: { privateKey: keys.privateKey, kid: 'registration-unit-key' }, issuer, endpoint: 'https://identity.test/internal/identity/authorization-state', authenticate, fetchImpl, consoleClientId: 'web-app', client });
  expect((await service.execute('activate', { registrationId, username: body.username, password: body.password, mfaCode: '', confirm: true })).schemaVersion).toBe(3);
  expect(JSON.parse(fetchImpl.mock.calls[0][1].body)).toEqual({ registrationId, subject: principal.id, consoleClientId: 'web-app' });
  client.mockResolvedValueOnce(null); await expect(service.execute('activate', { registrationId, username: body.username, password: body.password, mfaCode: '', confirm: true })).rejects.toMatchObject({ status: 503 }); expect(fetchImpl).toHaveBeenCalledTimes(1);
});
