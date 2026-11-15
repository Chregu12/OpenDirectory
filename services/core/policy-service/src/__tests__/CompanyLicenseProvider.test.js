'use strict';

const { randomUUID } = require('node:crypto');
const express = require('express');
const request = require('supertest');
const { CompanyLicenses } = require('../licenses/CompanyLicenses');
const { CompanyLicenseProvider } = require('../licenses/CompanyLicenseProvider');
const { companyLicenseRoutes } = require('../licenses/companyRoutes');
const { ProviderError } = require('../licenses/fulfillment/transport');
const { COMPANY_LICENSE_PERMISSIONS } = require('../../../../../packages/company-license-contract');
const { listenLoopback, closeServer } = require('../../../../../scripts/lib/loopback-test-server.cjs');

let source; let authority; let database; let store; let options; let inspect; let user; let server;
const authorization = 'Bearer original.company';
const product = { skuId: randomUUID(), skuPartNumber: 'ACTUAL_SKU', appliesTo: 'User', capabilityStatus: 'Enabled',
  prepaidUnits: { enabled: 5, warning: 0, suspended: 0, lockedOut: 0 }, consumedUnits: 2 };
beforeEach(() => {
  const now = Math.floor(Date.now() / 1000);
  source = { schemaVersion: 1, actorUserId: randomUUID(), tenant: { id: randomUUID(), version: '1', generation: '1' }, validUntil: now + 300 };
  user = { actor_type: 'user' };
  authority = { read: jest.fn(async () => source) };
  database = { query: jest.fn(async () => ({ rows: [] })), getClient: jest.fn() };
  database.getClient.mockImplementation(async () => ({ query: database.query, release: jest.fn() }));
  store = new CompanyLicenses({ database }, { authority });
  inspect = jest.fn(async () => [product]);
  options = { tenantId: source.tenant.id, filename: '/private/reviewed.json',
    load: jest.fn(() => ({ provider: 'microsoft-365', tenantId: randomUUID(), clientSecret: 'private.fixture.secret' })),
    createClient: jest.fn(() => ({ inspect })) };
  const config = options.load(); options.load.mockReset().mockReturnValue(config);
});
afterEach(async () => { if (server) await closeServer(server); server = null; });

test('a confirmed snapshot is bound to the own actor/company and retains the exact normalized vendor counts', async () => {
  const result = await new CompanyLicenseProvider(store, options).inspect(user, authorization);
  expect(result).toEqual({ schemaVersion: 1, companyLicenseProviderProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id,
    provider: 'microsoft-365', state: 'connected', microsoftTenantId: options.load().tenantId, checkedAt: expect.any(String), products: [product] });
  expect(authority.read).toHaveBeenCalledTimes(3); expect(authority.read.mock.calls.every(args => args[0] === authorization && args[1] === user)).toBe(true);
  expect(database.query).toHaveBeenCalledWith('SELECT license_company_receiving()');
  expect(database.query.mock.calls.every(([sql]) => sql.startsWith('SELECT') || sql.startsWith('BEGIN') || sql.startsWith('SET LOCAL') || sql === 'COMMIT')).toBe(true);
  expect(JSON.stringify(result)).not.toContain('private.fixture.secret');
});
test.each(['absent', 'another-company'])('%s configuration returns no cloud identity and performs no provider or file access', async kind => {
  if (kind === 'absent') Object.assign(options, { tenantId: undefined, filename: undefined });
  else options.tenantId = randomUUID();
  expect(await new CompanyLicenseProvider(store, options).inspect(user, authorization)).toMatchObject({ state: 'not_configured', tenantId: source.tenant.id });
  expect(options.load).not.toHaveBeenCalled(); expect(options.createClient).not.toHaveBeenCalled(); expect(inspect).not.toHaveBeenCalled();
});
test.each([{ tenantId: undefined }, { filename: undefined }, { tenantId: 'common' }])('partial or invalid operator bindings fail closed: %j', changes => {
  Object.assign(options, changes);
  return expect(new CompanyLicenseProvider(store, options).inspect(user, authorization)).rejects.toMatchObject({ status: 503 });
});
test('an unsafe file or another provider is not a callable company connection', async () => {
  options.load.mockImplementationOnce(() => { throw Object.assign(new Error('private filename and secret'), { status: 400 }); });
  await expect(new CompanyLicenseProvider(store, options).inspect(user, authorization)).rejects.toMatchObject({ status: 503, message: 'Company provider configuration unavailable' });
  options.load.mockReturnValue({ provider: 'github-copilot' });
  await expect(new CompanyLicenseProvider(store, options).inspect(user, authorization)).rejects.toMatchObject({ status: 503 });
  expect(options.createClient).not.toHaveBeenCalled();
});
test('denied authority prevents configuration access and any cloud call', async () => {
  authority.read.mockRejectedValue(Object.assign(new Error('Revoked'), { status: 401 }));
  await expect(new CompanyLicenseProvider(store, options).inspect(user, authorization)).rejects.toMatchObject({ status: 401 });
  expect(options.load).not.toHaveBeenCalled(); expect(inspect).not.toHaveBeenCalled();
});
test.each([2, 3])('a source changed on authority check %s cannot return the provider result', async changedAt => {
  let calls = 0; authority.read.mockImplementation(async () => ++calls >= changedAt ? { ...source, tenant: { ...source.tenant, generation: '2' } } : source);
  await expect(new CompanyLicenseProvider(store, options).inspect(user, authorization)).rejects.toMatchObject({ status: 401 });
  expect(inspect).toHaveBeenCalledTimes(1);
});
test('a changed protected configuration discards a completed observation', async () => {
  options.load.mockReturnValueOnce(options.load()).mockReturnValue({ provider: 'microsoft-365', tenantId: randomUUID(), clientSecret: 'rotated.fixture.secret' });
  await expect(new CompanyLicenseProvider(store, options).inspect(user, authorization)).rejects.toMatchObject({ status: 503 });
});
test('a provider denial remains a bounded failure and cannot disclose response bodies or credentials', async () => {
  const error = new ProviderError('graph_capacity_http_429', { retryAfter: 90 }); error.message = 'private.fixture.secret'; inspect.mockRejectedValue(error);
  const result = await new CompanyLicenseProvider(store, options).inspect(user, authorization);
  expect(result).toMatchObject({ state: 'failed', errorCode: 'graph_capacity_http_429', retryAfter: 90 });
  expect(result.products).toBeUndefined(); expect(JSON.stringify(result)).not.toContain('private.fixture.secret'); expect(authority.read).toHaveBeenCalledTimes(3);
});
test('HTTP route preserves the own source, rejects selectors and HEAD/body/API-key aliases before cloud work', async () => {
  source.permissions = [...COMPANY_LICENSE_PERMISSIONS];
  const app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); });
  app.use('/company', companyLicenseRoutes({ database }, { authority, provider: options })); server = await listenLoopback(app);
  const result = await request(server).get('/company/provider').set('Authorization', authorization);
  expect(result.status).toBe(200); expect(result.body.state).toBe('connected'); expect(result.headers['cache-control']).toBe('no-store');
  expect(result.headers['x-correlation-id']).toMatch(/^[a-f0-9-]{36}$/); inspect.mockClear();
  expect((await request(server).get('/company/provider?tenantId=forged')).status).toBe(400);
  expect((await request(server).head('/company/provider')).status).toBe(404);
  expect((await request(server).get('/company/provider').send({})).status).toBe(400);
  expect((await request(server).get('/company/provider').set('X-API-Key', '')).status).toBe(400);
  expect(inspect).not.toHaveBeenCalled();
});
