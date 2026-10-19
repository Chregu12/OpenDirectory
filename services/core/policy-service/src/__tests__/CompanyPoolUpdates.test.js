'use strict';

const { randomUUID } = require('node:crypto');
const express = require('express');
const request = require('supertest');
const { CompanyLicenses } = require('../licenses/CompanyLicenses');
const { companyLicenseRoutes } = require('../licenses/companyRoutes');
const { companyLicenseContext } = require('../licenses/CompanyLicenseContext');
const { COMPANY_LICENSE_PERMISSIONS, poolUpdateValues, poolEtag } = require('../../../../../packages/company-license-contract');

const authorization = 'Bearer actual.company.update';
const reason = 'Reviewed actual local catalog and stock correction';
let user; let source; let row; let values; let database; let allocator; let authority; let store; let command;
beforeEach(() => {
  const actorUserId = randomUUID(); const tenantId = randomUUID();
  user = { identity_authorization: { userId: actorUserId } };
  source = { actorUserId, tenant: { id: tenantId }, permissions: [...COMPANY_LICENSE_PERMISSIONS], validUntil: Math.floor(Date.now() / 1000) + 300, target: null };
  row = { id: randomUUID(), business_tenant_id: tenantId, business_revision: '9007199254740993', company_valid: true, name: 'Original App', vendor: 'Original Vendor', description: '',
    total_seats: 2, active_seats: 1, license_type: 'per_user', created_at: new Date(), updated_at: new Date() };
  values = { name: 'Updated App', vendor: 'Updated Vendor', description: 'Reviewed local catalog', totalSeats: 3, reason, confirm: true };
  database = { query: jest.fn(async (sql, parameters) => {
    if (sql.includes('AS supported')) return { rows: [{ supported: true }] };
    if (sql.includes('license_company_begin')) { command = JSON.parse(parameters[1]); return { rows: [{ command_id: command.id }] }; }
    if (sql.includes('license_company_finish')) { row.business_revision = (BigInt(row.business_revision) + 1n).toString(); return { rows: [{ event_id: command.id }] }; }
    if (sql.startsWith('UPDATE license_catalog')) { Object.assign(row, { name: parameters[1], vendor: parameters[2], description: parameters[3], total_seats: parameters[4] }); return { rowCount: 1, rows: [] }; }
    return { rows: [row] };
  }), getClient: jest.fn() };
  const client = { query: database.query, release: jest.fn() }; database.getClient.mockResolvedValue(client);
  allocator = { database, audit: jest.fn(), transaction: jest.fn(async operation => {
    const scope = companyLicenseContext.getStore(); await scope.verify(client, false); await operation(client); await scope.verify(client, true); await scope.complete(client);
  }) };
  authority = { read: jest.fn(async () => source) }; store = new CompanyLicenses(allocator, { authority }); command = null;
});

test('confirmed catalog values reuse normalization without introducing new permissions or mutable ownership', () => {
  expect(poolUpdateValues({ ...values, name: '  Updated App  ', reason: '  ' + reason + '  ' })).toEqual(values);
  expect(COMPANY_LICENSE_PERMISSIONS).toEqual(['company.apps.read', 'company.apps.create', 'company.apps.assign']);
});
test.each([
  input => ({ ...input, tenantId: randomUUID() }), input => ({ ...input, licenseType: 'device' }), input => ({ ...input, confirm: false }),
  input => { const { confirm, ...rest } = input; return rest; }, input => ({ ...input, reason: 'short' }), input => ({ ...input, name: ' ' }),
  input => ({ ...input, vendor: 'vendor\nsecret' }), input => ({ ...input, totalSeats: 0 }), input => ({ ...input, totalSeats: 10001 }),
  input => ({ ...input, totalSeats: 1.5 }), input => ({ ...input, totalSeats: '3' }), input => ({ ...input, description: 'x'.repeat(2001) }),
])('invalid confirmed edits fail before live authority or any transaction (%#)', async transform => {
  await expect(store.update(row.id, transform(values), poolEtag({ id: row.id, revision: row.business_revision }), user, authorization)).rejects.toMatchObject({ status: 400 });
  expect(authority.read).not.toHaveBeenCalled(); expect(allocator.transaction).not.toHaveBeenCalled();
});
test.each([[undefined, 428], ['*', 412], ['W/"pool"', 412], ['"company-pool-' + randomUUID() + '-1"', 412]])('missing or nonexact version %s never enters original source transport', async (version, status) => {
  await expect(store.update(row.id, values, version, user, authorization)).rejects.toMatchObject({ status }); expect(authority.read).not.toHaveBeenCalled();
});
test('a real edit uses one existing allocator transaction, exact old BIGINT, original source and existing audit path', async () => {
  const revision = row.business_revision; const correlationId = randomUUID();
  const result = await store.update(row.id, values, poolEtag({ id: row.id, revision }), user, authorization, correlationId);
  expect(result).toMatchObject({ id: row.id, tenantId: source.tenant.id, revision: '9007199254740994', name: values.name, vendor: values.vendor, description: values.description, totalSeats: 3, usedSeats: 1, availableSeats: 2 });
  expect(command).toMatchObject({ correlationId, licenseId: row.id, expectedVersion: revision, action: 'update', values: { name: values.name, vendor: values.vendor, description: values.description, totalSeats: 3 }, assignmentId: null, reason });
  expect(allocator.transaction).toHaveBeenCalledTimes(1);
  expect(allocator.audit).toHaveBeenCalledWith(expect.anything(), row.id, 'pool-updated', source.actorUserId, { before: { name: 'Original App', vendor: 'Original Vendor', description: '', totalSeats: 2 }, after: command.values, reason });
  expect(database.query.mock.calls.findIndex(([sql]) => sql === 'SELECT license_company_edit_receiving()')).toBeLessThan(database.query.mock.calls.findIndex(([sql]) => sql.includes('license_company_begin')));
  expect(authority.read.mock.calls.every(call => call.length === 2 || call[2] === null)).toBe(true); expect(companyLicenseContext.getStore()).toBeUndefined();
});
test.each(['no-op', 'occupied-floor'])('%s cannot cause catalog or audit effects', async condition => {
  if (condition === 'no-op') values = { ...values, name: row.name, vendor: row.vendor, description: row.description, totalSeats: row.total_seats };
  else { row.active_seats = 2; values.totalSeats = 1; }
  await expect(store.update(row.id, values, poolEtag({ id: row.id, revision: row.business_revision }), user, authorization)).rejects.toMatchObject({ status: 409 });
  expect(database.query.mock.calls.some(([sql]) => sql.startsWith('UPDATE'))).toBe(false); expect(allocator.audit).not.toHaveBeenCalled();
});
test.each(['foreign', 'stale', 'governed'])('%s pool is rejected before a writable transaction', async condition => {
  if (condition === 'foreign') store.ownPool = jest.fn().mockRejectedValue(Object.assign(new Error('Not own'), { status: 404 }));
  if (condition === 'stale') row.business_revision = '9007199254740994';
  if (condition === 'governed') store.supported = jest.fn().mockRejectedValue(Object.assign(new Error('Separate governance'), { status: 409 }));
  await expect(store.update(row.id, values, poolEtag({ id: row.id, revision: '9007199254740993' }), user, authorization)).rejects.toMatchObject({ status: condition === 'foreign' ? 404 : condition === 'stale' ? 412 : 409 });
  expect(allocator.transaction).not.toHaveBeenCalled();
});
test('missing update receiver fails closed before admission and writable effects', async () => {
  const query = database.query.getMockImplementation(); database.query.mockImplementation(async (sql, parameters) => { if (sql.includes('license_company_edit_receiving')) throw new Error('Missing 024'); return query(sql, parameters); });
  await expect(store.update(row.id, values, poolEtag({ id: row.id, revision: row.business_revision }), user, authorization)).rejects.toThrow('Missing 024');
  expect(command).toBeNull(); expect(database.query.mock.calls.some(([sql]) => sql.startsWith('UPDATE'))).toBe(false);
});
test('edit capability is own-pool and exact-version bound after current source and receiving checks', async () => {
  const result = await store.editCapabilities(row.id, user, authorization);
  expect(result).toEqual({ schemaVersion: 1, companyPoolEditProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, poolId: row.id, poolRevision: row.business_revision });
  expect(database.query).toHaveBeenCalledWith('SELECT license_company_edit_receiving()'); expect(allocator.transaction).not.toHaveBeenCalled();
});
test('authority lost after storage capability validation cannot leave an edit capability', async () => {
  authority.read.mockResolvedValueOnce(source).mockRejectedValueOnce(Object.assign(new Error('Original revoked'), { status: 401 }));
  await expect(store.editCapabilities(row.id, user, authorization)).rejects.toMatchObject({ status: 401 });
});
test('an allocator result without actual completion is never a successful edit', async () => {
  allocator.transaction.mockResolvedValue({ id: row.id });
  await expect(store.update(row.id, values, poolEtag({ id: row.id, revision: row.business_revision }), user, authorization)).rejects.toMatchObject({ status: 503 });
});
test('PATCH returns the real pool version and a server-generated correlation while forwarding the original bearer', async () => {
  const result = { id: row.id, revision: '9007199254740994' }; const spy = jest.spyOn(CompanyLicenses.prototype, 'update').mockResolvedValue(result);
  try {
    const app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); }); app.use('/company', companyLicenseRoutes(allocator, { authority }));
    const version = poolEtag({ id: row.id, revision: row.business_revision });
    const response = await request(app).patch('/company/pools/' + row.id).set('Authorization', authorization).set('If-Match', version).set('X-Correlation-ID', randomUUID()).send(values);
    expect(response.status).toBe(200); expect(response.headers.etag).toBe(poolEtag(result)); expect(response.headers['cache-control']).toBe('no-store');
    expect(spy).toHaveBeenCalledWith(row.id, values, version, user, authorization, response.headers['x-correlation-id']);
  } finally { spy.mockRestore(); }
});
test.each(['GET', 'PATCH'])('extra HTTP selectors on %s never reach the edit handler', async method => {
  const spy = jest.spyOn(CompanyLicenses.prototype, method === 'GET' ? 'editCapabilities' : 'update').mockResolvedValue({});
  try {
    const app = express(); app.use(express.json()); app.use('/company', companyLicenseRoutes(allocator, { authority }));
    const route = '/company/pools/' + row.id + (method === 'GET' ? '/edit-capabilities' : '');
    const response = await request(app)[method.toLowerCase()](route + '?tenantId=' + source.tenant.id).send(method === 'GET' ? {} : values);
    expect(response.status).toBe(400); expect(spy).not.toHaveBeenCalled();
  } finally { spy.mockRestore(); }
});
