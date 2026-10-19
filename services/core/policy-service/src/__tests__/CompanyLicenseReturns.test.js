'use strict';

const { randomUUID } = require('node:crypto');
const express = require('express');
const request = require('supertest');
const { CompanyLicenses } = require('../licenses/CompanyLicenses');
const { companyLicenseRoutes } = require('../licenses/companyRoutes');
const { returnValues } = require('../../../../../packages/company-license-contract');

let store; let source; let user; let database; let authority; let items;
const authorization = 'Bearer original.company.return';
const reason = 'Confirmed inactive employee local license return';
beforeEach(() => {
  user = { identity_authorization: { userId: randomUUID() } };
  source = { actorUserId: user.identity_authorization.userId, tenant: { id: randomUUID() }, validUntil: Math.floor(Date.now() / 1000) + 200, target: null };
  items = Array.from({ length: 3 }, () => ({ poolId: randomUUID(), assignmentId: randomUUID(), poolRevision: '2' }));
  database = { query: jest.fn(async sql => ({ rows: sql.includes('AS supported') ? [{ supported: true }] : [{ id: items[0].assignmentId }] })) };
  authority = { read: jest.fn(async (_bearer, _user, userId) => ({ ...source, target: userId ? { id: userId, enabled: false, deleted: false, revision: '2', eligibilityRevision: '2' } : null })) };
  store = new CompanyLicenses({ database }, { authority });
  store.ownPool = jest.fn(async (_database, id) => ({ id, business_revision: '2' }));
  store.revoke = jest.fn(async () => ({}));
});
const input = () => ({ reason, confirm: true, assignments: items });

test('a normalized captured return page keeps exact positive BIGINT revisions without adding tenant or permission selectors', () => {
  items[0].poolRevision = '9223372036854775807';
  expect(returnValues({ ...input(), reason: '  ' + reason + '  ' })).toEqual(input());
});
test.each([
  body => ({ ...body, tenantId: randomUUID() }), body => ({ ...body, confirm: false }), body => ({ ...body, reason: 'short' }),
  body => ({ ...body, assignments: [] }), body => ({ ...body, assignments: Array(26).fill(body.assignments[0]) }),
  body => ({ ...body, assignments: [body.assignments[0], body.assignments[0]] }),
  body => ({ ...body, assignments: [{ ...body.assignments[0], poolRevision: '9223372036854775808' }] }),
  body => ({ ...body, assignments: [{ ...body.assignments[0], poolRevision: 2 }] }),
  body => ({ ...body, assignments: [{ ...body.assignments[0], poolRevision: '02' }] }),
  body => ({ ...body, assignments: [{ ...body.assignments[0], grantId: randomUUID() }] }),
  body => ({ ...body, assignments: [{ ...body.assignments[0], assignmentId: '*' }] }),
])('invalid or oversized manifest is rejected before any original source lookup (%#)', async transform => {
  await expect(store.returnLicenses(randomUUID(), transform(input()), user, authorization)).rejects.toMatchObject({ status: 400 });
  expect(authority.read).not.toHaveBeenCalled(); expect(store.revoke).not.toHaveBeenCalled();
});
test.each([404, 412, 409])('every manifest pool is preflighted before target eligibility or any release (%s)', async status => {
  if (status === 404) store.ownPool.mockRejectedValueOnce(Object.assign(new Error('foreign'), { status }));
  if (status === 412) store.ownPool.mockResolvedValueOnce({ business_revision: '3' });
  if (status === 409) database.query.mockResolvedValueOnce({ rows: [{ supported: false }] });
  await expect(store.returnLicenses(randomUUID(), input(), user, authorization)).rejects.toMatchObject({ status });
  expect(authority.read).toHaveBeenCalledTimes(1); expect(store.revoke).not.toHaveBeenCalled();
});
test('a replaced current assignment cannot be retargeted to the same employee or a new grant', async () => {
  database.query.mockImplementation(async sql => ({ rows: sql.includes('AS supported') ? [{ supported: true }] : [] }));
  await expect(store.returnLicenses(randomUUID(), input(), user, authorization)).rejects.toMatchObject({ status: 404 });
  expect(authority.read).toHaveBeenCalledTimes(1); expect(store.revoke).not.toHaveBeenCalled();
});
test('an enabled own employee is not implicitly disabled by a return request', async () => {
  authority.read.mockImplementation(async (_bearer, _user, userId) => ({ ...source, target: userId ? { id: userId, enabled: true } : null }));
  await expect(store.returnLicenses(randomUUID(), input(), user, authorization)).rejects.toMatchObject({ status: 403 });
  expect(store.revoke).not.toHaveBeenCalled();
});
test('all successful releases share one actual correlation and exact captured inactive source', async () => {
  const userId = randomUUID(); const correlationId = randomUUID();
  const result = await store.returnLicenses(userId, input(), user, authorization, correlationId);
  expect(result).toEqual({ schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, userId, correlationId,
    results: items.map(item => ({ poolId: item.poolId, assignmentId: item.assignmentId, status: 'released', code: 200 })) });
  expect(store.revoke).toHaveBeenCalledTimes(3);
  for (let index = 0; index < items.length; index += 1) {
    expect(store.revoke.mock.calls[index].slice(0, 7)).toEqual([items[index].poolId, items[index].assignmentId, { userId, reason, confirm: true }, `"company-pool-${items[index].poolId}-2"`, user, authorization, correlationId]);
    expect(store.revoke.mock.calls[index][7].target).toMatchObject({ id: userId, enabled: false });
  }
});
test.each([412, 503, undefined])('one uncertain result stops later operations without pretending rollback or retry (%s)', async status => {
  store.revoke.mockResolvedValueOnce({}).mockRejectedValueOnce(Object.assign(new Error('Not confirmed'), { status }));
  const result = await store.returnLicenses(randomUUID(), input(), user, authorization);
  expect(result.results.map(item => [item.status, item.code])).toEqual([['released', 200], ['unconfirmed', status || 503], ['not_attempted', null]]);
  expect(store.revoke).toHaveBeenCalledTimes(2);
});
test('a changed original source between actor and target preflight cannot borrow the earlier authority', async () => {
  authority.read.mockResolvedValueOnce(source).mockResolvedValueOnce({ ...source, tenant: { id: randomUUID() }, target: { enabled: false } });
  await expect(store.returnLicenses(randomUUID(), input(), user, authorization)).rejects.toMatchObject({ status: 401 });
  expect(store.revoke).not.toHaveBeenCalled();
});
test('lost original authority at the final response checkpoint withholds the batch summary', async () => {
  authority.read.mockImplementation(async (_bearer, _user, userId) => {
    if (store.revoke.mock.calls.length) throw Object.assign(new Error('Original withdrawn'), { status: 401 });
    return { ...source, target: userId ? { id: userId, enabled: false } : null };
  });
  await expect(store.returnLicenses(randomUUID(), input(), user, authorization)).rejects.toMatchObject({ status: 401 });
  expect(store.revoke).toHaveBeenCalledTimes(3);
});
test('return preview refuses more than 25 rows and arbitrary selectors before source transport', async () => {
  await expect(store.returnPreview(randomUUID(), { limit: '26' }, user, authorization)).rejects.toMatchObject({ status: 400 });
  await expect(store.returnPreview(randomUUID(), { tenantId: randomUUID() }, user, authorization)).rejects.toMatchObject({ status: 400 });
  expect(authority.read).not.toHaveBeenCalled();
});
test.each([false, true])('the HTTP response distinguishes all confirmed from stopped partial results (%s)', async partial => {
  const userId = randomUUID(); const results = [{ poolId: items[0].poolId, assignmentId: items[0].assignmentId, status: partial ? 'unconfirmed' : 'released', code: partial ? 503 : 200 }];
  const spy = jest.spyOn(CompanyLicenses.prototype, 'returnLicenses').mockImplementation(async (_id, _body, _user, _bearer, correlationId) => ({ schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, userId, correlationId, results }));
  try {
    const app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); }); app.use('/company', companyLicenseRoutes({ database }, { authority }));
    const response = await request(app).post(`/company/users/${userId}/license-returns`).set('Authorization', authorization).send(input());
    expect(response.status).toBe(partial ? 207 : 200); expect(response.headers['cache-control']).toBe('no-store');
    expect(response.body.correlationId).toBe(response.headers['x-correlation-id']); expect(response.body.results).toEqual(results);
  } finally { spy.mockRestore(); }
});
