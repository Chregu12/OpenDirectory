'use strict';

const { randomUUID } = require('node:crypto');
const { CompanyOffboardingIdentity } = require('../licenses/CompanyOffboardingIdentity');
const { offboardingIntent, offboardingContinuation, offboardingVersion } = require('../../../../../packages/company-license-contract');
const userId = randomUUID(); const tenantId = randomUUID(); const workflowId = randomUUID();
const source = { tenant: { id: tenantId }, target: { id: userId, enabled: true, eligibilityRevision: '104' } };
const job = { id: workflowId, userId, state: { requestedRevision: '9007199254740993' } };
const authorization = 'Bearer original.workflow';
const receipt = () => ({ schemaVersion: 1, workflowId, tenantId, userId, actorUserId: randomUUID(), operationId: randomUUID(), action: 'disabled',
  beforeRevision: job.state.requestedRevision, afterRevision: '9007199254740999', beforeEligibilityRevision: '104', afterEligibilityRevision: '162', createdAt: new Date().toISOString(), deliveryStatus: 'pending' });
const response = (body, headers = {}, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

test('the original bearer uses only the fixed Identity origin/path and exact idempotent account intent', async () => {
  const body = receipt(); const fetchImpl = jest.fn().mockResolvedValue(response(body)); const client = new CompanyOffboardingIdentity({ origin: 'https://identity.fixture', fetchImpl });
  expect(await client.disable(job, authorization, source)).toEqual(body);
  const [url, request] = fetchImpl.mock.calls[0]; expect(url.href).toBe(`https://identity.fixture/api/users/${userId}/company-offboarding`);
  expect(request.headers.Authorization).toBe(authorization); expect(request.redirect).toBe('error'); expect(request.cache).toBe('no-store');
  expect(JSON.parse(request.body)).toEqual({ workflowId, expectedRevision: job.state.requestedRevision, confirm: true });
});
test('a minimal authorized employee projection binds the exact record ETag, target status and existing name', async () => {
  const fetchImpl = jest.fn().mockResolvedValue(response({ id: userId, revision: job.state.requestedRevision, username: 'actual-employee', displayName: 'Actual Employee', enabled: true }, { etag: `"user-${userId}-${job.state.requestedRevision}"` }));
  const client = new CompanyOffboardingIdentity({ origin: 'https://identity.fixture', fetchImpl });
  expect(await client.user(userId, authorization, source)).toEqual({ id: userId, name: 'Actual Employee', userRevision: job.state.requestedRevision, eligibilityRevision: '104', enabled: true });
});
test.each([
  body => ({ ...body, tenantId: randomUUID() }), body => ({ ...body, workflowId: randomUUID() }), body => ({ ...body, userId: randomUUID() }),
  body => ({ ...body, bearer: authorization }), body => ({ ...body, operationId: null }), body => ({ ...body, action: 'completed' }),
  body => ({ ...body, afterRevision: '9223372036854775808' }), body => ({ ...body, afterEligibilityRevision: body.beforeEligibilityRevision }),
  body => ({ ...body, beforeRevision: '1' }), body => ({ ...body, createdAt: 'invalid' }), body => ({ ...body, deliveryStatus: 'delivered' }),
])('a swapped, incomplete or invented Identity success is never a confirmed offboarding checkpoint (%#)', async change => {
  const client = new CompanyOffboardingIdentity({ fetchImpl: jest.fn().mockResolvedValue(response(change(receipt()))) });
  await expect(client.disable(job, authorization, source)).rejects.toMatchObject({ status: 503 });
});
test('already-disabled observation has no invented mutation id or revision advance', async () => {
  const body = { ...receipt(), operationId: null, action: 'already_disabled', afterRevision: job.state.requestedRevision, afterEligibilityRevision: '104' };
  const client = new CompanyOffboardingIdentity({ fetchImpl: jest.fn().mockResolvedValue(response(body)) });
  expect(await client.disable(job, authorization, source)).toEqual(body);
});
test.each([400, 401, 403, 404, 409, 412, 428])('upstream rejection %s is preserved without retry or a service credential fallback', async status => {
  const fetchImpl = jest.fn().mockResolvedValue(response({ error: 'rejected' }, {}, status)); const client = new CompanyOffboardingIdentity({ fetchImpl });
  await expect(client.disable(job, authorization, source)).rejects.toMatchObject({ status }); expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test.each(['https://identity.fixture/path', 'https://name:secret@identity.fixture', 'https://identity.fixture/?target=other', 'file:///tmp/source'])('caller-selected or credential-bearing Identity origins are unsupported: %s', origin => {
  expect(() => new CompanyOffboardingIdentity({ origin })).toThrow();
});
test('oversized source responses and unknown transport completion remain unconfirmed', async () => {
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ padding: 'x'.repeat(65537) })).mockRejectedValueOnce(new Error('late lost response'));
  const client = new CompanyOffboardingIdentity({ fetchImpl });
  for (let index = 0; index < 2; index += 1) await expect(client.disable(job, authorization, source)).rejects.toMatchObject({ status: 503 });
});
test('a durable account receipt may arrive after the read budget without retrying the mutation', async () => {
  jest.useFakeTimers();
  try {
    const body = receipt(); let signal;
    const fetchImpl = jest.fn((_url, options) => new Promise((resolve, reject) => {
      signal = options.signal;
      const timer = setTimeout(() => resolve(response(body)), 6000);
      signal.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
    }));
    const pending = new CompanyOffboardingIdentity({ fetchImpl }).disable(job, authorization, source);
    await jest.advanceTimersByTimeAsync(5001); expect(signal.aborted).toBe(false);
    await jest.advanceTimersByTimeAsync(999); await expect(pending).resolves.toEqual(body);
    expect(fetchImpl).toHaveBeenCalledTimes(1); expect(signal.aborted).toBe(true);
    expect(jest.getTimerCount()).toBe(0);
  } finally { jest.useRealTimers(); }
});
test.each(['headers', 'body'])('the complete account response still has a bounded deadline while waiting for %s', async phase => {
  jest.useFakeTimers();
  try {
    let signal;
    const fetchImpl = jest.fn((_url, options) => {
      signal = options.signal;
      const untilAbort = () => new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
      return phase === 'headers' ? untilAbort() : Promise.resolve({ status: 200, headers: new Headers({ 'content-type': 'application/json' }),
        body: (async function* () { await untilAbort(); yield Buffer.from('{}'); })() });
    });
    const pending = new CompanyOffboardingIdentity({ fetchImpl }).disable(job, authorization, source);
    const rejected = expect(pending).rejects.toMatchObject({ status: 503 });
    await jest.advanceTimersByTimeAsync(29999); expect(signal.aborted).toBe(false);
    await jest.advanceTimersByTimeAsync(1); await rejected;
    expect(fetchImpl).toHaveBeenCalledTimes(1); expect(signal.aborted).toBe(true); expect(jest.getTimerCount()).toBe(0);
  } finally { jest.useRealTimers(); }
});
test('employee reads retain their shorter deadline and never retry', async () => {
  jest.useFakeTimers();
  try {
    const fetchImpl = jest.fn((_url, { signal }) => new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true })));
    const rejected = expect(new CompanyOffboardingIdentity({ fetchImpl }).user(userId, authorization, source)).rejects.toMatchObject({ status: 503 });
    await jest.advanceTimersByTimeAsync(5000); await rejected;
    expect(fetchImpl).toHaveBeenCalledTimes(1); expect(jest.getTimerCount()).toBe(0);
  } finally { jest.useRealTimers(); }
});
test('workflow input rejects selectors and requires the exact captured workflow ETag', () => {
  const intent = { workflowId, userId, userRevision: '1', eligibilityRevision: '2', reason: 'Confirmed original local offboarding', confirm: true };
  expect(offboardingIntent(intent)).toEqual(intent); expect(() => offboardingIntent({ ...intent, tenantId })).toThrow();
  expect(() => offboardingContinuation({ confirm: true, reason: intent.reason, userRevision: '1', assignments: Array(26).fill({}) })).toThrow();
  expect(offboardingVersion(workflowId, `"company-offboarding-${workflowId}-9007199254740993"`)).toBe('9007199254740993');
  for (const expected of [undefined, '*', `"company-offboarding-${randomUUID()}-1"`]) expect(() => offboardingVersion(workflowId, expected)).toThrow();
});
