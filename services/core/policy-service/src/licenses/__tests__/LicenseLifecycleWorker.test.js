'use strict';

const { LicenseLifecycleWorker } = require('../LicenseLifecycleWorker');

function fixture() {
  const allocator = { database: { query: jest.fn().mockResolvedValue({ rows: [] }) }, offboard: jest.fn().mockResolvedValue({}), expireAll: jest.fn().mockResolvedValue(0) };
  const bus = { subscribe: jest.fn().mockResolvedValue(undefined) };
  const logger = { warn: jest.fn(), error: jest.fn() };
  const metadata = { ack: jest.fn(), nack: jest.fn() };
  return { allocator, bus, logger, metadata, worker: new LicenseLifecycleWorker({ allocator, bus, logger }) };
}

test('acknowledges a lifecycle delivery only after the revocation transaction resolves', async () => {
  const { allocator, metadata, worker } = fixture();
  let complete;
  allocator.offboard.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  const handling = worker.handleUserEvent({ userId: 'departed-user' }, metadata);
  expect(metadata.ack).not.toHaveBeenCalled();
  await Promise.resolve();
  complete({});
  await handling;
  expect(allocator.offboard).toHaveBeenCalledWith('departed-user', 'system:license-lifecycle', { systemActor: true });
  expect(metadata.ack).toHaveBeenCalledTimes(1);
});

test('a company-owned subject is rejected before legacy lifecycle offboarding', async () => {
  const { allocator, metadata, worker } = fixture();
  allocator.database.query.mockResolvedValue({ rows: [{ exists: true }] });
  await worker.handleUserEvent({ userId: 'owned-company-user' }, metadata);
  expect(allocator.database.query.mock.calls[0][0]).toContain('business_tenant_id IS NOT NULL');
  expect(allocator.offboard).not.toHaveBeenCalled();
  expect(metadata.ack).not.toHaveBeenCalled();
  expect(metadata.nack).toHaveBeenCalledWith(false);
});

test('missing subject ownership storage does not fall through to legacy offboarding', async () => {
  const { allocator, metadata, worker } = fixture();
  allocator.database.query.mockRejectedValue(new Error('Ownership storage unavailable'));
  await worker.handleUserEvent({ userId: 'owned-company-user' }, metadata);
  expect(allocator.offboard).not.toHaveBeenCalled();
  expect(metadata.ack).not.toHaveBeenCalled();
  expect(metadata.nack).toHaveBeenCalledWith(true);
});

test('requeues a transient storage failure without acknowledging success', async () => {
  const { allocator, metadata, worker } = fixture();
  allocator.offboard.mockRejectedValue(new Error('Database unavailable'));
  await worker.handleUserEvent({ userId: 'departed-user' }, metadata);
  expect(metadata.ack).not.toHaveBeenCalled();
  expect(metadata.nack).toHaveBeenCalledWith(true);
});

test('does not retry malformed lifecycle events indefinitely', async () => {
  const { allocator, metadata, worker } = fixture();
  await worker.handleUserEvent({ userId: {} }, metadata);
  expect(allocator.offboard).not.toHaveBeenCalled();
  expect(metadata.nack).toHaveBeenCalledWith(false);
});

test('does not overlap expiry sweeps while the previous transaction is pending', async () => {
  const { allocator, worker } = fixture();
  let complete;
  allocator.expireAll.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
  const first = worker.sweep();
  await worker.sweep();
  expect(allocator.expireAll).toHaveBeenCalledTimes(1);
  complete(0);
  await first;
  await worker.sweep();
  expect(allocator.expireAll).toHaveBeenCalledTimes(2);
});

test('group reconciliation requires an explicitly configured source credential', async () => {
  const { allocator, bus, logger } = fixture();
  const groups = { reconcileAll: jest.fn() };
  const worker = new LicenseLifecycleWorker({ allocator, bus, logger, groups });
  await worker.sweep();
  expect(groups.reconcileAll).not.toHaveBeenCalled();
  worker.groupAuthorization = 'Bearer narrow-source-reader';
  await worker.sweep();
  expect(groups.reconcileAll).toHaveBeenCalledWith('Bearer narrow-source-reader');
});

test('eligibility reconciliation requires its own narrow credential and precedes group grants', async () => {
  const { allocator, bus, logger } = fixture(); const order = [];
  const users = { reconcileAll: jest.fn(async () => { order.push('users'); }) };
  const groups = { reconcileAll: jest.fn(async () => { order.push('groups'); }) };
  const worker = new LicenseLifecycleWorker({ allocator, bus, logger, users, groups, groupAuthorization: 'Bearer groups-only' });
  await worker.sweep();
  expect(users.reconcileAll).not.toHaveBeenCalled();
  worker.userAuthorization = 'Bearer users-only'; order.length = 0;
  await worker.sweep();
  expect(users.reconcileAll).toHaveBeenCalledWith('Bearer users-only');
  expect(order).toEqual(['users', 'groups']);
});

test('slow initial reconciliation never delays lifecycle subscription or service startup', async () => {
  const { allocator, bus, worker } = fixture();
  let complete;
  allocator.expireAll.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
  try {
    await worker.start();
    expect(bus.subscribe).toHaveBeenCalledTimes(1);
    expect(worker.running).toBe(true);
    complete(0);
    await Promise.resolve();
  } finally { worker.stop(); }
});

test('registers deletion, completed and incomplete offboarding subscriptions and stops its timer', async () => {
  const { bus, worker } = fixture();
  try {
    await worker.start();
    expect(bus.subscribe).toHaveBeenCalledWith('policy.license.user-lifecycle', ['identity.user.deleted', 'user.offboarded', 'user.offboarding.incomplete'], expect.any(Function));
  } finally { worker.stop(); }
  expect(worker.timer).toBeNull();
});

test('retries local release after a partial offboarding event with the legacy publisher metadata', async () => {
  const { allocator, bus, metadata, worker } = fixture();
  try {
    await worker.start();
    const handler = bus.subscribe.mock.calls[0][2];
    await handler({ userId: 'departed-user', licensesReleased: false, _meta: { routingKey: 'user.offboarding.incomplete' } }, metadata);
    expect(allocator.offboard).toHaveBeenCalledWith('departed-user', 'system:license-lifecycle', { systemActor: true });
    expect(metadata.ack).toHaveBeenCalledTimes(1);
  } finally { worker.stop(); }
});
