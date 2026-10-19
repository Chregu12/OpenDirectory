'use strict';
/**
 * EventBusSagaFlow.integration.test.js
 *
 * End-to-end saga flow tests using MemoryTransport in shared mode.
 * All clients that need to communicate share the same underlying handler map
 * (simulating a real message broker).
 *
 * Sagas are inlined to avoid the 3-second startup delay in SagaBase.start().
 */

const EventBusClient  = require('../EventBusClient');
const MemoryTransport = require('../transports/MemoryTransport');

let _busId = 0;

function makeSharedClient(name, sharedKey) {
  return new EventBusClient({ transport: 'memory', source: name, shared: true, sharedKey });
}

function waitFor(ms = 80) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

beforeEach(() => {
  _busId += 1;
});

afterEach(() => {
  MemoryTransport.resetShared(String(_busId));
});

// ─── Flow 1: device.enrolled → compliance recheck → monitoring ───────────────
//
// device-service  publishes  device.enrolled
//   → ComplianceSaga subscribes and publishes device.compliance.recheck
//   → monitoring-service subscribes to device.compliance.recheck and stores it

describe('Saga flow: device.enrolled → compliance recheck → monitoring', () => {
  let deviceService;
  let complianceSaga;
  let monitoringService;
  let key;

  beforeEach(async () => {
    key               = String(_busId);
    deviceService     = makeSharedClient('device-service',    key);
    complianceSaga    = makeSharedClient('compliance-saga',   key);
    monitoringService = makeSharedClient('monitoring-service', key);

    await deviceService.connect();
    await complianceSaga.connect();
    await monitoringService.connect();
  });

  afterEach(async () => {
    await deviceService.close();
    await complianceSaga.close();
    await monitoringService.close();
  });

  test('device.enrolled triggers compliance recheck which is received by monitoring', async () => {
    const monitoringStore = [];

    // monitoring-service subscribes to device.compliance.recheck
    await monitoringService.subscribe(
      'q.monitoring.compliance',
      ['device.compliance.recheck'],
      (payload) => { monitoringStore.push(payload); },
    );

    // ComplianceSaga subscribes to device.enrolled, then publishes device.compliance.recheck
    await complianceSaga.subscribe(
      'q.saga.compliance',
      ['device.enrolled'],
      async (payload) => {
        await complianceSaga.publish('device.compliance.recheck', {
          deviceId:    payload.deviceId,
          reason:      'enrollment_trigger',
          triggeredBy: payload._source,
        });
      },
    );

    // device-service fires the initial event
    await deviceService.publish('device.enrolled', { deviceId: 'dev-100', platform: 'macOS' });

    // Two async hops: enrolled → recheck (setImmediate) → monitoring (setImmediate)
    await waitFor(120);

    expect(monitoringStore).toHaveLength(1);
    expect(monitoringStore[0].deviceId).toBe('dev-100');
    expect(monitoringStore[0].reason).toBe('enrollment_trigger');
    expect(monitoringStore[0].triggeredBy).toBe('device-service');
  });

  test('monitoring receives _source and _ts on recheck event', async () => {
    let received = null;

    await monitoringService.subscribe(
      'q.monitoring.meta',
      ['device.compliance.recheck'],
      (payload) => { received = payload; },
    );

    await complianceSaga.subscribe(
      'q.saga.compliance-meta',
      ['device.enrolled'],
      async (payload) => {
        await complianceSaga.publish('device.compliance.recheck', {
          deviceId: payload.deviceId,
        });
      },
    );

    const before = Date.now();
    await deviceService.publish('device.enrolled', { deviceId: 'dev-101' });
    await waitFor(120);
    const after = Date.now();

    expect(received).not.toBeNull();
    expect(received._source).toBe('compliance-saga');
    expect(received._ts).toBeGreaterThanOrEqual(before);
    expect(received._ts).toBeLessThanOrEqual(after + 10);
  });

  test('unrelated event (policy.created) does not reach compliance saga', async () => {
    const sagaReceived = [];

    await complianceSaga.subscribe(
      'q.saga.compliance-filter',
      ['device.enrolled'],
      (payload) => sagaReceived.push(payload),
    );

    await deviceService.publish('policy.created', { policyId: 'pol-1' });
    await waitFor();

    expect(sagaReceived).toHaveLength(0);
  });

  test('wildcard device.* in compliance saga catches multiple enrollment types', async () => {
    const sagaReceived = [];

    await complianceSaga.subscribe(
      'q.saga.compliance-wildcard',
      ['device.*'],
      (payload, { routingKey }) => sagaReceived.push(routingKey),
    );

    await deviceService.publish('device.enrolled', { deviceId: 'dev-200' });
    await deviceService.publish('device.seen',     { deviceId: 'dev-201' });
    await deviceService.publish('policy.created',  { policyId: 'pol-1'  });
    await waitFor();

    expect(sagaReceived).toContain('device.enrolled');
    expect(sagaReceived).toContain('device.seen');
    expect(sagaReceived).not.toContain('policy.created');
  });
});

// ─── Flow 2: identity.user.created → license.assign → notification ────────────
//
// auth-service     publishes  identity.user.created
//   → UserOnboardingSaga subscribes and publishes license.assign.requested
//   → notification-service receives notification.send

describe('Saga flow: identity.user.created → license assign → notification', () => {
  let authService;
  let onboardingSaga;
  let licenseStore;
  let notificationStore;
  let licenseService;
  let notificationService;
  let key;

  beforeEach(async () => {
    key                  = String(_busId);
    authService          = makeSharedClient('auth-service',          key);
    onboardingSaga       = makeSharedClient('user-onboarding-saga',  key);
    licenseService       = makeSharedClient('license-service',       key);
    notificationService  = makeSharedClient('notification-service',  key);
    licenseStore         = [];
    notificationStore    = [];

    await authService.connect();
    await onboardingSaga.connect();
    await licenseService.connect();
    await notificationService.connect();
  });

  afterEach(async () => {
    await authService.close();
    await onboardingSaga.close();
    await licenseService.close();
    await notificationService.close();
  });

  test('identity.user.created triggers license.assign.requested and notification.send', async () => {
    // license-service listens for license.assign.requested
    await licenseService.subscribe(
      'q.license.assign',
      ['license.assign.requested'],
      (payload) => licenseStore.push(payload),
    );

    // notification-service listens for notification.send
    await notificationService.subscribe(
      'q.notifications',
      ['notification.send'],
      (payload) => notificationStore.push(payload),
    );

    // Inline UserOnboardingSaga logic — mirrors UserOnboardingSaga._onUserCreated
    await onboardingSaga.subscribe(
      'q.saga.user-onboarding',
      ['identity.user.created'],
      async (payload) => {
        const { userId, username, email } = payload;

        await onboardingSaga.publish('license.assign.requested', {
          userId,
          username,
          licenseType: 'default',
          reason:      'new_user_onboarding',
        });

        await onboardingSaga.publish('notification.send', {
          channel:   'email',
          recipient: email || username,
          level:     'info',
          title:     'Willkommen bei OpenDirectory',
          message:   `Ihr Konto (${username}) wurde erfolgreich erstellt.`,
          userId,
        });
      },
    );

    // auth-service fires the initial event
    await authService.publish('identity.user.created', {
      userId:   'user-42',
      username: 'jdoe',
      email:    'jdoe@example.com',
      roles:    ['user'],
    });

    await waitFor(120);

    // license.assign.requested was published
    expect(licenseStore).toHaveLength(1);
    expect(licenseStore[0].userId).toBe('user-42');
    expect(licenseStore[0].licenseType).toBe('default');
    expect(licenseStore[0].reason).toBe('new_user_onboarding');

    // notification.send was published
    expect(notificationStore).toHaveLength(1);
    expect(notificationStore[0].recipient).toBe('jdoe@example.com');
    expect(notificationStore[0].channel).toBe('email');
    expect(notificationStore[0].userId).toBe('user-42');
  });

  test('identity.user.deleted triggers license revoke and admin notification', async () => {
    await licenseService.subscribe(
      'q.license.revoke',
      ['license.revoke.requested'],
      (payload) => licenseStore.push(payload),
    );

    await notificationService.subscribe(
      'q.notifications.delete',
      ['notification.send'],
      (payload) => notificationStore.push(payload),
    );

    // Inline UserOnboardingSaga._onUserDeleted
    await onboardingSaga.subscribe(
      'q.saga.user-onboarding-delete',
      ['identity.user.deleted'],
      async (payload) => {
        const { userId, username } = payload;

        await onboardingSaga.publish('license.revoke.requested', {
          userId,
          reason: 'user_deleted',
        });

        await onboardingSaga.publish('notification.send', {
          channel: 'admin',
          level:   'warning',
          title:   'Benutzer gelöscht',
          message: `Benutzer ${username} (${userId}) wurde entfernt.`,
          userId,
        });
      },
    );

    await authService.publish('identity.user.deleted', {
      userId:   'user-99',
      username: 'msmith',
    });

    await waitFor(120);

    expect(licenseStore).toHaveLength(1);
    expect(licenseStore[0].userId).toBe('user-99');
    expect(licenseStore[0].reason).toBe('user_deleted');

    expect(notificationStore).toHaveLength(1);
    expect(notificationStore[0].channel).toBe('admin');
    expect(notificationStore[0].level).toBe('warning');
  });

  test('saga does not process unrelated events from a different topic', async () => {
    const sagaReceived = [];

    await onboardingSaga.subscribe(
      'q.saga.unrelated-filter',
      ['identity.user.created'],
      (payload) => sagaReceived.push(payload),
    );

    await authService.publish('device.enrolled', { deviceId: 'dev-x' });
    await waitFor();

    expect(sagaReceived).toHaveLength(0);
  });

  test('multiple users created — each triggers independent saga steps', async () => {
    await licenseService.subscribe(
      'q.license.multi',
      ['license.assign.requested'],
      (payload) => licenseStore.push(payload),
    );

    await onboardingSaga.subscribe(
      'q.saga.multi-user',
      ['identity.user.created'],
      async (payload) => {
        await onboardingSaga.publish('license.assign.requested', {
          userId:      payload.userId,
          licenseType: 'default',
        });
      },
    );

    await authService.publish('identity.user.created', { userId: 'u1', username: 'alice', email: 'a@x.com' });
    await authService.publish('identity.user.created', { userId: 'u2', username: 'bob',   email: 'b@x.com' });
    await authService.publish('identity.user.created', { userId: 'u3', username: 'carol', email: 'c@x.com' });

    await waitFor(150);

    expect(licenseStore).toHaveLength(3);
    const userIds = licenseStore.map((p) => p.userId).sort();
    expect(userIds).toEqual(['u1', 'u2', 'u3']);
  });
});
