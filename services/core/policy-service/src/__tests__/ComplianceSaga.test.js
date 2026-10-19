'use strict';

// Use fake timers to control setTimeout calls
jest.useFakeTimers();

const ComplianceSaga = require('../application/ComplianceSaga');

function makeBus(connected = true) {
  return {
    isConnected: jest.fn(() => connected),
    subscribe: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn(),
  };
}

function makeSvc() {
  return {
    evaluateCompliance: jest.fn().mockResolvedValue({ isCompliant: true, violations: [] }),
  };
}

function makeDb() {
  return {
    query: jest.fn().mockResolvedValue({ rows: [] }),
  };
}

describe('ComplianceSaga', () => {
  afterEach(() => {
    jest.clearAllTimers();
    jest.clearAllMocks();
  });

  describe('start()', () => {
    it('returns early when no messageBus', () => {
      const logger = { info: jest.fn(), warn: jest.fn() };
      const saga = new ComplianceSaga({ messageBus: null, policyApplicationService: makeSvc(), db: makeDb(), logger });
      saga.start();
      // no errors thrown
    });

    it('schedules subscriptions with setTimeout delay', () => {
      const bus = makeBus(true);
      const saga = new ComplianceSaga({
        messageBus: bus,
        policyApplicationService: makeSvc(),
        db: makeDb(),
        logger: { info: jest.fn(), warn: jest.fn() },
      });
      saga.start();
      // subscriptions are delayed by 3000ms, none called yet
      expect(bus.subscribe).not.toHaveBeenCalled();
    });

    it('subscribes to device.enrolled and policy.created/updated after timeout', async () => {
      const bus = makeBus(true);
      const saga = new ComplianceSaga({
        messageBus: bus,
        policyApplicationService: makeSvc(),
        db: makeDb(),
        logger: { info: jest.fn(), warn: jest.fn() },
      });
      saga.start();
      // advance all timers
      await jest.runAllTimersAsync();
      expect(bus.subscribe).toHaveBeenCalledTimes(2);
      const queueNames = bus.subscribe.mock.calls.map(c => c[0]);
      expect(queueNames).toContain('compliance.device-check');
      expect(queueNames).toContain('compliance.policy-change');
    });

    it('does not subscribe immediately when bus is not connected', async () => {
      const bus = makeBus(false); // not connected initially
      const saga = new ComplianceSaga({
        messageBus: bus,
        policyApplicationService: makeSvc(),
        db: makeDb(),
        logger: { info: jest.fn(), warn: jest.fn() },
      });
      saga.start();
      // Advance just past the initial 3s delay — the handler will see bus not connected
      // and schedule a 5s retry. We advance only enough to trigger the first attempt.
      await jest.advanceTimersByTimeAsync(3001);
      // Bus not connected, so subscribe should not be called yet
      expect(bus.subscribe).not.toHaveBeenCalled();
    });
  });

  describe('device enrolled handler', () => {
    it('calls evaluateCompliance when device.enrolled fires', async () => {
      const svc = makeSvc();
      const bus = makeBus(true);

      // Capture the handler passed to subscribe
      let enrolledHandler;
      bus.subscribe.mockImplementation(async (queueName, routingKeys, handler) => {
        if (queueName === 'compliance.device-check') {
          enrolledHandler = handler;
        }
      });

      const saga = new ComplianceSaga({
        messageBus: bus,
        policyApplicationService: svc,
        db: makeDb(),
        logger: { info: jest.fn(), warn: jest.fn() },
      });
      saga.start();
      await jest.runAllTimersAsync();

      expect(enrolledHandler).toBeDefined();
      await enrolledHandler({ deviceId: 'dev-1', platform: 'macos', properties: {} });

      expect(svc.evaluateCompliance).toHaveBeenCalledWith({
        deviceId: 'dev-1',
        devicePlatform: 'macos',
        deviceProperties: {},
      });
    });

    it('logs warning but does not throw when evaluateCompliance fails', async () => {
      const svc = makeSvc();
      svc.evaluateCompliance.mockRejectedValue(new Error('DB error'));
      const logger = { info: jest.fn(), warn: jest.fn() };
      const bus = makeBus(true);

      let enrolledHandler;
      bus.subscribe.mockImplementation(async (queueName, routingKeys, handler) => {
        if (queueName === 'compliance.device-check') enrolledHandler = handler;
      });

      const saga = new ComplianceSaga({ messageBus: bus, policyApplicationService: svc, db: makeDb(), logger });
      saga.start();
      await jest.runAllTimersAsync();

      await expect(enrolledHandler({ deviceId: 'dev-1', platform: 'macos' })).resolves.toBeUndefined();
      expect(logger.warn).toHaveBeenCalled();
    });
  });

  describe('policy change handler', () => {
    // NOTE: as of commit 22619c6 ("fix: resolve critical database isolation
    // violations across 3 services"), the policy-change handler no longer
    // queries the devices table directly (cross-service DB access) — it calls
    // device-service over HTTP via the Node 18 built-in fetch(), falling back
    // to the event payload's deviceId if the call fails. These tests mock
    // global.fetch instead of db.query to match that behaviour.
    const originalFetch = global.fetch;

    afterEach(() => {
      global.fetch = originalFetch;
    });

    it('publishes recheck events for each active device', async () => {
      const bus = makeBus(true);
      const db = makeDb();
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({
          devices: [{ id: 'dev-1', platform: 'windows' }, { id: 'dev-2', platform: 'macos' }],
        }),
      });

      let policyChangeHandler;
      bus.subscribe.mockImplementation(async (queueName, routingKeys, handler) => {
        if (queueName === 'compliance.policy-change') policyChangeHandler = handler;
      });

      const saga = new ComplianceSaga({
        messageBus: bus,
        policyApplicationService: makeSvc(),
        db,
        logger: { info: jest.fn(), warn: jest.fn() },
      });
      saga.start();
      await jest.runAllTimersAsync();

      await policyChangeHandler({ policyId: 'pol-1' });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/devices?status=active&limit=1000'),
        expect.any(Object)
      );
      expect(bus.publish).toHaveBeenCalledTimes(2);
      expect(bus.publish).toHaveBeenCalledWith('device.compliance.recheck', expect.objectContaining({ deviceId: 'dev-1' }));
      expect(bus.publish).toHaveBeenCalledWith('device.compliance.recheck', expect.objectContaining({ deviceId: 'dev-2' }));
    });

    it('logs warning and falls back to the event payload when device-service is unreachable', async () => {
      const bus = makeBus(true);
      const db = makeDb();
      global.fetch = jest.fn().mockRejectedValue(new Error('device-service unreachable'));
      const logger = { info: jest.fn(), warn: jest.fn() };

      let policyChangeHandler;
      bus.subscribe.mockImplementation(async (queueName, routingKeys, handler) => {
        if (queueName === 'compliance.policy-change') policyChangeHandler = handler;
      });

      const saga = new ComplianceSaga({ messageBus: bus, policyApplicationService: makeSvc(), db, logger });
      saga.start();
      await jest.runAllTimersAsync();

      // No deviceId on the payload → fallback list stays empty → no publish, no throw.
      await expect(policyChangeHandler({ policyId: 'pol-1' })).resolves.toBeUndefined();
      expect(logger.warn).toHaveBeenCalled();
      expect(bus.publish).not.toHaveBeenCalled();
    });

    it('falls back to the event payload deviceId when device-service is unreachable', async () => {
      const bus = makeBus(true);
      const db = makeDb();
      global.fetch = jest.fn().mockRejectedValue(new Error('device-service unreachable'));
      const logger = { info: jest.fn(), warn: jest.fn() };

      let policyChangeHandler;
      bus.subscribe.mockImplementation(async (queueName, routingKeys, handler) => {
        if (queueName === 'compliance.policy-change') policyChangeHandler = handler;
      });

      const saga = new ComplianceSaga({ messageBus: bus, policyApplicationService: makeSvc(), db, logger });
      saga.start();
      await jest.runAllTimersAsync();

      await policyChangeHandler({ policyId: 'pol-1', deviceId: 'dev-fallback', platform: 'linux' });

      expect(logger.warn).toHaveBeenCalled();
      expect(bus.publish).toHaveBeenCalledTimes(1);
      expect(bus.publish).toHaveBeenCalledWith('device.compliance.recheck', expect.objectContaining({ deviceId: 'dev-fallback' }));
    });
  });
});
