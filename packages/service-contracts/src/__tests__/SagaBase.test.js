'use strict';

jest.useFakeTimers();

const SagaBase = require('../sagas/SagaBase');

function makeBus(connected = true) {
  return {
    isConnected: jest.fn(() => connected),
    subscribe: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn(),
  };
}

describe('SagaBase', () => {
  afterEach(() => {
    jest.clearAllTimers();
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('initialises with messageBus and logger', () => {
      const bus = makeBus();
      const logger = { info: jest.fn(), warn: jest.fn() };
      const saga = new SagaBase(bus, logger);
      expect(saga._bus).toBe(bus);
      expect(saga._log).toBe(logger);
    });

    it('uses console as default logger', () => {
      const saga = new SagaBase(makeBus());
      expect(saga._log).toBe(console);
    });
  });

  describe('on()', () => {
    it('registers a handler and returns this for chaining', () => {
      const saga = new SagaBase(makeBus());
      const handler = jest.fn();
      const result = saga.on('some.event', handler);
      expect(result).toBe(saga);
      expect(saga._handlers.get('some.event')).toBe(handler);
    });

    it('overwrites a handler for the same routing key', () => {
      const saga = new SagaBase(makeBus());
      const h1 = jest.fn();
      const h2 = jest.fn();
      saga.on('key', h1).on('key', h2);
      expect(saga._handlers.get('key')).toBe(h2);
    });
  });

  describe('start()', () => {
    it('logs warning and returns when no bus', async () => {
      const logger = { warn: jest.fn(), info: jest.fn() };
      const saga = new SagaBase(null, logger);
      await saga.start('queue', ['key']);
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('No message bus'));
    });

    it('schedules subscription with 3s delay', async () => {
      const bus = makeBus(true);
      const saga = new SagaBase(bus);
      saga.start('my-queue', ['event.one']);
      expect(bus.subscribe).not.toHaveBeenCalled();
    });

    it('subscribes after 3s when bus is connected', async () => {
      const bus = makeBus(true);
      const logger = { info: jest.fn(), warn: jest.fn() };
      const saga = new SagaBase(bus, logger);
      saga.start('my-queue', ['event.one']);
      await jest.runAllTimersAsync();
      expect(bus.subscribe).toHaveBeenCalledWith('my-queue', ['event.one'], expect.any(Function));
      expect(logger.info).toHaveBeenCalledWith(expect.stringContaining("started on queue 'my-queue'"));
    });

    it('does not subscribe when bus is not connected (first attempt)', async () => {
      const bus = makeBus(false);
      const saga = new SagaBase(bus);
      saga.start('my-queue', ['e']);
      // Advance only past the initial 3s delay to trigger the first try
      await jest.advanceTimersByTimeAsync(3001);
      expect(bus.subscribe).not.toHaveBeenCalled();
    });

    it('retries after 5s when subscribe throws', async () => {
      const bus = makeBus(true);
      bus.subscribe.mockRejectedValueOnce(new Error('connection error'));
      const logger = { info: jest.fn(), warn: jest.fn() };
      const saga = new SagaBase(bus, logger);
      saga.start('my-queue', ['e']);
      await jest.runAllTimersAsync();
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('subscribe error'));
    });

    it('dispatches payload to registered handler', async () => {
      const bus = makeBus(true);
      let capturedHandler;
      bus.subscribe.mockImplementation(async (q, keys, handler) => { capturedHandler = handler; });

      const saga = new SagaBase(bus);
      const mockHandler = jest.fn().mockResolvedValue(undefined);
      saga.on('test.event', mockHandler);
      saga.start('my-queue', ['test.event']);
      await jest.runAllTimersAsync();

      const rawMsg = { fields: { routingKey: 'test.event' } };
      await capturedHandler({ data: 1 }, rawMsg);
      expect(mockHandler).toHaveBeenCalledWith({ data: 1 });
    });

    it('handler error is propagated (causes NACK)', async () => {
      const bus = makeBus(true);
      let capturedHandler;
      bus.subscribe.mockImplementation(async (q, keys, handler) => { capturedHandler = handler; });

      const saga = new SagaBase(bus, { warn: jest.fn(), info: jest.fn() });
      saga.on('fail.event', jest.fn().mockRejectedValue(new Error('handler boom')));
      saga.start('my-queue', ['fail.event']);
      await jest.runAllTimersAsync();

      const rawMsg = { fields: { routingKey: 'fail.event' } };
      await expect(capturedHandler({}, rawMsg)).rejects.toThrow('handler boom');
    });

    it('ignores messages with no matching handler', async () => {
      const bus = makeBus(true);
      let capturedHandler;
      bus.subscribe.mockImplementation(async (q, keys, handler) => { capturedHandler = handler; });

      const saga = new SagaBase(bus);
      saga.start('my-queue', ['known.event']);
      await jest.runAllTimersAsync();

      const rawMsg = { fields: { routingKey: 'unknown.event' } };
      await expect(capturedHandler({}, rawMsg)).resolves.toBeUndefined();
    });
  });

  describe('publish()', () => {
    it('returns false when bus is not connected', () => {
      const bus = makeBus(false);
      const saga = new SagaBase(bus);
      expect(saga.publish('key', { data: 1 })).toBe(false);
    });

    it('publishes with _saga metadata and returns result', () => {
      const bus = makeBus(true);
      bus.publish.mockReturnValue(true);
      const saga = new SagaBase(bus);
      const result = saga.publish('my.event', { data: 'value' });
      expect(result).toBe(true);
      expect(bus.publish).toHaveBeenCalledWith('my.event', expect.objectContaining({
        data: 'value',
        _saga: 'SagaBase',
      }));
    });

    it('returns false when bus.publish throws', () => {
      const bus = makeBus(true);
      bus.publish.mockImplementation(() => { throw new Error('publish error'); });
      const saga = new SagaBase(bus, { warn: jest.fn() });
      expect(saga.publish('key', {})).toBe(false);
    });

    it('returns false when no bus', () => {
      const saga = new SagaBase(null);
      expect(saga.publish('key', {})).toBe(false);
    });
  });

  // ─── Max retries exhausted ──────────────────────────────────────────────────

  describe('retry behaviour', () => {
    it('keeps retrying on repeated subscribe errors and logs each attempt', async () => {
      const bus = makeBus(true);
      // Fail twice, succeed on third attempt
      bus.subscribe
        .mockRejectedValueOnce(new Error('err1'))
        .mockRejectedValueOnce(new Error('err2'))
        .mockResolvedValue(undefined);

      const logger = { info: jest.fn(), warn: jest.fn() };
      const saga = new SagaBase(bus, logger);
      saga.start('q', ['e']);

      // Advance timers: 3 s initial + 5 s retry + 5 s retry = 13 s total
      await jest.advanceTimersByTimeAsync(3001);  // first attempt — fails
      await jest.advanceTimersByTimeAsync(5001);  // second attempt — fails
      await jest.advanceTimersByTimeAsync(5001);  // third attempt — succeeds

      // subscribe() should have been called 3 times
      expect(bus.subscribe).toHaveBeenCalledTimes(3);
      // warn should have been called for each failure
      expect(logger.warn).toHaveBeenCalledTimes(2);
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('subscribe error'));
    });

    it('retry count never goes below zero — warn log count equals number of failures', async () => {
      const bus = makeBus(true);
      // Fail 3 times; SagaBase has no max-retry cap — it keeps retrying indefinitely
      bus.subscribe
        .mockRejectedValueOnce(new Error('fail-1'))
        .mockRejectedValueOnce(new Error('fail-2'))
        .mockRejectedValueOnce(new Error('fail-3'))
        .mockResolvedValue(undefined);

      const logger = { info: jest.fn(), warn: jest.fn() };
      const saga = new SagaBase(bus, logger);
      saga.start('q', ['e']);

      // Drive through all retries
      await jest.advanceTimersByTimeAsync(3001);
      await jest.advanceTimersByTimeAsync(5001);
      await jest.advanceTimersByTimeAsync(5001);
      await jest.advanceTimersByTimeAsync(5001);

      // Exactly 3 warn calls — one per failure, not an inflated negative counter
      expect(logger.warn).toHaveBeenCalledTimes(3);
      expect(bus.subscribe).toHaveBeenCalledTimes(4);
    });

    it('retry delay is 5 s — retry fires after the initial attempt plus 5000 ms', async () => {
      const bus = makeBus(true);
      bus.subscribe
        .mockRejectedValueOnce(new Error('delay-test'))
        .mockResolvedValue(undefined);

      const logger = { info: jest.fn(), warn: jest.fn() };
      const saga = new SagaBase(bus, logger);
      saga.start('q', ['e']);

      // Advance past the initial 3 s delay so the first attempt fires and fails
      await jest.advanceTimersByTimeAsync(3001);
      expect(bus.subscribe).toHaveBeenCalledTimes(1);

      // Advance well short of the 5 s retry window — retry must NOT have fired
      await jest.advanceTimersByTimeAsync(2000);
      expect(bus.subscribe).toHaveBeenCalledTimes(1);

      // Advance past the remaining retry delay — retry fires
      await jest.advanceTimersByTimeAsync(3001);
      expect(bus.subscribe).toHaveBeenCalledTimes(2);
    });
  });

  // ─── Concurrent saga instances ──────────────────────────────────────────────

  describe('concurrent saga instances', () => {
    it('events on saga A do not trigger saga B handlers', async () => {
      const busA = makeBus(true);
      const busB = makeBus(true);

      let capturedHandlerA;
      let capturedHandlerB;
      busA.subscribe.mockImplementation(async (q, keys, handler) => { capturedHandlerA = handler; });
      busB.subscribe.mockImplementation(async (q, keys, handler) => { capturedHandlerB = handler; });

      const handlerA = jest.fn().mockResolvedValue(undefined);
      const handlerB = jest.fn().mockResolvedValue(undefined);

      const sagaA = new SagaBase(busA);
      const sagaB = new SagaBase(busB);

      sagaA.on('some.event', handlerA);
      sagaB.on('some.event', handlerB);

      sagaA.start('q-a', ['some.event']);
      sagaB.start('q-b', ['some.event']);

      await jest.runAllTimersAsync();

      // Trigger saga A's internal handler only
      const rawMsg = { fields: { routingKey: 'some.event' } };
      await capturedHandlerA({ data: 'a-only' }, rawMsg);

      expect(handlerA).toHaveBeenCalledTimes(1);
      expect(handlerA).toHaveBeenCalledWith({ data: 'a-only' });
      // Saga B's handler must NOT have been invoked
      expect(handlerB).not.toHaveBeenCalled();
    });

    it('two saga instances maintain independent handler registries', () => {
      const sagaA = new SagaBase(makeBus());
      const sagaB = new SagaBase(makeBus());

      const hA = jest.fn();
      const hB = jest.fn();

      sagaA.on('x.event', hA);
      sagaB.on('x.event', hB);

      expect(sagaA._handlers.get('x.event')).toBe(hA);
      expect(sagaB._handlers.get('x.event')).toBe(hB);
      // Registries are separate objects
      expect(sagaA._handlers).not.toBe(sagaB._handlers);
    });
  });

  // ─── Bus not-connected retry loop ───────────────────────────────────────────

  describe('start() bus not connected — retry loop', () => {
    it('keeps polling at 5 s intervals until bus becomes connected', async () => {
      // Bus starts disconnected; becomes connected after the second poll
      let callCount = 0;
      const bus = {
        isConnected: jest.fn(() => {
          callCount += 1;
          return callCount >= 3; // connected starting from 3rd call
        }),
        subscribe: jest.fn().mockResolvedValue(undefined),
        publish: jest.fn(),
      };

      const logger = { info: jest.fn(), warn: jest.fn() };
      const saga = new SagaBase(bus, logger);
      saga.start('q', ['e']);

      // First poll (3 s delay) — not connected
      await jest.advanceTimersByTimeAsync(3001);
      expect(bus.subscribe).not.toHaveBeenCalled();

      // Second poll (5 s later) — not connected
      await jest.advanceTimersByTimeAsync(5001);
      expect(bus.subscribe).not.toHaveBeenCalled();

      // Third poll (5 s later) — now connected
      await jest.advanceTimersByTimeAsync(5001);
      expect(bus.subscribe).toHaveBeenCalledTimes(1);
    });
  });
});
