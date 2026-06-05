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
});
