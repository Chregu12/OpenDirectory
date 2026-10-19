'use strict';

// Mock amqplib so tests don't require a real RabbitMQ connection
jest.mock('amqplib', () => {
  const mockChannel = {
    assertExchange: jest.fn().mockResolvedValue({}),
    assertQueue: jest.fn().mockResolvedValue({}),
    bindQueue: jest.fn().mockResolvedValue({}),
    publish: jest.fn().mockReturnValue(true),
    prefetch: jest.fn(),
    consume: jest.fn().mockResolvedValue({ consumerTag: 'tag-1' }),
    checkQueue: jest.fn().mockResolvedValue({ messageCount: 0 }),
    close: jest.fn().mockResolvedValue({}),
    on: jest.fn(),
  };
  const mockConnection = {
    createChannel: jest.fn().mockResolvedValue(mockChannel),
    close: jest.fn().mockResolvedValue({}),
    on: jest.fn(),
  };
  return {
    connect: jest.fn().mockResolvedValue(mockConnection),
    _mockChannel: mockChannel,
    _mockConnection: mockConnection,
  };
});

const amqplib = require('amqplib');
const MessageBus = require('../messageBus');

// Reset singleton between tests
beforeEach(() => {
  MessageBus._instance = null;
  jest.clearAllMocks();
  // Reset mock channel state
  amqplib._mockChannel.assertExchange.mockResolvedValue({});
  amqplib._mockChannel.assertQueue.mockResolvedValue({});
  amqplib._mockChannel.bindQueue.mockResolvedValue({});
  amqplib._mockChannel.publish.mockReturnValue(true);
  amqplib._mockChannel.prefetch.mockReturnValue(undefined);
  amqplib._mockChannel.consume.mockResolvedValue({ consumerTag: 'tag-1' });
  amqplib.connect.mockResolvedValue(amqplib._mockConnection);
  amqplib._mockConnection.createChannel.mockResolvedValue(amqplib._mockChannel);
});

describe('MessageBus', () => {
  describe('constructor', () => {
    it('starts in disconnected state', () => {
      const bus = new MessageBus();
      expect(bus.isConnected()).toBe(false);
    });
  });

  describe('getInstance()', () => {
    it('returns the same instance each time', () => {
      const a = MessageBus.getInstance();
      const b = MessageBus.getInstance();
      expect(a).toBe(b);
    });
  });

  describe('connect()', () => {
    it('connects and sets isConnected to true', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      expect(bus.isConnected()).toBe(true);
      expect(amqplib.connect).toHaveBeenCalledWith('amqp://localhost');
    });

    it('is idempotent — does not reconnect if already connected', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      await bus.connect('amqp://localhost');
      expect(amqplib.connect).toHaveBeenCalledTimes(1);
    });

    it('asserts both exchanges on connect', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      expect(amqplib._mockChannel.assertExchange).toHaveBeenCalledWith('opendirectory.events', 'topic', { durable: true });
      expect(amqplib._mockChannel.assertExchange).toHaveBeenCalledWith('od.device.commands', 'direct', { durable: true });
    });
  });

  describe('isConnected()', () => {
    it('returns false before connecting', () => {
      const bus = new MessageBus();
      expect(bus.isConnected()).toBe(false);
    });

    it('returns true after connecting', async () => {
      const bus = new MessageBus();
      await bus.connect();
      expect(bus.isConnected()).toBe(true);
    });
  });

  describe('publish()', () => {
    it('returns false when not connected', () => {
      const bus = new MessageBus();
      const result = bus.publish('test.event', { data: 1 });
      expect(result).toBe(false);
    });

    it('publishes to the events exchange when connected', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      const result = bus.publish('device.enrolled', { deviceId: 'd1' });
      expect(result).toBe(true);
      expect(amqplib._mockChannel.publish).toHaveBeenCalledWith(
        'opendirectory.events',
        'device.enrolled',
        expect.any(Buffer),
        expect.objectContaining({ persistent: true, contentType: 'application/json' })
      );
    });

    it('includes _meta with routingKey and ts in the message', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      bus.publish('test.event', { key: 'value' });
      const publishCall = amqplib._mockChannel.publish.mock.calls[0];
      const content = JSON.parse(publishCall[2].toString());
      expect(content._meta.routingKey).toBe('test.event');
      expect(content._meta.ts).toBeTruthy();
      expect(content.key).toBe('value');
    });

    it('returns false when channel.publish throws', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      amqplib._mockChannel.publish.mockImplementation(() => { throw new Error('channel error'); });
      const result = bus.publish('test', {});
      expect(result).toBe(false);
    });
  });

  describe('subscribe()', () => {
    it('does not throw when not connected (defers binding)', async () => {
      const bus = new MessageBus();
      await expect(bus.subscribe('my-queue', ['event.#'], jest.fn())).resolves.toBeUndefined();
    });

    it('asserts queue and binds routing keys when connected', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      await bus.subscribe('my-queue', ['device.enrolled', 'device.seen'], jest.fn());
      expect(amqplib._mockChannel.assertQueue).toHaveBeenCalledWith('my-queue', expect.any(Object));
      expect(amqplib._mockChannel.bindQueue).toHaveBeenCalledWith('my-queue', 'opendirectory.events', 'device.enrolled');
      expect(amqplib._mockChannel.bindQueue).toHaveBeenCalledWith('my-queue', 'opendirectory.events', 'device.seen');
    });

    it('registers subscription for re-bind after reconnect', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      await bus.subscribe('q1', ['e'], jest.fn());
      expect(bus._subscriptions).toHaveLength(1);
      expect(bus._subscriptions[0].queueName).toBe('q1');
    });

    it('does not duplicate subscriptions for the same queue name', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      const handler = jest.fn();
      await bus.subscribe('q1', ['e1'], handler);
      await bus.subscribe('q1', ['e2'], handler); // same queue name
      expect(bus._subscriptions).toHaveLength(1);
    });
  });

  describe('getQueueDepth()', () => {
    it('returns null when not connected', async () => {
      const bus = new MessageBus();
      const result = await bus.getQueueDepth('my-queue');
      expect(result).toBeNull();
    });

    it('returns message count when connected', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      amqplib._mockChannel.checkQueue.mockResolvedValue({ messageCount: 42 });
      const result = await bus.getQueueDepth('my-queue');
      expect(result).toBe(42);
    });
  });

  describe('queueDeviceCommand()', () => {
    it('returns false when not connected', async () => {
      const bus = new MessageBus();
      const result = await bus.queueDeviceCommand('device-1', { type: 'install' });
      expect(result).toBe(false);
    });

    it('queues a command when connected', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      const result = await bus.queueDeviceCommand('device-1', { type: 'install', appId: 'x' });
      expect(result).toBe(true);
      expect(amqplib._mockChannel.publish).toHaveBeenCalledWith(
        'od.device.commands',
        'device-1',
        expect.any(Buffer),
        expect.any(Object)
      );
    });
  });

  describe('close()', () => {
    it('closes channel and connection gracefully', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      await bus.close();
      expect(amqplib._mockChannel.close).toHaveBeenCalled();
      expect(amqplib._mockConnection.close).toHaveBeenCalled();
      expect(bus.isConnected()).toBe(false);
    });

    it('can be called multiple times without errors', async () => {
      const bus = new MessageBus();
      await bus.connect('amqp://localhost');
      await bus.close();
      await expect(bus.close()).resolves.toBeUndefined();
    });
  });
});
