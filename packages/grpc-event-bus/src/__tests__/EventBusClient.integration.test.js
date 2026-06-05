'use strict';
const EventBusClient = require('../EventBusClient');
const MemoryTransport = require('../transports/MemoryTransport');

// Each test gets its own shared bus so subscriptions are visible across clients.
// We use a counter to generate unique sharedKey per test.
let _busId = 0;
function makeClient(name) {
  // NOTE: sharedKey is set per-test via makeSharedClient; this factory is only
  // used in tests that do NOT need cross-client pub/sub.
  return new EventBusClient({ transport: 'memory', source: name });
}

function makeSharedClient(name, sharedKey) {
  return new EventBusClient({ transport: 'memory', source: name, shared: true, sharedKey });
}

// Helper: wait for async delivery (setImmediate inside MemoryTransport)
function waitFor(ms = 60) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Reset singleton between tests
beforeEach(() => {
  EventBusClient._instance = null;
  _busId += 1;
});

afterEach(() => {
  // Clean up shared buses created during this test
  MemoryTransport.resetShared(String(_busId));
});

// ─── Full pub/sub flow ────────────────────────────────────────────────────────

describe('EventBusClient integration (MemoryTransport)', () => {
  // 1. Single publisher, single subscriber
  test('single publisher, single subscriber receives event', async () => {
    const key        = String(_busId);
    const publisher  = makeSharedClient('device-service', key);
    const subscriber = makeSharedClient('compliance-service', key);

    await publisher.connect();
    await subscriber.connect();

    const received = [];
    await subscriber.subscribe('q.compliance', ['device.enrolled'], (payload) => {
      received.push(payload);
    });

    await publisher.publish('device.enrolled', { deviceId: 'dev-1' });
    await waitFor();

    expect(received).toHaveLength(1);
    expect(received[0].deviceId).toBe('dev-1');
  });

  // 2. Wildcard routing device.*
  test('device.* matches device.enrolled and device.seen but not policy.created', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('pub', key);
    const sub = makeSharedClient('sub', key);
    await pub.connect();
    await sub.connect();

    const received = [];
    await sub.subscribe('q.wildcard', ['device.*'], (payload, { routingKey }) => {
      received.push(routingKey);
    });

    await pub.publish('device.enrolled', {});
    await pub.publish('device.seen', {});
    await pub.publish('policy.created', {});
    await waitFor();

    expect(received).toContain('device.enrolled');
    expect(received).toContain('device.seen');
    expect(received).not.toContain('policy.created');
  });

  // 3. # wildcard
  test('security.# matches security.pim.granted and security.mfa.enabled', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('pub', key);
    const sub = makeSharedClient('sub', key);
    await pub.connect();
    await sub.connect();

    const received = [];
    await sub.subscribe('q.security-hash', ['security.#'], (payload, { routingKey }) => {
      received.push(routingKey);
    });

    await pub.publish('security.pim.granted', {});
    await pub.publish('security.mfa.enabled', {});
    await pub.publish('device.enrolled', {});
    await waitFor();

    expect(received).toContain('security.pim.granted');
    expect(received).toContain('security.mfa.enabled');
    expect(received).not.toContain('device.enrolled');
  });

  // 4. Multiple subscribers same queue — competing consumers
  test('competing consumers — at least one handler receives the message', async () => {
    const key  = String(_busId);
    const pub  = makeSharedClient('pub', key);
    const sub1 = makeSharedClient('sub1', key);
    const sub2 = makeSharedClient('sub2', key);
    await pub.connect();
    await sub1.connect();
    await sub2.connect();

    const received1 = [];
    const received2 = [];

    // Both subscribe to the SAME queue name — they both receive since MemoryTransport
    // fans out to all handlers registered on a queue (no round-robin exclusion at
    // transport level; competing consumer semantics are enforced at the application layer).
    await sub1.subscribe('q.competing', ['device.enrolled'], (payload) => received1.push(payload));
    await sub2.subscribe('q.competing', ['device.enrolled'], (payload) => received2.push(payload));

    await pub.publish('device.enrolled', { deviceId: 'dev-2' });
    await waitFor();

    const total = received1.length + received2.length;
    expect(total).toBeGreaterThanOrEqual(1);
  });

  // 5. Multiple queues same event — both queues receive it (fan-out)
  test('multiple queues same event — fan-out to all queues', async () => {
    const key  = String(_busId);
    const pub  = makeSharedClient('pub', key);
    const sub1 = makeSharedClient('sub1', key);
    const sub2 = makeSharedClient('sub2', key);
    await pub.connect();
    await sub1.connect();
    await sub2.connect();

    const received1 = [];
    const received2 = [];
    await sub1.subscribe('q.fanout-a', ['device.enrolled'], (payload) => received1.push(payload));
    await sub2.subscribe('q.fanout-b', ['device.enrolled'], (payload) => received2.push(payload));

    await pub.publish('device.enrolled', { deviceId: 'dev-3' });
    await waitFor();

    expect(received1).toHaveLength(1);
    expect(received2).toHaveLength(1);
  });

  // 6. Payload integrity
  test('published payload arrives unchanged at subscriber', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('pub', key);
    const sub = makeSharedClient('sub', key);
    await pub.connect();
    await sub.connect();

    const original = { deviceId: 'dev-42', tags: ['mac', 'managed'], nested: { x: 1 } };
    let received = null;
    await sub.subscribe('q.payload', ['device.enrolled'], (payload) => {
      received = payload;
    });

    await pub.publish('device.enrolled', original);
    await waitFor();

    expect(received.deviceId).toBe('dev-42');
    expect(received.tags).toEqual(['mac', 'managed']);
    expect(received.nested).toEqual({ x: 1 });
  });

  // 7. Source field — _source and _ts are injected
  test('_source and _ts are injected by EventBusClient', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('device-service', key);
    const sub = makeSharedClient('sub', key);
    await pub.connect();
    await sub.connect();

    let received = null;
    await sub.subscribe('q.meta', ['device.enrolled'], (payload) => {
      received = payload;
    });

    const before = Date.now();
    await pub.publish('device.enrolled', { deviceId: 'dev-5' });
    await waitFor();
    const after = Date.now();

    expect(received._source).toBe('device-service');
    expect(received._ts).toBeGreaterThanOrEqual(before);
    expect(received._ts).toBeLessThanOrEqual(after);
  });

  // 8. connect() is idempotent
  test('connect() called twice does not throw', async () => {
    const client = makeClient('idempotent');
    await expect(client.connect()).resolves.not.toThrow();
    await expect(client.connect()).resolves.not.toThrow();
    // isConnected is a method (returns boolean when called)
    expect(client.isConnected()).toBe(true);
  });

  // 9. publish() before connect() — should not throw (graceful no-op)
  test('publish() before connect() does not throw', async () => {
    const client = makeClient('early-publisher');
    await expect(client.publish('device.enrolled', { deviceId: 'x' })).resolves.not.toThrow();
  });

  // 10. close() — after close, publish to the same transport is a no-op
  test('after close(), a separate client on same shared bus still receives pre-close events', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('pub', key);
    const sub = makeSharedClient('sub', key);
    await pub.connect();
    await sub.connect();

    const received = [];
    await sub.subscribe('q.close-test', ['device.enrolled'], (payload) => received.push(payload));

    // Publish before close
    await pub.publish('device.enrolled', { deviceId: 'before-close' });
    await waitFor();
    expect(received).toHaveLength(1);

    // Close publisher — subsequent publishes from this transport instance are harmless
    await pub.close();
    // Even after close, publish does not throw
    await expect(pub.publish('device.enrolled', { deviceId: 'after-close' })).resolves.not.toThrow();
  });

  // 11. EventBusClient.create() static factory
  test('EventBusClient.create() connects and returns a client', async () => {
    const client = await EventBusClient.create({ transport: 'memory', source: 'factory-test' });
    expect(client).toBeInstanceOf(EventBusClient);
    expect(client.isConnected()).toBe(true);
    await client.close();
  });

  // 12. EventBusClient.getInstance() singleton
  test('EventBusClient.getInstance() returns the same instance twice', () => {
    const instance1 = EventBusClient.getInstance({ transport: 'memory', source: 'singleton' });
    const instance2 = EventBusClient.getInstance({ transport: 'memory', source: 'singleton' });
    expect(instance1).toBe(instance2);
  });
});

// ─── MemoryTransport wildcard matching directly ───────────────────────────────

describe('MemoryTransport wildcard matching', () => {
  let transport;

  beforeEach(() => {
    transport = new MemoryTransport();
  });

  test('device.* matches device.enrolled', () => {
    expect(transport._match('device.*', 'device.enrolled')).toBe(true);
  });

  test('device.* does NOT match device.compliance.check (only one segment)', () => {
    expect(transport._match('device.*', 'device.compliance.check')).toBe(false);
  });

  test('device.# matches device.compliance.check', () => {
    expect(transport._match('device.#', 'device.compliance.check')).toBe(true);
  });

  test('*.enrolled matches device.enrolled', () => {
    expect(transport._match('*.enrolled', 'device.enrolled')).toBe(true);
  });

  test('# matches everything', () => {
    expect(transport._match('#', 'device.enrolled')).toBe(true);
    expect(transport._match('#', 'security.pim.granted')).toBe(true);
    expect(transport._match('#', 'a.b.c.d.e')).toBe(true);
  });
});
