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

// ─── Error handling and edge cases ───────────────────────────────────────────

describe('Error handling and edge cases', () => {
  // 1. publish before connect()
  test('publish() before connect() does not throw (fire-and-forget)', async () => {
    const client = makeClient('pre-connect-publisher');
    // No connect() call — should not throw
    await expect(
      client.publish('device.enrolled', { deviceId: 'pre-connect' })
    ).resolves.not.toThrow();
  });

  // 2. close() then publish()
  test('publish() after close() does not throw (graceful no-op)', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('pub-close', key);
    await pub.connect();
    await pub.close();
    await expect(
      pub.publish('device.enrolled', { deviceId: 'post-close' })
    ).resolves.not.toThrow();
  });

  // 3. subscribe with empty patterns array
  test('subscribe with empty patterns array does not throw and delivers no messages', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('pub-empty', key);
    const sub = makeSharedClient('sub-empty', key);
    await pub.connect();
    await sub.connect();

    const received = [];
    await expect(
      sub.subscribe('q.empty-patterns', [], (payload) => received.push(payload))
    ).resolves.not.toThrow();

    await pub.publish('device.enrolled', { deviceId: 'no-match' });
    await waitFor();

    expect(received).toHaveLength(0);
  });

  // 4. large payload (100 KB)
  test('large payload (100 KB string) arrives intact at subscriber', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('pub-large', key);
    const sub = makeSharedClient('sub-large', key);
    await pub.connect();
    await sub.connect();

    const bigString = 'x'.repeat(100 * 1024); // 100 KB
    let received = null;
    await sub.subscribe('q.large-payload', ['device.enrolled'], (payload) => {
      received = payload;
    });

    await pub.publish('device.enrolled', { deviceId: 'big', data: bigString });
    await waitFor();

    expect(received).not.toBeNull();
    expect(received.data).toHaveLength(100 * 1024);
    expect(received.data).toBe(bigString);
  });

  // 5. rapid fire — 10 publishes before any tick
  test('rapid fire: 10 publishes all arrive at subscriber', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('pub-rapid', key);
    const sub = makeSharedClient('sub-rapid', key);
    await pub.connect();
    await sub.connect();

    const received = [];
    await sub.subscribe('q.rapid-fire', ['device.enrolled'], (payload) => {
      received.push(payload);
    });

    // Publish 10 events synchronously (tight loop, no await on each publish)
    const publishes = [];
    for (let i = 0; i < 10; i++) {
      publishes.push(pub.publish('device.enrolled', { seq: i }));
    }
    await Promise.all(publishes);
    await waitFor(120);

    expect(received).toHaveLength(10);
    const seqs = received.map((p) => p.seq).sort((a, b) => a - b);
    expect(seqs).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  // 6. unsubscribe isolation — two separate shared buses with different sharedKeys
  test('buses with different sharedKeys do not leak messages to each other', async () => {
    const keyA = String(_busId) + '-A';
    const keyB = String(_busId) + '-B';

    const pubA = makeSharedClient('pub-a', keyA);
    const subA = makeSharedClient('sub-a', keyA);
    const pubB = makeSharedClient('pub-b', keyB);
    const subB = makeSharedClient('sub-b', keyB);

    await pubA.connect();
    await subA.connect();
    await pubB.connect();
    await subB.connect();

    const receivedA = [];
    const receivedB = [];

    await subA.subscribe('q.isolation', ['device.enrolled'], (payload) => receivedA.push(payload));
    await subB.subscribe('q.isolation', ['device.enrolled'], (payload) => receivedB.push(payload));

    // Publish on bus A only
    await pubA.publish('device.enrolled', { deviceId: 'bus-a-only' });
    await waitFor();

    expect(receivedA).toHaveLength(1);
    expect(receivedA[0].deviceId).toBe('bus-a-only');
    // Bus B subscriber must NOT receive events from bus A
    expect(receivedB).toHaveLength(0);

    // Clean up extra keys
    MemoryTransport.resetShared(keyA);
    MemoryTransport.resetShared(keyB);
  });

  // 7. connect() is idempotent — 3 calls do not duplicate subscriptions
  test('connect() called 3 times does not duplicate subscriptions', async () => {
    const key = String(_busId);
    const pub = makeSharedClient('pub-idem', key);
    const sub = makeSharedClient('sub-idem', key);

    await sub.connect();
    await sub.connect();
    await sub.connect();

    await pub.connect();

    const received = [];
    await sub.subscribe('q.idempotent-connect', ['device.enrolled'], (payload) => {
      received.push(payload);
    });

    await pub.publish('device.enrolled', { deviceId: 'idem' });
    await waitFor();

    // Should receive exactly once regardless of how many times connect() was called
    expect(received).toHaveLength(1);
  });
});

// ─── MemoryTransport.resetShared() ───────────────────────────────────────────

describe('MemoryTransport.resetShared()', () => {
  test('after resetShared(), previously subscribed handlers no longer receive messages', async () => {
    const key = String(_busId) + '-reset';
    const pub = makeSharedClient('pub-reset', key);
    const sub = makeSharedClient('sub-reset', key);

    await pub.connect();
    await sub.connect();

    const received = [];
    await sub.subscribe('q.reset-test', ['device.enrolled'], (payload) => received.push(payload));

    // Confirm subscription works before reset
    await pub.publish('device.enrolled', { deviceId: 'before-reset' });
    await waitFor();
    expect(received).toHaveLength(1);

    // Reset the shared bus — clears all handler registrations
    MemoryTransport.resetShared(key);

    // Now create a new publisher on the same key (fresh shared map)
    const pub2 = makeSharedClient('pub-reset-2', key);
    await pub2.connect();
    await pub2.publish('device.enrolled', { deviceId: 'after-reset' });
    await waitFor();

    // Old subscriber is gone — it was referencing the now-deleted map
    // Total should still be 1 (the before-reset message)
    expect(received).toHaveLength(1);

    MemoryTransport.resetShared(key);
  });

  test('after resetShared(), new subscribers on same key work correctly', async () => {
    const key = String(_busId) + '-reset-new';

    // First round: set up and reset
    const pub1 = makeSharedClient('pub-rn-1', key);
    const sub1 = makeSharedClient('sub-rn-1', key);
    await pub1.connect();
    await sub1.connect();

    const old = [];
    await sub1.subscribe('q.reset-new', ['device.enrolled'], (payload) => old.push(payload));
    MemoryTransport.resetShared(key);

    // Second round: fresh subscribers on the same key
    const pub2 = makeSharedClient('pub-rn-2', key);
    const sub2 = makeSharedClient('sub-rn-2', key);
    await pub2.connect();
    await sub2.connect();

    const fresh = [];
    await sub2.subscribe('q.reset-new', ['device.enrolled'], (payload) => fresh.push(payload));

    await pub2.publish('device.enrolled', { deviceId: 'fresh-sub' });
    await waitFor();

    // New subscriber receives the message
    expect(fresh).toHaveLength(1);
    expect(fresh[0].deviceId).toBe('fresh-sub');
    // Old subscriber remains silent (detached map)
    expect(old).toHaveLength(0);

    MemoryTransport.resetShared(key);
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
