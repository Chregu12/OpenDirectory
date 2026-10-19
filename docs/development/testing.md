# Testing Guide

OpenDirectory has 307+ test files across all packages and services, covering unit tests, integration tests, and end-to-end API tests.

## Test structure

Each service and package follows the same layout:

```
services/core/device-service/src/
  __tests__/
    DeviceAggregate.test.js          # domain aggregate unit tests
    DeviceId.test.js                 # value object unit tests
    ComplianceStatusValueObject.test.js
    PlatformValueObject.test.js
    DeviceApplicationService.test.js # application service unit tests
    InstallJobAggregate.test.js
    InstallApplicationService.test.js
    api.e2e.test.js                  # HTTP API end-to-end tests
```

The `packages/grpc-event-bus/src/__tests__/` directory contains integration tests for the event bus:

```
packages/grpc-event-bus/src/__tests__/
  EventBusClient.integration.test.js  # transport-level integration tests
  EventBusSagaFlow.integration.test.js # saga / choreography flow tests
```

## Running all tests

### Single service

```bash
cd services/core/device-service
npx jest --no-coverage --forceExit
```

### All services and packages

```bash
for dir in packages/grpc-event-bus services/core/* services/enterprise/* services/platform/*; do
  if [ -f "$dir/package.json" ]; then
    echo "=== $dir ==="
    (cd "$dir" && npx jest --no-coverage --forceExit 2>&1) || true
  fi
done
```

### Frontend

```bash
cd frontend/web-app
npx jest --no-coverage --forceExit
```

## Unit tests

### Domain aggregates

Aggregates encapsulate business rules. Tests cover state transitions and invariant enforcement:

```js
const DeviceAggregate = require('../domain/aggregates/DeviceAggregate');

describe('DeviceAggregate', () => {
  it('sets status to active by default', () => {
    const device = new DeviceAggregate({ id: 'dev-1', hostname: 'box', platform: 'macos' });
    expect(device.status).toBe('active');
  });

  it('marks device non-compliant on policy violation', () => {
    const device = new DeviceAggregate({ id: 'dev-1', hostname: 'box', platform: 'macos' });
    device.markNonCompliant('firewall-disabled');
    expect(device.isCompliant).toBe(false);
  });
});
```

### Value objects

Value objects are immutable. Tests verify construction validation and equality:

```js
const PlatformValueObject = require('../domain/value-objects/PlatformValueObject');

it('rejects unknown platforms', () => {
  expect(() => new PlatformValueObject('bsd')).toThrow();
});
```

### Application services

Application services orchestrate domain objects and I/O. Tests use in-memory or mocked dependencies:

```js
const DeviceApplicationService = require('../application/DeviceApplicationService');

describe('DeviceApplicationService', () => {
  let svc;
  beforeEach(() => {
    svc = new DeviceApplicationService({ db: mockDb, messageBus: mockBus, logger: console });
  });
  // ...
});
```

## Integration tests — EventBusClient flows

Use `MemoryTransport` with `shared: true` to simulate a real message broker in tests. Two clients with the same `sharedKey` share the same in-memory subscription registry.

```js
const { EventBusClient } = require('@opendirectory/grpc-event-bus');

describe('event bus publish/subscribe', () => {
  afterEach(() => {
    EventBusClient.resetShared
      ? EventBusClient.resetShared()
      : require('@opendirectory/grpc-event-bus/src/transports/MemoryTransport').resetShared();
  });

  it('delivers events to subscribers', async () => {
    const publisher = new EventBusClient({
      source: 'test-pub', transport: 'memory', shared: true, sharedKey: 'test',
    });
    const subscriber = new EventBusClient({
      source: 'test-sub', transport: 'memory', shared: true, sharedKey: 'test',
    });

    await publisher.connect();
    await subscriber.connect();

    const received = [];
    await subscriber.subscribe('my-queue', ['device.*'], async (payload) => {
      received.push(payload);
    });

    await publisher.publish('device.enrolled', { deviceId: 'abc' });

    // MemoryTransport delivers via setImmediate — flush the microtask queue
    await new Promise(resolve => setImmediate(resolve));

    expect(received).toHaveLength(1);
    expect(received[0].deviceId).toBe('abc');
  });
});
```

**Important:** Call `MemoryTransport.resetShared()` (or `EventBusClient.resetShared()` if exposed) in `afterEach` to prevent subscription state leaking between tests.

### Wildcard patterns

`MemoryTransport` implements AMQP-style wildcard matching:
- `*` matches exactly one routing-key word (e.g. `device.*` matches `device.enrolled` but not `device.install.job.created`)
- `#` matches zero or more words (e.g. `device.#` matches `device.enrolled` and `device.install.job.created`)

## Integration tests — Saga patterns

Sagas coordinate multi-step workflows across services. Test them by wiring an application service to a shared in-memory bus and asserting that follow-up events are published:

```js
it('compliance saga reacts to device.enrolled', async () => {
  const bus = new EventBusClient({
    source: 'test', transport: 'memory', shared: true, sharedKey: 'saga-test',
  });
  await bus.connect();

  const saga = new ComplianceSaga({ messageBus: bus, db: mockDb, logger: console });
  await saga.start();

  const published = [];
  await bus.subscribe('test-sink', ['compliance.#'], async (p, { routingKey }) => {
    published.push(routingKey);
  });

  await bus.publish('device.enrolled', { deviceId: 'dev-1' });
  await new Promise(resolve => setTimeout(resolve, 50));

  expect(published).toContain('compliance.check.passed');
});
```

## E2E API tests

End-to-end API tests use `supertest` for HTTP and `nock` to mock downstream service calls:

```js
const request = require('supertest');
const nock = require('nock');
const app = require('../index');

describe('POST /api/devices', () => {
  it('creates a device and returns 201', async () => {
    nock('http://auth-service:3002')
      .post('/api/auth/verify')
      .reply(200, { valid: true });

    const res = await request(app)
      .post('/api/devices')
      .send({ hostname: 'test-box', platform: 'linux', serial: 'SN123' });

    expect(res.status).toBe(201);
    expect(res.body.hostname).toBe('test-box');
  });
});
```

## Frontend tests

Frontend component tests use React Testing Library and `@testing-library/jest-dom`:

```tsx
import { render, screen } from '@testing-library/react';
import EnrollmentWizard from '@/components/views/EnrollmentWizard';

test('renders platform selection step', () => {
  render(<EnrollmentWizard onClose={() => {}} />);
  expect(screen.getByText('macOS')).toBeInTheDocument();
  expect(screen.getByText('Windows')).toBeInTheDocument();
});
```

## Adding tests for a new service

### jest.config.js template

```js
'use strict';

module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/src/__tests__/**/*.test.js'],
  coverageDirectory: 'coverage',
  collectCoverageFrom: ['src/**/*.js', '!src/__tests__/**'],
  testTimeout: 30000,
};
```

### Mock patterns

**Mock the database pool:**
```js
const mockDb = {
  query: jest.fn().mockResolvedValue({ rows: [] }),
  testConnection: jest.fn().mockResolvedValue(true),
  runMigrations: jest.fn().mockResolvedValue(),
  shutdown: jest.fn().mockResolvedValue(),
};
```

**Mock the event bus:**
```js
const mockBus = {
  connect: jest.fn().mockResolvedValue(),
  publish: jest.fn().mockResolvedValue(),
  subscribe: jest.fn().mockResolvedValue(),
  close: jest.fn().mockResolvedValue(),
  isConnected: jest.fn().mockReturnValue(true),
};
```

**Prefer the real MemoryTransport** over a mocked bus when testing event-driven flows — it exercises the actual routing logic.
