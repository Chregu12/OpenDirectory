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

### Repository gating suites

```bash
npm test
```

### Frontend

```bash
cd frontend/web-app
npx jest --no-coverage --forceExit
```

## CI checks

`.github/workflows/ci.yml` validates workflows with checksum-pinned actionlint 1.7.12,
checks workflow formatting without rewriting files, validates tracked manifests,
and runs service and PostgreSQL/browser suites. Missing test scripts or Jest suites
fail the run. Services with committed locks use `npm ci`; installation failures also
stop the local `scripts/test-all.sh` runner before it can reuse stale dependencies.

The two Docker matrix entries validate the full and lite Compose configurations,
including optional profiles, with their configured Dockerfile build contexts.
`docker compose build --check` is a static BuildKit check: it does not execute image
build commands or prove that an application starts. Image build/deployment and
live application verification remain separate checks.

`npm run test:runtime-images` builds the App Store and Kerberos images through their
actual full-Compose contexts and starts them on an isolated Docker network with
fresh PostgreSQL databases. The separate CI startup job checks database-backed
health, denied anonymous catalog/principal requests, non-root writable package
storage, the patched gRPC dependency, preserved independent PostgreSQL/KDC
passwords, the foreground Kerberos API and a real native `kinit`/`klist` ticket.
It removes only its randomly named containers, network and image tags. It requires
Node 20, Docker and Compose; it does not deploy or prove every other service image.

The App Store image owns its default `/data/packages` directory. Its Compose build
context must be the repository root because it copies shared packages. Kerberos
generates its configuration in the entrypoint, uses the same Node 20 runtime as
CI, preserves the PostgreSQL `DB_PASSWORD`, and runs its REST API in the foreground
so a crashed API cannot be hidden by an unrelated `tail` process.

The root `npm audit --audit-level=high` now fails on findings and runs independently
of application tests. Its scope is the root lock and its npm workspaces; nested
service dependencies outside those workspaces need their own audit. A failed
security scan must not be presented as an application test failure.

PostgreSQL integration fixtures need an actual disposable database owner. CI uses
PostgreSQL 16 with SCRAM password authentication and
`max_locks_per_transaction=256`, matching the local harness lock budget. Restricted
SQL-login tests set their own random passwords and assert `session_user` before
checking the original permission denial. They must not pass merely because login
itself failed.

Legacy fixture cleanup uses `scripts/lib/reset-directory-fixture.cjs` only in
explicit UUID-named disposable schemas and only while new company-role storage is
empty. It restores retention triggers transactionally and checks their receiver;
nonempty role history refuses cleanup. `fixtureReset.postgres.cjs` covers retained
history, rollback, rejected namespaces/commands and historical pre-role schemas.
Production retention guards are unchanged.

Browser screenshots use `test.info().outputPath(...)`, never a host-specific
`/private/tmp` path. CI retains the per-test screenshots and failure traces as the
`frontend-browser-evidence` artifact for seven days. Shared read-only device
fixtures include the current agent and hardware response contracts, so layout
and inventory-only checks do not depend on obsolete labels or missing endpoints.

Identity fixture files run serially: each repeatedly creates/drops a complete
protected schema, and unrelated fixture DDL must not compete against a different
file's one-second authorization query budget on the same PostgreSQL container.
Coordinated multi-connection races inside the individual tests remain enabled.
The integration job installs Device dependencies separately because its real
Identity/Device company-role checks run in a different runner from Service Tests.

Migration replay tests must run the complete ordered migration set, as service
startup does. A hand-maintained subset can overwrite a function without updating
later pinned manifests and correctly makes current authorization unavailable.
Physical MFA-expiry tests leave admission headroom, wait past the original proof
cutoff only after the application callback, and assert that the commit checkpoint
was reached before accepting the SQL denial and unchanged data.

The 2026-11-14 root lock cleanup removes unused Lerna/Turbo dependencies and pins
both gRPC workspaces to `@grpc/grpc-js >=1.14.7 <2`. A clean Node 20 install passes
the high-severity audit gate; the scan still reports six low and nine moderate
findings. These are not suppressed or treated as proof that nested production
service images have been audited. Apple MDM, Monitoring and Quick Actions locks
also include their previously missing declared dependencies.

The release workflow validates version input as data, shares the exact normalized
tag with its archive job, and creates the archive outside its source directory.
Validating these steps locally does not publish or prove a GitHub Release.

## Verifying canonical database backups

`deploy/k8s/verify-postgres-restore.py` takes read-only backups from an explicitly
selected PostgreSQL pod and restores them in a disposable Docker PostgreSQL with
no network access. It requires Python 3.11+, POSIX, kubectl and Docker:

```bash
python3 deploy/k8s/verify-postgres-restore.py \
  --context default --namespace opendirectory --pod opendirectory-postgres-0 \
  --database identity --database devices --database app_store \
  --docker-context desktop-linux \
  --output-dir "$HOME/Library/Application Support/OpenDirectory/backups/new-rehearsal"
```

Choose the actual contexts and a new output directory. The directory must not
exist; backups are never overwritten. It retains sensitive database archives and
diagnostics with directory mode 0700 and file mode 0600, and removes only its own
randomly named Docker container.

Each database uses one exported read-only snapshot for both its archive and row
checksums. A successful `verification.json` confirms that full archive restore,
table counts, per-table row checksums and selected receiving guards passed.
Ownership and privileges are restored without skipping archive errors. The tool
supports the canonical public-schema databases with one common database owner;
additional schemas or missing roles fail verification.

These are separate consistent snapshots, not a coordinated platform recovery.
Cluster roles, signing keys, other services, recovery time and physical agent
reconnection need separate recovery checks.

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
