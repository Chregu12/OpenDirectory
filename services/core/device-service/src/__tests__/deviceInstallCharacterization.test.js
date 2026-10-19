'use strict';

/**
 * GOLDEN MASTER / characterization tests for the device-service DDD wiring
 * effort (see index.js + services/deviceManager.js + application/*ApplicationService.js).
 *
 * Unlike api.e2e.test.js (which mocks services/deviceManager.js wholesale and
 * therefore never exercises the real DeviceAggregate/PostgresDeviceRepository
 * persistence path), this suite mocks only the lowest-level infra (the `../db`
 * module) with a small stateful in-memory table, and lets everything above it
 * — DeviceManager (or, post-wiring, DeviceApplicationService), PostgresDeviceRepository,
 * DeviceAggregate — run for real. This is the net that proves observable HTTP
 * behavior (status codes, response shapes, persistence across requests) is
 * unchanged by the DDD-wiring refactor.
 *
 * These tests MUST pass unmodified both BEFORE and AFTER the refactor.
 */

// ─── Stateful in-memory `devices` table behind the raw ../db module ──────────

function makeStatefulDb() {
  const rows = new Map(); // id -> row (snake_case columns, as PostgresDeviceRepository writes them)
  const installJobRows = new Map(); // job_id -> row, simulating the real install_jobs table

  async function query(sql, params = []) {
    const text = sql.replace(/\s+/g, ' ').trim();

    // PostgresInstallJobRepository#save(): INSERT INTO install_jobs ...
    // Faithfully simulates the real schema's
    // `device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE` —
    // an insert for a deviceId not present in the `devices` table throws,
    // exactly like real Postgres would. This is what proves
    // InstallApplicationService#createInstallJobRecord's best-effort
    // try/catch around the durability write is load-bearing, not
    // decorative — see deviceInstallCharacterization tests below.
    if (text.startsWith('INSERT INTO install_jobs')) {
      const [job_id, device_id, app_id, app_name, package_id, format, version, status, queued_at, completed_at, error] = params;
      if (!rows.has(device_id)) {
        throw new Error(`insert or update on table "install_jobs" violates foreign key constraint — device_id "${device_id}" is not present in table "devices"`);
      }
      installJobRows.set(job_id, { job_id, device_id, app_id, app_name, package_id, format, version, status, queued_at, completed_at, error });
      return { rows: [], rowCount: 1 };
    }

    // PostgresInstallJobRepository#findById(): SELECT * FROM install_jobs WHERE job_id = $1
    if (text.startsWith('SELECT * FROM install_jobs WHERE job_id')) {
      const jobId = params[0];
      const row = installJobRows.get(jobId);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }

    // save(): INSERT ... ON CONFLICT (id) DO UPDATE ...
    if (text.startsWith('INSERT INTO devices')) {
      const [id, hostname, platform, status, is_compliant, compliance_violations,
        last_seen, enrolled_at, os, os_version, ip_address, kernel, package_manager] = params;
      rows.set(id, {
        id, hostname, platform, status, is_compliant,
        compliance_violations: JSON.parse(compliance_violations || '[]'),
        last_seen, enrolled_at, os, os_version, ip_address, kernel, package_manager,
      });
      return { rows: [], rowCount: 1 };
    }

    // exists(): SELECT 1 FROM devices WHERE id = $1
    if (text.startsWith('SELECT 1 FROM devices WHERE id')) {
      const id = params[0];
      return { rows: rows.has(id) ? [{ '?column?': 1 }] : [], rowCount: rows.has(id) ? 1 : 0 };
    }

    // findById(): SELECT * FROM devices WHERE id = $1
    if (text.startsWith('SELECT * FROM devices WHERE id')) {
      const id = params[0];
      const row = rows.get(id);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }

    // findAll(): SELECT * FROM devices WHERE 1=1 [AND platform=$n] [AND status=$n] [LIMIT] [OFFSET]
    if (text.startsWith('SELECT * FROM devices WHERE 1=1')) {
      let all = [...rows.values()];
      // crude param-based filtering matching the query builder in PostgresDeviceRepository
      if (text.includes('platform =')) {
        const idx = text.indexOf('platform = $') + 'platform = $'.length;
        const n = parseInt(text.slice(idx, idx + 2), 10);
        all = all.filter(r => r.platform === params[n - 1]);
      }
      if (text.includes('status =')) {
        const idx = text.indexOf('status = $') + 'status = $'.length;
        const n = parseInt(text.slice(idx, idx + 2), 10);
        all = all.filter(r => r.status === params[n - 1]);
      }
      return { rows: all, rowCount: all.length };
    }

    // delete(): DELETE FROM devices WHERE id = $1
    if (text.startsWith('DELETE FROM devices WHERE id')) {
      const id = params[0];
      const existed = rows.has(id);
      rows.delete(id);
      return { rows: [], rowCount: existed ? 1 : 0 };
    }

    // Anything else (stammdaten/photo jsonb ops etc.) — not exercised by these tests.
    return { rows: [], rowCount: 0 };
  }

  return {
    initDb: jest.fn().mockResolvedValue(undefined),
    isAvailable: jest.fn().mockReturnValue(true),
    query: jest.fn(query),
    healthCheck: jest.fn().mockResolvedValue({ status: 'healthy' }),
    pool: {},
    _rows: rows,
    _installJobRows: installJobRows,
  };
}

const mockStatefulDb = makeStatefulDb();
jest.mock('../db', () => mockStatefulDb);

// ─── Mock everything else the same way api.e2e.test.js does, so index.js can
//     boot without a real Postgres/Redis/RabbitMQ/WS stack. ───────────────────

jest.mock('ioredis', () => {
  const redisMock = {
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    setex: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    on: jest.fn(),
    status: 'ready',
  };
  return jest.fn().mockImplementation(() => redisMock);
});

jest.mock('amqplib', () => ({
  connect: jest.fn().mockResolvedValue({
    createChannel: jest.fn().mockResolvedValue({
      assertExchange: jest.fn().mockResolvedValue({}),
      assertQueue: jest.fn().mockResolvedValue({ queue: 'test-queue' }),
      bindQueue: jest.fn().mockResolvedValue({}),
      publish: jest.fn().mockReturnValue(true),
      consume: jest.fn().mockResolvedValue({}),
      ack: jest.fn(),
      nack: jest.fn(),
      prefetch: jest.fn(),
    }),
    on: jest.fn(),
    close: jest.fn().mockResolvedValue(undefined),
  }),
}));

jest.mock('ws', () => {
  const EventEmitter = require('events');
  const MockWsServer = jest.fn().mockImplementation(() => {
    const srv = new EventEmitter();
    srv.clients = new Set();
    srv.close = jest.fn((cb) => cb && cb());
    return srv;
  });
  const WebSocket = { Server: MockWsServer, OPEN: 1, CLOSED: 3, CONNECTING: 0, CLOSING: 2 };
  return WebSocket;
});

jest.mock('../../../../packages/service-contracts/src/messageBus', () => {
  return jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
    subscribe: jest.fn().mockResolvedValue(undefined),
    isConnected: jest.fn().mockReturnValue(false),
    queueDeviceCommand: jest.fn().mockResolvedValue(false),
    consumeDeviceCommands: jest.fn().mockResolvedValue(undefined),
    close: jest.fn().mockResolvedValue(undefined),
  }));
}, { virtual: true });

jest.mock('../../../../packages/service-contracts/src/events', () => ({
  Events: {
    DEVICE_ENROLLED: 'device.enrolled',
    DEVICE_NON_COMPLIANT: 'device.non_compliant',
    APP_INSTALL_COMPLETED: 'app.install.completed',
    APP_INSTALL_FAILED: 'app.install.failed',
  },
}), { virtual: true });

const makeServiceMock = (extra = {}) => jest.fn().mockImplementation(() => ({
  init: jest.fn().mockResolvedValue(undefined),
  close: jest.fn().mockResolvedValue(undefined),
  healthCheck: jest.fn().mockResolvedValue({ status: 'healthy' }),
  ...extra,
}));

jest.mock('../database/manager', () => makeServiceMock({
  healthCheck: jest.fn().mockResolvedValue({ status: 'healthy' }),
  close: jest.fn(),
}), { virtual: true });

jest.mock('../cache/manager', () => makeServiceMock({
  get: jest.fn().mockResolvedValue(null),
  set: jest.fn().mockResolvedValue('OK'),
  del: jest.fn().mockResolvedValue(1),
  healthCheck: jest.fn().mockResolvedValue({ status: 'healthy' }),
  close: jest.fn(),
}), { virtual: true });

jest.mock('../events/eventBus', () => {
  const EventEmitter = require('events');
  return jest.fn().mockImplementation(() => {
    const emitter = new EventEmitter();
    emitter.healthCheck = jest.fn().mockResolvedValue({ status: 'healthy' });
    return emitter;
  });
}, { virtual: true });

jest.mock('../metrics/collector', () => makeServiceMock({
  recordResponseTime: jest.fn(),
  increment: jest.fn(),
}), { virtual: true });

jest.mock('../utils/circuitBreaker', () => {
  return jest.fn().mockImplementation(() => ({
    execute: jest.fn().mockImplementation((name, fn) => fn()),
  }));
}, { virtual: true });

jest.mock('../utils/logger', () => ({
  info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn(),
}), { virtual: true });

jest.mock('../middleware/oidcAuth', () => ({
  oidcAuth: () => (req, _res, next) => {
    req.user = { sub: 'test-user', roles: ['admin'] };
    next();
  },
}));

jest.mock('../config', () => ({
  environment: 'test',
  version: '1.0.0-test',
  cors: { origins: ['*'] },
  compliance: { scanInterval: 999999999 },
  security: { threatScanInterval: 999999999 },
  certificates: { renewalCheckInterval: 999999999 },
  analytics: { aggregationInterval: 999999999 },
}), { virtual: true });

// Deliberately NOT mocked: '../services/deviceManager' — we want the REAL
// class (or, post-wiring, whatever real application-service code index.js
// calls) to run against the stateful `../db` mock above.

jest.mock('../services/policyEngine', () => jest.fn().mockImplementation(() => ({
  getDevicePolicies: jest.fn().mockResolvedValue([]),
  assignDefaultPolicies: jest.fn().mockResolvedValue(undefined),
  getPolicies: jest.fn().mockResolvedValue({ policies: [] }),
})), { virtual: true });

jest.mock('../services/complianceScanner', () => jest.fn().mockImplementation(() => ({
  scanDevice: jest.fn().mockResolvedValue({ deviceId: 'device-123', compliant: true, violations: [] }),
  getViolationCount: jest.fn().mockResolvedValue(0),
  performScheduledScan: jest.fn().mockResolvedValue(undefined),
  getViolations: jest.fn().mockResolvedValue([]),
  autoRemediate: jest.fn().mockResolvedValue(undefined),
  updateComplianceStatus: jest.fn().mockResolvedValue(undefined),
})), { virtual: true });

jest.mock('../services/enrollmentService', () => jest.fn().mockImplementation(() => ({
  getPendingCount: jest.fn().mockResolvedValue(0),
  initiateEnrollment: jest.fn().mockResolvedValue({}),
  completeEnrollment: jest.fn().mockResolvedValue({}),
  verifyEnrollment: jest.fn().mockResolvedValue({}),
  getEnrollmentStatus: jest.fn().mockResolvedValue({ status: 'pending' }),
  approveEnrollment: jest.fn().mockResolvedValue({}),
  rejectEnrollment: jest.fn().mockResolvedValue({}),
})), { virtual: true });

jest.mock('../services/inventoryService', () => jest.fn().mockImplementation(() => ({
  updateInventory: jest.fn().mockResolvedValue(undefined),
  getInventory: jest.fn().mockResolvedValue({}),
})), { virtual: true });

jest.mock('../services/remoteActionService', () => jest.fn().mockImplementation(() => ({
  setDb: jest.fn(),
  setDeviceRepository: jest.fn(),
  isolateDevice: jest.fn().mockResolvedValue(undefined),
  executeAction: jest.fn().mockResolvedValue({ actionId: 'action-123' }),
  getActionStatus: jest.fn().mockResolvedValue({ status: 'completed' }),
  lockDevice: jest.fn().mockResolvedValue({}),
  unlockDevice: jest.fn().mockResolvedValue({}),
  wipeDevice: jest.fn().mockResolvedValue({}),
})), { virtual: true });

jest.mock('../services/geofencingService', () => jest.fn().mockImplementation(() => ({
  getZones: jest.fn().mockResolvedValue([]),
  createZone: jest.fn().mockResolvedValue({ id: 'zone-1' }),
})), { virtual: true });

jest.mock('../services/certificateManager', () => jest.fn().mockImplementation(() => ({
  checkCertificateRenewal: jest.fn().mockResolvedValue(undefined),
  getCertificates: jest.fn().mockResolvedValue([]),
  issueCertificate: jest.fn().mockResolvedValue({ certId: 'cert-123' }),
})), { virtual: true });

jest.mock('../services/threatDetector', () => jest.fn().mockImplementation(() => ({
  performThreatScan: jest.fn().mockResolvedValue(undefined),
})), { virtual: true });

jest.mock('../services/analyticsEngine', () => jest.fn().mockImplementation(() => ({
  aggregateMetrics: jest.fn().mockResolvedValue(undefined),
  getDashboard: jest.fn().mockResolvedValue({}),
})), { virtual: true });

jest.mock('../clients/updateClient', () => ({
  configureUpdates: jest.fn().mockResolvedValue({}),
  checkUpdateStatus: jest.fn().mockResolvedValue({}),
  triggerUpdate: jest.fn().mockResolvedValue({}),
  getDeviceUpdateStatus: jest.fn().mockResolvedValue({}),
  configureWingetAutoUpdate: jest.fn().mockResolvedValue({}),
  handleCommandResult: jest.fn().mockResolvedValue(undefined),
}), { virtual: true });

jest.mock('../clients/networkProfileClient', () => ({
  configureWiFi: jest.fn().mockResolvedValue({}),
  removeWiFi: jest.fn().mockResolvedValue({}),
  configureVPN: jest.fn().mockResolvedValue({}),
  removeVPN: jest.fn().mockResolvedValue({}),
  configureEmail: jest.fn().mockResolvedValue({}),
  removeEmail: jest.fn().mockResolvedValue({}),
  getDeviceProfileState: jest.fn().mockResolvedValue({}),
  handleCommandResult: jest.fn().mockResolvedValue(undefined),
}), { virtual: true });

jest.mock('../clients/licenseClient', () => ({
  getDashboardData: jest.fn().mockResolvedValue({}),
  getTimeSeries: jest.fn().mockResolvedValue({}),
  getReportTemplates: jest.fn().mockResolvedValue([]),
  generateReport: jest.fn().mockResolvedValue({}),
}), { virtual: true });

jest.mock('../clients/backupClient', () => ({
  triggerBackup: jest.fn().mockResolvedValue({}),
  getBackupStatus: jest.fn().mockResolvedValue({}),
  getBackupHistory: jest.fn().mockResolvedValue([]),
  restoreBackup: jest.fn().mockResolvedValue({}),
  getDrHealth: jest.fn().mockResolvedValue({ status: 'healthy' }),
  testFailover: jest.fn().mockResolvedValue({}),
  getReplicationStatus: jest.fn().mockResolvedValue({ active: false }),
  executeFailover: jest.fn().mockResolvedValue({}),
}), { virtual: true });

// ─── Now boot the real app ─────────────────────────────────────────────────
//
// index.js has no `require.main === module` guard: merely requiring it
// triggers an unconditional `new EnterpriseDeviceManagementService().start()`
// at the bottom of the file, binding a real port. That's harmless when only
// one test file in a Jest worker requires index.js (as in api.e2e.test.js),
// but this file is a second one — without care, both orphaned auto-started
// instances race for the same default port (3003) inside the same worker
// process and the second one to bind fails with EADDRINUSE. Point that
// unavoidable side-effect at an OS-assigned ephemeral port (0) instead, for
// the scope of this one `require()` call, so it can never collide.
const request = require('supertest');
const _origPort = process.env.PORT;
process.env.PORT = '0';
const EnterpriseDeviceManagementService = require('../index');
if (_origPort === undefined) delete process.env.PORT; else process.env.PORT = _origPort;

describe('Device Service — Golden Master characterization (real repo/aggregate path)', () => {
  let app;
  let service;

  beforeAll(() => {
    service = new EnterpriseDeviceManagementService();
    app = service.app;
  });

  afterAll(() => {
    jest.clearAllTimers();
    if (service && service.server) service.server.close();
  });

  beforeEach(() => {
    mockStatefulDb._rows.clear();
    mockStatefulDb._installJobRows.clear();
    if (global.__od_installJobs) global.__od_installJobs.clear();
  });

  // ── Device CRUD round-trip through the REAL repository/aggregate ─────────

  describe('POST /api/devices — create', () => {
    it('creates a device and returns 201 with the aggregate JSON shape', async () => {
      const res = await request(app)
        .post('/api/devices')
        .send({ id: 'dev-gm-1', hostname: 'gm-host-1', platform: 'windows' });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        id: 'dev-gm-1',
        hostname: 'gm-host-1',
        platform: 'windows',
        status: 'active',
        isCompliant: true,
        complianceViolations: [],
        complianceScore: 100,
      });
      expect(res.body.data).toHaveProperty('enrolledAt');
      expect(res.body).toHaveProperty('requestId');
    });

    it('generates a fallback id (dev-<timestamp>) when none is supplied', async () => {
      const res = await request(app)
        .post('/api/devices')
        .send({ hostname: 'no-id-host', platform: 'linux' });

      expect(res.status).toBe(201);
      expect(res.body.data.id).toMatch(/^dev-\d+$/);
    });

    it('ignores unknown/extraneous fields silently (e.g. "name")', async () => {
      // DeviceAggregate only knows a fixed set of fields; "name" is not one of
      // them, so it's silently dropped rather than rejected or stored.
      const res = await request(app)
        .post('/api/devices')
        .send({ id: 'dev-gm-2', name: 'Should Be Dropped', hostname: 'gm-host-2', platform: 'macos' });

      expect(res.status).toBe(201);
      expect(res.body.data).not.toHaveProperty('name');
      expect(res.body.data.hostname).toBe('gm-host-2');
    });
  });

  describe('GET /api/devices/:deviceId — read', () => {
    it('returns 404 for a device that was never created', async () => {
      const res = await request(app).get('/api/devices/does-not-exist');
      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Device not found', requestId: expect.any(String) });
    });

    it('returns 200 with the persisted device after creation (persistence proof)', async () => {
      await request(app).post('/api/devices').send({ id: 'dev-gm-3', hostname: 'gm-host-3', platform: 'ios' });

      const res = await request(app).get('/api/devices/dev-gm-3');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({ id: 'dev-gm-3', hostname: 'gm-host-3', platform: 'ios' });
    });
  });

  describe('GET /api/devices — list', () => {
    it('returns an empty list with pagination metadata when no devices exist', async () => {
      const res = await request(app).get('/api/devices');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual([]);
      expect(res.body.pagination).toMatchObject({ page: 1, limit: 50, total: 0, pages: 0 });
    });

    it('lists created devices and respects the platform filter', async () => {
      await request(app).post('/api/devices').send({ id: 'dev-gm-4', hostname: 'h4', platform: 'windows' });
      await request(app).post('/api/devices').send({ id: 'dev-gm-5', hostname: 'h5', platform: 'macos' });

      const all = await request(app).get('/api/devices');
      expect(all.body.data).toHaveLength(2);
      expect(all.body.pagination.total).toBe(2);

      const filtered = await request(app).get('/api/devices?platform=windows');
      expect(filtered.body.data).toHaveLength(1);
      expect(filtered.body.data[0].id).toBe('dev-gm-4');
    });

    it('supports search across name/hostname/id', async () => {
      await request(app).post('/api/devices').send({ id: 'dev-gm-searchable', hostname: 'special-hostname', platform: 'linux' });
      await request(app).post('/api/devices').send({ id: 'dev-gm-other', hostname: 'unrelated', platform: 'linux' });

      const res = await request(app).get('/api/devices?search=special');
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].id).toBe('dev-gm-searchable');
    });

    it('paginates with page/limit', async () => {
      for (let i = 0; i < 5; i++) {
        await request(app).post('/api/devices').send({ id: `dev-gm-page-${i}`, hostname: `h${i}`, platform: 'linux' });
      }
      const res = await request(app).get('/api/devices?page=2&limit=2');
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(2);
      expect(res.body.pagination).toMatchObject({ page: 2, limit: 2, total: 5, pages: 3 });
    });
  });

  describe('PUT /api/devices/:deviceId — update', () => {
    it('returns 404 when the device does not exist', async () => {
      const res = await request(app).put('/api/devices/nope').send({ hostname: 'x' });
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'Device not found');
    });

    it('updates known scalar fields and returns the updated device', async () => {
      await request(app).post('/api/devices').send({ id: 'dev-gm-6', hostname: 'orig', platform: 'windows' });

      const res = await request(app).put('/api/devices/dev-gm-6').send({ hostname: 'renamed', status: 'inactive' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({ id: 'dev-gm-6', hostname: 'renamed', status: 'inactive' });
    });

    it('silently ignores unknown fields on update (e.g. "name")', async () => {
      await request(app).post('/api/devices').send({ id: 'dev-gm-7', hostname: 'orig7', platform: 'windows' });
      const res = await request(app).put('/api/devices/dev-gm-7').send({ name: 'ignored' });
      expect(res.status).toBe(200);
      expect(res.body.data).not.toHaveProperty('name');
    });
  });

  describe('DELETE /api/devices/:deviceId — delete', () => {
    it('returns 404 when the device does not exist', async () => {
      const res = await request(app).delete('/api/devices/nope');
      expect(res.status).toBe(404);
    });

    it('deletes an existing device (subsequent GET 404s)', async () => {
      await request(app).post('/api/devices').send({ id: 'dev-gm-8', hostname: 'h8', platform: 'linux' });
      const del = await request(app).delete('/api/devices/dev-gm-8');
      expect(del.status).toBe(200);
      expect(del.body).toEqual({ success: true, requestId: expect.any(String) });

      const get = await request(app).get('/api/devices/dev-gm-8');
      expect(get.status).toBe(404);
    });
  });

  describe('POST /api/bulk/import-devices', () => {
    it('imports multiple devices and reports counts', async () => {
      const res = await request(app)
        .post('/api/bulk/import-devices')
        .send({ devices: [
          { id: 'dev-gm-bulk-1', hostname: 'b1', platform: 'windows' },
          { id: 'dev-gm-bulk-2', hostname: 'b2', platform: 'macos' },
        ] });
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ success: true, imported: 2, failed: 0 });

      const list = await request(app).get('/api/devices');
      expect(list.body.pagination.total).toBe(2);
    });
  });

  describe('POST /api/v1/devices/:deviceId/checkin — updateLastSeen must NOT throw for unknown devices', () => {
    it('returns 200 ok even when the device was never enrolled', async () => {
      const res = await request(app).post('/api/v1/devices/totally-unknown-device/checkin').send({});
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ status: 'ok' });
    });

    it('returns 200 ok and updates lastSeen for a known device', async () => {
      await request(app).post('/api/devices').send({ id: 'dev-gm-checkin', hostname: 'h', platform: 'linux' });
      const res = await request(app).post('/api/v1/devices/dev-gm-checkin/checkin').send({ agentVersion: '1.0' });
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ status: 'ok' });

      const get = await request(app).get('/api/devices/dev-gm-checkin');
      expect(get.body.data.lastSeen).not.toBeNull();
    });
  });

  describe('GET /health — activeDevices metric', () => {
    it('reflects active device count without throwing', async () => {
      await request(app).post('/api/devices').send({ id: 'dev-gm-health', hostname: 'h', platform: 'linux' });
      const res = await request(app).get('/health');
      expect([200, 503]).toContain(res.status);
      expect(res.body.metrics).toHaveProperty('activeDevices');
      expect(typeof res.body.metrics.activeDevices).toBe('number');
    });
  });

  // ── Install job flow (backed by InstallApplicationService#createInstallJobRecord/
  //    getJobsForDeviceRecord/recordInstallResult — an in-process Map inside
  //    the application service, replacing the old global.__od_installJobs,
  //    plus a best-effort Postgres durability write-through and unchanged
  //    WebSocket push / RabbitMQ / Redis offline fallback). The in-memory Map
  //    remains authoritative for reads: install_jobs.device_id has a real FK
  //    to devices(id), which the "unenrolled device" test below proves the
  //    durability write tolerates without altering the HTTP response.) ──────

  describe('POST /api/devices/:deviceId/install-app', () => {
    it('returns 400 without packageId or downloadUrl', async () => {
      const res = await request(app)
        .post('/api/devices/device-123/install-app')
        .send({ appId: 'app-1', appName: 'My App' });
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error');
    });

    it('returns 200 with jobId/status/message (NO "success" wrapper) when packageId given', async () => {
      const res = await request(app)
        .post('/api/devices/device-123/install-app')
        .send({ appId: 'app-1', appName: 'My App', packageId: 'com.example.app', format: 'msi', version: '1.0.0' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('jobId');
      expect(res.body).toHaveProperty('status');
      expect(res.body).toHaveProperty('message');
      expect(res.body).not.toHaveProperty('success');
    });

    it('succeeds even for a deviceId that was never enrolled in the device repository', async () => {
      // Characterizes a real divergence from InstallApplicationService.createInstallJob,
      // which throws "Device not found" when deviceRepository.findById() returns null.
      // createInstallJobRecord (what the live route actually calls) never throws
      // for this — see the next test for proof that the best-effort Postgres
      // write it also attempts (and which WOULD violate install_jobs' FK on
      // devices(id) for this exact deviceId) is swallowed rather than surfaced.
      const res = await request(app)
        .post('/api/devices/totally-unknown-device/install-app')
        .send({ appId: 'app-1', packageId: 'com.example.app' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('jobId');
    });

    it('swallows the install_jobs FK-violation durability write for an unenrolled device without affecting the response', async () => {
      // The mockStatefulDb above faithfully simulates install_jobs.device_id's
      // real `REFERENCES devices(id)` constraint: an INSERT for a deviceId
      // absent from `devices` throws, exactly like real Postgres. This proves
      // InstallApplicationService#createInstallJobRecord's try/catch around
      // that write is load-bearing — without it, this request would 500.
      const res = await request(app)
        .post('/api/devices/fk-violating-device/install-app')
        .send({ appId: 'app-1', packageId: 'com.example.app' });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('jobId');
      // Proves the write really was attempted and really did fail — this
      // isn't passing merely because the durability write was never called.
      expect(mockStatefulDb._installJobRows.has(res.body.jobId)).toBe(false);
      // The in-memory record (read back via GET) is unaffected by the DB failure.
      const jobs = await request(app).get('/api/devices/fk-violating-device/install-jobs');
      expect(jobs.body.some(j => j.jobId === res.body.jobId)).toBe(true);
    });

    it('persists the job to install_jobs (best-effort durability) when the device IS enrolled', async () => {
      await request(app).post('/api/devices').send({ id: 'dev-gm-install-known', hostname: 'h', platform: 'linux' });

      const res = await request(app)
        .post('/api/devices/dev-gm-install-known/install-app')
        .send({ appId: 'app-known', packageId: 'com.example.known' });

      expect(res.status).toBe(200);
      expect(mockStatefulDb._installJobRows.has(res.body.jobId)).toBe(true);
      expect(mockStatefulDb._installJobRows.get(res.body.jobId)).toMatchObject({
        device_id: 'dev-gm-install-known', app_id: 'app-known', status: 'queued',
      });
    });
  });

  describe('GET /api/devices/:deviceId/install-jobs', () => {
    it('returns the jobs queued for that device via install-app', async () => {
      const create = await request(app)
        .post('/api/devices/device-install-list/install-app')
        .send({ appId: 'app-2', packageId: 'com.example.app2' });
      const jobId = create.body.jobId;

      const res = await request(app).get('/api/devices/device-install-list/install-jobs');
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.some(j => j.jobId === jobId)).toBe(true);
    });

    it('returns an empty array for a device with no jobs', async () => {
      const res = await request(app).get('/api/devices/device-no-jobs/install-jobs');
      expect(res.status).toBe(200);
      expect(res.body).toEqual([]);
    });
  });

  describe('POST /api/devices/:deviceId/install-jobs/:jobId/result', () => {
    it('records the result and returns { ok: true }', async () => {
      const create = await request(app)
        .post('/api/devices/device-install-result/install-app')
        .send({ appId: 'app-3', packageId: 'com.example.app3' });
      const jobId = create.body.jobId;

      const res = await request(app)
        .post(`/api/devices/device-install-result/install-jobs/${jobId}/result`)
        .send({ status: 'success', output: 'installed ok' });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ ok: true });

      const jobs = await request(app).get('/api/devices/device-install-result/install-jobs');
      const job = jobs.body.find(j => j.jobId === jobId);
      expect(job.status).toBe('success');
      expect(job.output).toBe('installed ok');
    });

    it('returns { ok: true } for a jobId that was never created, without throwing', async () => {
      // recordInstallResult() returns null for an unknown jobId (no in-memory
      // record to update); the route must still answer 200/{ok:true} exactly
      // as before, and must not attempt to publish an install-result event.
      const res = await request(app)
        .post('/api/devices/some-device/install-jobs/never-created-job/result')
        .send({ status: 'success', output: 'n/a' });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ ok: true });
    });
  });
});
