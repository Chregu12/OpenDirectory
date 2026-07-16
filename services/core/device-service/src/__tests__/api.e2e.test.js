'use strict';

/**
 * E2E API tests for Device Service
 * Uses supertest in-process with mocked external dependencies
 */

// ─── Mock external dependencies BEFORE any require ────────────────────────────

// Mock pg
jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation(() => ({
    query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    connect: jest.fn().mockResolvedValue({
      query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
      release: jest.fn(),
    }),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  })),
}));

// Mock ioredis
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

// Mock amqplib
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

// Mock ws (WebSocket)
jest.mock('ws', () => {
  const EventEmitter = require('events');

  const MockWsServer = jest.fn().mockImplementation(() => {
    const srv = new EventEmitter();
    srv.clients = new Set();
    srv.close = jest.fn((cb) => cb && cb());
    return srv;
  });

  // The module is used as `const WebSocket = require('ws')`
  // and then `new WebSocket.Server(...)` — so we need WebSocket to have .Server
  const WebSocket = {
    Server: MockWsServer,
    OPEN: 1,
    CLOSED: 3,
    CONNECTING: 0,
    CLOSING: 2,
  };
  return WebSocket;
});

// Mock service-contracts
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

// ─── Mock missing local service files ─────────────────────────────────────────

const makeServiceMock = (extra = {}) => jest.fn().mockImplementation(() => ({
  init: jest.fn().mockResolvedValue(undefined),
  close: jest.fn().mockResolvedValue(undefined),
  healthCheck: jest.fn().mockResolvedValue({ status: 'healthy' }),
  ...extra,
}));

// Database Manager
jest.mock('../database/manager', () => makeServiceMock({
  healthCheck: jest.fn().mockResolvedValue({ status: 'healthy' }),
  close: jest.fn(),
}), { virtual: true });

// Cache Manager
jest.mock('../cache/manager', () => makeServiceMock({
  get: jest.fn().mockResolvedValue(null),
  set: jest.fn().mockResolvedValue('OK'),
  del: jest.fn().mockResolvedValue(1),
  healthCheck: jest.fn().mockResolvedValue({ status: 'healthy' }),
  close: jest.fn(),
}), { virtual: true });

// Event Bus
jest.mock('../events/eventBus', () => {
  const EventEmitter = require('events');
  return jest.fn().mockImplementation(() => {
    const emitter = new EventEmitter();
    emitter.healthCheck = jest.fn().mockResolvedValue({ status: 'healthy' });
    return emitter;
  });
}, { virtual: true });

// Metrics Collector
jest.mock('../metrics/collector', () => makeServiceMock({
  recordResponseTime: jest.fn(),
  increment: jest.fn(),
}), { virtual: true });

// Circuit Breaker
jest.mock('../utils/circuitBreaker', () => {
  return jest.fn().mockImplementation(() => ({
    execute: jest.fn().mockImplementation((name, fn) => fn()),
  }));
}, { virtual: true });

// Logger
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
}), { virtual: true });

// OIDC auth — pass through; this suite tests the routes, not authentication
jest.mock('../middleware/oidcAuth', () => ({
  oidcAuth: () => (req, _res, next) => {
    req.user = { sub: 'test-user', roles: ['admin'] };
    next();
  },
}));

// Config
jest.mock('../config', () => ({
  environment: 'test',
  version: '1.0.0-test',
  cors: { origins: ['*'] },
  compliance: { scanInterval: 999999999 },
  security: { threatScanInterval: 999999999 },
  certificates: { renewalCheckInterval: 999999999 },
  analytics: { aggregationInterval: 999999999 },
}), { virtual: true });

// DeviceApplicationService — index.js wires the device CRUD/list/checkin
// routes to this DDD application service (ported from the old
// transaction-script services/deviceManager.js; see DeviceApplicationService.js
// for the rationale). Method names below mirror index.js's call sites:
//   getDevices          -> listDevicesPaginated
//   createDevice        -> createDeviceRecord
//   getDevice           -> getDeviceWithExtras
//   updateDevice        -> updateDeviceRecord
//   deleteDevice        -> deleteDeviceRecord
//   updateLastSeen      -> touchLastSeen
//   getActiveDeviceCount -> countActiveDevices
const mockDeviceApplicationService = {
  listDevicesPaginated: jest.fn().mockResolvedValue({
    devices: [],
    pagination: { page: 1, limit: 50, total: 0, totalPages: 0 },
  }),
  createDeviceRecord: jest.fn().mockResolvedValue({
    id: 'device-123',
    name: 'Test Device',
    platform: 'windows',
    status: 'active',
  }),
  getDeviceWithExtras: jest.fn().mockResolvedValue(null),
  updateDeviceRecord: jest.fn().mockResolvedValue({}),
  deleteDeviceRecord: jest.fn().mockResolvedValue(undefined),
  touchLastSeen: jest.fn().mockResolvedValue(undefined),
  countActiveDevices: jest.fn().mockResolvedValue(0),
};
jest.mock('../application/DeviceApplicationService', () =>
  jest.fn().mockImplementation(() => mockDeviceApplicationService)
, { virtual: true });

// PolicyEngine
jest.mock('../services/policyEngine', () => jest.fn().mockImplementation(() => ({
  getDevicePolicies: jest.fn().mockResolvedValue([]),
  assignDefaultPolicies: jest.fn().mockResolvedValue(undefined),
})), { virtual: true });

// ComplianceScanner
jest.mock('../services/complianceScanner', () => jest.fn().mockImplementation(() => ({
  scanDevice: jest.fn().mockResolvedValue({ deviceId: 'device-123', compliant: true, violations: [] }),
  getViolationCount: jest.fn().mockResolvedValue(0),
  performScheduledScan: jest.fn().mockResolvedValue(undefined),
  getViolations: jest.fn().mockResolvedValue([]),
  autoRemediate: jest.fn().mockResolvedValue(undefined),
  updateComplianceStatus: jest.fn().mockResolvedValue(undefined),
})), { virtual: true });

// EnrollmentService
jest.mock('../services/enrollmentService', () => jest.fn().mockImplementation(() => ({
  getPendingCount: jest.fn().mockResolvedValue(0),
  initiateEnrollment: jest.fn().mockResolvedValue({
    enrollmentId: 'enroll-123',
    token: 'enroll-token',
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
  }),
  completeEnrollment: jest.fn().mockResolvedValue({}),
  verifyEnrollment: jest.fn().mockResolvedValue({}),
  getEnrollmentStatus: jest.fn().mockResolvedValue({ status: 'pending' }),
  approveEnrollment: jest.fn().mockResolvedValue({}),
  rejectEnrollment: jest.fn().mockResolvedValue({}),
})), { virtual: true });

// InventoryService
jest.mock('../services/inventoryService', () => jest.fn().mockImplementation(() => ({
  updateInventory: jest.fn().mockResolvedValue(undefined),
  getInventory: jest.fn().mockResolvedValue({}),
})), { virtual: true });

// RemoteActionService
jest.mock('../services/remoteActionService', () => jest.fn().mockImplementation(() => ({
  setDb: jest.fn(),
  setDeviceRepository: jest.fn(),
  isolateDevice: jest.fn().mockResolvedValue(undefined),
  executeAction: jest.fn().mockResolvedValue({ actionId: 'action-123' }),
  getActionStatus: jest.fn().mockResolvedValue({ status: 'completed' }),
})), { virtual: true });

// GeofencingService
jest.mock('../services/geofencingService', () => jest.fn().mockImplementation(() => ({
  getZones: jest.fn().mockResolvedValue([]),
  createZone: jest.fn().mockResolvedValue({ id: 'zone-1' }),
})), { virtual: true });

// CertificateManager
jest.mock('../services/certificateManager', () => jest.fn().mockImplementation(() => ({
  checkCertificateRenewal: jest.fn().mockResolvedValue(undefined),
  getCertificates: jest.fn().mockResolvedValue([]),
  issueCertificate: jest.fn().mockResolvedValue({ certId: 'cert-123' }),
})), { virtual: true });

// ThreatDetector
jest.mock('../services/threatDetector', () => jest.fn().mockImplementation(() => ({
  performThreatScan: jest.fn().mockResolvedValue(undefined),
})), { virtual: true });

// AnalyticsEngine
jest.mock('../services/analyticsEngine', () => jest.fn().mockImplementation(() => ({
  aggregateMetrics: jest.fn().mockResolvedValue(undefined),
  getDashboard: jest.fn().mockResolvedValue({}),
})), { virtual: true });

// HTTP Clients
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

// ─── Now require the app ───────────────────────────────────────────────────────
const request = require('supertest');
const EnterpriseDeviceManagementService = require('../index');

describe('Device Service - E2E API Tests', () => {
  let app;
  let service;

  beforeAll(() => {
    // Instantiate service without starting it (no real DB/WebSocket server)
    service = new EnterpriseDeviceManagementService();
    app = service.app;
  });

  afterAll(() => {
    // Clean up setInterval timers in AnalyticsBridge etc.
    jest.clearAllTimers();
    if (service && service.server) {
      service.server.close();
    }
  });

  // ─── Health Check ────────────────────────────────────────────────────────────
  describe('GET /health', () => {
    it('returns 200 or 503 with service health info', async () => {
      const res = await request(app).get('/health');
      expect([200, 503]).toContain(res.status);
      expect(res.body).toHaveProperty('service', 'device-management-service');
      expect(res.body).toHaveProperty('status');
      expect(res.body).toHaveProperty('timestamp');
    });

    it('health response includes checks object', async () => {
      const res = await request(app).get('/health');
      expect(res.body).toHaveProperty('checks');
    });
  });

  // ─── GET /api/devices ────────────────────────────────────────────────────────
  describe('GET /api/devices', () => {
    it('returns 200 with devices list', async () => {
      mockDeviceApplicationService.listDevicesPaginated.mockResolvedValueOnce({
        devices: [],
        pagination: { page: 1, limit: 50, total: 0, totalPages: 0 },
      });
      const res = await request(app).get('/api/devices');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('data');
      expect(Array.isArray(res.body.data)).toBe(true);
    });

    it('returns 200 with pagination info', async () => {
      mockDeviceApplicationService.listDevicesPaginated.mockResolvedValueOnce({
        devices: [
          { id: 'd1', name: 'Laptop-001', platform: 'windows', status: 'active' },
        ],
        pagination: { page: 1, limit: 50, total: 1, totalPages: 1 },
      });
      const res = await request(app).get('/api/devices');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('pagination');
    });

    it('supports query parameters', async () => {
      mockDeviceApplicationService.listDevicesPaginated.mockResolvedValueOnce({
        devices: [],
        pagination: { page: 1, limit: 10, total: 0, totalPages: 0 },
      });
      const res = await request(app).get('/api/devices?page=1&limit=10&platform=windows');
      expect(res.status).toBe(200);
    });
  });

  // ─── POST /api/devices ───────────────────────────────────────────────────────
  describe('POST /api/devices', () => {
    it('returns 201 when creating a device', async () => {
      mockDeviceApplicationService.createDeviceRecord.mockResolvedValueOnce({
        id: 'device-new-1',
        name: 'New-Device',
        platform: 'macos',
        status: 'pending',
        enrolledAt: new Date().toISOString(),
      });

      const res = await request(app)
        .post('/api/devices')
        .send({ name: 'New-Device', platform: 'macos' });
      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('data');
      expect(res.body.data).toHaveProperty('id');
    });

    it('returns 500 when device creation fails', async () => {
      mockDeviceApplicationService.createDeviceRecord.mockRejectedValueOnce(new Error('DB error'));

      const res = await request(app)
        .post('/api/devices')
        .send({ name: 'Bad-Device' });
      expect(res.status).toBe(500);
      expect(res.body).toHaveProperty('error');
    });
  });

  // ─── GET /api/devices/:deviceId ──────────────────────────────────────────────
  describe('GET /api/devices/:deviceId', () => {
    it('returns 404 when device not found', async () => {
      mockDeviceApplicationService.getDeviceWithExtras.mockResolvedValueOnce(null);
      const res = await request(app).get('/api/devices/nonexistent-device-id');
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'Device not found');
    });

    it('returns 200 with device data when found', async () => {
      mockDeviceApplicationService.getDeviceWithExtras.mockResolvedValueOnce({
        id: 'device-123',
        name: 'LAPTOP-001',
        platform: 'windows',
        status: 'active',
        complianceStatus: 'compliant',
        enrolledAt: new Date().toISOString(),
      });

      const res = await request(app).get('/api/devices/device-123');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('data');
      expect(res.body.data).toHaveProperty('id', 'device-123');
    });
  });

  // ─── POST /api/enrollment/initiate ──────────────────────────────────────────
  describe('POST /api/enrollment/initiate', () => {
    it('returns 201 with enrollment token on success', async () => {
      service.enrollmentService.initiateEnrollment.mockResolvedValueOnce({
        enrollmentId: 'enroll-abc123',
        token: 'tok-xyz789',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        status: 'pending',
      });

      const res = await request(app)
        .post('/api/enrollment/initiate')
        .send({ deviceName: 'Corp-Laptop', platform: 'windows', userId: 'user-1' });
      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('success', true);
    });

    it('returns 500 when enrollment fails', async () => {
      service.enrollmentService.initiateEnrollment.mockRejectedValueOnce(new Error('Enrollment error'));

      const res = await request(app)
        .post('/api/enrollment/initiate')
        .send({ deviceName: 'Test-Device' });
      expect(res.status).toBe(500);
    });
  });

  // ─── GET /api/compliance/violations ─────────────────────────────────────────
  describe('GET /api/compliance/violations', () => {
    it('returns 200 with violations list', async () => {
      service.complianceScanner.getViolations.mockResolvedValueOnce([
        {
          id: 'v-1',
          deviceId: 'device-123',
          rule: 'encryption_required',
          severity: 'high',
          description: 'Device encryption not enabled',
        },
      ]);

      const res = await request(app).get('/api/compliance/violations');
      expect(res.status).toBe(200);
    });
  });

  // ─── GET /api/v1/agents/connected ────────────────────────────────────────────
  describe('GET /api/v1/agents/connected', () => {
    it('returns 200 with connected agents', async () => {
      const res = await request(app).get('/api/v1/agents/connected');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('total');
      expect(res.body).toHaveProperty('agents');
      expect(Array.isArray(res.body.agents)).toBe(true);
    });
  });

  // ─── GET /api/devices/:deviceId/stammdaten ────────────────────────────────────
  describe('GET /api/devices/:deviceId/stammdaten', () => {
    it('returns 200 with stammdaten (DB not available)', async () => {
      const res = await request(app).get('/api/devices/device-123/stammdaten');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('data');
    });
  });

  // ─── POST /api/agent/policy/apply ────────────────────────────────────────────
  describe('POST /api/agent/policy/apply', () => {
    it('returns 200 for policy apply request', async () => {
      const res = await request(app)
        .post('/api/agent/policy/apply')
        .send({ deviceId: 'device-123', policy: { id: 'policy-1', type: 'security' } });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  // ─── GET /api/agent/policy/status/:deviceId ───────────────────────────────────
  describe('GET /api/agent/policy/status/:deviceId', () => {
    it('returns 200 with policy status for device', async () => {
      const res = await request(app).get('/api/agent/policy/status/device-123');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  // ─── PUT /api/devices/:deviceId ─────────────────────────────────────────────
  describe('PUT /api/devices/:deviceId', () => {
    it('returns 200 with updated device on success', async () => {
      mockDeviceApplicationService.updateDeviceRecord.mockResolvedValueOnce({
        id: 'device-123',
        name: 'Updated-Laptop',
        platform: 'windows',
        status: 'active',
      });

      const res = await request(app)
        .put('/api/devices/device-123')
        .send({ name: 'Updated-Laptop', status: 'active' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('data');
    });

    it('returns 500 when update fails', async () => {
      mockDeviceApplicationService.updateDeviceRecord.mockRejectedValueOnce(new Error('DB error'));

      const res = await request(app)
        .put('/api/devices/device-123')
        .send({ name: 'Bad' });
      expect(res.status).toBe(500);
      expect(res.body).toHaveProperty('error');
    });
  });

  // ─── DELETE /api/devices/:deviceId ──────────────────────────────────────────
  describe('DELETE /api/devices/:deviceId', () => {
    it('returns 200 on successful deletion', async () => {
      // deviceManager.deleteDevice resolves true on success, false when missing
      mockDeviceApplicationService.deleteDeviceRecord.mockResolvedValueOnce(true);

      const res = await request(app).delete('/api/devices/device-123');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });

    it('returns 500 when deletion fails', async () => {
      mockDeviceApplicationService.deleteDeviceRecord.mockRejectedValueOnce(new Error('Device locked'));

      const res = await request(app).delete('/api/devices/device-456');
      expect(res.status).toBe(500);
      expect(res.body).toHaveProperty('error');
    });
  });

  // ─── POST /api/v1/devices/:deviceId/commands ────────────────────────────────
  describe('POST /api/v1/devices/:deviceId/commands', () => {
    it('returns 200 with queued_offline status when device is not connected via WS', async () => {
      const res = await request(app)
        .post('/api/v1/devices/device-offline/commands')
        .send({ command_type: 'run_script', data: { script: 'echo hello' } });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('status');
      expect(['delivered', 'queued_offline']).toContain(res.body.status);
      expect(res.body).toHaveProperty('deviceId', 'device-offline');
    });

    it('returns 200 even without a body (graceful no-op command)', async () => {
      const res = await request(app)
        .post('/api/v1/devices/device-abc/commands')
        .send({});
      expect(res.status).toBe(200);
    });
  });

  // ─── GET /api/compliance/scan/:deviceId ────────────────────────────────────
  describe('GET /api/compliance/scan/:deviceId', () => {
    it('returns 200 with compliance scan result', async () => {
      const res = await request(app).get('/api/compliance/scan/device-123');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('data');
    });
  });

  // ─── GET /api/compliance/violations ── additional cases ─────────────────────
  describe('GET /api/compliance/violations — additional cases', () => {
    it('returns 200 with empty array when no violations exist', async () => {
      // getViolations returns { violations, pagination }; the handler spreads it
      service.complianceScanner.getViolations.mockResolvedValueOnce({
        violations: [], pagination: { page: 1, limit: 50, total: 0 },
      });
      const res = await request(app).get('/api/compliance/violations');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(Array.isArray(res.body.violations)).toBe(true);
    });
  });

  // ─── POST /api/devices/:deviceId/install-app ────────────────────────────────
  describe('POST /api/devices/:deviceId/install-app', () => {
    it('returns 400 when neither packageId nor downloadUrl is provided', async () => {
      const res = await request(app)
        .post('/api/devices/device-123/install-app')
        .send({ appId: 'app-1', appName: 'My App' });
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error');
    });

    it('returns 200 with jobId when packageId is provided', async () => {
      const res = await request(app)
        .post('/api/devices/device-123/install-app')
        .send({ appId: 'app-1', appName: 'My App', packageId: 'com.example.app', format: 'msi', version: '1.0.0' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('jobId');
      expect(res.body).toHaveProperty('status');
    });

    it('returns 200 with jobId when downloadUrl is provided', async () => {
      const res = await request(app)
        .post('/api/devices/device-123/install-app')
        .send({ appId: 'app-2', downloadUrl: 'https://example.com/app.msi' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('jobId');
    });
  });

  // ─── GET /api/devices/:deviceId/install-jobs ────────────────────────────────
  describe('GET /api/devices/:deviceId/install-jobs', () => {
    it('returns 200 with array of install jobs', async () => {
      const res = await request(app).get('/api/devices/device-123/install-jobs');
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });
  });

  // ─── GET /api/v1/agents/download/:platform ──────────────────────────────────
  describe('GET /api/v1/agents/download/:platform', () => {
    it('returns 400 for an unknown platform', async () => {
      const res = await request(app).get('/api/v1/agents/download/solaris');
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error');
    });

    it('returns 404 when agent file is not present on disk', async () => {
      // Agent scripts do not exist in the test environment
      const res = await request(app).get('/api/v1/agents/download/windows');
      expect([200, 404]).toContain(res.status);
    });
  });

  // ─── POST /api/enrollment/complete ──────────────────────────────────────────
  describe('POST /api/enrollment/complete', () => {
    it('returns 200 on successful completion', async () => {
      service.enrollmentService.completeEnrollment.mockResolvedValueOnce({
        deviceId: 'device-999',
        status: 'enrolled',
      });
      const res = await request(app)
        .post('/api/enrollment/complete')
        .send({ enrollmentId: 'enroll-123', token: 'tok-xyz789' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });

    it('returns 500 when completion fails', async () => {
      service.enrollmentService.completeEnrollment.mockRejectedValueOnce(new Error('Token expired'));
      const res = await request(app)
        .post('/api/enrollment/complete')
        .send({ enrollmentId: 'enroll-bad' });
      expect(res.status).toBe(500);
    });
  });

  // ─── POST /api/backup/restore ─────────────────────────────────────────────
  describe('POST /api/backup/restore', () => {
    it('returns 400 when backupId is missing', async () => {
      const res = await request(app)
        .post('/api/backup/restore')
        .send({});
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error');
    });

    it('returns 200 when backupId is provided', async () => {
      const res = await request(app)
        .post('/api/backup/restore')
        .send({ backupId: 'bak-001' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  // ─── POST /api/dr/failover/execute ──────────────────────────────────────────
  describe('POST /api/dr/failover/execute', () => {
    it('returns 400 when confirm is not true', async () => {
      const res = await request(app)
        .post('/api/dr/failover/execute')
        .send({ confirm: false });
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error');
    });

    it('returns 200 when confirm is true', async () => {
      const res = await request(app)
        .post('/api/dr/failover/execute')
        .send({ confirm: true });
      expect(res.status).toBe(200);
    });
  });

  // ─── POST /api/reports/generate ─────────────────────────────────────────────
  describe('POST /api/reports/generate', () => {
    it('returns 400 when template or format is missing', async () => {
      const res = await request(app)
        .post('/api/reports/generate')
        .send({ template: 'compliance' });
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error');
    });

    it('returns 200 when template and format are provided', async () => {
      const res = await request(app)
        .post('/api/reports/generate')
        .send({ template: 'compliance', format: 'pdf' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });
});
