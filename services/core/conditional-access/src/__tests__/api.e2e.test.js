'use strict';

/**
 * E2E API tests for the Conditional Access service.
 *
 * Context: src/index.js had an unresolved git merge-conflict marker
 * (startBackgroundServices(), around line 418) that made the whole file a
 * syntax error — the service could not even be required, let alone start.
 * Fixing that surfaced two further "the service still can't actually boot"
 * bugs that this suite guards against regressing:
 *   - src/controllers/DeploymentController.js, PIMController.js, and
 *     EmergencyAccessController.js were required by index.js but did not
 *     exist on disk (MODULE_NOT_FOUND).
 *   - `const rateLimitMiddleware = require('./middleware/rateLimit')`
 *     imported the whole `{ rateLimitMiddleware, strictRateLimit, ... }`
 *     exports object instead of destructuring it, so
 *     `app.use(rateLimitMiddleware)` threw
 *     "app.use() requires a middleware function" the moment the service
 *     was constructed.
 *
 * `pg` is mocked with a small stateful fake so the DB-backed persistence
 * paths (encryption recovery keys, PIM break-glass audit, emergency-access
 * break-glass audit) can be exercised without a real Postgres — following
 * the same pattern used by least-privilege's and oauth-provider's
 * api.e2e.test.js suites. `oidcAuth` is mocked the same way least-privilege
 * does it: the bearer token is parsed as JSON straight into req.user, so
 * each test can supply whatever identity it needs while still exercising
 * the real 401 (missing/invalid token) behavior at the route level.
 *
 * Scope: this does not attempt to cover all routes. It proves (a) the
 * service now constructs and mounts its full route tree without throwing,
 * and (b) the specific persistence gaps named in the audit — encryption
 * recovery keys, and break-glass audit (both the PIM and Emergency-Access
 * variants) — actually reach the DB layer when one is configured, and fall
 * back to in-memory storage without crashing when it is not.
 */

// ─── Mock pg BEFORE requiring the app ─────────────────────────────────────
jest.mock('pg', () => {
  const fakeTables = {
    recoveryKeys: new Map(),   // device_id -> row
    breakGlassAudit: [],       // append-only rows
  };

  const mockPool = {
    query: jest.fn(async (sql, params = []) => {
      const s = String(sql).trim();

      if (s === 'SELECT 1') return { rows: [{ '?column?': 1 }] };

      if (s.startsWith('INSERT INTO encryption_recovery_keys')) {
        const [deviceId, keyEncrypted, storedAt] = params;
        fakeTables.recoveryKeys.set(deviceId, {
          device_id: deviceId,
          key_encrypted: keyEncrypted,
          stored_at: storedAt,
          access_count: 0,
          last_accessed: null,
        });
        return { rows: [] };
      }

      if (s.startsWith('UPDATE encryption_recovery_keys')) {
        const [deviceId] = params;
        const row = fakeTables.recoveryKeys.get(deviceId);
        if (!row) return { rows: [] };
        row.access_count += 1;
        row.last_accessed = new Date();
        return { rows: [{ key_encrypted: row.key_encrypted, stored_at: row.stored_at, access_count: row.access_count }] };
      }

      if (s.startsWith('INSERT INTO break_glass_audit')) {
        const [sessionId, userId, reason, approverId, startedAt, endedAt, actions] = params;
        const row = {
          id: fakeTables.breakGlassAudit.length + 1,
          session_id: sessionId,
          user_id: userId,
          reason,
          approver_id: approverId,
          started_at: startedAt,
          ended_at: endedAt,
          actions,
          created_at: new Date(),
        };
        fakeTables.breakGlassAudit.push(row);
        return { rows: [row] };
      }

      // Migrations (CREATE TABLE/INDEX/RULE ...) and anything else: no-op OK.
      return { rows: [] };
    }),
    connect: jest.fn().mockResolvedValue({ query: jest.fn(), release: jest.fn() }),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  };

  return { Pool: jest.fn(() => mockPool), __fakeTables: fakeTables, __mockPool: mockPool };
});

// ─── Mock oidcAuth BEFORE requiring the app ────────────────────────────────
// jose verifies against a live JWKS endpoint that isn't reachable in tests.
// Mirrors services/core/least-privilege/src/__tests__/api.e2e.test.js.
jest.mock('../middleware/oidcAuth', () => {
  function oidcAuth({ skipPaths = [] } = {}) {
    return (req, res, next) => {
      if (skipPaths.some(p => req.path === p || req.path.startsWith(p + '/') || req.path === p)) return next();
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'unauthorized' });
      }
      try {
        req.user = JSON.parse(auth.slice(7));
      } catch {
        return res.status(403).json({ error: 'invalid_token' });
      }
      next();
    };
  }
  return { oidcAuth };
});

process.env.EVENT_BUS_TRANSPORT = 'memory';

const request = require('supertest');
const pg = require('pg');

function bearer(user) {
  return `Bearer ${JSON.stringify(user)}`;
}
const ADMIN = { id: 'admin-1', sub: 'admin-1', roles: ['admin'] };
const adminAuth = () => bearer(ADMIN);

let ConditionalAccessService;
let svc;
let app;

beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});

  ConditionalAccessService = require('../index');
  svc = new ConditionalAccessService();
  app = svc.app;

  // Avoid real file I/O from the audit logger / winston during route tests —
  // the audit *calls* being made is exercised separately where relevant.
  svc.auditLogger.logEvent = jest.fn().mockResolvedValue('mock-event-id');
});

afterAll(() => {
  jest.restoreAllMocks();
});

beforeEach(() => {
  pg.__mockPool.query.mockClear();
});

// ─── Service boots and mounts routes ───────────────────────────────────────

describe('service construction', () => {
  it('constructs without throwing and exposes an Express app', () => {
    expect(svc).toBeInstanceOf(ConditionalAccessService);
    expect(typeof app).toBe('function'); // Express app is a request handler function
  });
});

describe('GET /health', () => {
  it('is reachable without auth', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'healthy', service: 'conditional-access' });
  });
});

describe('GET /discovery', () => {
  it('lists all mounted endpoint groups, including the previously-missing controllers', async () => {
    const res = await request(app).get('/discovery');
    expect(res.status).toBe(200);
    expect(res.body.endpoints).toMatchObject({
      deployment: '/api/v1/deployment',
      pim: '/api/v1/pim',
      emergencyAccess: '/api/v1/emergency-access',
    });
  });
});

describe('authentication gate', () => {
  it('rejects unauthenticated requests to protected API routes', async () => {
    const res = await request(app).get('/api/v1/pim/roles');
    expect(res.status).toBe(401);
  });

  it('allows authenticated requests through to the route handler', async () => {
    const res = await request(app).get('/api/v1/pim/roles').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBeGreaterThan(0);
  });
});

describe('route mounting for the previously-missing controllers', () => {
  it('DeploymentController: GET /api/v1/deployment/profiles responds (not 404)', async () => {
    const res = await request(app).get('/api/v1/deployment/profiles').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBeGreaterThan(0); // 3 default profiles
  });

  it('PIMController: GET /api/v1/pim/roles responds (not 404)', async () => {
    const res = await request(app).get('/api/v1/pim/roles').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
  });

  it('EmergencyAccessController: GET /api/v1/emergency-access/accounts responds (not 404)', async () => {
    const res = await request(app).get('/api/v1/emergency-access/accounts').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBeGreaterThan(0); // 3 default emergency accounts
  });
});

// ─── Persistence: encryption recovery keys ─────────────────────────────────

describe('Encryption recovery-key persistence (DB-first, in-memory fallback)', () => {
  const deviceId = 'device-recovery-key-test';

  beforeEach(() => {
    // Register the device the way POST /encryption/status would, without
    // paying for the (multi-second, simulated) BitLocker enable flow.
    svc.encryptionManager.deviceEncryptionStates.set(deviceId, {
      deviceId,
      platform: 'windows',
      status: { encrypted: true },
      lastChecked: new Date(),
      policy: svc.encryptionManager.getApplicablePolicy({ operatingSystem: 'windows' }),
    });
  });

  it('writes the recovery key to the DB (encrypted, not plaintext) and reads it back decrypted over HTTP', async () => {
    const plaintextKey = '111111-222222-333333-444444-555555-666666-777777-888888';
    await svc.encryptionManager.storeRecoveryKey(deviceId, plaintextKey);

    // The DB row must exist and must NOT contain the plaintext key.
    const row = pg.__fakeTables.recoveryKeys.get(deviceId);
    expect(row).toBeDefined();
    expect(row.key_encrypted).toEqual(expect.any(String));
    expect(row.key_encrypted).not.toContain(plaintextKey);

    const res = await request(app)
      .post('/api/v1/encryption/recovery-key')
      .set('Authorization', adminAuth())
      .send({ deviceId, justification: 'lost device, unlocking for IT support' });

    expect(res.status).toBe(200);
    expect(res.body.data.recoveryKey).toBe(plaintextKey);

    // Confirms the read actually went through the DB layer, not just memory.
    expect(pg.__mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining('UPDATE encryption_recovery_keys'),
      expect.arrayContaining([deviceId])
    );
  });

  it('rotate-key persists a new encrypted value under the DB row', async () => {
    await svc.encryptionManager.storeRecoveryKey(deviceId, 'old-key-000');
    const before = pg.__fakeTables.recoveryKeys.get(deviceId).key_encrypted;

    const res = await request(app)
      .post(`/api/v1/encryption/devices/${deviceId}/rotate-key`)
      .set('Authorization', adminAuth());

    expect(res.status).toBe(200);
    const after = pg.__fakeTables.recoveryKeys.get(deviceId).key_encrypted;
    expect(after).toBeDefined();
    expect(after).not.toBe(before);
  });

  it('falls back to in-memory storage (and still works) when the DB write fails', async () => {
    const originalQuery = pg.__mockPool.query.getMockImplementation();
    pg.__mockPool.query.mockImplementation(async (sql) => {
      if (String(sql).startsWith('INSERT INTO encryption_recovery_keys')) {
        throw new Error('simulated DB outage');
      }
      return originalQuery(sql);
    });

    const plaintextKey = 'fallback-key-999';
    await expect(svc.encryptionManager.storeRecoveryKey(deviceId, plaintextKey)).resolves.not.toThrow();

    // No DB row (write failed) — but the in-memory cache must have it.
    const cached = svc.encryptionManager.recoveryKeys.get(deviceId);
    expect(cached).toBeDefined();

    pg.__mockPool.query.mockImplementation(async (sql) => {
      if (String(sql).startsWith('UPDATE encryption_recovery_keys')) {
        return { rows: [] }; // DB has no row for this device
      }
      return originalQuery(sql);
    });

    const result = await svc.encryptionManager.getRecoveryKey(deviceId);
    expect(result.key).toBe(plaintextKey);

    pg.__mockPool.query.mockImplementation(originalQuery);
  });
});

// ─── Persistence: PIM break-glass audit ────────────────────────────────────

describe('PIM break-glass persistence (WORM break_glass_audit)', () => {
  it('persists an activation row and a termination row via the real HTTP endpoints', async () => {
    const reqRes = await request(app)
      .post('/api/v1/pim/breakglass/request')
      .set('Authorization', adminAuth())
      .send({ userId: 'user-1', reason: 'prod outage', systemsAffected: ['db-1'], estimatedDuration: 30 });
    expect(reqRes.status).toBe(201);
    const { breakGlassId } = reqRes.body;
    expect(breakGlassId).toBeDefined();

    const activateRes = await request(app)
      .post(`/api/v1/pim/breakglass/${breakGlassId}/activate`)
      .set('Authorization', adminAuth())
      .send({ managerId: 'manager-1' }); // must differ from requester (dual control)
    expect(activateRes.status).toBe(200);
    expect(activateRes.body.status).toBe('ACTIVE');

    let auditRows = pg.__fakeTables.breakGlassAudit.filter(r => r.session_id === breakGlassId);
    expect(auditRows).toHaveLength(1);
    expect(auditRows[0].ended_at).toBeNull();
    expect(auditRows[0].approver_id).toBe('manager-1');

    const terminateRes = await request(app)
      .post(`/api/v1/pim/breakglass/${breakGlassId}/terminate`)
      .set('Authorization', adminAuth())
      .send({ terminatedBy: 'manager-1', outcome: 'resolved' });
    expect(terminateRes.status).toBe(200);

    auditRows = pg.__fakeTables.breakGlassAudit.filter(r => r.session_id === breakGlassId);
    expect(auditRows).toHaveLength(2); // append-only: activation row + termination row
    expect(auditRows[1].ended_at).not.toBeNull();
  });

  it('still grants break-glass access when the audit DB write fails (best-effort, non-blocking)', async () => {
    const originalQuery = pg.__mockPool.query.getMockImplementation();
    pg.__mockPool.query.mockImplementation(async (sql) => {
      if (String(sql).startsWith('INSERT INTO break_glass_audit')) {
        throw new Error('simulated DB outage');
      }
      return originalQuery(sql);
    });

    const reqRes = await request(app)
      .post('/api/v1/pim/breakglass/request')
      .set('Authorization', adminAuth())
      .send({ userId: 'user-2', reason: 'urgent', systemsAffected: [], estimatedDuration: 15 });
    const { breakGlassId } = reqRes.body;

    const activateRes = await request(app)
      .post(`/api/v1/pim/breakglass/${breakGlassId}/activate`)
      .set('Authorization', adminAuth())
      .send({ managerId: 'manager-2' });

    expect(activateRes.status).toBe(200);
    expect(activateRes.body.status).toBe('ACTIVE');

    pg.__mockPool.query.mockImplementation(originalQuery);
  });
});

// ─── Persistence: Emergency Access (break-glass) audit ─────────────────────

describe('Emergency Access break-glass persistence (WORM break_glass_audit)', () => {
  it('persists a grant row and a termination row via the real HTTP endpoints', async () => {
    const reqRes = await request(app)
      .post('/api/v1/emergency-access/request')
      .set('Authorization', adminAuth())
      .send({
        requesterInfo: { userId: 'user-em-1', name: 'Alice', role: 'IT_SUPPORT', location: 'HQ', deviceId: 'dev-1' },
        emergencyDetails: {
          type: 'system-outage',
          urgency: 'CRITICAL', // single required approver: IT_MANAGER
          justification: 'core switch down',
          estimatedDuration: 1,
          requiredAccess: ['NETWORK_ADMIN'],
          affectedSystems: ['switch-1'],
        },
      });
    expect(reqRes.status).toBe(201);
    const { requestId } = reqRes.body.data;
    expect(requestId).toBeDefined();

    const approveRes = await request(app)
      .post(`/api/v1/emergency-access/${requestId}/approve`)
      .set('Authorization', adminAuth())
      .send({
        approverInfo: { userId: 'approver-em-1', name: 'Bob', role: 'IT_MANAGER' },
        approvalDetails: { justification: 'confirmed outage' },
      });
    expect(approveRes.status).toBe(200);
    const { accessId } = approveRes.body.data;
    expect(accessId).toBeDefined();

    let auditRows = pg.__fakeTables.breakGlassAudit.filter(r => r.session_id === accessId);
    expect(auditRows).toHaveLength(1);
    expect(auditRows[0].ended_at).toBeNull();

    const terminateRes = await request(app)
      .post(`/api/v1/emergency-access/sessions/${accessId}/terminate`)
      .set('Authorization', adminAuth())
      .send({ reason: 'restored' });
    expect(terminateRes.status).toBe(200);

    auditRows = pg.__fakeTables.breakGlassAudit.filter(r => r.session_id === accessId);
    expect(auditRows).toHaveLength(2);
    expect(auditRows[1].ended_at).not.toBeNull();
  });
});

// ─── db.js: real migration runner ──────────────────────────────────────────

describe('db.js initDb()/runMigrations()', () => {
  it('marks the DB available and executes all three migration files', async () => {
    jest.resetModules();
    // Re-mock pg for the isolated module registry created by resetModules().
    jest.doMock('pg', () => {
      const mockPool = {
        query: jest.fn().mockResolvedValue({ rows: [] }),
        on: jest.fn(),
      };
      return { Pool: jest.fn(() => mockPool) };
    });

    const db = require('../db');
    expect(db.isAvailable()).toBe(false);

    await db.initDb();

    expect(db.isAvailable()).toBe(true);
    const calledSql = db.query.mock ? null : null; // (kept for clarity; real assertion below)
    const allSql = require('pg').Pool.mock.results[0].value.query.mock.calls.map(c => c[0]);
    expect(allSql.some(s => s.includes('break_glass_audit'))).toBe(true);
    expect(allSql.some(s => s.includes('pim_sessions'))).toBe(true);
    expect(allSql.some(s => s.includes('encryption_recovery_keys'))).toBe(true);

    jest.dontMock('pg');
  });
});
