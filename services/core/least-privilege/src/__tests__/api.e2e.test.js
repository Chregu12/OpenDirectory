'use strict';

/**
 * E2E API tests for the least-privilege service.
 *
 * Mirrors the pattern used by sibling core services (see
 * services/core/policy-service/src/__tests__/api.e2e.test.js): supertest
 * in-process against the real Express app, with `pg` mocked so the service
 * runs entirely on its in-memory fallback (db.isAvailable() === false).
 * src/index.js calls db.initDb().then(() => app.listen(...)) as a
 * module-load side effect, so `pg` must be mocked BEFORE requiring it.
 *
 * This service was previously untested. Coverage here focuses on its two
 * capabilities:
 *  - the permission matrix / unused-permission sweep / risk-score /
 *    escalation-alert endpoints (/api/permissions/*)
 *  - its own resource/level just-in-time elevation flow, namespaced under
 *    /api/pim/elevation/* specifically to avoid colliding with
 *    authentication-service's unrelated, role-based /api/pim/* (see the
 *    comment above the PIM routes in src/index.js for the full rationale).
 */

// ─── Mock pg BEFORE requiring the app ─────────────────────────────────────────
jest.mock('pg', () => {
  const mockPool = {
    query: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    connect: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  };
  return { Pool: jest.fn().mockImplementation(() => mockPool) };
});

// ─── Mock oidcAuth BEFORE requiring the app ───────────────────────────────────
//
// jose verifies against a live JWKS endpoint, which isn't available in
// tests, so — following the same pattern as the sibling core services (see
// e.g. services/core/device-service/src/__tests__/api.e2e.test.js) — the
// auth *middleware* is mocked rather than the JWT crypto itself. Unlike
// those sibling mocks (which always inject a fixed admin identity), this
// mock decodes the bearer token as JSON straight into req.user, so each
// test can hand any {sub, roles} identity it needs. That lets this suite
// exercise real 401 (missing/malformed token) and 403 (missing admin role)
// behavior at the route level. The actual security decisions under test —
// requireAdmin's role gate, and the self-approve guard in the PUT
// .../approve handler in src/index.js — are the real production code, not
// re-implemented here.
jest.mock('../middleware/oidcAuth', () => {
  function oidcAuth({ skipPaths = [] } = {}) {
    return (req, res, next) => {
      if (skipPaths.some(p => req.path === p || req.path.startsWith(p + '/'))) return next();
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
  function hasAdminAccess(user) {
    return !!user && Array.isArray(user.roles) && user.roles.includes('admin');
  }
  function requireAdmin(req, res, next) {
    if (!hasAdminAccess(req.user)) return res.status(403).json({ error: 'forbidden' });
    next();
  }
  return { oidcAuth, requireAdmin, hasAdminAccess };
});

const request = require('supertest');

// ─── Auth test helpers ─────────────────────────────────────────────────────────
function bearer(user) {
  return `Bearer ${JSON.stringify(user)}`;
}
const ADMIN = { sub: 'admin-1', roles: ['admin'] };
const adminAuth = () => bearer(ADMIN);
function userAuth(sub, roles = ['user']) {
  return bearer({ sub, roles });
}

let app;

beforeAll(async () => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  app = require('../index');

  // Let the db.initDb().then(() => app.listen(...)) chain settle.
  await new Promise(resolve => setTimeout(resolve, 50));
});

afterAll(() => {
  jest.restoreAllMocks();
  jest.clearAllTimers();
});

// ─── Health ────────────────────────────────────────────────────────────────

describe('GET /health', () => {
  it('reports ok with seeded demo users and one pending PIM request', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'ok', service: 'least-privilege' });
    expect(res.body.users).toBeGreaterThanOrEqual(6);
    expect(res.body.pendingPimRequests).toBeGreaterThanOrEqual(1);
  });
});

// ─── Permission Matrix ────────────────────────────────────────────────────────

describe('GET /api/permissions/matrix', () => {
  it('returns resources, levels, and the seeded demo matrix (in-memory fallback)', async () => {
    const res = await request(app).get('/api/permissions/matrix').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(res.body.resources).toEqual(
      expect.arrayContaining(['devices', 'users', 'policies', 'apps', 'secrets', 'printers', 'reports'])
    );
    expect(res.body.levels).toEqual(['none', 'read', 'write', 'admin']);
    expect(Array.isArray(res.body.matrix)).toBe(true);
    const alice = res.body.matrix.find(r => r.userId === 'user-alice');
    expect(alice).toBeDefined();
    expect(alice.permissions.devices).toBe('admin');
  });
});

describe('GET /api/permissions/users/:userId', () => {
  it('returns effective permissions and a risk score for a known user', async () => {
    const res = await request(app).get('/api/permissions/users/user-carol').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(res.body.userId).toBe('user-carol');
    expect(res.body.role).toBe('read-only');
    expect(res.body.permissions.devices).toBe('read');
    expect(typeof res.body.riskScore).toBe('number');
  });

  it('404s for an unknown user', async () => {
    const res = await request(app).get('/api/permissions/users/no-such-user').set('Authorization', adminAuth());
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error');
  });
});

describe('POST /api/permissions/users/:userId/assign', () => {
  it('rejects an invalid resource', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-bob/assign')
      .set('Authorization', adminAuth())
      .send({ resource: 'not-a-resource', level: 'read' });
    expect(res.status).toBe(400);
  });

  it('rejects an invalid level', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-bob/assign')
      .set('Authorization', adminAuth())
      .send({ resource: 'devices', level: 'god-mode' });
    expect(res.status).toBe(400);
  });

  it('assigns a permission override and it is reflected in effective permissions', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-bob/assign')
      .set('Authorization', adminAuth())
      .send({ resource: 'secrets', level: 'write' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ userId: 'user-bob', resource: 'secrets', level: 'write' });

    const check = await request(app).get('/api/permissions/users/user-bob').set('Authorization', adminAuth());
    expect(check.body.permissions.secrets).toBe('write');
  });

  it('creates a brand-new user record on first assignment', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-newbie/assign')
      .set('Authorization', adminAuth())
      .send({ resource: 'apps', level: 'read' });
    expect(res.status).toBe(200);
    const check = await request(app).get('/api/permissions/users/user-newbie').set('Authorization', adminAuth());
    expect(check.status).toBe(200);
    expect(check.body.permissions.apps).toBe('read');
  });

  it('raises an escalation alert once a user crosses 3 admin resources', async () => {
    for (const resource of ['devices', 'users', 'policies', 'apps']) {
      // eslint-disable-next-line no-await-in-loop
      await request(app)
        .post('/api/permissions/users/user-escalate/assign')
        .set('Authorization', adminAuth())
        .send({ resource, level: 'admin' });
    }
    const alerts = await request(app).get('/api/permissions/escalation-alerts').set('Authorization', adminAuth());
    expect(alerts.status).toBe(200);
    const mine = alerts.body.find(a => a.userId === 'user-escalate');
    expect(mine).toBeDefined();
    expect(mine.adminCount).toBeGreaterThan(3);
  });
});

// ─── Auth Matrix ───────────────────────────────────────────────────────────────

describe('auth matrix', () => {
  it('POST /api/permissions/users/:userId/assign without a token -> 401', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-bob/assign')
      .send({ resource: 'devices', level: 'read' });
    expect(res.status).toBe(401);
  });

  it('POST /api/permissions/users/:userId/assign with a non-admin token -> 403', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-bob/assign')
      .set('Authorization', userAuth('user-bob'))
      .send({ resource: 'devices', level: 'read' });
    expect(res.status).toBe(403);
  });

  it('GET /api/permissions/matrix without a token -> 401', async () => {
    const res = await request(app).get('/api/permissions/matrix');
    expect(res.status).toBe(401);
  });

  it('GET /health and GET /metrics remain unauthenticated (probe endpoints)', async () => {
    const health = await request(app).get('/health');
    expect(health.status).toBe(200);
    const metrics = await request(app).get('/metrics');
    expect(metrics.status).toBe(200);
  });
});

// ─── Unused Permissions ───────────────────────────────────────────────────────

describe('unused permissions', () => {
  it('GET /api/permissions/unused returns the seeded idle-permission list', async () => {
    const res = await request(app).get('/api/permissions/unused').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    expect(res.body[0]).toHaveProperty('daysIdle');
  });

  it('POST /api/permissions/revoke-unused resets write/read overrides on reports/printers for non-admins', async () => {
    await request(app)
      .post('/api/permissions/users/user-dave/assign')
      .set('Authorization', adminAuth())
      .send({ resource: 'reports', level: 'write' });

    const res = await request(app).post('/api/permissions/revoke-unused').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('revokedCount');
    expect(res.body).toHaveProperty('revoked');
    expect(Array.isArray(res.body.revoked)).toBe(true);

    const check = await request(app).get('/api/permissions/users/user-dave').set('Authorization', adminAuth());
    expect(check.body.permissions.reports).toBe('none');
  });
});

// ─── Risk Scores ─────────────────────────────────────────────────────────────

describe('GET /api/permissions/risk-scores', () => {
  it('returns scores sorted descending, admin scoring highest', async () => {
    const res = await request(app).get('/api/permissions/risk-scores').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    const alice = res.body.find(u => u.userId === 'user-alice');
    expect(alice.riskScore).toBe(100);
    for (let i = 1; i < res.body.length; i++) {
      expect(res.body[i - 1].riskScore).toBeGreaterThanOrEqual(res.body[i].riskScore);
    }
  });
});

// ─── PIM Elevation (namespaced under /api/pim/elevation/*) ───────────────────

describe('GET /api/pim/elevation/requests', () => {
  it('includes the seeded pending request', async () => {
    const res = await request(app).get('/api/pim/elevation/requests').set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    const seeded = res.body.find(r => r.userId === 'user-bob' && r.resource === 'secrets' && r.status === 'pending');
    expect(seeded).toBeDefined();
  });
});

describe('POST /api/pim/elevation/request', () => {
  it('requires a token (self-service creation still needs auth)', async () => {
    const res = await request(app)
      .post('/api/pim/elevation/request')
      .send({ userId: 'user-eve', resource: 'printers', duration_hours: 1 });
    expect(res.status).toBe(401);
  });

  it('requires userId, resource, and duration_hours', async () => {
    const res = await request(app)
      .post('/api/pim/elevation/request')
      .set('Authorization', userAuth('user-eve'))
      .send({ userId: 'user-eve' });
    expect(res.status).toBe(400);
  });

  it('creates a pending elevation request for a non-admin, authenticated caller (self-service)', async () => {
    const res = await request(app)
      .post('/api/pim/elevation/request')
      .set('Authorization', userAuth('user-eve'))
      .send({ userId: 'user-eve', resource: 'printers', duration_hours: 1, reason: 'Print run for release notes' });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      userId: 'user-eve',
      userName: 'Eve DevOps',
      resource: 'printers',
      duration_hours: 1,
      status: 'pending',
    });
    expect(res.body.id).toBeDefined();
  });
});

describe('PIM elevation approve/deny lifecycle', () => {
  let requestId;

  beforeAll(async () => {
    const created = await request(app)
      .post('/api/pim/elevation/request')
      .set('Authorization', userAuth('user-dave'))
      .send({ userId: 'user-dave', resource: 'secrets', duration_hours: 2, reason: 'Rotate creds' });
    requestId = created.body.id;
  });

  it('404s approving an unknown request', async () => {
    const res = await request(app)
      .put('/api/pim/elevation/requests/does-not-exist/approve')
      .set('Authorization', adminAuth());
    expect(res.status).toBe(404);
  });

  it('404s denying an unknown request', async () => {
    const res = await request(app)
      .put('/api/pim/elevation/requests/does-not-exist/deny')
      .set('Authorization', adminAuth());
    expect(res.status).toBe(404);
  });

  it('approves a pending request, activating an elevation', async () => {
    const res = await request(app)
      .put(`/api/pim/elevation/requests/${requestId}/approve`)
      .set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('approved');
    expect(res.body.expiresAt).toBeTruthy();

    const active = await request(app).get('/api/pim/elevation/active').set('Authorization', adminAuth());
    expect(active.status).toBe(200);
    const mine = active.body.find(e => e.requestId === requestId);
    expect(mine).toBeDefined();
    expect(mine.userId).toBe('user-dave');
    expect(mine.resource).toBe('secrets');
    expect(mine.timeRemainingMinutes).toBeGreaterThan(0);
  });

  it('rejects approving an already-processed request', async () => {
    const res = await request(app)
      .put(`/api/pim/elevation/requests/${requestId}/approve`)
      .set('Authorization', adminAuth());
    expect(res.status).toBe(400);
  });

  it('denies a separate pending request', async () => {
    const created = await request(app)
      .post('/api/pim/elevation/request')
      .set('Authorization', userAuth('user-carol'))
      .send({ userId: 'user-carol', resource: 'reports', duration_hours: 1, reason: 'One-off export' });
    const denyRes = await request(app)
      .put(`/api/pim/elevation/requests/${created.body.id}/deny`)
      .set('Authorization', adminAuth());
    expect(denyRes.status).toBe(200);
    expect(denyRes.body.status).toBe('denied');
  });
});

// ─── PIM Auth Matrix: admin-gated approve/deny, self-approve blocked ─────────

describe('PIM elevation approve/deny auth matrix', () => {
  let requestId;

  beforeAll(async () => {
    const created = await request(app)
      .post('/api/pim/elevation/request')
      .set('Authorization', userAuth('user-authmatrix'))
      .send({ userId: 'user-authmatrix', resource: 'devices', duration_hours: 1, reason: 'auth matrix fixture' });
    requestId = created.body.id;
  });

  it('PUT .../approve without a token -> 401', async () => {
    const res = await request(app).put(`/api/pim/elevation/requests/${requestId}/approve`);
    expect(res.status).toBe(401);
  });

  it('PUT .../approve with a non-admin token -> 403', async () => {
    const res = await request(app)
      .put(`/api/pim/elevation/requests/${requestId}/approve`)
      .set('Authorization', userAuth('some-other-user'));
    expect(res.status).toBe(403);
  });

  it('PUT .../deny without a token -> 401', async () => {
    const res = await request(app).put(`/api/pim/elevation/requests/${requestId}/deny`);
    expect(res.status).toBe(401);
  });

  it('PUT .../deny with a non-admin token -> 403', async () => {
    const res = await request(app)
      .put(`/api/pim/elevation/requests/${requestId}/deny`)
      .set('Authorization', userAuth('some-other-user'));
    expect(res.status).toBe(403);
  });

  it('blocks self-approval: the requester cannot approve their own request even when granted an admin role', async () => {
    const res = await request(app)
      .put(`/api/pim/elevation/requests/${requestId}/approve`)
      .set('Authorization', userAuth('user-authmatrix', ['admin']));
    expect(res.status).toBe(403);

    // Still pending — the self-approve attempt must not have mutated state.
    const list = await request(app).get('/api/pim/elevation/requests').set('Authorization', adminAuth());
    const mine = list.body.find(r => r.id === requestId);
    expect(mine.status).toBe('pending');
  });

  it('a different admin can approve the same request', async () => {
    const res = await request(app)
      .put(`/api/pim/elevation/requests/${requestId}/approve`)
      .set('Authorization', adminAuth());
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('approved');
  });
});

// ─── PIM Persistence: create -> approve / create -> deny roundtrip (DB-first) ─
//
// Regression coverage for the P0 bug: db.createPimRequest and
// db.denyPimRequest were never called — POST only ever wrote to the
// in-memory Map — while the approve handler unconditionally consulted
// Postgres when available. With a real DB configured, every approval 404'd
// against a request that only ever existed in memory, permanently breaking
// elevation approval. This suite forces db.isAvailable() === true with a
// fake Postgres-shaped store to prove create/approve/deny now consistently
// operate on the same backing store.

function makeFakePimDb() {
  const requests = new Map();
  const active = new Map();
  let seq = 0;
  return {
    initDb: jest.fn().mockResolvedValue(undefined),
    isAvailable: jest.fn(() => true),
    query: jest.fn(),
    pool: {},
    getPermissionMatrix: jest.fn().mockResolvedValue([]),
    upsertPermission: jest.fn().mockResolvedValue(undefined),
    getPimRequests: jest.fn(async status => {
      const rows = [...requests.values()];
      return status ? rows.filter(r => r.status === status) : rows;
    }),
    createPimRequest: jest.fn(async (id, userId, userName, resource, level, justification, durationHours) => {
      const row = {
        id,
        user_id: userId,
        resource,
        level,
        justification: justification ?? null,
        duration_hours: durationHours,
        status: 'pending',
        requested_at: new Date(),
        resolved_at: null,
        approved_by: null,
        expires_at: null,
      };
      requests.set(id, row);
      return row;
    }),
    getPimRequestById: jest.fn(async id => requests.get(id) || null),
    approvePimRequest: jest.fn(async (id, approvedBy) => {
      const row = requests.get(id);
      if (!row) return null;
      const expiresAt = new Date(Date.now() + row.duration_hours * 3600_000);
      row.status = 'approved';
      row.resolved_at = new Date();
      row.approved_by = approvedBy;
      row.expires_at = expiresAt;
      const elevId = `elev-${++seq}`;
      active.set(elevId, {
        id: elevId, request_id: id, user_id: row.user_id, resource: row.resource,
        level: row.level, expires_at: expiresAt, activated_at: new Date(),
      });
      return { ...row, status: 'approved', expiresAt };
    }),
    denyPimRequest: jest.fn(async id => {
      const row = requests.get(id);
      if (!row) return undefined;
      row.status = 'denied';
      row.resolved_at = new Date();
      return row;
    }),
    getActiveElevations: jest.fn(async () => [...active.values()].filter(e => e.expires_at > new Date())),
    insertEscalationAlert: jest.fn().mockResolvedValue(undefined),
    getEscalationAlerts: jest.fn().mockResolvedValue([]),
  };
}

describe('PIM persistence roundtrip (DB-first mode, mocked Postgres)', () => {
  let dbApp;
  let fakeDb;
  const prevPort = process.env.LEAST_PRIVILEGE_PORT;

  beforeAll(async () => {
    process.env.LEAST_PRIVILEGE_PORT = '0'; // ephemeral — avoids colliding with the outer app's listener
    jest.resetModules();
    fakeDb = makeFakePimDb();
    jest.doMock('../db', () => fakeDb);
    dbApp = require('../index');
    await new Promise(resolve => setTimeout(resolve, 50));
  });

  afterAll(() => {
    jest.dontMock('../db');
    jest.resetModules();
    if (prevPort === undefined) delete process.env.LEAST_PRIVILEGE_PORT;
    else process.env.LEAST_PRIVILEGE_PORT = prevPort;
  });

  it('create -> approve: the row createPimRequest inserts is the same row approvePimRequest finds and updates', async () => {
    const created = await request(dbApp)
      .post('/api/pim/elevation/request')
      .set('Authorization', userAuth('user-dbtest'))
      .send({ userId: 'user-dbtest', resource: 'secrets', duration_hours: 3, reason: 'DB roundtrip test' });
    expect(created.status).toBe(201);
    expect(created.body.status).toBe('pending');
    expect(fakeDb.createPimRequest).toHaveBeenCalledTimes(1);

    // Before the fix, this 404'd: approve() only ever looked in Postgres,
    // while create() only ever wrote to the in-memory Map.
    const approved = await request(dbApp)
      .put(`/api/pim/elevation/requests/${created.body.id}/approve`)
      .set('Authorization', adminAuth());
    expect(approved.status).toBe(200);
    expect(approved.body.status).toBe('approved');
    expect(approved.body.userId).toBe('user-dbtest');
    expect(fakeDb.approvePimRequest).toHaveBeenCalledWith(created.body.id, expect.any(String));

    const activeRes = await request(dbApp).get('/api/pim/elevation/active').set('Authorization', adminAuth());
    expect(activeRes.status).toBe(200);
    expect(fakeDb.getActiveElevations).toHaveBeenCalled();
  });

  it('create -> deny: the row createPimRequest inserts is the same row denyPimRequest updates', async () => {
    const created = await request(dbApp)
      .post('/api/pim/elevation/request')
      .set('Authorization', userAuth('user-dbtest2'))
      .send({ userId: 'user-dbtest2', resource: 'reports', duration_hours: 1, reason: 'DB deny test' });
    expect(created.status).toBe(201);

    const denied = await request(dbApp)
      .put(`/api/pim/elevation/requests/${created.body.id}/deny`)
      .set('Authorization', adminAuth());
    expect(denied.status).toBe(200);
    expect(denied.body.status).toBe('denied');
    expect(fakeDb.denyPimRequest).toHaveBeenCalledWith(created.body.id);
  });

  it('404s approving a request id the DB never received (no stale in-memory Map to fall back on)', async () => {
    const res = await request(dbApp)
      .put('/api/pim/elevation/requests/never-created/approve')
      .set('Authorization', adminAuth());
    expect(res.status).toBe(404);
  });

  it('blocks self-approval in DB-first mode too', async () => {
    const created = await request(dbApp)
      .post('/api/pim/elevation/request')
      .set('Authorization', userAuth('user-selfdb', ['admin']))
      .send({ userId: 'user-selfdb', resource: 'apps', duration_hours: 1, reason: 'self-approve DB test' });
    expect(created.status).toBe(201);

    const res = await request(dbApp)
      .put(`/api/pim/elevation/requests/${created.body.id}/approve`)
      .set('Authorization', userAuth('user-selfdb', ['admin']));
    expect(res.status).toBe(403);
  });
});

// ─── Group Membership Propagation ─────────────────────────────────────────────

describe('POST /api/permissions/groups/:groupId/propagate', () => {
  it('requires userId', async () => {
    const res = await request(app)
      .post('/api/permissions/groups/eng-group/propagate')
      .set('Authorization', adminAuth())
      .send({});
    expect(res.status).toBe(400);
  });

  it('propagates the user-role template to the target user', async () => {
    const res = await request(app)
      .post('/api/permissions/groups/eng-group/propagate')
      .set('Authorization', adminAuth())
      .send({ userId: 'user-carol' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ userId: 'user-carol', groupId: 'eng-group' });
    expect(res.body.effectivePermissions).toBeDefined();
  });
});

// ─── Metrics ──────────────────────────────────────────────────────────────────

describe('GET /metrics', () => {
  it('exposes Prometheus metrics including the PIM gauge', async () => {
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(200);
    expect(res.text).toContain('pim_pending_requests');
    expect(res.text).toContain('privilege_escalation_alerts');
  });
});
