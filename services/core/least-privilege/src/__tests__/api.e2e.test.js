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

const request = require('supertest');

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
    const res = await request(app).get('/api/permissions/matrix');
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
    const res = await request(app).get('/api/permissions/users/user-carol');
    expect(res.status).toBe(200);
    expect(res.body.userId).toBe('user-carol');
    expect(res.body.role).toBe('read-only');
    expect(res.body.permissions.devices).toBe('read');
    expect(typeof res.body.riskScore).toBe('number');
  });

  it('404s for an unknown user', async () => {
    const res = await request(app).get('/api/permissions/users/no-such-user');
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error');
  });
});

describe('POST /api/permissions/users/:userId/assign', () => {
  it('rejects an invalid resource', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-bob/assign')
      .send({ resource: 'not-a-resource', level: 'read' });
    expect(res.status).toBe(400);
  });

  it('rejects an invalid level', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-bob/assign')
      .send({ resource: 'devices', level: 'god-mode' });
    expect(res.status).toBe(400);
  });

  it('assigns a permission override and it is reflected in effective permissions', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-bob/assign')
      .send({ resource: 'secrets', level: 'write' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ userId: 'user-bob', resource: 'secrets', level: 'write' });

    const check = await request(app).get('/api/permissions/users/user-bob');
    expect(check.body.permissions.secrets).toBe('write');
  });

  it('creates a brand-new user record on first assignment', async () => {
    const res = await request(app)
      .post('/api/permissions/users/user-newbie/assign')
      .send({ resource: 'apps', level: 'read' });
    expect(res.status).toBe(200);
    const check = await request(app).get('/api/permissions/users/user-newbie');
    expect(check.status).toBe(200);
    expect(check.body.permissions.apps).toBe('read');
  });

  it('raises an escalation alert once a user crosses 3 admin resources', async () => {
    for (const resource of ['devices', 'users', 'policies', 'apps']) {
      // eslint-disable-next-line no-await-in-loop
      await request(app)
        .post('/api/permissions/users/user-escalate/assign')
        .send({ resource, level: 'admin' });
    }
    const alerts = await request(app).get('/api/permissions/escalation-alerts');
    expect(alerts.status).toBe(200);
    const mine = alerts.body.find(a => a.userId === 'user-escalate');
    expect(mine).toBeDefined();
    expect(mine.adminCount).toBeGreaterThan(3);
  });
});

// ─── Unused Permissions ───────────────────────────────────────────────────────

describe('unused permissions', () => {
  it('GET /api/permissions/unused returns the seeded idle-permission list', async () => {
    const res = await request(app).get('/api/permissions/unused');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    expect(res.body[0]).toHaveProperty('daysIdle');
  });

  it('POST /api/permissions/revoke-unused resets write/read overrides on reports/printers for non-admins', async () => {
    await request(app)
      .post('/api/permissions/users/user-dave/assign')
      .send({ resource: 'reports', level: 'write' });

    const res = await request(app).post('/api/permissions/revoke-unused');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('revokedCount');
    expect(res.body).toHaveProperty('revoked');
    expect(Array.isArray(res.body.revoked)).toBe(true);

    const check = await request(app).get('/api/permissions/users/user-dave');
    expect(check.body.permissions.reports).toBe('none');
  });
});

// ─── Risk Scores ─────────────────────────────────────────────────────────────

describe('GET /api/permissions/risk-scores', () => {
  it('returns scores sorted descending, admin scoring highest', async () => {
    const res = await request(app).get('/api/permissions/risk-scores');
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
    const res = await request(app).get('/api/pim/elevation/requests');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    const seeded = res.body.find(r => r.userId === 'user-bob' && r.resource === 'secrets' && r.status === 'pending');
    expect(seeded).toBeDefined();
  });
});

describe('POST /api/pim/elevation/request', () => {
  it('requires userId, resource, and duration_hours', async () => {
    const res = await request(app).post('/api/pim/elevation/request').send({ userId: 'user-eve' });
    expect(res.status).toBe(400);
  });

  it('creates a pending elevation request', async () => {
    const res = await request(app)
      .post('/api/pim/elevation/request')
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
      .send({ userId: 'user-dave', resource: 'secrets', duration_hours: 2, reason: 'Rotate creds' });
    requestId = created.body.id;
  });

  it('404s approving an unknown request', async () => {
    const res = await request(app).put('/api/pim/elevation/requests/does-not-exist/approve');
    expect(res.status).toBe(404);
  });

  it('404s denying an unknown request', async () => {
    const res = await request(app).put('/api/pim/elevation/requests/does-not-exist/deny');
    expect(res.status).toBe(404);
  });

  it('approves a pending request, activating an elevation', async () => {
    const res = await request(app).put(`/api/pim/elevation/requests/${requestId}/approve`);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('approved');
    expect(res.body.expiresAt).toBeTruthy();

    const active = await request(app).get('/api/pim/elevation/active');
    expect(active.status).toBe(200);
    const mine = active.body.find(e => e.requestId === requestId);
    expect(mine).toBeDefined();
    expect(mine.userId).toBe('user-dave');
    expect(mine.resource).toBe('secrets');
    expect(mine.timeRemainingMinutes).toBeGreaterThan(0);
  });

  it('rejects approving an already-processed request', async () => {
    const res = await request(app).put(`/api/pim/elevation/requests/${requestId}/approve`);
    expect(res.status).toBe(400);
  });

  it('denies a separate pending request', async () => {
    const created = await request(app)
      .post('/api/pim/elevation/request')
      .send({ userId: 'user-carol', resource: 'reports', duration_hours: 1, reason: 'One-off export' });
    const denyRes = await request(app).put(`/api/pim/elevation/requests/${created.body.id}/deny`);
    expect(denyRes.status).toBe(200);
    expect(denyRes.body.status).toBe('denied');
  });
});

// ─── Group Membership Propagation ─────────────────────────────────────────────

describe('POST /api/permissions/groups/:groupId/propagate', () => {
  it('requires userId', async () => {
    const res = await request(app).post('/api/permissions/groups/eng-group/propagate').send({});
    expect(res.status).toBe(400);
  });

  it('propagates the user-role template to the target user', async () => {
    const res = await request(app)
      .post('/api/permissions/groups/eng-group/propagate')
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
