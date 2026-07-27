'use strict';

/**
 * E2E API tests for identity-service.
 *
 * identity-service was previously untested (a 152-line stub with in-memory
 * Maps, no auth, and no persistence). This suite exercises the rebuilt
 * service against its real Express app (../index.js) via supertest, with:
 *
 *   - `pg` replaced by a small STATEFUL fake (see `makeFakePool` below) that
 *     actually stores rows in JS Maps/arrays and answers the exact SQL
 *     strings src/db.js and src/index.js issue. This is deliberately more
 *     realistic than the "always resolve `{rows: [], rowCount: 0}`" mock
 *     used elsewhere in this monorepo: that shape makes db.isAvailable()
 *     true (SELECT 1 resolves) while every subsequent SELECT still comes
 *     back empty, which would make a create -> get roundtrip look like
 *     persistence when it's actually silently falling through. The fake
 *     here proves the DB code path itself round-trips data, which is what
 *     "Persistenz über den DB-Pfad" in the task asks for.
 *   - `jose` mocked with a fake jwtVerify() that decodes a base64url JSON
 *     payload instead of doing real signature verification — lets this
 *     suite drive the REAL oidcAuth/requireAdmin middleware (not bypass it)
 *     to assert 401 (no token) and 403 (non-admin) without a real IdP/JWKS.
 *   - `@opendirectory/grpc-event-bus` mocked (virtual — same pattern as
 *     services/core/oauth-provider/src/__tests__/api.e2e.test.js) since the
 *     real package isn't installed here and the default transport
 *     (rabbitmq) would otherwise try to dial a real broker.
 *
 * A second file (inMemoryFallback.test.js) covers the other half of
 * "DB-first mit in-memory-Fallback": pg rejecting every query, proving the
 * service still boots and serves CRUD correctly with no database at all.
 */

process.env.PORT = '0'; // ephemeral port — supertest wraps the exported app directly
process.env.JWKS_URI = 'https://idp.test/jwks';
process.env.OIDC_ISSUER = 'https://idp.test';

// ─── Fake stateful pg ───────────────────────────────────────────────────────

function makeFakePool() {
  const usersTbl = new Map();
  const groupsTbl = new Map();
  const groupMembers = []; // {group_id, user_id}
  const ousTbl = new Map();

  function query(sql, params = []) {
    const s = sql.trim();

    if (/^SELECT 1\b/i.test(s)) return Promise.resolve({ rows: [{ '?column?': 1 }], rowCount: 1 });

    // Migrations are executed verbatim against this fake — no-op them.
    if (/^CREATE TABLE/i.test(s) || /^CREATE INDEX/i.test(s)) return Promise.resolve({ rows: [], rowCount: 0 });

    // ── users ──
    if (/^INSERT INTO users/i.test(s)) {
      const [id, username, email, display_name, department, title, enabled] = params;
      usersTbl.set(id, { id, username, email, display_name, department, title, enabled, created_at: new Date(), updated_at: null });
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    if (/^UPDATE users/i.test(s)) {
      const [username, email, display_name, department, title, enabled, updated_at, id] = params;
      const row = usersTbl.get(id);
      if (row) Object.assign(row, { username, email, display_name, department, title, enabled, updated_at: new Date(updated_at) });
      return Promise.resolve({ rows: [], rowCount: row ? 1 : 0 });
    }
    if (/^DELETE FROM users/i.test(s)) {
      const [id] = params;
      const existed = usersTbl.delete(id);
      return Promise.resolve({ rows: [], rowCount: existed ? 1 : 0 });
    }
    if (/FROM users WHERE id=/i.test(s)) {
      const [id] = params;
      const row = usersTbl.get(id);
      return Promise.resolve({ rows: row ? [row] : [], rowCount: row ? 1 : 0 });
    }
    if (/FROM users/i.test(s)) {
      return Promise.resolve({ rows: [...usersTbl.values()], rowCount: usersTbl.size });
    }

    // ── groups ──
    if (/^INSERT INTO groups/i.test(s)) {
      const [id, name, description] = params;
      groupsTbl.set(id, { id, name, description, created_at: new Date() });
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    if (/^DELETE FROM groups/i.test(s)) {
      const [id] = params;
      const existed = groupsTbl.delete(id);
      for (let i = groupMembers.length - 1; i >= 0; i--) {
        if (groupMembers[i].group_id === id) groupMembers.splice(i, 1);
      }
      return Promise.resolve({ rows: [], rowCount: existed ? 1 : 0 });
    }
    if (/^INSERT INTO group_members/i.test(s)) {
      const [group_id, user_id] = params;
      if (!groupMembers.some(m => m.group_id === group_id && m.user_id === user_id)) {
        groupMembers.push({ group_id, user_id });
      }
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    if (/FROM group_members WHERE group_id=/i.test(s)) {
      const [id] = params;
      return Promise.resolve({ rows: groupMembers.filter(m => m.group_id === id).map(m => ({ user_id: m.user_id })) });
    }
    if (/FROM group_members/i.test(s)) {
      return Promise.resolve({ rows: groupMembers.map(m => ({ group_id: m.group_id, user_id: m.user_id })) });
    }
    if (/FROM groups WHERE id=/i.test(s)) {
      const [id] = params;
      const row = groupsTbl.get(id);
      return Promise.resolve({ rows: row ? [row] : [], rowCount: row ? 1 : 0 });
    }
    if (/FROM groups/i.test(s)) {
      return Promise.resolve({ rows: [...groupsTbl.values()], rowCount: groupsTbl.size });
    }

    // ── ous ──
    if (/^INSERT INTO ous/i.test(s)) {
      const [id, name, description, parent_id] = params;
      ousTbl.set(id, { id, name, description, parent_id, created_at: new Date(), updated_at: null });
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    if (/^UPDATE ous/i.test(s)) {
      const [name, description, parent_id, updated_at, id] = params;
      const row = ousTbl.get(id);
      if (row) Object.assign(row, { name, description, parent_id, updated_at: new Date(updated_at) });
      return Promise.resolve({ rows: [], rowCount: row ? 1 : 0 });
    }
    if (/^DELETE FROM ous/i.test(s)) {
      const [id] = params;
      const existed = ousTbl.delete(id);
      return Promise.resolve({ rows: [], rowCount: existed ? 1 : 0 });
    }
    if (/FROM ous WHERE id=/i.test(s)) {
      const [id] = params;
      const row = ousTbl.get(id);
      return Promise.resolve({ rows: row ? [row] : [], rowCount: row ? 1 : 0 });
    }
    if (/FROM ous/i.test(s)) {
      return Promise.resolve({ rows: [...ousTbl.values()], rowCount: ousTbl.size });
    }

    return Promise.resolve({ rows: [], rowCount: 0 });
  }

  return {
    query: jest.fn(query),
    connect: jest.fn().mockResolvedValue({ query: jest.fn(query), release: jest.fn() }),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  };
}

const mockFakePool = makeFakePool();

jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation(() => mockFakePool),
}));

jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

// ─── Fake jose: drives the real oidcAuth/requireAdmin logic ───────────────

jest.mock('jose', () => ({
  createRemoteJWKSet: jest.fn(() => ({})),
  jwtVerify: jest.fn(async (token) => {
    if (token === 'expired') {
      const err = new Error('expired'); err.code = 'ERR_JWT_EXPIRED'; throw err;
    }
    if (token === 'garbage') {
      throw new Error('invalid signature');
    }
    try {
      const payload = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
      return { payload };
    } catch {
      throw new Error('malformed token');
    }
  }),
}));

function makeToken(claims) {
  return Buffer.from(JSON.stringify(claims)).toString('base64url');
}
const adminToken = makeToken({ sub: 'admin-1', roles: ['admin'] });
const userToken = makeToken({ sub: 'user-1', roles: ['user'] });

// ─── Now require the app ───────────────────────────────────────────────────

const request = require('supertest');
let app;

beforeAll(async () => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  app = require('../index');
  // Let db.initDb() (fire-and-forget at module load) settle.
  await new Promise(resolve => setTimeout(resolve, 50));
});

afterAll(() => {
  jest.restoreAllMocks();
});

const admin = (req) => req.set('Authorization', `Bearer ${adminToken}`);
const user = (req) => req.set('Authorization', `Bearer ${userToken}`);

// ─── Health ─────────────────────────────────────────────────────────────────

describe('GET /health', () => {
  it('is reachable with no auth token and reports healthy', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'healthy', service: 'identity-service' });
    expect(res.body).toHaveProperty('timestamp');
  });
});

// ─── Auth enforcement ───────────────────────────────────────────────────────

describe('Auth enforcement', () => {
  it('GET /api/users returns 401 with no token', async () => {
    const res = await request(app).get('/api/users');
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'unauthorized');
  });

  it('GET /api/users succeeds with a valid non-admin token (reads are auth-only)', async () => {
    const res = await user(request(app).get('/api/users'));
    expect(res.status).toBe(200);
  });

  it('POST /api/users returns 401 with no token', async () => {
    const res = await request(app).post('/api/users').send({ username: 'x', email: 'x@example.com' });
    expect(res.status).toBe(401);
  });

  it('POST /api/users returns 403 for a valid non-admin token (mutation is admin-only)', async () => {
    const res = await user(request(app).post('/api/users')).send({ username: 'x', email: 'x@example.com' });
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'forbidden');
  });

  it('rejects a garbage bearer token with 403', async () => {
    const res = await request(app).get('/api/users').set('Authorization', 'Bearer garbage');
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'invalid_token');
  });

  it('rejects an expired bearer token with 401', async () => {
    const res = await request(app).get('/api/users').set('Authorization', 'Bearer expired');
    expect(res.status).toBe(401);
  });

  it('POST /api/groups returns 403 for a non-admin token', async () => {
    const res = await user(request(app).post('/api/groups')).send({ name: 'g' });
    expect(res.status).toBe(403);
  });

  it('POST /api/ous returns 403 for a non-admin token', async () => {
    const res = await user(request(app).post('/api/ous')).send({ name: 'ou' });
    expect(res.status).toBe(403);
  });
});

// ─── Users CRUD roundtrip (DB path) ────────────────────────────────────────

describe('Users CRUD roundtrip', () => {
  let userId;

  it('POST /api/users creates a user (201) and persists via the DB path', async () => {
    const res = await admin(request(app).post('/api/users')).send({
      username: 'jdoe', email: 'jdoe@example.com', displayName: 'Jane Doe', department: 'Eng', title: 'Engineer',
    });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      username: 'jdoe', email: 'jdoe@example.com', displayName: 'Jane Doe', department: 'Eng', title: 'Engineer', enabled: true,
    });
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('createdAt');
    expect(res.body).not.toHaveProperty('updatedAt'); // golden-master: absent until first PUT
    userId = res.body.id;
  });

  it('400s when username or email is missing', async () => {
    const res = await admin(request(app).post('/api/users')).send({ username: 'onlyname' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'username and email are required' });
  });

  it('GET /api/users/:id retrieves the created user from the DB path (not just the in-memory mirror)', async () => {
    // Prove real persistence: read through a fresh in-memory Map would still
    // pass even without a working DB path, so assert against the fake pool
    // directly that the row actually landed in its users table.
    expect(mockFakePool.query).toHaveBeenCalledWith(expect.stringMatching(/INSERT INTO users/i), expect.arrayContaining([userId]));

    const res = await admin(request(app).get(`/api/users/${userId}`));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: userId, username: 'jdoe', email: 'jdoe@example.com' });
  });

  it('GET /api/users lists the created user with pagination shape intact', async () => {
    const res = await admin(request(app).get('/api/users'));
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('total');
    expect(res.body).toHaveProperty('page', 1);
    expect(Array.isArray(res.body.users)).toBe(true);
    expect(res.body.users.some(u => u.id === userId)).toBe(true);
  });

  it('GET /api/users?search= filters by displayName/email', async () => {
    const res = await admin(request(app).get('/api/users').query({ search: 'jane' }));
    expect(res.status).toBe(200);
    expect(res.body.users.every(u => u.id === userId)).toBe(true);
  });

  it('PUT /api/users/:id updates and persists the change via the DB path', async () => {
    const res = await admin(request(app).put(`/api/users/${userId}`)).send({ title: 'Senior Engineer' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: userId, title: 'Senior Engineer', username: 'jdoe' });
    expect(res.body).toHaveProperty('updatedAt');

    const reread = await admin(request(app).get(`/api/users/${userId}`));
    expect(reread.body.title).toBe('Senior Engineer');
  });

  it('PUT /api/users/:id 404s for an unknown id', async () => {
    const res = await admin(request(app).put('/api/users/does-not-exist')).send({ title: 'x' });
    expect(res.status).toBe(404);
  });

  it('DELETE /api/users/:id removes the user (204) and it is gone from the DB path', async () => {
    const del = await admin(request(app).delete(`/api/users/${userId}`));
    expect(del.status).toBe(204);

    const reread = await admin(request(app).get(`/api/users/${userId}`));
    expect(reread.status).toBe(404);
  });

  it('DELETE /api/users/:id 404s the second time', async () => {
    const res = await admin(request(app).delete(`/api/users/${userId}`));
    expect(res.status).toBe(404);
  });
});

// ─── Groups CRUD roundtrip (DB path), including membership ────────────────

describe('Groups CRUD roundtrip', () => {
  let groupId;
  let memberId;

  it('POST /api/groups creates a group (201) with empty members', async () => {
    const res = await admin(request(app).post('/api/groups')).send({ name: 'Engineering', description: 'Eng team' });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ name: 'Engineering', description: 'Eng team', members: [] });
    expect(res.body).toHaveProperty('id');
    groupId = res.body.id;
  });

  it('400s when name is missing', async () => {
    const res = await admin(request(app).post('/api/groups')).send({});
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'name is required' });
  });

  it('GET /api/groups/:id retrieves the created group from the DB path', async () => {
    const res = await admin(request(app).get(`/api/groups/${groupId}`));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: groupId, name: 'Engineering', members: [] });
  });

  it('POST /api/groups/:id/members adds a member and persists it via group_members', async () => {
    const uRes = await admin(request(app).post('/api/users')).send({ username: 'member1', email: 'm1@example.com' });
    memberId = uRes.body.id;

    const res = await admin(request(app).post(`/api/groups/${groupId}/members`)).send({ userId: memberId });
    expect(res.status).toBe(200);
    expect(res.body.members).toContain(memberId);

    expect(mockFakePool.query).toHaveBeenCalledWith(expect.stringMatching(/INSERT INTO group_members/i), [groupId, memberId]);

    const reread = await admin(request(app).get(`/api/groups/${groupId}`));
    expect(reread.body.members).toEqual([memberId]);
  });

  it('adding the same member twice does not duplicate it', async () => {
    const res = await admin(request(app).post(`/api/groups/${groupId}/members`)).send({ userId: memberId });
    expect(res.status).toBe(200);
    expect(res.body.members).toEqual([memberId]);
  });

  it('GET /api/groups lists the group with its member', async () => {
    const res = await admin(request(app).get('/api/groups'));
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('total');
    const g = res.body.groups.find(x => x.id === groupId);
    expect(g).toBeDefined();
    expect(g.members).toEqual([memberId]);
  });

  it('DELETE /api/groups/:id removes the group (204) and it is gone from the DB path', async () => {
    const del = await admin(request(app).delete(`/api/groups/${groupId}`));
    expect(del.status).toBe(204);

    const reread = await admin(request(app).get(`/api/groups/${groupId}`));
    expect(reread.status).toBe(404);
  });
});

// ─── OUs CRUD roundtrip (DB path) — new coverage, no prior routes existed ──

describe('OUs CRUD roundtrip', () => {
  let ouId;

  it('POST /api/ous creates an OU (201)', async () => {
    const res = await admin(request(app).post('/api/ous')).send({ name: 'Finance', description: 'Finance dept' });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ name: 'Finance', description: 'Finance dept' });
    expect(res.body).toHaveProperty('id');
    expect(res.body).not.toHaveProperty('parentId');
    ouId = res.body.id;
  });

  it('400s when name is missing', async () => {
    const res = await admin(request(app).post('/api/ous')).send({});
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'name is required' });
  });

  it('GET /api/ous/:id retrieves the created OU from the DB path', async () => {
    const res = await admin(request(app).get(`/api/ous/${ouId}`));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: ouId, name: 'Finance' });
  });

  it('GET /api/ous lists the OU', async () => {
    const res = await admin(request(app).get('/api/ous'));
    expect(res.status).toBe(200);
    expect(res.body.ous.some(o => o.id === ouId)).toBe(true);
    expect(res.body).toHaveProperty('total');
  });

  it('supports a child OU via parentId', async () => {
    const res = await admin(request(app).post('/api/ous')).send({ name: 'Accounting', parentId: ouId });
    expect(res.status).toBe(201);
    expect(res.body.parentId).toBe(ouId);
  });

  // Ported from authentication-service's now-removed /api/ous implementation
  // (src/routes/directory.js there used to build this same parent/child
  // nesting on every GET /api/ous) as part of consolidating /api/ous onto
  // this service — see the comment above buildOuTree() in ../index.js.
  it('GET /api/ous also returns a nested parent/child tree alongside the flat list', async () => {
    const res = await admin(request(app).get('/api/ous'));
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.tree)).toBe(true);

    const financeNode = res.body.tree.find((o) => o.id === ouId);
    expect(financeNode).toBeDefined();
    expect(financeNode.children.some((c) => c.name === 'Accounting')).toBe(true);
    // The flat `ous`/`total` shape existing consumers rely on is unchanged.
    expect(res.body.ous.some((o) => o.id === ouId)).toBe(true);
  });

  it('PUT /api/ous/:id updates and persists via the DB path', async () => {
    const res = await admin(request(app).put(`/api/ous/${ouId}`)).send({ description: 'Updated' });
    expect(res.status).toBe(200);
    expect(res.body.description).toBe('Updated');

    const reread = await admin(request(app).get(`/api/ous/${ouId}`));
    expect(reread.body.description).toBe('Updated');
  });

  it('PUT /api/ous/:id 404s for an unknown id', async () => {
    const res = await admin(request(app).put('/api/ous/does-not-exist')).send({ name: 'x' });
    expect(res.status).toBe(404);
  });

  it('DELETE /api/ous/:id removes the OU (204) and it is gone from the DB path', async () => {
    const del = await admin(request(app).delete(`/api/ous/${ouId}`));
    expect(del.status).toBe(204);

    const reread = await admin(request(app).get(`/api/ous/${ouId}`));
    expect(reread.status).toBe(404);
  });
});

// ─── Identity search (LDAP-compatible) ─────────────────────────────────────

describe('GET /api/identity/search', () => {
  it('combines users and groups with a total count', async () => {
    await admin(request(app).post('/api/users')).send({ username: 'searchme', email: 'searchme@example.com' });
    await admin(request(app).post('/api/groups')).send({ name: 'SearchGroup' });

    const res = await admin(request(app).get('/api/identity/search'));
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('entries');
    expect(res.body).toHaveProperty('total', res.body.entries.length);
    expect(res.body.entries.some(e => e.username === 'searchme')).toBe(true);
    expect(res.body.entries.some(e => e.name === 'SearchGroup')).toBe(true);
  });
});
