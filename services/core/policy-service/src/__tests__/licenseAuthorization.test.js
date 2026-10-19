'use strict';

jest.mock('../middleware/oidcAuth', () => ({
  oidcAuth: () => (req, res, next) => {
    const identities = {
      alice: { sub: 'alice', name: 'Alice', roles: ['user'] },
      bob: { sub: 'bob', roles: ['user'] },
      manager: { sub: 'manager', roles: ['license-manager'] },
      reviewer: { sub: 'reviewer', roles: ['license-approver'] },
      reader: { sub: 'reader', roles: ['license-reader'] },
      admin: { sub: 'admin', roles: ['admin'] },
      subjectless: { roles: ['admin'] },
      blank: { sub: ' ', roles: ['admin'] },
      offboarder: { sub: 'offboarder', permissions: ['users.offboard'] },
    };
    const identity = identities[req.headers.authorization?.replace('Bearer ', '')];
    req.user = identity ? { iss: require('./fixtures/licenseIdentities.cjs').issuer, ...identity } : undefined;
    next();
  },
}));

jest.mock('../db/postgres', () => ({
  query: jest.fn(),
  getClient: jest.fn().mockRejectedValue(new Error('Database offline')),
  testConnection: jest.fn().mockResolvedValue(false),
  runMigrations: jest.fn(),
  shutdown: jest.fn(),
}));

jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
    subscribe: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

jest.mock('../licenses/GroupSnapshotClient', () => {
  const { GroupSnapshotClient } = jest.requireActual('../licenses/GroupSnapshotClient');
  return { ...jest.requireActual('../licenses/GroupSnapshotClient'), GroupSnapshotClient: class extends GroupSnapshotClient {
    async subject(_authorization, expected) { return require('./fixtures/licenseIdentities.cjs').principal(expected.subject, expected.issuer); }
    async user(userId) { return { schemaVersion: 1, userId, revision: '1', enabled: true, deleted: false }; }
  } };
});

const { userId, principal, issuer } = require('./fixtures/licenseIdentities.cjs');
const bound = request => ({ license_id: 'license-id', identity_bound: true, requester_issuer: issuer, requester_subject: 'original-subject', ...request });
const request = require('supertest');
const { GroupLicenseAllocator } = require('../licenses/GroupLicenseAllocator');
const db = require('../db/postgres');
let app;
let demoApp;
let DemoGroups;
let DemoSource;
let productionApp;

beforeAll(() => {
  const previousMode = process.env.LICENSE_DEMO_MODE;
  delete process.env.LICENSE_DEMO_MODE;
  app = require('../index');
  process.env.LICENSE_DEMO_MODE = 'true';
  jest.isolateModules(() => { demoApp = require('../index'); DemoGroups = require('../licenses/GroupLicenseAllocator').GroupLicenseAllocator; DemoSource = require('../licenses/GroupSnapshotClient').GroupSnapshotClient; });
  const previousEnvironment = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  jest.isolateModules(() => { productionApp = require('../index'); });
  if (previousEnvironment === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = previousEnvironment;
  if (previousMode === undefined) delete process.env.LICENSE_DEMO_MODE;
  else process.env.LICENSE_DEMO_MODE = previousMode;
});

beforeEach(() => {
  db.query.mockReset().mockRejectedValue(new Error('Database offline'));
  db.getClient.mockReset().mockRejectedValue(new Error('Database offline'));
});

function mockLicenseTransaction(storedRequest) {
  const client = { release: jest.fn(), query: jest.fn(async (sql, parameters = []) => {
    if (sql.startsWith('SELECT * FROM license_subjects')) return { rows: [{ disabled: false }] };
    if (sql.startsWith('SELECT * FROM license_catalog')) return { rows: [{ id: 'license-id', name: 'Office', total_seats: 10, auto_approve: false }] };
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: sql.includes('AS expires_at') ? 1 : 0, expires_at: null }] };
    if (sql.startsWith('SELECT * FROM license_requests WHERE id')) return { rows: [storedRequest] };
    if (sql.startsWith('INSERT INTO license_assignments')) return { rows: [{ id: 'assignment-id', assigned_by: parameters[4] }] };
    if (sql.startsWith('INSERT INTO license_requests')) return { rows: [{ requester_id: parameters[2], status: parameters[8] }] };
    if (sql.startsWith('UPDATE license_requests')) return { rows: [{ status: parameters[1], decided_by: parameters[2] }] };
    return { rows: [] };
  }) };
  db.getClient.mockResolvedValue(client);
  return client;
}

function mockLegacyVisibility() {
  db.query.mockImplementation(async (sql, parameters) => {
    if (sql === 'SELECT id,business_tenant_id FROM license_catalog WHERE id=$1' && ['license-id', 'lic-demo-1', 'lic-demo-2'].includes(parameters[0])) return { rows: [{ id: parameters[0], business_tenant_id: null }] };
    if (sql === 'SELECT business_tenant_id FROM license_subjects WHERE user_id=$1') return { rows: [] };
    throw new Error('Database offline');
  });
}

describe('License boundary', () => {
  test('a group transaction failure cannot fall through to fake demo group-seat allocation', async () => {
    const before = await request(demoApp).get('/api/licenses').set('Authorization', 'Bearer manager');
    const operation = jest.spyOn(DemoGroups.prototype, 'assign').mockRejectedValue(new Error('Storage offline before transaction'));
    try {
      const response = await request(demoApp).post('/api/licenses/lic-demo-1/assign').set('Authorization', 'Bearer manager').send({ assignee_type: 'group', assignee_id: '11111111-1111-4111-8111-111111111111' });
      expect(response.status).toBe(503);
      const after = await request(demoApp).get('/api/licenses').set('Authorization', 'Bearer manager');
      expect(after.body.licenses.map(license => license.used_seats)).toEqual(before.body.licenses.map(license => license.used_seats));
    } finally { operation.mockRestore(); }
  });
  test('group allocation uses the verified operator header and reports capacity blockage as pending provisioning', async () => {
    mockLegacyVisibility();
    const operation = jest.spyOn(GroupLicenseAllocator.prototype, 'assign').mockResolvedValue({ kind: 'group', localOnly: true, rule: { status: 'capacity-blocked' } });
    try {
      const response = await request(app).post('/api/licenses/license-id/assign').set('Authorization', 'Bearer manager')
        .send({ assignee_type: 'group', assignee_id: 'group-id', authorization: 'Bearer forged', members: ['forged-user'] });
      expect(response.status).toBe(202);
      expect(operation).toHaveBeenCalledWith('license-id', { assignee_type: 'group', assignee_id: 'group-id', assignee_name: undefined, expires_at: undefined }, userId('manager'), { authorization: 'Bearer manager', principal: principal('manager') });
    } finally { operation.mockRestore(); }
  });

  test.each([['get', '/api/licenses/groups'], ['post', '/api/licenses/license-id/groups/group-id/reconcile']])('ordinary users cannot manage or inspect group rules: %s %s', async (method, path) => {
    const response = await request(app)[method](path).set('Authorization', 'Bearer alice').send({});
    expect(response.status).toBe(403);
    expect(db.query).not.toHaveBeenCalled();
  });
  test.each([undefined, 'subjectless', 'blank'])('requires an authenticated subject: %s', async identity => {
    const operation = request(app).get('/api/licenses/access');
    if (identity) operation.set('Authorization', `Bearer ${identity}`);
    expect((await operation).status).toBe(401);
    expect(db.query).not.toHaveBeenCalled();
  });

  test.each([
    ['get', '/api/licenses'],
    ['get', '/api/licenses/license-id'],
    ['post', '/api/licenses'],
    ['put', '/api/licenses/license-id'],
    ['delete', '/api/licenses/license-id'],
    ['get', '/api/licenses/license-id/assignments'],
    ['post', '/api/licenses/license-id/assign'],
    ['delete', '/api/licenses/license-id/assignments/alice'],
    ['post', '/api/licenses/requests/request-id/approve'],
    ['post', '/api/licenses/requests/request-id/deny'],
    ['post', '/api/licenses/users/bob/offboard'],
    ['post', '/api/licenses/users/bob/activate'],
    ['get', '/api/licenses/license-id/audit'],
  ])('blocks ordinary users before storage access: %s %s', async (method, url) => {
    const response = await request(app)[method](url).set('Authorization', 'Bearer alice').send({});
    expect(response.status).toBe(403);
    expect(db.query).not.toHaveBeenCalled();
  });

  test('exposes only the authenticated account capabilities', async () => {
    const response = await request(app).get('/api/licenses/access').set('Authorization', 'Bearer manager');
    expect(response.body).toMatchObject({ subject: userId('manager'), tokenSubject: 'manager', identityState: 'active', demoMode: false });
    expect(response.body.permissions).toContain('licenses.catalog.manage');
    expect(response.body.permissions).not.toContain('licenses.requests.review');
  });

  test('lets a delegated reader read the catalog but not change it', async () => {
    db.query.mockResolvedValue({ rows: [] });
    expect((await request(app).get('/api/licenses').set('Authorization', 'Bearer reader')).status).toBe(200);
    expect((await request(app).post('/api/licenses').set('Authorization', 'Bearer reader').send({ name: 'Test' })).status).toBe(403);
    expect(db.query).toHaveBeenCalledTimes(1);
  });

  test('does not give approvers catalog administration privileges', async () => {
    const response = await request(app).post('/api/licenses').set('Authorization', 'Bearer reviewer').send({ name: 'Test' });
    expect(response.status).toBe(403);
  });

  test('does not give managers approval privileges', async () => {
    const response = await request(app).post('/api/licenses/requests/request-id/approve').set('Authorization', 'Bearer manager').send({});
    expect(response.status).toBe(403);
  });
});

describe('Self-service with persistent storage', () => {
  beforeEach(mockLegacyVisibility);
  test('restricts request history to the subject, even with a forged requester filter', async () => {
    db.query.mockResolvedValue({ rows: [] });
    const response = await request(app).get('/api/licenses/requests?status=pending&requester_id=bob').set('Authorization', 'Bearer alice');
    expect(response.status).toBe(200);
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('status = $1 AND identity_bound = true AND requester_id = $2'), ['pending', userId('alice')]);
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('license_id IN (SELECT id FROM license_catalog WHERE business_tenant_id IS NULL)'), ['pending', userId('alice')]);
  });

  test('lets approvers read the review queue', async () => {
    db.query.mockResolvedValue({ rows: [] });
    const response = await request(app).get('/api/licenses/requests').set('Authorization', 'Bearer reviewer');
    expect(response.status).toBe(200);
    expect(db.query).toHaveBeenCalledWith(expect.not.stringContaining('WHERE requester_id'), []);
  });

  test('ignores forged requester and display name fields', async () => {
    const client = mockLicenseTransaction();
    const response = await request(app).post('/api/licenses/license-id/request').set('Authorization', 'Bearer alice')
      .send({ requester_id: 'bob', requester_name: 'Administrator', justification: 'Work' });
    expect(response.status).toBe(201);
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO license_requests'), ['license-id', 'Office', userId('alice'), 'Alice', 'user', userId('alice'), 'Alice', 'Work', 'pending', issuer, 'alice']);
    expect(client.query).toHaveBeenCalledWith('COMMIT');
  });

  test.each([
    { assignee_id: userId('bob') },
    { assignee_type: 'group', assignee_id: 'finance' },
    { assignee_type: 'device', assignee_id: 'laptop' },
  ])('blocks delegated requests from ordinary users: %j', async payload => {
    const response = await request(app).post('/api/licenses/license-id/request').set('Authorization', 'Bearer alice').send(payload);
    expect(response.status).toBe(403);
    expect(db.query).not.toHaveBeenCalled();
  });

  test.each(['approve', 'deny'])('blocks self-%s for global admins as well', async action => {
    db.query.mockResolvedValueOnce({ rows: [bound({ requester_id: userId('admin'), assignee_type: 'user', assignee_id: userId('alice'), status: 'pending' })] });
    const response = await request(app).post(`/api/licenses/requests/request-id/${action}`).set('Authorization', 'Bearer admin').send({ decided_by: 'reviewer' });
    expect(response.status).toBe(403);
    expect(db.query).toHaveBeenCalledTimes(2);
    expect(db.query).toHaveBeenLastCalledWith('SELECT id,business_tenant_id FROM license_catalog WHERE id=$1', ['license-id']);
  });

  test('blocks approval by the beneficiary of a delegated request', async () => {
    db.query.mockResolvedValueOnce({ rows: [bound({ requester_id: userId('manager'), assignee_type: 'user', assignee_id: userId('reviewer'), status: 'pending' })] });
    const response = await request(app).post('/api/licenses/requests/request-id/approve').set('Authorization', 'Bearer reviewer').send({});
    expect(response.status).toBe(403);
  });

  test('records a trusted decision maker instead of a body-supplied identity', async () => {
    const storedRequest = bound({ id: 'request-id', license_id: 'license-id', requester_id: userId('alice'), assignee_type: 'user', assignee_id: userId('alice'), status: 'pending' });
    db.query.mockResolvedValueOnce({ rows: [storedRequest] });
    const client = mockLicenseTransaction(storedRequest);
    const response = await request(app).post('/api/licenses/requests/request-id/deny').set('Authorization', 'Bearer reviewer').send({ decided_by: 'forged' });
    expect(response.status).toBe(200);
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('UPDATE license_requests'), ['request-id', 'denied', userId('reviewer')]);
  });

  test('records the authenticated license manager on a direct assignment', async () => {
    const client = mockLicenseTransaction();
    const response = await request(app).post('/api/licenses/license-id/assign').set('Authorization', 'Bearer manager')
      .send({ assignee_type: 'user', assignee_id: userId('alice'), assigned_by: 'forged' });
    expect(response.status).toBe(201);
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO license_assignments'), ['license-id', 'user', userId('alice'), null, userId('manager'), null]);
  });

  test.each([
    ['get', '/api/licenses/kiosk', 'alice'],
    ['get', '/api/licenses/requests', 'alice'],
    ['get', '/api/licenses', 'manager'],
    ['post', '/api/licenses', 'manager'],
    ['post', '/api/licenses/license-id/request', 'alice'],
    ['post', '/api/licenses/requests/request-id/approve', 'reviewer'],
  ])('fails closed on a storage outage: %s %s', async (method, url, identity) => {
    const response = await request(app)[method](url).set('Authorization', `Bearer ${identity}`).send({ name: 'Test' });
    expect(response.status).toBe(503);
  });
});

describe('Explicit development demo', () => {
  beforeEach(mockLegacyVisibility);
  test.each(['assign', 'request'].flatMap(operation => ['offline', 'inactive'].map(state => [operation, state])))('target eligibility failure never falls through to a demo grant: %s %s', async (operation, state) => {
    const source = jest.spyOn(DemoSource.prototype, 'user');
    if (state === 'offline') source.mockRejectedValue(new Error('Source unavailable'));
    else source.mockImplementation(async userId => ({ schemaVersion: 1, userId, revision: '2', enabled: false, deleted: false }));
    try {
      const before = await request(demoApp).get('/api/licenses').set('Authorization', 'Bearer manager');
      const result = await request(demoApp).post(`/api/licenses/lic-demo-1/${operation}`).set('Authorization', 'Bearer manager')
        .send({ assignee_type: 'user', assignee_id: userId('alice') });
      expect(result.status).toBe(503);
      const after = await request(demoApp).get('/api/licenses').set('Authorization', 'Bearer manager');
      expect(after.body.licenses.map(license => license.used_seats)).toEqual(before.body.licenses.map(license => license.used_seats));
    } finally { source.mockRestore(); }
  });
  test.each(['offline', 'unlinked', 'disabled'])('demo fallback never bypasses authoritative identity state: %s', async state => {
    const source = jest.spyOn(DemoSource.prototype, 'subject');
    if (state === 'offline') source.mockRejectedValue(new Error('Source offline'));
    else source.mockResolvedValue({ ...principal('manager'), ...(state === 'unlinked' ? { userId: null, enabled: null } : { enabled: false }) });
    try {
      const capabilities = await request(demoApp).get('/api/licenses/access').set('Authorization', 'Bearer manager');
      expect(capabilities.status).toBe(200);
      expect(capabilities.body.identityState).toBe(state === 'offline' ? 'unavailable' : state);
      expect(capabilities.body.permissions).toEqual([]);
      const response = await request(demoApp).post('/api/licenses/lic-demo-1/request').set('Authorization', 'Bearer manager').send({});
      expect(response.status).toBe(state === 'offline' ? 503 : 403);
      expect(db.getClient).not.toHaveBeenCalled();
    } finally { source.mockRestore(); }
  });
  test('a delegated offboarding operator can revoke eligibility but cannot reactivate or allocate licenses', async () => {
    expect((await request(demoApp).post(`/api/licenses/users/${userId('limited-offboarding-user')}/offboard`).set('Authorization', 'Bearer offboarder').send({})).status).toBe(200);
    expect((await request(demoApp).post(`/api/licenses/users/${userId('limited-offboarding-user')}/activate`).set('Authorization', 'Bearer offboarder').send({})).status).toBe(403);
    expect((await request(demoApp).post('/api/licenses/lic-demo-1/assign').set('Authorization', 'Bearer offboarder').send({ assignee_type: 'user', assignee_id: userId('bob') })).status).toBe(403);
    expect((await request(demoApp).get('/api/licenses').set('Authorization', 'Bearer offboarder')).status).toBe(403);
  });
  test('does not let a license manager offboard identities', async () => {
    const response = await request(demoApp).post('/api/licenses/users/bob/offboard').set('Authorization', 'Bearer manager').send({});
    expect(response.status).toBe(403);
    const activation = await request(demoApp).post('/api/licenses/users/bob/activate').set('Authorization', 'Bearer manager').send({});
    expect(activation.status).toBe(403);
  });

  test('offboarding releases demo seats and blocks new assignments to that user', async () => {
    const assignment = await request(demoApp).post('/api/licenses/lic-demo-2/assign').set('Authorization', 'Bearer manager')
      .send({ assignee_type: 'user', assignee_id: userId('departing-user') });
    expect(assignment.status).toBe(201);
    const offboarded = await request(demoApp).post(`/api/licenses/users/${userId('departing-user')}/offboard`).set('Authorization', 'Bearer admin').send({ decided_by: 'forged' });
    expect(offboarded.status).toBe(200);
    expect(offboarded.body.assignmentsRevoked).toBe(1);
    const forbidden = await request(demoApp).post('/api/licenses/lic-demo-2/assign').set('Authorization', 'Bearer manager')
      .send({ assignee_type: 'user', assignee_id: userId('departing-user') });
    expect(forbidden.status).toBe(403);
    const reactivated = await request(demoApp).post(`/api/licenses/users/${userId('departing-user')}/activate`).set('Authorization', 'Bearer admin').send({});
    expect(reactivated.status).toBe(200);
  });

  test('transaction failures never fall through into demo storage after BEGIN', async () => {
    const client = { release: jest.fn(), query: jest.fn().mockRejectedValue(new Error('Transaction interrupted')) };
    db.getClient.mockResolvedValue(client);
    const response = await request(demoApp).post('/api/licenses/lic-demo-1/assign').set('Authorization', 'Bearer manager')
      .send({ assignee_type: 'user', assignee_id: userId('alice') });
    expect(response.status).toBe(503);
    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
    expect(client.release).toHaveBeenCalled();
  });
  test('never enables fallback in production, even if explicitly configured', async () => {
    const access = await request(productionApp).get('/api/licenses/access').set('Authorization', 'Bearer admin');
    expect(access.body.demoMode).toBe(false);
    const catalog = await request(productionApp).get('/api/licenses').set('Authorization', 'Bearer admin');
    expect(catalog.status).toBe(503);
  });
  test('retains ownership filtering and independent approval in fallback mode', async () => {
    const aliceRequest = await request(demoApp).post('/api/licenses/lic-demo-1/request').set('Authorization', 'Bearer alice').send({ requester_id: 'bob' });
    expect(aliceRequest.status).toBe(201);
    expect(aliceRequest.body.requester_id).toBe(userId('alice'));
    const bobHistory = await request(demoApp).get('/api/licenses/requests').set('Authorization', 'Bearer bob');
    expect(bobHistory.body.requests).toEqual([]);
    const ownRequest = await request(demoApp).post('/api/licenses/lic-demo-1/request').set('Authorization', 'Bearer admin').send({});
    const selfApproval = await request(demoApp).post(`/api/licenses/requests/${ownRequest.body.id}/approve`).set('Authorization', 'Bearer admin').send({});
    expect(selfApproval.status).toBe(403);
    const independentApproval = await request(demoApp).post(`/api/licenses/requests/${aliceRequest.body.id}/approve`).set('Authorization', 'Bearer reviewer').send({ decided_by: 'forged' });
    expect(independentApproval.status).toBe(200);
    expect(independentApproval.body.decided_by).toBe(userId('reviewer'));
  });

  test('hides private fields and advertises fallback mode', async () => {
    const catalog = await request(demoApp).get('/api/licenses/kiosk').set('Authorization', 'Bearer alice');
    expect(catalog.status).toBe(200);
    expect(catalog.body.licenses[0]).not.toHaveProperty('cost_per_seat');
    expect(catalog.body.licenses[0]).not.toHaveProperty('notes');
    const access = await request(demoApp).get('/api/licenses/access').set('Authorization', 'Bearer alice');
    expect(access.body.demoMode).toBe(true);
  });
});
