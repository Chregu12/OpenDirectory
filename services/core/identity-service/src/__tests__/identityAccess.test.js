'use strict';

jest.mock('../db', () => ({ isAvailable: jest.fn(() => true), initDb: jest.fn(async () => false), query: jest.fn(async () => ({ rows: [] })), transaction:jest.fn(), pool: { end: jest.fn() } }));
jest.mock('jose', () => ({ createRemoteJWKSet: jest.fn(), jwtVerify: jest.fn() }));
jest.mock('../../../../../packages/oidc-access-state', () => ({ createAccessStateClient: jest.fn(() => jest.fn(async () => {})) }));
jest.mock('../../../../../packages/oidc-tenant-state', () => ({ createTenantStateClient:jest.fn(() => jest.fn(async()=>({id:'11111111-1111-4111-8111-111111111111',version:'1',generation:'2'}))) }));
jest.mock('@opendirectory/grpc-event-bus', () => ({ EventBusClient: jest.fn(() => ({ connect: jest.fn(), publish: jest.fn(async () => {}) })) }), { virtual: true });

const request = require('supertest');
const app = require('../index');
const db = require('../db');
const { jwtVerify } = require('jose');
const { getIdentityPermissions, requireIdentityAccess } = require('../middleware/identityAccess');

const operations = [
  ['GET', '/users', 'users.read'], ['POST', '/users', 'users.create'], ['PUT', '/users/id', 'users.update'], ['DELETE', '/users/id', 'users.delete'],
  ['GET', '/groups', 'groups.read'], ['POST', '/groups', 'groups.create'], ['PUT', '/groups/id', 'groups.update'], ['DELETE', '/groups/id', 'groups.delete'],
  ['POST', '/groups/id/members', 'groups.members.manage'], ['DELETE', '/groups/id/members/user', 'groups.members.manage'],
  ['GET', '/ous', 'ous.read'], ['POST', '/ous', 'ous.create'], ['PUT', '/ous/id', 'ous.update'], ['DELETE', '/ous/id', 'ous.delete'],
  ['GET', '/identity/search', 'users.read'], ['GET', '/license-groups/id/snapshot', 'licenses.groups.read'],
  ['POST', '/identity/links', 'identities.links.manage'], ['DELETE', '/identity/links', 'identities.links.manage'],
  ['GET', '/identity/roles/catalog', 'identities.roles.read'], ['GET', '/users/id/roles', 'identities.roles.read'],
  ['POST', '/users/id/roles', 'identities.roles.manage'], ['DELETE', '/users/id/roles/assignment', 'identities.roles.manage'],
  ['GET', '/identity/pim/eligibilities', 'pim.eligibilities.read'], ['POST', '/identity/pim/eligibilities', 'pim.eligibilities.manage'],
  ['DELETE', '/identity/pim/eligibilities/id', 'pim.eligibilities.manage'], ['GET', '/identity/pim/requests', 'pim.requests.read'],
  ['POST', '/identity/pim/requests/id/approve', 'pim.requests.review'], ['POST', '/identity/pim/requests/id/deny', 'pim.requests.review'],
  ['POST', '/identity/pim/requests/id/revoke', 'pim.activations.revoke'],
  ['GET','/identity/membership-reviews/policies/groups/id','groups.reviews.policies.read'],
  ['POST','/identity/membership-reviews/policies','groups.reviews.policies.manage'],
  ['POST','/identity/membership-reviews/policies/id/retire','groups.reviews.policies.manage'],
  ['GET','/identity/membership-reviews/assigned','groups.reviews.assigned.read'],
  ['POST','/identity/membership-reviews/id/decisions','groups.reviews.decide'],
];

beforeEach(() => {
  jest.clearAllMocks();
  db.isAvailable.mockReturnValue(true);
  db.query.mockResolvedValue({ rows: [] });
  db.transaction.mockImplementation(operation=>operation(db));
  jwtVerify.mockResolvedValue({ payload: { token_use: 'access', sub: 'operator', permissions: [] } });
});

test.each(operations)('requires the specific permission before %s %s can reach storage', (method, route, permission) => {
  const next = jest.fn(); const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  requireIdentityAccess({ method, path: route, user: { sub: 'ordinary', scope: `identity.admin ${permission}`, permissions: [] }, body: {} }, response, next);
  expect(response.status).toHaveBeenCalledWith(403);
  expect(next).not.toHaveBeenCalled();
});

test.each(operations.filter(([, route]) => route !== '/identity/search'))('accepts the narrow grant for %s %s', (method, route, permission) => {
  const next = jest.fn(); const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  requireIdentityAccess({ method, path: route, user: { sub: 'operator', permissions: [permission] }, body: {} }, response, next);
  expect(next).toHaveBeenCalledTimes(1);
});

test('scope-only administration and malformed roles do not become permissions', () => {
  for (const claims of [{ scope: 'identity.admin' }, { roles: 'admin' }, { roles: ['constructor'] }, { permissions: '*' }, { roles: [null, {}] }]) expect(getIdentityPermissions(claims)).toEqual([]);
  expect(getIdentityPermissions({ roles: ['license-group-reader'] })).toEqual(['licenses.groups.read']);
  expect(getIdentityPermissions({roles:['license-scope-policy-administrator']})).toEqual(['licenses.delegates.read','licenses.activation-reviewers.read']);
  expect(getIdentityPermissions({roles:['license-scope-policy-reader']})).toEqual([]);
});
test('group review duties are disjoint and global administration is not an implicit new writer',()=>{
 expect(getIdentityPermissions({roles:['group-review-administrator']})).toEqual(['groups.reviews.policies.read','groups.reviews.policies.manage','groups.reviews.all.read']);
 expect(getIdentityPermissions({roles:['group-reviewer']})).toEqual(['groups.reviews.assigned.read','groups.reviews.decide']);expect(getIdentityPermissions({roles:['group-review-reader']})).toEqual(['groups.reviews.policies.read','groups.reviews.all.read']);
 expect(getIdentityPermissions({roles:['admin']})).not.toContain('groups.reviews.decide');expect(getIdentityPermissions({roles:['admin']})).not.toContain('groups.reviews.policies.manage');expect(getIdentityPermissions({roles:['admin','group-reviewer']})).toContain('groups.reviews.decide');
});

test('unknown routes and missing subjects are denied before any handler can execute', () => {
  for (const identity of [{ roles: ['admin'] }, { sub: '', roles: ['admin'] }, { sub: 'operator', roles: ['admin'] }]) {
    const next = jest.fn(); const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    requireIdentityAccess({ method: 'POST', path: '/unreviewed-route', user: identity }, response, next);
    expect(next).not.toHaveBeenCalled();
  }
});

test('ID tokens cannot authorize the identity API', async () => {
  jwtVerify.mockResolvedValue({ payload: { token_use: 'access', sub: 'operator', roles: ['admin'], token_use: 'id' } });
  expect((await request(app).get('/api/users').set('Authorization', 'Bearer token')).status).toBe(403);
  expect(db.query).not.toHaveBeenCalled();
});

test('a post-startup read failure returns 503, not a process-local cache', async () => {
  jwtVerify.mockResolvedValue({ payload: { token_use: 'access', sub: 'operator',roles:['admin'],actor_type:'user',iss:process.env.OIDC_ISSUER||'http://localhost:3001',exp:Math.floor(Date.now()/1000)+300,
    identity_authorization:{userId:'22222222-2222-4222-8222-222222222222',revision:'1',linkRevision:'2',rolesRevision:'a'.repeat(64)} } });
  db.query.mockRejectedValue(new Error('database connection lost'));
  const response = await request(app).get('/api/groups').set('Authorization', 'Bearer token');
  expect(response.status).toBe(503);
  expect(response.body.groups).toBeUndefined();
  expect((await request(app).get('/health')).status).toBe(503);
});

test('storage is mandatory without an explicit development demo setting', async () => {
  db.isAvailable.mockReturnValue(false);
  jwtVerify.mockResolvedValue({ payload: { token_use: 'access', sub: 'operator', roles: ['admin'] } });
  expect((await request(app).post('/api/users').set('Authorization', 'Bearer token').send({ username: 'not-persisted', email: 'test@example.com' })).status).toBe(503);
});

test('production ignores the demo flag and refuses startup without migrated storage', async () => {
  const original = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  process.env.IDENTITY_DEMO_MODE = 'true';
  const listen = jest.spyOn(app, 'listen');
  try {
    await expect(app.start()).rejects.toThrow('requires a migrated database'); expect(listen).not.toHaveBeenCalled();
    let productionApp;
    jest.isolateModules(() => {
      productionApp = require('../index');
      require('../db').isAvailable.mockReturnValue(false);
      require('jose').jwtVerify.mockResolvedValue({ payload: { token_use: 'access', sub: 'operator', roles: ['admin'] } });
    });
    const access = await request(productionApp).get('/api/identity/access').set('Authorization', 'Bearer token');
    expect(access.body.demoMode).toBe(false);
    expect((await request(productionApp).get('/api/groups').set('Authorization', 'Bearer token')).status).toBe(503);
  }
  finally { process.env.NODE_ENV = original; delete process.env.IDENTITY_DEMO_MODE; listen.mockRestore(); }
});
