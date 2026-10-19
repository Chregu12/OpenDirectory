'use strict';

const { randomUUID } = require('node:crypto');
const { getPolicyPermissions, requirePolicyAccess, ROUTES, ALL_PERMISSIONS } = require('../middleware/policyAccess');
const { ROLES, PROTECTED, MFA_LOCKED_ROLES } = require('../../../../../packages/directory-role-contract');
const userId = randomUUID();
function actor(roles = ['user'], fresh = false) {
  const authTime = Math.floor(Date.now() / 1000);
  return { actor_type: 'user', sub: 'operator', iss: 'https://policy.test', roles,
    identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
    ...(fresh ? { auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', methods: ['pwd', 'otp'], authTime } } : {}) };
}
function invoke(method, path, user, body = {}) {
  const req = { method, path, user, body, query: {}, headers: {} };
  const res = { set: jest.fn().mockReturnThis(), status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() };
  const next = jest.fn(); requirePolicyAccess(req, res, next);
  return { req, res, next };
}

test('canonical catalog duties separate policy management, deployment and reading without license or directory powers', () => {
  for (const role of ['policy-reader', 'policy-administrator']) expect(ROLES).toContain(role);
  expect(PROTECTED).toContain('policy-administrator'); expect(MFA_LOCKED_ROLES).toContain('policy-administrator');
  expect(getPolicyPermissions(actor(['policy-reader']))).toEqual(['policies.read', 'policies.preview', 'policies.audit.read']);
  expect(getPolicyPermissions(actor(['policy-deployment-operator']))).not.toContain('policies.manage');
  expect(getPolicyPermissions(actor(['policy-administrator']))).toContain('policies.publication.request');
  expect(getPolicyPermissions(actor(['policy-administrator']))).not.toContain('policies.publication.review');
  expect(getPolicyPermissions(actor(['policy-publication-reviewer']))).toContain('policies.publication.review');
  expect(getPolicyPermissions(actor(['policy-publication-reviewer']))).not.toContain('policies.manage');
  expect(PROTECTED).toContain('policy-publication-reviewer'); expect(MFA_LOCKED_ROLES).toContain('policy-publication-reviewer');
  expect(getPolicyPermissions(actor(['license-manager', 'license-scope-administrator', 'directory-reader']))).toEqual([]);
});
test('even global administration does not advertise or acquire the separate review duty without its explicit protected role',()=>{
  expect(getPolicyPermissions(actor(['admin']))).not.toContain('policies.publication.review');
  expect(getPolicyPermissions(actor(['admin','policy-publication-reviewer']))).toContain('policies.publication.review');
});

test.each(['permissions', 'scope', 'realm_access', 'body'])('does not borrow unexpected %s authority', field => {
  const user = actor(); user[field] = field === 'realm_access' ? { roles: ['admin'] } : field === 'permissions' ? ALL_PERMISSIONS : 'policies.manage';
  const result = invoke('POST', '/policies', user, { roles: ['admin'], permissions: ALL_PERMISSIONS });
  expect(result.res.status).toHaveBeenCalledWith(403); expect(result.next).not.toHaveBeenCalled();
});

test.each([undefined, {}, { ...actor(['admin']), actor_type: 'application' }, { ...actor(['admin']), identity_authorization: null }])('requires a canonical human context', user => {
  expect(invoke('GET', '/policies/access', user).res.status).toHaveBeenCalledWith(403);
});

const paths = [
  ['POST', '/policies/delivery/frame'],
  ['GET', '/policies/id/publications'], ['POST', '/policies/id/publications'], ['POST', '/policies/id/publications/request-id/decisions'],
  ['GET', '/blueprints/id/publications'], ['POST', '/blueprints/id/publications'], ['POST', '/blueprints/id/publications/request-id/decisions'],
  ['GET', '/policies'], ['GET', '/policies/templates'], ['GET', '/policies/conflicts'], ['GET', '/policies/baselines'], ['GET', '/policies/simulate'],
  ['GET', '/policies/inheritance/ou'], ['GET', '/policies/inheritance/group/group-id'], ['GET', '/policies/id/audit'], ['GET', '/policies/id/assignments'],
  ['GET', '/policies/id/links'], ['GET', '/policies/id'], ['POST', '/policies/evaluate'], ['POST', '/policies/rsop'], ['POST', '/policies/id/compile/windows'],
  ['POST', '/policies'], ['POST', '/policies/from-template'], ['PUT', '/policies/id'], ['DELETE', '/policies/id'], ['POST', '/policies/id/wmi-filter'],
  ['POST', '/policies/id/activate'], ['POST', '/policies/id/deactivate'], ['POST', '/policies/id/assign'], ['POST', '/policies/id/link'],
  ['DELETE', '/policies/id/link/link-id'], ['POST', '/policies/baselines/id/apply'], ['GET', '/update-rings'], ['PUT', '/update-rings/stable'],
  ['POST', '/update-rings/stable/assign'], ['GET', '/gpo'], ['GET', '/gpo/effective/windows'], ['POST', '/gpo'], ['PUT', '/gpo/id'], ['DELETE', '/gpo/id'],
  ['POST', '/gpo/id/apply'], ['GET', '/blueprints'], ['GET', '/blueprints/id'], ['GET', '/blueprints/id/assignments'], ['POST', '/blueprints'],
  ['PUT', '/blueprints/id'], ['DELETE', '/blueprints/id'], ['POST', '/blueprints/id/configurations'], ['DELETE', '/blueprints/id/configurations/config-id'],
  ['POST', '/blueprints/id/assign'], ['POST', '/blueprints/id/apply'],
  ['POST', '/blueprints/preview'],
];
test.each(paths)('denies an ordinary user before business work: %s %s', (method, path) => {
  const result = invoke(method, path, actor()); expect(result.res.status).toHaveBeenCalledWith(403); expect(result.next).not.toHaveBeenCalled();
});

test('the deny matrix covers every currently registered non-license business route and fails when a route is added without review', () => {
  const source = require('node:fs').readFileSync(require('node:path').join(__dirname, '../policyConfigurationRoutes.js'), 'utf8');
  const registered = [...source.matchAll(/router\.(get|post|put|patch|delete)\('([^']+)'/g)]
    .map(match => [match[1].toUpperCase(), match[2].replace(/^\/api/, '')]).filter(([, path]) => path.startsWith('/') && !path.startsWith('/licenses') && !['/health'].includes(path));
  expect(registered).toHaveLength(paths.length + 1);
  for (const [method, path] of registered) {
    const concrete = path.replace(/:[A-Za-z0-9_]+/g, 'known-id');
    expect(ROUTES.some(([verb, pattern]) => verb === method && pattern.test(concrete))).toBe(true);
    if (path !== '/policies/access') expect(invoke(method, concrete, actor()).res.status).toHaveBeenCalledWith(403);
  }
});

test.each(paths.filter(([method, path]) => !['policies.read', 'policies.preview', 'policies.audit.read'].includes(ROUTES.find(([verb, pattern]) => verb === method && pattern.test(path))[2])))('denies a reader mutation: %s %s', (method, path) => {
  const result = invoke(method, path, actor(['policy-reader'], true)); expect(result.res.status).toHaveBeenCalledWith(403); expect(result.next).not.toHaveBeenCalled();
});

test.each(['admin', 'policy-administrator', 'policy-deployment-operator'])('sensitive operations require independently bound fresh MFA even for %s', role => {
  const user = actor([role]); expect(invoke('POST', '/policies/id/activate', user).res.status).toHaveBeenCalledWith(428);
  const fresh = actor([role], true); expect(invoke('POST', '/policies/id/activate', fresh).next).toHaveBeenCalledTimes(1);
  const aged = structuredClone(fresh); aged.auth_time -= 301; aged.mfa_authorization.authTime = aged.auth_time;
  expect(invoke('POST', '/policies/id/activate', aged).res.status).toHaveBeenCalledWith(428);
  fresh.mfa_authorization.userId = randomUUID(); expect(invoke('POST', '/policies/id/activate', fresh).res.status).toHaveBeenCalledWith(428);
});

test.each([['PATCH', '/policies/id'], ['POST', '/policies/id/unknown'], ['GET', '/unknown'], ['GET', '/licenses-forged'], ['HEAD', '/policies']])('defaults to deny new or unsupported operations: %s %s', (method, path) => {
  const result = invoke(method, path, actor(['admin'], true)); expect(result.res.status).toHaveBeenCalledWith(404); expect(result.next).not.toHaveBeenCalled();
});

test('license paths retain their independent existing receiver boundary, not a new policy grant', () => {
  const result = invoke('POST', '/licenses/id/assign', actor()); expect(result.next).toHaveBeenCalledTimes(1); expect(result.req.policyActor).toBeUndefined();
});

test('the attributed actor is only the verified canonical user, never an input alias', () => {
  const result = invoke('POST', '/policies', actor(['policy-administrator'], true), { created_by: 'someone-else', actor: 'root' });
  expect(result.next).toHaveBeenCalledTimes(1); expect(result.req.policyActor).toBe(userId);
});
