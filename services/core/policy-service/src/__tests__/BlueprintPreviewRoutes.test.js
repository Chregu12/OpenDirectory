'use strict';

const express = require('express');
const request = require('supertest');
const { randomUUID } = require('node:crypto');
const { PolicyConfiguration, etag } = require('../PolicyConfiguration');
const { policyConfigurationRoutes } = require('../policyConfigurationRoutes');
const { requirePolicyAccess, getPolicyPermissions } = require('../middleware/policyAccess');

const actorId = randomUUID();
const blueprintId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const configurationId = randomUUID();
const publicationId = randomUUID();
const bearer = 'Bearer owned.preview.route';
let fixture;
let app;
let store;
let database;
let delivery;
let authority;
let publication;
let queries;
let released;
let afterSnapshot;

function actor(roles = ['policy-reader'], fresh = false) {
  const authTime = Math.floor(Date.now() / 1000);
  return { actor_type: 'user', token_use: 'access', iss: 'https://blueprint-preview-routes.test', sub: 'owned-preview-reader',
    client_id: 'owned-preview-client', jti: randomUUID(), exp: authTime + 3600, iat: authTime, roles,
    identity_authorization: { userId: actorId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
    ...(fresh ? { auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: {
      schemaVersion: 1, userId: actorId, revision: '1', authTime, methods: ['pwd', 'otp'],
    } } : {}) };
}
const input = () => ({ platform: 'windows', blueprints: [{ id: blueprintId, version: 2 }] });
const source = id => ({ blueprintId, configurationId: id });
function setup(user = actor()) {
  fixture = { row: { id: blueprintId, name: 'Owned route blueprint', platform: 'windows', version: 2 }, assignments: [],
    configurations: [{ id: configurationId, blueprint_id: blueprintId, config_type: 'wifi', config_name: 'Owned wifi', payload: { ssid: 'Owned' } }],
    previewRows: [{ id: configurationId, blueprint_id: blueprintId, config_type: 'wifi', payload_json: '{"ssid": "Owned"}', payload_rank: '1' }] };
  queries = [];
  released = jest.fn();
  afterSnapshot = null;
  const client = { release: released, query: jest.fn(async (sql, parameters) => {
    queries.push({ sql, parameters });
    if (sql.includes('FROM blueprints')) return { rows: fixture.row ? [structuredClone(fixture.row)] : [] };
    if (sql.includes('FROM blueprint_assignments')) return { rows: structuredClone(fixture.assignments) };
    if (sql.includes('dense_rank()')) return { rows: structuredClone(fixture.previewRows) };
    if (sql.includes('FROM blueprint_configurations')) {
      const rows = structuredClone(fixture.configurations);
      if (afterSnapshot) await afterSnapshot();
      return { rows };
    }
    if (/^(BEGIN|SET LOCAL|COMMIT|ROLLBACK)/.test(sql)) return { rows: [] };
    throw new Error('Unexpected preview test SQL: ' + sql);
  }) };
  database = { getClient: jest.fn(async () => client), query: jest.fn() };
  authority = jest.fn(async () => {});
  store = new PolicyConfiguration(database, { authority });
  publication = jest.spyOn(store.publications, 'assertUse').mockResolvedValue({ id: publicationId, state: 'approved' });
  delivery = { request: jest.fn(async () => ({ body: { id: 'owned-device-command', policyReceipt: { state: 'queued' } } })) };
  app = express();
  app.use(express.json());
  app.use((req, res, next) => { req.user = user; next(); });
  app.use(requirePolicyAccess);
  app.use(policyConfigurationRoutes(database, { store, delivery, loadTemplates: () => [], catalog: { baselines: [] },
    rsopEngine: {}, conflictResolver: {}, inheritanceEngine: {}, compilers: {} }));
}
const post = body => request(app).post('/blueprints/preview').set('Authorization', bearer).send(body);
function apply(body = { acknowledgeScope: true, publicationId }, version = 2) {
  return request(app).post('/blueprints/' + blueprintId + '/apply').set('Authorization', bearer)
    .set('If-Match', etag('blueprint', { id: blueprintId, version })).send(body);
}
function conflicting() {
  const second = randomUUID();
  fixture.configurations.push({ id: second, blueprint_id: blueprintId, config_type: 'wifi', config_name: 'Different actual SQL variant', payload: { ssid: 'Different' } });
  fixture.previewRows.push({ id: second, blueprint_id: blueprintId, config_type: 'wifi', payload_json: '{"ssid": "Different"}', payload_rank: '2' });
  return second;
}

beforeEach(() => setup());
afterEach(() => jest.restoreAllMocks());

test('POST preview uses actual read-only authority, exact PostgreSQL payload text and a no-store response without publication or delivery', async () => {
  const previewMethod = jest.spyOn(store, 'previewBlueprints');
  const response = await post(input());
  expect(response.status).toBe(200);
  expect(response.headers['cache-control']).toBe('no-store');
  expect(response.body).toEqual({ schemaVersion: 1, scope: 'selected-blueprint-versions', comparison: 'whole-config-type', platform: 'windows',
    previewOnly: true, enforcementConfirmed: false, licenseReservations: 0,
    blueprints: [{ id: blueprintId, name: 'Owned route blueprint', platform: 'windows', version: 2 }],
    configurationCount: 1, hasConflicts: false, effectiveConfigurations: [{ configType: 'wifi', payloadJson: '{"ssid": "Owned"}', sources: [source(configurationId)] }], conflicts: [] });
  expect(previewMethod).toHaveBeenCalledWith(input(), expect.objectContaining({ roles: ['policy-reader'] }), bearer, expect.any(AbortSignal));
  expect(authority).toHaveBeenCalledTimes(2);
  expect(authority.mock.calls.every(([authorization]) => authorization === bearer)).toBe(true);
  expect(queries[0].sql).toBe('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  expect(queries.at(-1).sql).toBe('COMMIT');
  expect(queries.some(({ sql }) => /\b(INSERT|UPDATE|DELETE|set_config)\b/i.test(sql))).toBe(false);
  expect(released).toHaveBeenCalledTimes(1);
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});

test('the route preserves actual SQL conflicts as preview data rather than reporting a deployment failure or effective winner', async () => {
  const second = conflicting();
  const response = await post(input());
  expect(response.status).toBe(200);
  expect(response.body.hasConflicts).toBe(true);
  expect(response.body.effectiveConfigurations).toEqual([]);
  expect(response.body.conflicts).toEqual([{ configType: 'wifi', variants: [
    { payloadJson: '{"ssid": "Owned"}', sources: [source(configurationId)] },
    { payloadJson: '{"ssid": "Different"}', sources: [source(second)] },
  ] }]);
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});

test.each(['policy-reader', 'policy-deployment-operator', 'policy-administrator', 'policy-publication-reviewer'])('preview retains the existing %s permissions without adding a new grant', async role => {
  const user = actor([role]);
  const before = getPolicyPermissions(user);
  setup(user);
  expect((await post(input())).status).toBe(200);
  expect(getPolicyPermissions(user)).toEqual(before);
  expect(getPolicyPermissions(user)).toContain('policies.preview');
});

test.each(['user', 'license-manager', 'directory-reader', 'organization-administrator'])('an unrelated %s cannot borrow preview rights from the request', async role => {
  const user = actor([role], true);
  user.scope = 'policies.preview';
  user.permissions = ['policies.preview'];
  setup(user);
  const response = await post({ ...input(), permissions: ['policies.preview'], roles: ['admin'] });
  expect(response.status).toBe(403);
  expect(response.body).toEqual({ error: 'forbidden', permission: 'policies.preview' });
  expect(database.getClient).not.toHaveBeenCalled();
  expect(authority).not.toHaveBeenCalled();
});

test.each(['application', 'service'])('a %s actor with administrator claims cannot become a canonical preview user', async kind => {
  setup({ ...actor(['admin'], true), actor_type: kind });
  const response = await post(input());
  expect(response.status).toBe(403);
  expect(response.body.error).toBe('canonical_policy_operator_required');
  expect(database.getClient).not.toHaveBeenCalled();
});

const invalidBodies = [
  ['empty object', {}], ['array', []], ['missing platform', { blueprints: [{ id: blueprintId, version: 2 }] }],
  ['all platform', { ...input(), platform: 'all' }], ['unknown platform', { ...input(), platform: 'ios' }],
  ['extra top-level field', { ...input(), priority: 100 }], ['empty selection', { ...input(), blueprints: [] }],
  ['too many selections', { ...input(), blueprints: Array.from({ length: 26 }, () => ({ id: randomUUID(), version: 1 })) }],
  ['duplicate UUID', { ...input(), blueprints: [{ id: blueprintId, version: 2 }, { id: blueprintId, version: 3 }] }],
  ['extra selected field', { ...input(), blueprints: [{ id: blueprintId, version: 2, priority: 0 }] }],
  ['uppercase UUID', { ...input(), blueprints: [{ id: blueprintId.toUpperCase(), version: 2 }] }],
  ['invalid UUID', { ...input(), blueprints: [{ id: 'not-a-uuid', version: 2 }] }],
  ['string version', { ...input(), blueprints: [{ id: blueprintId, version: '2' }] }],
  ['zero version', { ...input(), blueprints: [{ id: blueprintId, version: 0 }] }],
  ['negative version', { ...input(), blueprints: [{ id: blueprintId, version: -1 }] }],
  ['fractional version', { ...input(), blueprints: [{ id: blueprintId, version: 1.5 }] }],
  ['overflow version', { ...input(), blueprints: [{ id: blueprintId, version: 2147483648 }] }],
  ['null selected item', { ...input(), blueprints: [null] }],
];
test.each(invalidBodies)('invalid %s is rejected before source reads with the exact bounded-request error', async (label, body) => {
  const response = await post(body);
  expect(response.status).toBe(400);
  expect(response.body).toEqual({ error: 'exact_blueprint_preview_required' });
  expect(database.getClient).not.toHaveBeenCalled();
  expect(authority).not.toHaveBeenCalled();
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});

test.each([
  ['missing', 404, 'policy_resource_not_found'],
  ['stale', 412, 'policy_configuration_changed'],
  ['platform', 409, 'blueprint_platform_mismatch'],
  ['corrupt', 503, 'blueprint_preview_source_unavailable'],
  ['limit', 409, 'blueprint_preview_limit_reached'],
])('source %s errors survive the HTTP boundary and roll back without external calls', async (kind, status, code) => {
  if (kind === 'missing') fixture.row = null;
  if (kind === 'stale') fixture.row.version = 3;
  if (kind === 'platform') fixture.row.platform = 'macos';
  if (kind === 'corrupt') fixture.previewRows[0].payload_json = '[]';
  if (kind === 'limit') fixture.previewRows = Array.from({ length: 1001 }, () => ({ ...fixture.previewRows[0], id: randomUUID() }));
  const response = await post(input());
  expect(response.status).toBe(status);
  expect(response.body).toEqual({ error: code });
  expect(queries.at(-1).sql).toBe('ROLLBACK');
  expect(released).toHaveBeenCalledTimes(1);
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});

test.each([1, 2])('original authority withdrawal on check %s never acknowledges a successful preview', async check => {
  authority.mockImplementation(async () => {
    if (authority.mock.calls.length === check) throw Object.assign(new Error('Owned original access withdrawn'), { status: 401, code: 'owned_access_withdrawn' });
  });
  const response = await post(input());
  expect(response.status).toBe(401);
  expect(response.body).toEqual({ error: 'owned_access_withdrawn' });
  expect(queries.some(({ sql }) => sql === 'COMMIT')).toBe(false);
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});

test('a successful preview does not give its reader deployment authority', async () => {
  expect((await post(input())).status).toBe(200);
  const response = await apply();
  expect(response.status).toBe(403);
  expect(response.body).toEqual({ error: 'forbidden', permission: 'policies.deploy' });
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});

test('a conflicting single-blueprint apply is blocked before independent publication lookup or any receiver request', async () => {
  setup(actor(['policy-deployment-operator'], true));
  conflicting();
  const previewMethod = jest.spyOn(store, 'previewBlueprints');
  const response = await apply();
  expect(response.status).toBe(409);
  expect(response.body).toEqual({ error: 'blueprint_configuration_conflict' });
  expect(previewMethod).toHaveBeenCalledWith(input(), expect.any(Object), bearer, expect.any(AbortSignal));
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});

test('stale apply source versions fail before both preview and publication admission', async () => {
  setup(actor(['policy-deployment-operator'], true));
  conflicting();
  const previewMethod = jest.spyOn(store, 'previewBlueprints');
  const response = await apply(undefined, 1);
  expect(response.status).toBe(412);
  expect(response.body.error).toBe('policy_configuration_changed');
  expect(previewMethod).not.toHaveBeenCalled();
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});

test('a source changing between apply snapshot and separate preview is rejected before publication rather than mixing generations', async () => {
  setup(actor(['policy-deployment-operator'], true));
  afterSnapshot = async () => { fixture.row.version = 3; };
  const response = await apply();
  expect(response.status).toBe(412);
  expect(response.body.error).toBe('policy_configuration_changed');
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});

test('nonconflicting preview is not a substitute for the mandatory independent publication', async () => {
  setup(actor(['policy-deployment-operator'], true));
  publication.mockRejectedValue(Object.assign(new Error('Owned publication absent'), { status: 409, code: 'current_independent_policy_publication_required' }));
  const response = await apply();
  expect(response.status).toBe(409);
  expect(response.body.error).toBe('current_independent_policy_publication_required');
  expect(publication).toHaveBeenCalledWith('blueprint', blueprintId, 2, publicationId, expect.any(Object), bearer, expect.any(AbortSignal));
  expect(delivery.request).not.toHaveBeenCalled();
});

test('a nonconflicting blueprint still checks publication before receiver admission and does not claim endpoint enforcement', async () => {
  setup(actor(['policy-deployment-operator'], true));
  const response = await apply();
  expect(response.status).toBe(200);
  expect(publication).toHaveBeenCalledTimes(1);
  expect(delivery.request).toHaveBeenCalledTimes(1);
  expect(publication.mock.invocationCallOrder[0]).toBeLessThan(delivery.request.mock.invocationCallOrder[0]);
  expect(delivery.request.mock.calls[0].slice(2)).toEqual(['devices', '/api/devices/policy-command-access']);
  expect(response.body.enforcementConfirmed).toBe(false);
  expect(response.body.phase).toBe('no-targets');
});

test('all-platform apply uses an explicit concrete preview scope without changing the original source platform', async () => {
  setup(actor(['policy-deployment-operator'], true));
  fixture.row.platform = 'all';
  const previewMethod = jest.spyOn(store, 'previewBlueprints');
  const response = await apply();
  expect(response.status).toBe(200);
  expect(previewMethod.mock.calls[0][0]).toEqual({ platform: 'macos', blueprints: [{ id: blueprintId, version: 2 }] });
  expect(fixture.row.platform).toBe('all');
});

test('fresh MFA remains mandatory for apply even though preview itself is read-only', async () => {
  setup(actor(['policy-deployment-operator']));
  expect((await post(input())).status).toBe(200);
  const response = await apply();
  expect(response.status).toBe(428);
  expect(response.body.error).toBe('fresh_mfa_required');
  expect(publication).not.toHaveBeenCalled();
  expect(delivery.request).not.toHaveBeenCalled();
});
