'use strict';

const { ClientRegistry, validClient, publicClient, etag, permissionsOf } = require('../ClientRegistry');
const { hashSecret } = require('../clientSecrets');
const user = (role = 'application-administrator', extra = {}) => ({ iss: 'https://issuer.test', sub: 'operator', client_id: 'console', actor_type: 'user', roles: [role], ...extra });
const metadata = extra => ({ name: 'Application', redirectUris: ['https://app.test/callback'], ...extra });
let registry;
beforeEach(() => { registry = new ClientRegistry({}, { demo: true, production: false }); });
test('source consent discovery returns only eligibility and the live generation of a dedicated confidential workload',async()=>{
 const created=await registry.create({name:'Dedicated group source',redirectUris:[],grantTypes:['client_credentials'],scopes:['licenses.groups.derive'],enabled:true},user('admin'));
 const proof=await registry.licenseSource(created.clientId,user('license-scope-administrator'));expect(proof).toEqual({schemaVersion:1,clientId:created.clientId,revision:'1',enabled:true,canReadGroupSources:true});expect(Object.keys(proof)).toHaveLength(5);expect(JSON.stringify(proof)).not.toContain(created.clientSecret);
 const mixed=await registry.create({name:'Not a dedicated source',redirectUris:[],grantTypes:['client_credentials'],scopes:['licenses.groups.derive','licenses.users.read'],enabled:true},user('admin'));expect((await registry.licenseSource(mixed.clientId,user('license-scope-reader'))).canReadGroupSources).toBe(false);await expect(registry.licenseSource(created.clientId,user('application-administrator'))).rejects.toMatchObject({status:403});
});

test('production can never substitute process-local client state', () => {
  expect(() => new ClientRegistry({}, { demo: true, production: true })).toThrow();
});
test('creation is disabled, has no privileged scope and discloses a generated secret only once', async () => {
  const created = await registry.create(metadata(), user());
  expect(created).toMatchObject({ enabled: false, scopes: ['openid','profile','email'], version: '1', protected: false });
  expect(created.clientSecret).toMatch(/^[A-Za-z0-9_-]{43}$/);
  const stored = await registry.get(created.clientId); expect(stored.clientSecretHash).toBe(hashSecret(created.clientSecret));
  expect(stored.clientSecret).toBeUndefined(); expect(created.clientSecretHash).toBeUndefined();
  const page = await registry.list(user('application-reader')); expect(page.clients[0]).toEqual(expect.objectContaining({ clientId: created.clientId }));
  expect(JSON.stringify(page)).not.toContain(created.clientSecret); expect(JSON.stringify(page)).not.toContain(stored.clientSecretHash);
});
test('safe metadata is an explicit projection, not a spread of future secret-bearing fields', async () => {
  const created = await registry.create(metadata(), user()); const stored = await registry.get(created.clientId);
  const safe = publicClient({ ...stored, clientSecret: 'unexpected', secret: 'unexpected', client_secret: 'unexpected' });
  for (const field of ['clientSecret','secret','client_secret','clientSecretHash']) expect(safe[field]).toBeUndefined();
  expect(() => registry.seed({ ...stored, clientSecret: 'unexpected' })).toThrow();
});
test('public clients use S256-compatible metadata and cannot request a shared secret', async () => {
  const created = await registry.create(metadata({ publicClient: true }), user());
  expect(created.clientSecret).toBeNull(); expect((await registry.get(created.clientId)).clientSecretHash).toBeNull();
  await expect(registry.mutate(created.clientId, etag(created), null, user(), 'rotated')).rejects.toMatchObject({ status: 400 });
});
test.each([
  { name: '' }, { name: 'x'.repeat(256) }, { publicClient: 'false' }, { enabled: 1 }, { clientId: 'chosen' }, { createdBy: 'forged' },
  { redirectUris: ['javascript:alert(1)'] }, { redirectUris: ['http://remote.test/callback'] }, { redirectUris: ['https://user:secret@host/callback'] },
  { redirectUris: ['https://app.test/callback#fragment'] }, { redirectUris: [] }, { redirectUris: ['https://app.test/callback','https://app.test/callback'] },
  { scopes: ['openid', {}] }, { scopes: ['openid','openid'] }, { scopes: 'openid' }, { scopes: ['x'.repeat(129)] },
  { grantTypes: ['password'] }, { grantTypes: [] }, { publicClient: true, grantTypes: ['client_credentials'] },
])('invalid, unbounded or actor-injected metadata fails: %j', async input => {
  await expect(registry.create(metadata(input), user('admin'))).rejects.toMatchObject({ status: 400 });
});
test.each(['roles','oauth.admin','gateway.admin','users.delete'])('delegated application management cannot grant %s or take over a privileged client', async scope => {
  await expect(registry.create(metadata({ scopes: [scope] }), user())).rejects.toMatchObject({ status: 403 });
  const sensitive = await registry.create(metadata({ scopes: [scope] }), user('admin'));
  for (const action of ['updated','rotated','deleted']) await expect(registry.mutate(sensitive.clientId, etag(sensitive), { name: 'Takeover' }, user(), action)).rejects.toMatchObject({ status: 403 });
});
test.each(['user','session-administrator','license-administrator'])('%s receives no implicit application authority', async role => {
  expect(permissionsOf(user(role))).toEqual([]); await expect(registry.list(user(role))).rejects.toMatchObject({ status: 403 });
});
test('workloads, oauth.admin scopes and realm labels cannot become a human application administrator', async () => {
  for (const actor of [user('user', { scope: 'oauth.admin' }), user('user', { realm_access: { roles: ['admin'] } }), user('admin', { actor_type: 'application', permissions: ['applications.create'] })]) {
    await expect(registry.create(metadata(), actor)).rejects.toMatchObject({ status: 403 });
  }
});
test('an application reader can inspect safe metadata, never create, rotate or disable', async () => {
  const created = await registry.create(metadata(), user());
  expect((await registry.list(user('application-reader'))).clients).toHaveLength(1);
  await expect(registry.create(metadata(), user('application-reader'))).rejects.toMatchObject({ status: 403 });
  for (const action of ['updated','rotated','deleted']) await expect(registry.mutate(created.clientId, etag(created), { enabled: false }, user('application-reader'), action)).rejects.toMatchObject({ status: 403 });
});
test('create-only delegation cannot bypass the independent activation permission by creating enabled', async () => {
  const creator = user('user', { permissions: ['applications.create'] });
  expect((await registry.create(metadata(), creator)).enabled).toBe(false);
  await expect(registry.create(metadata({ enabled: true }), creator)).rejects.toMatchObject({ status: 403 });
});
test('an unsupported action cannot become an unversioned or unaudited mutation', async () => {
  const client = await registry.create(metadata(), user());
  await expect(registry.mutate(client.clientId, etag(client), {}, user(), 'unknown')).rejects.toMatchObject({ status: 400 });
});
test('updates require an exact single version; concurrent writes cannot overwrite the winner', async () => {
  const created = await registry.create(metadata(), user());
  for (const match of [undefined, '*', etag(created) + ', "other"']) await expect(registry.mutate(created.clientId, match, { enabled: true }, user())).rejects.toMatchObject({ status: match ? 412 : 428 });
  const results = await Promise.allSettled([registry.mutate(created.clientId, etag(created), { enabled: true }, user()), registry.mutate(created.clientId, etag(created), { name: 'Stale' }, user())]);
  expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1); expect((await registry.get(created.clientId)).name).toBe('Application');
});
test('client authentication type is immutable and the current issuing client cannot self-replace', async () => {
  const created = await registry.create(metadata(), user());
  await expect(registry.mutate(created.clientId, etag(created), { publicClient: true }, user())).rejects.toMatchObject({ status: 400 });
  await expect(registry.mutate(created.clientId, etag(created), {}, user('admin', { client_id: created.clientId }))).rejects.toMatchObject({ status: 409 });
});
test('disable, re-enable, rotation and scope changes fence old access/refresh generations permanently', async () => {
  let created = await registry.create(metadata({ enabled: true }), user()); const originalSecret = created.clientSecret;
  const token = { client_id: created.clientId, client_revision: created.version, actor_type: 'user' };
  expect(await registry.active(token)).toBe(true);
  created = await registry.mutate(created.clientId, etag(created), { enabled: false }, user()); expect(await registry.active(token)).toBe(false);
  created = await registry.mutate(created.clientId, etag(created), { enabled: true }, user()); expect(await registry.active(token)).toBe(false);
  expect(await registry.active({ ...token, client_revision: created.version })).toBe(true);
  created = await registry.mutate(created.clientId, etag(created), null, user(), 'rotated');
  expect(registry.authenticated(await registry.get(created.clientId), originalSecret)).toBe(false);
  expect(registry.authenticated(await registry.get(created.clientId), created.clientSecret)).toBe(true);
  const rotated = { ...token, client_revision: created.version };
  created = await registry.mutate(created.clientId, etag(created), { scopes: ['openid'] }, user()); expect(await registry.active(rotated)).toBe(false);
  await registry.mutate(created.clientId, etag(created), null, user(), 'deleted');
  expect(await registry.get(created.clientId)).toBeNull(); expect(await registry.active({ ...token, client_revision: created.version })).toBe(false);
});
test.each([{}, { client_id: 'missing' }, { client_id: 'bad id', client_revision: '1' }, { client_id: 'client', client_revision: 1 }, { client_id: 'client', client_revision: '01' }])('unbound and legacy access claims cannot become current: %j', async payload => {
  expect(await registry.active(payload)).toBe(false);
});
test('no read, mutation or source outage can fall back to a formerly successful SQL authorization', async () => {
  const database = { isAvailable: jest.fn(() => true), pool: { connect: jest.fn().mockRejectedValue(new Error('offline secret')) } };
  const persistent = new ClientRegistry(database);
  await expect(persistent.get('known')).rejects.toMatchObject({ status: 503, code: 'client_authority_unavailable' });
  database.isAvailable.mockReturnValue(false);
  await expect(persistent.active({ client_id: 'known', client_revision: '1' })).rejects.toMatchObject({ status: 503 });
  expect(database.pool.connect).toHaveBeenCalledTimes(1);
});
test('failed audit/commit never returns the generated secret or acknowledges a creation', async () => {
  const query = jest.fn(async sql => { if (sql.startsWith('INSERT INTO oauth_client_audit')) throw new Error('audit offline'); return { rows: [] }; });
  const connection = { query, release: jest.fn() }; const persistent = new ClientRegistry({ isAvailable: () => true, pool: { connect: async () => connection } });
  const actor = user('admin', { identity_authorization: { userId: '351b774a-d60f-450a-86d4-cf4e90336d58', revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } });
  await expect(persistent.create(metadata(), actor)).rejects.toMatchObject({ status: 503 });
  expect(query).toHaveBeenCalledWith('ROLLBACK'); expect(query).not.toHaveBeenCalledWith('COMMIT'); expect(connection.release).toHaveBeenCalled();
});
test('registry initialization is one-time and never resurrects a tombstoned configured ID', async () => {
  const seed = { clientId: 'initial', name: 'Initial', clientSecretHash: hashSecret('disposable'), publicClient: false, redirectUris: [], grantTypes: ['client_credentials'], scopes: [] };
  await registry.initialize([seed]); const initial = await registry.get('initial');
  await registry.mutate('initial', etag(initial), null, user('admin'), 'deleted');
  await registry.initialize([seed]); expect(await registry.get('initial')).toBeNull();
});
test('the client validator rejects malformed persisted generations and secrets', () => {
  expect(validClient({ clientId: 'x', name: 'x', publicClient: false, enabled: true, version: '1', clientSecretHash: 'plaintext', redirectUris: [], grantTypes: ['client_credentials'], scopes: [] })).toBe(false);
});
