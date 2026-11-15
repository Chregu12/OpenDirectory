'use strict';

const { randomUUID } = require('node:crypto');
const { DeviceReturnAuthority } = require('../DeviceReturnAuthority');
const { INVENTORY_PERMISSIONS } = require('../../../../../packages/device-inventory-contract');
let user; let source; let fetchImpl; let authority; let workflowId; let userId;
beforeEach(() => {
  const now = Math.floor(Date.now() / 1000); workflowId = randomUUID(); userId = randomUUID();
  user = { actor_type: 'user', iss: 'https://returns.test', sub: 'original', jti: randomUUID(), exp: now + 3600, auth_time: now,
    identity_authorization: { userId: randomUUID(), revision: '1', linkRevision: '2', rolesRevision: 'a'.repeat(64) } };
  const tenant = { id: randomUUID(), version: '1', generation: '2' };
  source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: structuredClone(user.identity_authorization), tenant,
    actorUserId: user.identity_authorization.userId, permissions: [...INVENTORY_PERMISSIONS], validUntil: now + 300,
    target: { id: userId, enabled: false, eligibilityRevision: '9007199254740993' }, deviceOffboardingReturnsProtocol: 1,
    parent: { workflowId, tenantId: tenant.id, userId, action: 'disabled', operationId: randomUUID(), afterRevision: '9007199254740994', afterEligibilityRevision: '9007199254740993', createdAt: new Date((now - 2) * 1000).toISOString(), deliveryStatus: 'pending' } };
  fetchImpl = jest.fn(async () => Response.json(source)); authority = new DeviceReturnAuthority({ endpoint: 'https://identity.test/api/identity/device-offboarding', fetchImpl });
});
test('only original bearer and exact workflow/user body cross the identity boundary', async () => {
  await expect(authority.read('Bearer original', user, workflowId, userId)).resolves.toEqual(source);
  expect(fetchImpl).toHaveBeenCalledWith(expect.any(URL), expect.objectContaining({ method: 'POST', headers: { Authorization: 'Bearer original', Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ workflowId, userId }), redirect: 'error', cache: 'no-store' }));
  expect(Object.keys(source)).toHaveLength(13); expect(source.target).not.toHaveProperty('revision');
});
test('retained alreadydisabled parent permits null canonical operationId', async () => { source.parent.action = 'already_disabled'; source.parent.operationId = null; await expect(authority.read('Bearer original', user, workflowId, userId)).resolves.toEqual(source); });
test.each(['issuer','subject','tokenId','expiresAt','actorUserId','validUntil','schemaVersion','deviceOffboardingReturnsProtocol'])('mismatched %s cannot substitute the original source', async field => {
  source[field] = typeof source[field] === 'number' ? source[field] + 1 : 'other'; await expect(authority.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 503 });
});
test.each([
  ['extra source field', value => { value.owner = true; }], ['missing source field', value => { delete value.target; }],
  ['context revision', value => { value.context.revision = '2'; }], ['context extra', value => { value.context.admin = true; }],
  ['tenant revision', value => { value.tenant.version = '0'; }], ['tenant uppercase', value => { value.tenant.id = value.tenant.id.toUpperCase(); }],
  ['permission order', value => { value.permissions.reverse(); }], ['extra permission', value => { value.permissions.push('admin'); }],
  ['enabled target', value => { value.target.enabled = true; }], ['foreign target', value => { value.target.id = randomUUID(); }],
  ['target authorization revision', value => { value.target.revision = '1'; }], ['target numeric eligibility', value => { value.target.eligibilityRevision = 2; }],
  ['target overflow eligibility', value => { value.target.eligibilityRevision = '9223372036854775808'; }],
  ['foreign workflow', value => { value.parent.workflowId = randomUUID(); }], ['foreign tenant', value => { value.parent.tenantId = randomUUID(); }],
  ['foreign parent user', value => { value.parent.userId = randomUUID(); }], ['parent eligibility mismatch', value => { value.parent.afterEligibilityRevision = '1'; }],
  ['parent missing', value => { value.parent = null; }], ['parent extra', value => { value.parent.permissions = ['admin']; }],
  ['parent failed delivery', value => { value.parent.deliveryStatus = 'delivered'; }], ['parent invalid action', value => { value.parent.action = 'enabled'; }],
  ['parent missing disable operation', value => { value.parent.operationId = null; }], ['parent fabricated operation', value => { value.parent.operationId = 'operation'; }],
  ['parent numeric record revision', value => { value.parent.afterRevision = 1; }], ['parent noncanonical timestamp', value => { value.parent.createdAt = '2026-01-01'; }],
  ['parent future timestamp', value => { value.parent.createdAt = new Date(Date.now() + 60000).toISOString(); }], ['expired source', value => { value.validUntil = 1; }],
])('rejects %s without fallback', async (_label, change) => { change(source); await expect(authority.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 503 }); });
test.each([400,401,403,404,409,428,503])('source rejection %i never falls back to role or owner claims', async status => {
  fetchImpl.mockResolvedValue(Response.json({}, { status })); await expect(authority.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status });
});
test.each([
  ['application', value => { value.actor_type = 'application'; }], ['missing tokenid', value => { delete value.jti; }],
  ['missing context', value => { delete value.identity_authorization; }], ['missing auth time', value => { delete value.auth_time; }],
  ['invalid expiry', value => { value.exp = NaN; }],
])('rejects %s before transport', async (_label, change) => { change(user); await expect(authority.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 401 }); expect(fetchImpl).not.toHaveBeenCalled(); });
test('self target is rejected before any parent disclosure', async () => { await expect(authority.read('Bearer original', user, workflowId, user.identity_authorization.userId)).rejects.toMatchObject({ status: 403 }); expect(fetchImpl).not.toHaveBeenCalled(); });
test.each(['https://identity.test/other','https://admin:password@identity.test/api/identity/device-offboarding','https://identity.test/api/identity/device-offboarding?tenant=other','https://identity.test/api/identity/device-offboarding#fragment','file:///api/identity/device-offboarding'])('refuses untrusted endpoint %s', endpoint => { expect(() => new DeviceReturnAuthority({ endpoint })).toThrow(); });
test('transport failure, redirect, nonJSON and oversized source remain unavailable', async () => {
  for (const response of [new Response('text', { status: 200 }), Response.json({}, { status: 302 }), new Response(' '.repeat(13000), { headers: { 'content-type': 'application/json' } })]) {
    fetchImpl.mockResolvedValueOnce(response); await expect(authority.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 503 });
  }
  fetchImpl.mockRejectedValueOnce(new Error('offline')); await expect(authority.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 503 });
});

describe('explicit scoped parent protocol', () => {
  let scoped, selected;
  beforeEach(() => {
    user.amr = ['pwd', 'otp']; user.mfa_authorization = { schemaVersion: 1, userId: user.identity_authorization.userId, revision: '1', authTime: user.auth_time, methods: ['pwd', 'otp'] };
    const root = randomUUID(), validUntil = String(source.validUntil);
    const inventory = { ...source, schemaVersion: 2, target: { id: userId, enabled: false, revision: '9007199254740995' },
      scope: { protocol: 1, inherent: [], units: [{ id: root, generation: '9007199254740994', roots: [root] }], resource: null,
        grants: INVENTORY_PERMISSIONS.map(permission => ({ permission, source: { id: randomUUID(), roleId: randomUUID(), roleRevision: '1', scopeType: 'device-ou', ouId: root, ouGeneration: '9007199254740994', targetType: 'user', targetId: source.actorUserId, membershipId: null, validUntil } })) } };
    delete inventory.deviceOffboardingReturnsProtocol; delete inventory.parent;
    source = { schemaVersion: 2, deviceOffboardingReturnsProtocol: 2, inventory, target: source.target, parent: source.parent };
    selected = { deviceId: randomUUID(), deviceRevision: '9223372036854775807', revision: '2', ou: { id: root, generation: '9007199254740994' } };
    scoped = new DeviceReturnAuthority({ scoped: true, endpoint: 'https://identity.test/api/identity/device-offboarding', fetchImpl });
  });
  test('preserves the original nested source without global permission coercion or conflating revisions', async () => {
    await expect(scoped.read('Bearer original', user, workflowId, userId)).resolves.toEqual(source);
    expect(fetchImpl).toHaveBeenCalledWith(expect.any(URL), expect.objectContaining({ headers: { Authorization: 'Bearer original', Accept: 'application/json', 'Content-Type': 'application/json', 'X-OD-Device-Scope-Protocol': '1' }, body: JSON.stringify({ workflowId, userId }), redirect: 'error', cache: 'no-store' }));
    expect(source).not.toHaveProperty('permissions'); expect(source.inventory.target.revision).toBe('9007199254740995');
    expect(source.target.eligibilityRevision).toBe('9007199254740993'); expect(source.parent.afterRevision).toBe('9007199254740994');
    expect(fetchImpl.mock.calls[0][1].signal.aborted).toBe(true);
  });
  test('binds the requested device and disabled recipient to the exact original source', async () => {
    source.inventory.scope.resource = selected;
    await expect(scoped.read('Bearer original', user, workflowId, userId, selected)).resolves.toEqual(source);
    expect(JSON.parse(fetchImpl.mock.calls[0][1].body)).toEqual({ workflowId, userId, device: selected });
    await expect(scoped.read('Bearer original', user, workflowId, userId, { ...selected, revision: '3' })).rejects.toMatchObject({ status: 503 });
  });
  test('a retained already-disabled parent has no invented account operation', async () => {
    source.parent.action = 'already_disabled'; source.parent.operationId = null;
    await expect(scoped.read('Bearer original', user, workflowId, userId)).resolves.toEqual(source);
    source.parent.operationId = randomUUID(); await expect(scoped.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 503 });
  });
  test('the default legacy receiver refuses a nested scoped source', async () => {
    await expect(authority.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 503 });
    expect(fetchImpl.mock.calls[0][1].headers).not.toHaveProperty('X-OD-Device-Scope-Protocol');
  });
  test.each([
    ['top-level permission coercion', value => { value.permissions = [...INVENTORY_PERMISSIONS]; }],
    ['schema coercion', value => { value.schemaVersion = 1; }],
    ['legacy nested source', value => { value.inventory.schemaVersion = 1; delete value.inventory.scope; }],
    ['foreign actor', value => { value.inventory.actorUserId = randomUUID(); }],
    ['changed original token', value => { value.inventory.tokenId = randomUUID(); }],
    ['changed context', value => { value.inventory.context.revision = '2'; }],
    ['missing scope', value => { delete value.inventory.scope; }],
    ['user OU source', value => { value.inventory.scope.grants[0].source.scopeType = 'ou'; }],
    ['lost root generation', value => { value.inventory.scope.units[0].generation = '1'; }],
    ['enabled inner recipient', value => { value.inventory.target.enabled = true; }],
    ['foreign inner recipient', value => { value.inventory.target.id = randomUUID(); }],
    ['eligibility in authorization domain', value => { value.inventory.target.eligibilityRevision = value.target.eligibilityRevision; delete value.inventory.target.revision; }],
    ['missing assignment duty', value => { value.inventory.permissions.pop(); value.inventory.scope.grants.pop(); }],
    ['foreign negative generation', value => { value.target.eligibilityRevision = '1'; }],
    ['enabled outer recipient', value => { value.target.enabled = true; }],
    ['foreign outer recipient', value => { value.target.id = randomUUID(); }],
    ['foreign workflow', value => { value.parent.workflowId = randomUUID(); }],
    ['foreign parent tenant', value => { value.parent.tenantId = randomUUID(); }],
    ['foreign parent user', value => { value.parent.userId = randomUUID(); }],
    ['noncanonical parent revision', value => { value.parent.afterRevision = 2; }],
    ['invented parent operation', value => { value.parent.operationId = null; }],
    ['nonpending parent outbox', value => { value.parent.deliveryStatus = 'delivered'; }],
    ['future parent', value => { value.parent.createdAt = new Date(Date.now() + 60000).toISOString(); }],
    ['expired original source', value => { value.inventory.validUntil = 1; }],
    ['extended MFA cutoff', value => { value.inventory.validUntil += 1; }],
  ])('rejects %s without a legacy fallback', async (_label, change) => {
    change(source); await expect(scoped.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 503 }); expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
  test('original proven MFA remains mandatory for a scoped source', async () => {
    user.amr = ['pwd']; await expect(scoped.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 503 });
  });
  test('invalid selected resources are rejected before transport', async () => {
    await expect(scoped.read('Bearer original', user, workflowId, userId, { ...selected, tenantId: randomUUID() })).rejects.toMatchObject({ status: 400 });
    await expect(authority.read('Bearer original', user, workflowId, userId, selected)).rejects.toMatchObject({ status: 400 }); expect(fetchImpl).not.toHaveBeenCalled();
  });
  test('an oversized scoped source never bypasses the bounded private response', async () => {
    fetchImpl.mockResolvedValue(new Response(' '.repeat(262145), { headers: { 'content-type': 'application/json' } }));
    await expect(scoped.read('Bearer original', user, workflowId, userId)).rejects.toMatchObject({ status: 503 });
  });
});
