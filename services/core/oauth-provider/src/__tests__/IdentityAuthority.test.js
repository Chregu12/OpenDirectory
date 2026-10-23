'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { IdentityAuthority } = require('../IdentityAuthority');
const { PATH, TYPE, PURPOSE, AUDIENCE, TARGET_PATH, TARGET_PURPOSE } = require('../../../../../packages/identity-authorization-contract');

const issuer = 'https://issuer.test'; const subject = 'verified-subject';
const context = { userId: crypto.randomUUID(), revision: '10', linkRevision: '11', rolesRevision: 'a'.repeat(64) };
const keys = { ...crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }), kid: 'authority-key' };
const authentication = { required: false, maxAgeSeconds: 86400 };
const tenant = { id: crypto.randomUUID(), version: '1', generation: '2' };
let fetchImpl; let authority;
beforeEach(() => {
  fetchImpl = jest.fn(async () => Response.json({ schemaVersion: 6, tenant, authentication, issuer, subject, active: true, context, roles: [], memberships: [] }));
  authority = new IdentityAuthority({ signingKeys: keys, issuer, fetchImpl,
    credentialAuthority: { state: async () => ({ known: false, ready: false, binding: null, invitation: null }) } });
});

test.each([undefined,{}, { required:'true',maxAgeSeconds:300 },{ required:true,maxAgeSeconds:299 },{ required:false,maxAgeSeconds:86401 },{ required:true,maxAgeSeconds:300,ignore:true }])('missing or malformed role assurance cannot become a permissive legacy response: %j', async policy => {
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion:6,tenant,authentication:policy,issuer,subject,active:true,context,roles:[],memberships:[] }));
  await expect(authority.state(subject)).rejects.toMatchObject({ status:503 });
});
test('schema 3 without role assurance is rejected and no old source fallback is attempted', async () => {
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion:3,issuer,subject,active:true,context,roles:[],memberships:[] }));
  await expect(authority.state(subject)).rejects.toMatchObject({ status:503 }); expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test('an offline owned-role plan is not a live identity-authority envelope or an eligible session', async () => {
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 1, canAuthorize: false, namespace: { id: crypto.randomUUID(), tenant, issuer },
    validUntil: new Date(Date.now() + 60000).toISOString(), users: [{ userId: context.userId, proposedRoles: ['admin'], proposedRolesRevision: 'a'.repeat(64) }], assignments: [] }));
  await expect(authority.state(subject)).rejects.toMatchObject({ status: 503, code: 'identity_authority_unavailable' }); expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test('canonical role policy applies even when role scope and emitted role claims are omitted', async () => {
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion:6,tenant,authentication:{ required:true,maxAgeSeconds:300 },issuer,subject,active:true,context,roles:['license-manager'],memberships:[] }));
  const base = { iss:issuer,sub:subject,actor_type:'user',identity_authorization:context,scope:'openid' };
  expect(await authority.active(base)).toBe(false);
  const authTime = Math.floor(Date.now()/1000);
  const strong = { ...base,auth_time:authTime,amr:['pwd','otp'],mfa_authorization:{ schemaVersion:1,userId:context.userId,revision:'1',authTime,methods:['pwd','otp'] } };
  expect(await authority.active(strong)).toBe(true);
  const old = authTime-301;
  expect(await authority.active({ ...strong,iat:authTime,auth_time:old,mfa_authorization:{ ...strong.mfa_authorization,authTime:old } })).toBe(false);
  expect(await authority.active({ ...base,amr:['pwd','otp'],auth_time:authTime })).toBe(false);
});

test('uses a narrow short-lived signed assertion bound to the fixed endpoint and selected subject', async () => {
  expect(await authority.context(subject)).toEqual(context);
  const [url, options] = fetchImpl.mock.calls[0]; expect(url.pathname).toBe(PATH); expect(options.redirect).toBe('error'); expect(options.cache).toBe('no-store');
  const token = options.headers.Authorization.slice(7);
  const claims = jwt.verify(token, keys.publicKey, { algorithms: ['RS256'], issuer, audience: AUDIENCE });
  expect(jwt.decode(token, { complete: true }).header.typ).toBe(TYPE);
  expect(claims).toMatchObject({ sub: 'oauth-provider', actor_type: 'workload', token_use: PURPOSE, htm: 'POST', htu: PATH, request_subject: subject, scope: 'identity.authorization.read' });
  expect(claims.exp - claims.iat).toBe(30); expect(JSON.parse(options.body)).toEqual({ subject });
});
test('no implicit nonproduction or production eligibility fallback exists', async () => {
  expect(() => new IdentityAuthority({ issuer, signingKeys: keys, demo: true, production: true })).toThrow();
  const demo = new IdentityAuthority({ issuer, signingKeys: keys, demo: true, production: false, fetchImpl });
  expect(await demo.context(subject)).toBeUndefined(); expect(fetchImpl).not.toHaveBeenCalled();
});
test.each(['https://evil.test/elsewhere', 'https://user:password@authority.test' + PATH, 'file:///tmp/state', 'https://authority.test' + PATH + '?target=evil'])('refuses an unsafe authority target: %s', endpoint => {
  expect(() => new IdentityAuthority({ issuer, signingKeys: keys, endpoint })).toThrow();
});
test('missing legacy contexts and different subject generations are not upgraded or grandfathered', async () => {
  const payload = { iss: issuer, sub: subject, actor_type: 'user', identity_authorization: context };
  expect(await authority.active(payload)).toBe(true);
  for (const invalid of [undefined, { ...context, revision: '9' }, { ...context, userId: crypto.randomUUID() }, { ...context, linkRevision: '12' }]) {
    expect(await authority.active({ ...payload, identity_authorization: invalid })).toBe(false);
  }
});
test('disabled, deleted and unlinked identities are denied, not fabricated from their subject', async () => {
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 1, issuer, subject, active: false }));
  await expect(authority.context(subject)).rejects.toMatchObject({ status: 403 });
  expect(await authority.active({ iss: issuer, sub: subject, actor_type: 'user', identity_authorization: context })).toBe(false);
});
test.each([
  { schemaVersion: 1 }, { schemaVersion: 4 }, { schemaVersion: 5 }, { tenant: undefined }, { tenant: { ...tenant, version: '0' } },
  { tenant: { ...tenant, tenantId: tenant.id } }, { issuer: 'https://other.test' }, { subject: 'another' }, { active: 'true' },
  { context: { ...context, revision: 10 } }, { context: { ...context, revision: '9223372036854775808' } },
  { context: { ...context, linkRevision: '0' } }, { context: { ...context, ignored: 'extra' } },
  { context: { ...context, revision: '10\n' } }, { context: { ...context, userId: context.userId + '\n' } },
])('invalid or mismatched authority data is unavailable, never authenticated: %j', override => {
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 6, tenant, authentication, issuer, subject, active: true, context, roles: [], memberships: [], ...override }));
  return expect(authority.context(subject)).rejects.toMatchObject({ status: 503 });
});
test.each([401, 403, 500, 503])('HTTP %i from the workload endpoint is an authority/configuration outage, not an eligible user', status => {
  fetchImpl.mockImplementation(async () => Response.json({}, { status }));
  return expect(authority.context(subject)).rejects.toMatchObject({ status: 503 });
});
test('network, wrong content and oversized bodies fail closed', async () => {
  for (const response of [new Response('not-json'), Response.json({ oversized: 'x'.repeat(4096) })]) {
    fetchImpl.mockResolvedValueOnce(response); await expect(authority.context(subject)).rejects.toMatchObject({ status: 503 });
  }
  fetchImpl.mockRejectedValueOnce(new Error('offline')); await expect(authority.context(subject)).rejects.toMatchObject({ status: 503 });
});
test('a stalled authority is aborted instead of holding refresh transactions indefinitely', async () => {
  fetchImpl.mockImplementation((_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  }));
  await expect(authority.context(subject)).rejects.toMatchObject({ status: 503 });
  expect(fetchImpl.mock.calls[0][1].signal.aborted).toBe(true);
});
test('application sessions stay separate from user eligibility, not a guessed directory mapping', async () => {
  expect(await authority.active({ actor_type: 'application', sub: subject })).toBe(true);
  expect(await authority.active({ actor_type: 'device', sub: subject })).toBe(false); expect(fetchImpl).not.toHaveBeenCalled();
});

test('role expiry fingerprints and source roles, not credential-store roles, determine live access', async () => {
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 6, tenant, authentication, issuer, subject, active: true, context, roles: ['license-manager'], memberships: [] }));
  expect((await authority.state(subject)).authorization).toEqual({ roles: ['license-manager'], permissions: [] });
  const payload = { iss: issuer, sub: subject, actor_type: 'user', identity_authorization: context, scope: 'roles', roles: ['license-manager'], permissions: [] };
  expect(await authority.active(payload)).toBe(true);
  expect(await authority.active({ ...payload, roles: ['admin'] })).toBe(false);
  expect(await authority.active({ ...payload, permissions: ['users.delete'] })).toBe(false);
  expect(await authority.active({ ...payload, identity_authorization: { ...context, rolesRevision: 'b'.repeat(64) } })).toBe(false);
  const { rolesRevision, ...legacy } = context;
  expect(await authority.active({ ...payload, identity_authorization: legacy })).toBe(false);
});
test.each([undefined, ['not-a-role'], ['admin', 'admin'], ['user', 'admin'], 'admin'])('invalid role authority responses fail closed: %j', async roles => {
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 6, tenant, authentication, issuer, subject, active: true, context, roles, memberships: [] }));
  await expect(authority.state(subject)).rejects.toMatchObject({ status: 503 });
});
test('canonical membership proofs are sorted UUID pairs, never credential-store group labels', async () => {
  const member = { groupId: crypto.randomUUID(),membershipId: crypto.randomUUID() };
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 6,tenant,authentication,issuer,subject,active: true,context,roles: [],memberships: [member] }));
  expect((await authority.state(subject)).memberships).toEqual([member]);
  for (const memberships of [undefined,['admins'],[{ groupId: member.groupId,membershipId: 'guessed' }],[member,member],Array(257).fill(member)]) {
    fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 6,tenant,authentication,issuer,subject,active: true,context,roles: [],memberships }));
    await expect(authority.state(subject)).rejects.toMatchObject({ status: 503 });
  }
});
test('role-only schema 2 cannot be mistaken for an authoritative empty membership set', async () => {
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 2,issuer,subject,active: true,context,roles: [] }));
  await expect(authority.state(subject)).rejects.toMatchObject({ status: 503 });
});
test('target eligibility uses its own signed purpose, exact actor/target tuple and fixed origin', async () => {
  const targetId = crypto.randomUUID(); const actorUserId = crypto.randomUUID();
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 1,targetType: 'group',targetId,active: true,revision: '4',actorIsMember: false }));
  expect((await authority.target('group',targetId,actorUserId)).revision).toBe('4');
  const [url,options] = fetchImpl.mock.calls[0]; expect(url.pathname).toBe(TARGET_PATH);
  const claims = jwt.verify(options.headers.Authorization.slice(7),keys.publicKey,{ algorithms: ['RS256'],issuer,audience: AUDIENCE });
  expect(claims).toMatchObject({ token_use: TARGET_PURPOSE,scope: 'identity.application-target.read',htu: TARGET_PATH,target_type: 'group',target_id: targetId,actor_user_id: actorUserId });
  expect(claims.request_subject).toBeUndefined(); expect(JSON.parse(options.body)).toEqual({ targetType: 'group',targetId,actorUserId });
});
test('inactive or mismatched targets cannot become a grant and oversize source bodies are bounded', async () => {
  const targetId = crypto.randomUUID(); const actorId = crypto.randomUUID();
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 1,targetType: 'user',targetId,active: false,revision: null,actorIsMember: false }));
  await expect(authority.target('user',targetId,actorId)).rejects.toMatchObject({ status: 403,code: 'application_target_ineligible' });
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 1,targetType: 'group',targetId,active: true,revision: '1',actorIsMember: false }));
  await expect(authority.target('user',targetId,actorId)).rejects.toMatchObject({ status: 503 });
  fetchImpl.mockImplementation(async () => Response.json({ schemaVersion: 6,tenant,authentication,issuer,subject,active: true,context,roles: [],memberships: [],oversized: 'x'.repeat(65536) }));
  await expect(authority.state(subject)).rejects.toMatchObject({ status: 503 });
});
