'use strict';

const { randomUUID } = require('node:crypto');
const { CompanyBlueprintAssignmentAuthority } = require('../licenses/CompanyBlueprintAssignmentAuthority');
const contract = require('../../../../../packages/company-blueprint-assignment-contract');
const blueprint = require('../../../../../packages/company-blueprint-contract');
const { COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS, validSource } = contract;
const actorUserId = randomUUID(); const targetId = randomUUID(); const tenant = { id: randomUUID(), version: '1', generation: '1' };
const bearer = 'Bearer original.assignment'; const endpoint = 'https://identity.test/api/identity/company-blueprint-assignments';
let user; let source;
beforeEach(() => {
  const now = Math.floor(Date.now() / 1000); const context = { userId: actorUserId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) };
  user = { actor_type: 'user', token_use: 'access', iss: 'https://assignment.test', sub: 'actual-owner', jti: randomUUID(), exp: now + 600, auth_time: now, amr: ['pwd', 'otp'], identity_authorization: context,
    mfa_authorization: { schemaVersion: 1, userId: actorUserId, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
  source = { schemaVersion: 1, companyBlueprintAssignmentsProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context, tenant, actorUserId,
    permissions: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS], validUntil: now + 300, target: null };
});
afterEach(() => jest.useRealTimers());
const response = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const target = () => ({ id: targetId, revision: '9007199254740993', eligibilityRevision: '9223372036854775807', enabled: true, deleted: false });

test('the package adds only source validation and reuses original blueprint helpers without assignment commands', () => {
  expect(Object.keys(contract)).toEqual(['COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS', 'fail', 'exact', 'identifier', 'revision', 'text', 'versionNumber', 'pagination', 'validSource']);
  for (const name of ['fail', 'exact', 'identifier', 'revision', 'text', 'versionNumber', 'pagination']) expect(contract[name]).toBe(blueprint[name]);
  expect(COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS).toEqual(['company.blueprints.assignments.read', 'company.blueprints.assign']); expect(Object.isFrozen(COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS)).toBe(true);
  expect(blueprint.COMPANY_BLUEPRINT_PERMISSIONS).toEqual(['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish']); expect(validSource(source, user)).toBe(true);
});
test('actor mode makes only a GET with the actual original bearer and no target or credential fallback', async () => {
  const fetchImpl = jest.fn(async () => response(source)); const reader = new CompanyBlueprintAssignmentAuthority({ endpoint, fetchImpl });
  expect(await reader.read(bearer, user)).toEqual(source); const [url, request] = fetchImpl.mock.calls[0];
  expect(url.href).toBe(endpoint); expect(request).toMatchObject({ method: 'GET', headers: { Authorization: bearer, Accept: 'application/json' }, redirect: 'error', cache: 'no-store' });
  expect(request.headers['Content-Type']).toBeUndefined(); expect(request.body).toBeUndefined(); expect(request.signal.aborted).toBe(true);
});
test.each([{ enabled: true }, { enabled: false }, { revision: null, enabled: false, deleted: true }])('target mode POST retains only exact positive/negative canonical user evidence: %j', async patch => {
  source.target = { ...target(), ...patch }; expect(validSource(source, user, targetId)).toBe(true); expect(validSource(source, user)).toBe(false);
  const fetchImpl = jest.fn(async () => response(source)); expect(await new CompanyBlueprintAssignmentAuthority({ endpoint, fetchImpl }).read(bearer, user, targetId)).toEqual(source);
  expect(fetchImpl.mock.calls[0][1]).toMatchObject({ method: 'POST', headers: { Authorization: bearer, 'Content-Type': 'application/json' }, body: JSON.stringify({ userId: targetId }) });
});
test.each([
  { schemaVersion: 2 }, { companyBlueprintAssignmentsProtocol: 2 }, { issuer: 'foreign' }, { subject: 'other' }, { tokenId: 'other' }, { expiresAt: 1 },
  { actorUserId: randomUUID() }, { actorUserId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, { context: null }, { target: target() }, { extra: true },
  { permissions: ['company.blueprints.read', 'company.blueprints.publish'] }, { permissions: ['company.blueprints.assign'] },
  { permissions: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS].reverse() }, { permissions: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS, 'company.apps.assign'] },
  { validUntil: 1 }, { validUntil: 9999999999 }, { validUntil: '9999999999' }, { validUntil: 1.5 },
  { tenant: { ...tenant, version: '0' } }, { tenant: { ...tenant, generation: '9223372036854775808' } },
])('exact source trust boundary rejects substitutions or expanded duties: %j', async patch => {
  const value = { ...source, ...patch }; expect(validSource(value, user)).toBe(false);
  await expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl: async () => response(value) }).read(bearer, user)).rejects.toMatchObject({ status: 503 });
});
test.each(['schemaVersion', 'companyBlueprintAssignmentsProtocol', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil', 'target'])('all twelve fields are mandatory, including %s', field => {
  delete source[field]; expect(validSource(source, user)).toBe(false);
});
test.each([
  { id: randomUUID() }, { revision: null }, { revision: '0' }, { revision: 1 }, { revision: '9223372036854775808' },
  { eligibilityRevision: '0' }, { eligibilityRevision: '01' }, { eligibilityRevision: 1 }, { enabled: 'true' }, { deleted: 'false' },
  { deleted: true }, { deleted: true, revision: null }, { email: 'forbidden profile projection' },
])('target evidence cannot substitute account state, add a profile or lose exact int8 generation: %j', async patch => {
  source.target = { ...target(), ...patch }; expect(validSource(source, user, targetId)).toBe(false);
  await expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl: async () => response(source) }).read(bearer, user, targetId)).rejects.toMatchObject({ status: 503 });
});
test('targeted transport cannot accept a null target or another requested recipient', async () => {
  const reader = new CompanyBlueprintAssignmentAuthority({ fetchImpl: async () => response(source) });
  await expect(reader.read(bearer, user, targetId)).rejects.toMatchObject({ status: 503 });
  source.target = target(); expect(validSource(source, user, randomUUID())).toBe(false);
});
test.each([{ token_use: 'refresh' }, { actor_type: 'application' }, { identity_authorization: null }, { jti: '' }, { exp: '9999999999' }, { auth_time: null }])('invalid original human %j is denied before transport', async patch => {
  const fetchImpl = jest.fn(); await expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl }).read(bearer, { ...user, ...patch })).rejects.toMatchObject({ status: 401 }); expect(fetchImpl).not.toHaveBeenCalled();
});
test.each([null, '', 'Basic original', 'Bearer original token', 'bearer original', 'Bearer ' + 'a'.repeat(16384)])('invalid original bearer %s cannot enter transport', async authorization => {
  const fetchImpl = jest.fn(); await expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl }).read(authorization, user)).rejects.toMatchObject({ status: 401 }); expect(fetchImpl).not.toHaveBeenCalled();
});
test.each(['alias', '', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', 1, {}])('a noncanonical target selector %j cannot enter transport', async userId => {
  const fetchImpl = jest.fn(); await expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl }).read(bearer, user, userId)).rejects.toMatchObject({ status: 400 }); expect(fetchImpl).not.toHaveBeenCalled();
});
test.each(['missing', 'password-only', 'unbound', 'stale', 'future'])('fresh independently bound MFA cannot be substituted by a valid-looking source: %s', async mode => {
  if (mode === 'missing') delete user.mfa_authorization;
  if (mode === 'password-only') { user.amr = ['pwd']; user.mfa_authorization.methods = ['pwd']; }
  if (mode === 'unbound') user.mfa_authorization.userId = randomUUID();
  if (mode === 'stale') { user.auth_time -= 301; user.mfa_authorization.authTime -= 301; }
  if (mode === 'future') { user.auth_time += 6; user.mfa_authorization.authTime += 6; }
  expect(validSource(source, user)).toBe(false); await expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl: async () => response(source) }).read(bearer, user)).rejects.toMatchObject({ status: 503 });
});
test('source expiry is strict at the captured deadline and never beyond the original token or now plus 300 seconds', () => {
  const now = user.auth_time * 1000; expect(validSource(source, user, null, now + 299999)).toBe(true); expect(validSource(source, user, null, now + 300000)).toBe(false);
  source.validUntil++; expect(validSource(source, user, null, now)).toBe(false);
  source.validUntil = user.auth_time + 300; user.exp = user.auth_time + 30; source.expiresAt = user.exp; expect(validSource(source, user, null, now)).toBe(false);
});
test.each([400, 401, 403, 404, 428, 429, 302, 500])('source denial HTTP %s never retries, redirects or falls back', async status => {
  const fetchImpl = jest.fn(async () => ({ status }));
  await expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl }).read(bearer, user)).rejects.toMatchObject({ status: [400, 401, 403, 404, 428].includes(status) ? status : 503 }); expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test.each(['file:///tmp/source', 'https://user:secret@identity.test/api/identity/company-blueprint-assignments', 'https://identity.test/api/identity/company-blueprints', endpoint + '?tenant=other', endpoint + '#fallback'])('unsupported source URL %s never opens a connection', value => {
  expect(() => new CompanyBlueprintAssignmentAuthority({ endpoint: value })).toThrow();
});
test.each(['not-json', 'json-suffix', 'missing-body', 'malformed-json', 'oversized'])('unavailable or invalid response %s fails closed', async mode => {
  const fetchImpl = async () => mode === 'not-json' ? new Response(JSON.stringify(source), { headers: { 'Content-Type': 'text/html' } })
    : mode === 'json-suffix' ? new Response(JSON.stringify(source), { headers: { 'Content-Type': 'application/json-not-actually-json' } })
    : mode === 'missing-body' ? { status: 200, headers: new Headers({ 'Content-Type': 'application/json' }) }
      : mode === 'malformed-json' ? new Response('{broken', { headers: { 'Content-Type': 'application/json' } })
        : { status: 200, headers: new Headers({ 'Content-Type': 'application/json' }), body: (async function* () { yield Buffer.alloc(4096); yield Buffer.alloc(4097); })() };
  await expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl }).read(bearer, user)).rejects.toMatchObject({ status: 503 });
});
test('exactly 8KiB of otherwise valid source JSON is accepted, one extra byte is not', async () => {
  const encoded = JSON.stringify(source); const padded = encoded + ' '.repeat(8192 - Buffer.byteLength(encoded));
  for (const extra of ['', ' ']) {
    const reader = new CompanyBlueprintAssignmentAuthority({ fetchImpl: async () => new Response(padded + extra, { headers: { 'Content-Type': 'application/json' } }) });
    if (extra) await expect(reader.read(bearer, user)).rejects.toMatchObject({ status: 503 }); else expect(await reader.read(bearer, user)).toEqual(source);
  }
});
test('the source transport aborts after 2.5 seconds', async () => {
  jest.useFakeTimers(); let started; const ready = new Promise(resolve => { started = resolve; });
  const reader = new CompanyBlueprintAssignmentAuthority({ fetchImpl: async (_url, { signal }) => { started(); return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('Aborted')))); } });
  const operation = expect(reader.read(bearer, user)).rejects.toMatchObject({ status: 503 }); await ready; await jest.advanceTimersByTimeAsync(2499); await jest.advanceTimersByTimeAsync(1); await operation;
});
test.each([200, 403])('a transport ignoring abort cannot return a late HTTP %s response', async status => {
  jest.useFakeTimers(); let complete; const fetchImpl = () => new Promise(resolve => { complete = resolve; });
  const operation = expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl }).read(bearer, user)).rejects.toMatchObject({ status: 503 });
  await jest.advanceTimersByTimeAsync(2500); complete(status === 200 ? response(source) : { status }); await operation;
});
test('a streamed response arriving after abort is not accepted', async () => {
  jest.useFakeTimers(); let complete; let started; const reading = new Promise(resolve => { started = resolve; });
  const fetchImpl = async () => ({ status: 200, headers: new Headers({ 'Content-Type': 'application/json' }), body: (async function* () { started(); await new Promise(resolve => { complete = resolve; }); yield Buffer.from(JSON.stringify(source)); })() });
  const operation = expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl }).read(bearer, user)).rejects.toMatchObject({ status: 503 });
  await reading; await jest.advanceTimersByTimeAsync(2500); complete(); await operation;
});
test('MFA expiring during a timely streamed response still discards the original source', async () => {
  jest.useFakeTimers().setSystemTime((user.auth_time + 299) * 1000);
  const fetchImpl = async () => ({ status: 200, headers: new Headers({ 'Content-Type': 'application/json' }), body: (async function* () { jest.setSystemTime((user.auth_time + 300) * 1000); yield Buffer.from(JSON.stringify(source)); })() });
  await expect(new CompanyBlueprintAssignmentAuthority({ fetchImpl }).read(bearer, user)).rejects.toMatchObject({ status: 503 });
});
