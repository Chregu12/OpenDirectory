'use strict';

const { randomUUID } = require('node:crypto');
const { CompanyLicenseAuthority } = require('../licenses/CompanyLicenseAuthority');
const { COMPANY_LICENSE_PERMISSIONS } = require('../../../../../packages/company-license-contract');
const actor = randomUUID(); const targetId = randomUUID(); const tenant = { id: randomUUID(), version: '1', generation: '1' };
let user; let source;
beforeEach(() => { const now = Math.floor(Date.now() / 1000); const context = { userId: actor, revision: '1', linkRevision: '1', rolesRevision: 'b'.repeat(64) };
  user = { actor_type: 'user', iss: 'https://own-company.test', sub: 'actual-owner', jti: randomUUID(), exp: now + 600, auth_time: now, identity_authorization: context };
  source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context, tenant, actorUserId: actor, permissions: [...COMPANY_LICENSE_PERMISSIONS], validUntil: now + 300, target: null };
});
const response = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
test('the actual original bearer reads only the fixed own-company source without a service credential or caller tenant', async () => {
  const fetchImpl = jest.fn(async () => response(source)); const reader = new CompanyLicenseAuthority({ endpoint: 'https://identity.test/api/identity/company-licenses', fetchImpl });
  expect(await reader.read('Bearer actual.original', user)).toEqual(source); const [url, request] = fetchImpl.mock.calls[0];
  expect(url.pathname).toBe('/api/identity/company-licenses'); expect(request).toMatchObject({ method: 'GET', headers: { Authorization: 'Bearer actual.original' }, redirect: 'error', cache: 'no-store' }); expect(request.body).toBeUndefined();
});
test.each([{ revision: '9007199254740993', enabled: true, deleted: false }, { revision: '2', enabled: false, deleted: false }, { revision: null, enabled: false, deleted: true }])('owned positive or negative targets retain exact generation: %j', async state => {
  source.target = { id: targetId, eligibilityRevision: '9223372036854775807', ...state }; const fetchImpl = jest.fn(async () => response(source));
  expect((await new CompanyLicenseAuthority({ fetchImpl }).read('Bearer actual.original', user, targetId)).target).toEqual(source.target);
  expect(JSON.parse(fetchImpl.mock.calls[0][1].body)).toEqual({ userId: targetId }); expect(fetchImpl.mock.calls[0][1].method).toBe('POST');
});
test.each([{ actorUserId: randomUUID() }, { tokenId: 'substituted' }, { issuer: 'https://foreign.test' }, { subject: 'other' }, { schemaVersion: 2 }, { context: null }, { tenant: { ...tenant, generation: '0' } }, { permissions: ['licenses.assignments.manage'] }, { password: 'not allowed' }, { validUntil: 9999999999 }, { validUntil: 1 }])('unconfirmed authority cannot substitute or broaden the original request: %j', async patch => {
  await expect(new CompanyLicenseAuthority({ fetchImpl: async () => response({ ...source, ...patch }) }).read('Bearer actual.original', user)).rejects.toMatchObject({ status: 503 });
});
test.each([{ revision: null, enabled: true, deleted: false }, { revision: '1', enabled: true, deleted: true }, { revision: '1', enabled: false, deleted: true }, { revision: '0', enabled: true, deleted: false }])('malformed positive/deletion proofs fail closed: %j', async target => {
  source.target = { id: targetId, eligibilityRevision: '1', ...target }; await expect(new CompanyLicenseAuthority({ fetchImpl: async () => response(source) }).read('Bearer actual.original', user, targetId)).rejects.toMatchObject({ status: 503 });
});
test.each([400, 401, 403, 404, 428, 429, 500])('actual source denial %s is preserved without a role, local fallback or retry', async status => {
  const fetchImpl = jest.fn(async () => ({ status })); await expect(new CompanyLicenseAuthority({ fetchImpl }).read('Bearer actual.original', user)).rejects.toMatchObject({ status: [400, 401, 403, 404, 428].includes(status) ? status : 503 }); expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test('a machine, missing original bearer or noncanonical selector cannot enter source transport', async () => {
  const fetchImpl = jest.fn(); const authority = new CompanyLicenseAuthority({ fetchImpl }); await expect(authority.read(null, user)).rejects.toMatchObject({ status: 401 }); await expect(authority.read('Bearer original', { ...user, actor_type: 'application' })).rejects.toMatchObject({ status: 401 }); await expect(authority.read('Bearer original', user, 'alias')).rejects.toMatchObject({ status: 400 }); expect(fetchImpl).not.toHaveBeenCalled();
});
test.each(['https://user:secret@identity.test/api/identity/company-licenses', 'https://identity.test/api/other', 'file:///tmp/source', 'https://identity.test/api/identity/company-licenses?tenant=other'])('an arbitrary source endpoint is unsupported: %s', endpoint => { expect(() => new CompanyLicenseAuthority({ endpoint })).toThrow(); });
test('oversized source content is bounded before any success can be parsed', async () => {
  const fetchImpl = jest.fn(async () => ({ status: 200, headers: new Headers({ 'Content-Type': 'application/json' }), body: (async function* () { yield Buffer.alloc(8193); })() }));
  await expect(new CompanyLicenseAuthority({ fetchImpl }).read('Bearer original', user)).rejects.toMatchObject({ status: 503 });
});
