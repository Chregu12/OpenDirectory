'use strict';
const { randomUUID } = require('node:crypto');
const { CompanyLicenseAutomationAuthority } = require('../licenses/CompanyLicenseAutomationAuthority');
const { validSource } = require('../../../../../packages/company-license-automation-contract');
const id = () => randomUUID(); const now = Math.floor(Date.now() / 1000);
const app = { actor_type: 'application', token_use: 'access', iss: 'https://automation.test', sub: 'worker', client_id: 'worker', client_revision: '1', jti: id(), exp: now + 3600, scope: 'company.automation', permissions: ['company.automation'] };
const context = { grantId: id(), jobId: id(), leaseToken: id(), ruleId: id(), groupId: id() }; const recipient = id();
const source = () => ({ schemaVersion: 1, companyLicenseAutomationProtocol: 1, kind: 'application', issuer: app.iss, subject: app.sub, tokenId: app.jti, expiresAt: app.exp, clientRevision: '1', tenant: { id: id(), version: '1', generation: '1' },
 grantId: context.grantId, jobId: context.jobId, leaseToken: context.leaseToken, ruleId: context.ruleId, retryCount: 0, validUntil: now + 45, permissions: ['licenses.groups.reconcile'], target: null,
 group: { schemaVersion: 3, groupId: context.groupId, name: 'Own canonical group', revision: '1', deleted: false, memberIds: [recipient], inactiveMemberIds: [], unresolvedMemberIds: [], memberships: [{ userId: recipient, membershipId: id(), eligibilityRevision: '1', reviewDeadlineAt: null }] } });
const endpoint = 'https://identity.test/api/identity/automation/license-source'; const response = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
test('pins the canonical source and forwards the original app bearer and the actual lease without a human context', async () => {
 const proof = source(); const fetchImpl = jest.fn(async () => response(proof)); const authority = new CompanyLicenseAutomationAuthority(context, { endpoint, fetchImpl });
 expect(await authority.read('Bearer original.app', app)).toEqual(proof);
 expect(fetchImpl.mock.calls[0][0].href).toBe(endpoint);
 expect(fetchImpl.mock.calls[0][1]).toMatchObject({ method: 'POST', headers: { Authorization: 'Bearer original.app' }, body: JSON.stringify({ grantId: context.grantId, jobId: context.jobId, leaseToken: context.leaseToken, groupId: context.groupId, userId: null }), redirect: 'error', cache: 'no-store' });
 expect(fetchImpl.mock.calls[0][1].signal.aborted).toBe(true);
});
test.each(['grantId', 'jobId', 'leaseToken', 'ruleId', 'tokenId', 'clientRevision'])('rejects substituted %s in a canonical response', async field => {
 const proof = source(); proof[field] = field === 'clientRevision' ? '2' : id();
 await expect(new CompanyLicenseAutomationAuthority(context, { endpoint, fetchImpl: async () => response(proof) }).read('Bearer original.app', app)).rejects.toMatchObject({ status: 503 });
});
test.each([401, 403, 404])('marks source denial %s so it cannot be reported as a blocked recipient', async status => {
 await expect(new CompanyLicenseAutomationAuthority(context, { endpoint, fetchImpl: async () => new Response('{}', { status }) }).read('Bearer original.app', app)).rejects.toMatchObject({ status, authorityDenied: true });
});
test('rejects duplicated memberships, noncanonical members and human authority fields', () => {
 const proof = source(); expect(validSource(proof, app)).toBe(true);
 expect(validSource({ ...proof, context: {} }, app)).toBe(false);
 expect(validSource({ ...proof, retryCount: 0.5 }, app)).toBe(false);
 const second = id(); proof.group.memberIds.push(second); proof.group.memberships.push({ ...proof.group.memberships[0], userId: second });
 expect(validSource(proof, app)).toBe(false);
 proof.group.memberships[1].membershipId = id(); expect(validSource(proof, app)).toBe(true);
 proof.group.memberIds[0] = recipient.toUpperCase(); expect(validSource(proof, app)).toBe(false);
});
test('a base lookup exposes no recipient and a target must match the requested canonical user', async () => {
 const proof = source(); proof.group = null;
 expect(await new CompanyLicenseAutomationAuthority({ ...context, groupId: null }, { endpoint, fetchImpl: async () => response(proof) }).read('Bearer original.app', app)).toEqual(proof);
 proof.target = { id: recipient, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false }; expect(validSource(proof, app, recipient)).toBe(false);
 proof.group = source().group; expect(validSource(proof, app, recipient)).toBe(true); expect(validSource(proof, app, id())).toBe(false);
});
test('invalid workload claims never reach transport and endpoints cannot add redirects, credentials or selectors', async () => {
 const fetchImpl = jest.fn(); const authority = new CompanyLicenseAutomationAuthority(context, { endpoint, fetchImpl });
 await expect(authority.read('Bearer original.app', { ...app, roles: ['admin'] })).rejects.toMatchObject({ status: 403 }); expect(fetchImpl).not.toHaveBeenCalled();
 for (const value of [endpoint + '?tenant=other', endpoint + '#fragment', 'https://identity.test/other', 'https://secret@identity.test/api/identity/automation/license-source']) expect(() => new CompanyLicenseAutomationAuthority(context, { endpoint: value })).toThrow();
});
