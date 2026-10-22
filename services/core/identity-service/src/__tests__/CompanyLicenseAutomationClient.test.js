'use strict';
const { randomUUID } = require('node:crypto'); const { CompanyLicenseAutomationClient } = require('../CompanyLicenseAutomationClient');
const job = { id: randomUUID(), grant_id: randomUUID(), rule_id: randomUUID(), lease_token: randomUUID(), retry_count: 0 };
const app = { client_id: 'actual-worker', client_revision: '1' }; const endpoint = 'https://policy.test/api/licenses/automation/groups/step';
const result = () => ({ schemaVersion: 1, companyLicenseAutomationProtocol: 1, grantId: job.grant_id, jobId: job.id, ruleId: job.rule_id,
 actor: { kind: 'application', id: job.grant_id, clientId: app.client_id, clientRevision: '1' }, progress: { runId: job.id, retryCount: 0, cycle: 1, completed: 1, total: 1, blocked: 1 },
 finished: true, hasBlocked: true, results: [{ userId: randomUUID(), status: 'blocked', code: 409 }] });
const response = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
test('forwards the current lease and preserves a confirmed partial result without relabeling it as success', async () => {
 const value = result(); const fetchImpl = jest.fn(async () => response(value));
 expect(await new CompanyLicenseAutomationClient({ endpoint, fetchImpl }).step(job, app, 'Bearer original.app')).toEqual(value);
 expect(fetchImpl.mock.calls[0][0].href).toBe(endpoint); expect(fetchImpl.mock.calls[0][1]).toMatchObject({ method: 'POST', headers: { Authorization: 'Bearer original.app' }, body: JSON.stringify({ grantId: job.grant_id, jobId: job.id, leaseToken: job.lease_token, ruleId: job.rule_id }), redirect: 'error', cache: 'no-store' });
});
test.each(['foreign-rule', 'wrong-client', 'wrong-epoch', 'false-success', 'duplicate-recipient', 'unknown-result'])('rejects unconfirmed %s', async mode => {
 const value = result();
 if (mode === 'foreign-rule') value.ruleId = randomUUID();
 if (mode === 'wrong-client') value.actor.clientId = 'other';
 if (mode === 'wrong-epoch') value.progress.retryCount++;
 if (mode === 'false-success') value.hasBlocked = false;
 if (mode === 'duplicate-recipient') { value.results.push({ ...value.results[0] }); value.progress.completed = value.progress.total = value.progress.blocked = 2; }
 if (mode === 'unknown-result') value.results[0].status = 'pending';
 await expect(new CompanyLicenseAutomationClient({ endpoint, fetchImpl: async () => response(value) }).step(job, app, 'Bearer original.app')).rejects.toMatchObject({ status: 503 });
});
test.each([401, 403, 404, 409, 412])('keeps receiver rejection %s distinct from an uncertain network result', async status => {
 await expect(new CompanyLicenseAutomationClient({ endpoint, fetchImpl: async () => new Response('{}', { status }) }).step(job, app, 'Bearer original.app')).rejects.toMatchObject({ status });
});
