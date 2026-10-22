import { api } from '@/lib/api';
import { companyAutomation } from '@/lib/companyAutomation';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const id = (n: number) => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');
const principal = { kind: 'owner' as const, userId: id(1), tenantId: id(2) }; const stamp = '2026-10-22T10:00:00.000Z';
const grant: any = { id: id(3), enrollmentId: id(4), tenantId: id(2), clientId: 'worker', clientRevision: '1', actions: ['directory.users.export'], expiresAt: '2099-10-22T10:00:00.000Z', status: 'active', revision: '1', createdAt: stamp };
const job: any = { id: id(5), grantId: id(3), tenantId: id(2), scheduleId: null, action: 'directory.users.export', format: 'json', status: 'queued', revision: '1', attemptCount: 0, retryCount: 0,
  availableAt: stamp, leaseUntil: null, errorCode: null, rowCount: null, artifactSha256: null, createdAt: stamp, updatedAt: stamp };
const envelope = (data: any) => ({ schemaVersion: 1, companyAutomationProtocol: 1, principal, ...data });
beforeEach(() => { jest.resetAllMocks(); Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: () => id(99) }); });
test('owner reads actual tenant grants without running a worker or mutation', async () => {
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data: envelope({ grants: [grant], page: 1, limit: 25, total: 1, supportedActions: ['directory.users.export', 'directory.groups.export', 'directory.ous.export','licenses.groups.reconcile'] }) });
  expect((await companyAutomation.grants(id(1))).grants[0].clientId).toBe('worker'); expect(api.post).not.toHaveBeenCalled();
});
test('queues a stable captured job without claiming execution or using a human worker', async () => {
  (api.post as jest.Mock).mockImplementation(async (_url, body) => ({ status: 201, data: envelope({ job: { ...job, id: body.id } }) }));
  const result = await companyAutomation.queue(grant, 'directory.users.export', 'json', principal); expect(result).toMatchObject({ status: 'queued' });
  expect(api.post).toHaveBeenCalledWith('/api/identity/automation/jobs', { id: id(99), grantId: grant.id, action: 'directory.users.export', format: 'json' });
});
test('rejects foreign tenant, undelegated actions and malformed receipt without confirming success', async () => {
  await expect(companyAutomation.queue({ ...grant, tenantId: id(9) }, 'directory.users.export', 'json', principal)).rejects.toThrow();
  await expect(companyAutomation.queue(grant, 'directory.groups.export', 'json', principal)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
  (api.post as jest.Mock).mockResolvedValue({ status: 201, data: envelope({ job: { ...job, id: id(99), tenantId: id(9) } }) });
  await expect(companyAutomation.queue(grant, 'directory.users.export', 'json', principal)).rejects.toThrow();
});
test('revocation uses the captured grant ETag and requires a revoked receipt', async () => {
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: envelope({ grant: { ...grant, status: 'revoked', revision: '2' } }) });
  expect((await companyAutomation.revoke(grant, principal)).status).toBe('revoked');
  expect((api.post as jest.Mock).mock.calls[0][2].headers['If-Match']).toBe('"company-automation-grant-' + grant.id + '-1"');
});
test('actual pages stay bound to the selected grant and current owner', async () => {
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data: envelope({ grantId: grant.id, tenantId: grant.tenantId, page: 1, limit: 25, total: 1, jobs: [job] }) });
  expect((await companyAutomation.jobs(grant, principal)).jobs).toHaveLength(1);
  await expect(companyAutomation.jobs(grant, { ...principal, userId: id(10) })).rejects.toThrow();
});
test('does not download an artifact substituted for another job', async () => {
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data: envelope({ jobId: id(9), grantId: grant.id, tenantId: grant.tenantId, rowCount: 1, sha256: 'a'.repeat(64), contentType: 'application/json', filename: 'export.json', content: '{}' }) });
  await expect(companyAutomation.artifact({ ...job, status: 'succeeded', rowCount: 1, artifactSha256: 'a'.repeat(64) }, principal)).rejects.toThrow();
});
test('license list refuses a claimed success without completed matching progress', async () => {
 const licensed = { ...grant, actions: ['licenses.groups.reconcile'] };
 (api.get as jest.Mock).mockResolvedValue({ status: 200, data: envelope({ grantId: grant.id, tenantId: grant.tenantId, page: 1, limit: 25, total: 1, jobs: [{ ...job, action: 'licenses.groups.reconcile', ruleId: id(7), progress: null, status: 'succeeded', rowCount: 1, artifactSha256: 'a'.repeat(64) }] }) });
 await expect(companyAutomation.jobs(licensed, principal)).rejects.toThrow();
});
test('a license report binds all progress counters, the actual app and every blocked member to the current job', async () => {
 const progress = { runId: job.id, retryCount: 0, cycle: 1, completed: 2, total: 2, blocked: 1 };
 const licensed = { ...grant, actions: ['licenses.groups.reconcile'] };
 const current = { ...job, action: 'licenses.groups.reconcile', ruleId: id(7), status: 'partial', rowCount: 2, progress };
 const report = { schemaVersion: 1, companyLicenseAutomationProtocol: 1, grantId: grant.id, jobId: job.id, ruleId: id(7), actor: { kind: 'application', id: grant.id, clientId: 'worker', clientRevision: '1' }, progress: { ...progress }, finished: true, hasBlocked: true,
  results: [{ userId: id(8), status: 'assigned', code: null }, { userId: id(9), status: 'blocked', code: 409 }] };
 const artifact = jest.spyOn(companyAutomation, 'artifact').mockImplementation(async () => ({ contentType: 'application/json', content: JSON.stringify(report) } as any));
 try {
  expect((await companyAutomation.licenseReport(current, licensed, principal)).hasBlocked).toBe(true);
  await expect(companyAutomation.licenseReport({ ...current, progress: { ...progress, blocked: 0 } }, licensed, principal)).rejects.toThrow();
  report.actor.clientId = 'foreign'; await expect(companyAutomation.licenseReport(current, licensed, principal)).rejects.toThrow();
  report.actor.clientId = 'worker'; report.results[1].code = null; await expect(companyAutomation.licenseReport(current, licensed, principal)).rejects.toThrow();
 } finally { artifact.mockRestore(); }
});
