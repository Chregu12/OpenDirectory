import { api } from '@/lib/api';
import { complianceAccess, complianceSettingsSchema, saveCompliancePolicy, type ComplianceContext } from '@/lib/deviceCompliance';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), put: jest.fn() } }));
const actor = '11111111-1111-4111-8111-111111111111', tenant = '22222222-2222-4222-8222-222222222222';
const context: ComplianceContext = { schemaVersion: 1, complianceProtocol: 1, actorUserId: actor, tenantId: tenant, permissions: ['devices.compliance.read', 'devices.compliance.manage'] };
const settings = { enabled: true, maxReportAgeSeconds: 3600, minimumOsVersion: '13.10', requireDiskEncryption: true, requireFirewall: false, minimumDiskFreePercent: null };
const policy = { tenantId: tenant, platform: 'macos' as const, revision: '9007199254740993', settings, createdAt: '2026-11-14T12:00:00.000Z', updatedAt: '2026-11-14T12:00:00.000Z' };
beforeEach(() => jest.resetAllMocks());
test('read-only duty and malformed settings cannot issue policy commands', async () => {
 expect(complianceSettingsSchema.safeParse({ ...settings, maxReportAgeSeconds: 301 }).success).toBe(false);
 await expect(saveCompliancePolicy({ ...context, permissions: ['devices.compliance.read'] }, policy, settings, 'Explicit company policy', new AbortController().signal)).rejects.toThrow(); expect(api.put).not.toHaveBeenCalled();
});
test('policy command preserves exact BIGINT revision, reason and confirmation', async () => {
 (api.put as jest.Mock).mockResolvedValue({ status: 200, data: { schemaVersion: 1, actorUserId: actor, policy: { ...policy, revision: '9007199254740994' }, eventId: actor, deliveryStatus: 'pending' } });
 await expect(saveCompliancePolicy(context, policy, settings, 'Explicit company security policy', new AbortController().signal)).resolves.toMatchObject({ revision: '9007199254740994' });
 expect(api.put).toHaveBeenCalledWith('/api/devices/compliance/policies/macos', { settings, reason: 'Explicit company security policy', confirm: true }, expect.objectContaining({ headers: { 'If-Match': `"device-compliance-${tenant}-macos-9007199254740993"` } }));
});
test('conflicting command is never automatically repeated and aborted capability response cannot be adopted', async () => {
 (api.put as jest.Mock).mockRejectedValue({ response: { status: 412 } }); await expect(saveCompliancePolicy(context, policy, settings, 'Explicit company policy', new AbortController().signal)).rejects.toMatchObject({ response: { status: 412 } }); expect(api.put).toHaveBeenCalledTimes(1);
 const controller = new AbortController(); controller.abort(); (api.get as jest.Mock).mockResolvedValue({ status: 200, data: context }); await expect(complianceAccess(controller.signal)).rejects.toThrow();
});
