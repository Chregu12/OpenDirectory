import { parseAgent, manageAgent } from '@/lib/deviceAgents';
import { api } from '@/lib/api';
jest.mock('@/lib/api', () => ({ api: { post: jest.fn(), get: jest.fn() } }));
const id = '11111111-1111-4111-8111-111111111111', actor = '22222222-2222-4222-8222-222222222222';
const device: any = { id, tenantId: actor, platform: 'linux' };
const state: any = { schemaVersion: 1, agentProtocol: 1, actorUserId: actor, tenantId: actor, deviceId: id, revision: '0', status: 'not-enrolled', enrolledAt: null, lastSeen: null, credentialExpiresAt: null, enrollmentExpiresAt: null, report: null, history: { page: 1, limit: 25, total: 0, events: [] } };
beforeEach(() => jest.clearAllMocks());
test('matches original actor, tenant, device and history page', () => { expect(parseAgent(state, device, actor)).toEqual(state); });
test.each([{ actorUserId: id }, { tenantId: id }, { deviceId: actor }, { credential_hash: 'secret' }, { status: 'connected' }, { revision: '9223372036854775808' }, { history: { page: 1, limit: 25, total: 1, events: [] } }])('rejects an inconsistent or foreign response %j', change => { expect(() => parseAgent({ ...state, ...change }, device, actor)).toThrow(); });
test('uses the exact original agent ETag and explicit confirmation', async () => {
 (api.post as jest.Mock).mockResolvedValue({ status: 200, data: { ...state, status: 'revoked', revision: '1' } }); const controller = new AbortController();
 await manageAgent(device, actor, state, 'revoke', 'Explicit own device revocation', controller.signal);
 expect(api.post).toHaveBeenCalledWith('/api/devices/' + id + '/agent/revoke', { reason: 'Explicit own device revocation', confirm: true }, { headers: { 'If-Match': `"agent-${id}-0"` }, signal: controller.signal });
});
test('rejects an issued code that is not bound to the pending connection deadline', async () => {
 (api.post as jest.Mock).mockResolvedValue({ status: 201, data: { connection: { ...state, status: 'pending', enrollmentExpiresAt: '2099-01-01T10:00:00Z' }, enrollmentToken: 'odae_' + 'a'.repeat(43), expiresAt: '2099-01-01T11:00:00Z' } });
 await expect(manageAgent(device, actor, state, 'issue', 'Explicit own device enrollment', new AbortController().signal)).rejects.toThrow();
});
