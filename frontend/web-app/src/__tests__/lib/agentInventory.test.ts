import { readAgentInventory, gibibytes, uptime } from '@/lib/agentInventory';
import { api } from '@/lib/api';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn() } }));
const id = '11111111-1111-4111-8111-111111111111', actor = '22222222-2222-4222-8222-222222222222';
const device: any = { id, tenantId: actor, platform: 'linux' };
const facts = { schemaVersion: 1, cpu: { model: 'Fixture CPU', logicalProcessors: 8 }, memory: { totalBytes: '9007199254740993', availableBytes: '0' }, systemDisk: null, uptimeSeconds: '86461' };
const receipt = () => ({ schemaVersion: 1, inventoryProtocol: 1, actorUserId: actor, tenantId: actor, deviceId: id, checkedAt: '2026-11-14T12:01:00.000Z', connectionStatus: 'connected', status: 'current', inventory: { schemaVersion: 1, receivedAt: '2026-11-14T12:00:00.000Z', enrolledAt: '2026-11-14T11:00:00.000Z', revision: '9007199254740993', platform: 'linux', agentVersion: '1.2.0', facts } });
const read = () => readAgentInventory(device, actor, new AbortController().signal);
beforeEach(() => jest.resetAllMocks());
test('original actor, tenant and device bind exact counters and unknown fields remain nullable', async () => {
 (api.get as jest.Mock).mockResolvedValue({ status: 200, data: receipt() }); const result = await read();
 expect(result.inventory?.facts.memory?.totalBytes).toBe('9007199254740993'); expect(result.inventory?.facts.systemDisk).toBeNull();
 expect(api.get).toHaveBeenCalledWith('/api/devices/' + id + '/agent/inventory', { signal: expect.any(AbortSignal) });
 expect(gibibytes('34359738368')).toBe('32 GiB'); expect(uptime('86461')).toBe('1 Tage · 0 Std. · 1 Min.');
});
test.each(['actor', 'tenant', 'device', 'future', 'stale', 'platform', 'counter', 'secret'])('unconfirmed %s is rejected', async issue => {
 const value: any = JSON.parse(JSON.stringify(receipt()));
 if (issue === 'actor') value.actorUserId = id;
 if (issue === 'tenant') value.tenantId = id;
 if (issue === 'device') value.deviceId = actor;
 if (issue === 'future') value.inventory.receivedAt = '2099-01-01T12:00:00.000Z';
 if (issue === 'stale') value.checkedAt = '2026-11-14T12:10:00.000Z';
 if (issue === 'platform') value.inventory.platform = 'windows';
 if (issue === 'counter') value.inventory.facts.memory.totalBytes = '1\n';
 if (issue === 'secret') value.inventory.deviceToken = 'secret';
 (api.get as jest.Mock).mockResolvedValue({ status: 200, data: value }); await expect(read()).rejects.toThrow();
});
test('a historical report remains bound to the same own device after a platform correction', async () => {
 (api.get as jest.Mock).mockResolvedValue({ status: 200, data: { ...receipt(), connectionStatus: 'revoked', status: 'historical', inventory: { ...receipt().inventory, platform: 'macos' } } });
 expect((await read()).status).toBe('historical');
});
