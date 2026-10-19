jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
import { api } from '@/lib/api';
import { policyCommands, PolicyCancellationReceipt } from '@/lib/policyCommands';
import type { PolicyCommandReceipt } from '@/lib/blueprintConfiguration';
const mock = api as jest.Mocked<typeof api>;
const userId = '11111111-1111-4111-8111-111111111111'; const resourceId = '22222222-2222-4222-8222-222222222222'; const commandId = '33333333-3333-4333-8333-333333333333'; const operationId = '44444444-4444-4444-8444-444444444444';
const original: PolicyCommandReceipt = { schemaVersion: 1, commandId, operationId: resourceId, deviceId: 'owned-device', deviceGeneration: '1', operatorUserId: userId,
  reference: { resourceKind: 'blueprint', resourceId, resourceVersion: 3, publicationId: commandId, configurationId: commandId }, configurationVersion: 2, configurationHash: 'a'.repeat(64), publicationVersion: 2, payloadHash: 'b'.repeat(64), expiresAt: '2025-01-01T00:00:00.000Z', persistence: 'committed' };
const reason = 'Stop this exact owned policy command';
const retained: PolicyCancellationReceipt = { schemaVersion: 1, commandId, deviceId: original.deviceId, operationId, cancelledByUserId: userId, cancelledAt: '2026-01-01T00:00:00.000Z', reason,
  previouslyOffered: false, policyReceipt: original, persistence: 'committed', furtherOffersStopped: true, enforcementConfirmed: false };
const envelope = (extra = {}) => ({ schemaVersion: 1, contract: 'owned-policy-cancellation-v1', userId, resourceKind: 'blueprint', resourceId,
  commands: [{ id: commandId, status: 'pending', policyReceipt: original, previouslyOffered: false, cancellationReceipt: null, enforcementConfirmed: false }], truncated: false, ...extra });
beforeEach(() => jest.resetAllMocks());
test('reads actual bounded owned history, including old expired receipts without requiring a newly approved source version', async () => {
  mock.get.mockResolvedValue({ status: 200, data: envelope() }); const result = await policyCommands.list(resourceId, userId, 200);
  expect(result.commands[0].policyReceipt).toEqual(original); expect(mock.get).toHaveBeenCalledWith('/api/devices/policy-commands', { params: { resourceKind: 'blueprint', resourceId, limit: 200, offset: 200 } });
});
test.each([{ schemaVersion: 0 }, { contract: 'legacy' }, { userId: resourceId }, { resourceId: userId }, { resourceKind: 'policy' }, { commands: [] , extra: true }, { truncated: 'false' }])('rejects mismatched or downlevel owned history: %j', async change => {
  mock.get.mockResolvedValue({ status: 200, data: envelope(change) }); await expect(policyCommands.list(resourceId, userId)).rejects.toThrow();
});
test.each([{ operatorUserId: resourceId }, { deviceGeneration: '0' }, { deviceGeneration: '9223372036854775808' }, { payloadHash: 'unverified' }, { persistence: 'memory' }, { reference: { ...original.reference, resourceId: userId } }, { expiresAt: 'yesterday' }, { configurationVersion: 4 }])('rejects unbound or fake SQL receipts: %j', async change => {
  const data = envelope(); Object.assign(data.commands[0], { policyReceipt: { ...original, ...change } }); mock.get.mockResolvedValue({ status: 200, data }); await expect(policyCommands.list(resourceId, userId)).rejects.toThrow();
});
test('does not report missing cancellation evidence, duplicate commands or actual enforcement as a valid history', async () => {
  for (const change of [{ status: 'cancelled' }, { enforcementConfirmed: true }, { status: 'applied' }]) {
    const data = envelope(); Object.assign(data.commands[0], change); mock.get.mockResolvedValue({ status: 200, data }); await expect(policyCommands.list(resourceId, userId)).rejects.toThrow();
  }
  const data = envelope(); data.commands.push(data.commands[0]); mock.get.mockResolvedValue({ status: 200, data }); await expect(policyCommands.list(resourceId, userId)).rejects.toThrow();
});
test('recovers a committed cancellation, its captured operation and exact reason from durable history', async () => {
  const data = envelope(); Object.assign(data.commands[0], { status: 'cancelled', cancellationReceipt: retained }); mock.get.mockResolvedValue({ status: 200, data });
  expect((await policyCommands.list(resourceId, userId)).commands[0].cancellationReceipt).toEqual(retained);
});
test('cancellation posts only the original immutable receipt, captured operation, explicit reason and acknowledgement', async () => {
  mock.post.mockResolvedValue({ status: 200, data: retained }); expect(await policyCommands.cancel(original, userId, operationId, reason)).toEqual(retained);
  expect(mock.post).toHaveBeenCalledWith(`/api/devices/owned-device/commands/${commandId}/cancel`, { policyReceipt: original, reason, acknowledgeScope: true }, { headers: { 'X-OD-Operation-Id': operationId } });
});
test.each([{ operationId: commandId }, { cancelledByUserId: resourceId }, { reason: 'A different persistent reason' }, { persistence: 'memory' }, { furtherOffersStopped: false }, { enforcementConfirmed: true }, { policyReceipt: { ...original, payloadHash: 'f'.repeat(64) } }])('a retargeted, rewritten or unverified cancellation response never acknowledges a stop: %j', async change => {
  mock.post.mockResolvedValue({ status: 200, data: { ...retained, ...change } }); await expect(policyCommands.cancel(original, userId, operationId, reason)).rejects.toThrow(); expect(mock.post).toHaveBeenCalledTimes(1);
});
test('invalid actor, operation, scope and reason fail before any mutation; an uncertain network write is not retried', async () => {
  await expect(policyCommands.cancel(original, resourceId, operationId, reason)).rejects.toThrow(); await expect(policyCommands.cancel(original, userId, 'guess', reason)).rejects.toThrow();
  for (const invalid of ['short', ' leading reason', 'Null\u0000justification', 'x'.repeat(501)]) await expect(policyCommands.cancel(original, userId, operationId, invalid)).rejects.toThrow();
  await expect(policyCommands.list(resourceId, userId, -1)).rejects.toThrow(); expect(mock.post).not.toHaveBeenCalled();
  mock.post.mockRejectedValue(new Error('Lost SQL acknowledgement')); await expect(policyCommands.cancel(original, userId, operationId, reason)).rejects.toThrow(); expect(mock.post).toHaveBeenCalledTimes(1);
});
