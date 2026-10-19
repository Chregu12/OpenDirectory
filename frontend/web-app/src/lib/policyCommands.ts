import { api } from './api';
import { canonical } from './policyGovernance';
import type { PolicyCommandReceipt } from './blueprintConfiguration';

export interface PolicyCancellationReceipt {
  schemaVersion: 1; commandId: string; deviceId: string; operationId: string; cancelledByUserId: string; cancelledAt: string;
  reason: string; previouslyOffered: boolean; policyReceipt: PolicyCommandReceipt; persistence: 'committed'; furtherOffersStopped: true; enforcementConfirmed: false;
}
export interface OwnedPolicyCommand { id: string; status: 'pending' | 'expired' | 'cancelled' | 'completed' | 'failed'; policyReceipt: PolicyCommandReceipt; previouslyOffered: boolean; cancellationReceipt: PolicyCancellationReceipt | null; enforcementConfirmed: false }
const uuid = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const date = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const hash = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const fail = (): never => { throw new Error('Geräteauftrag oder Stornierung nicht bestätigt. Gespeicherten Status neu laden, nicht blind wiederholen.'); };
const same = (first: unknown, second: unknown) => JSON.stringify(canonical(first)) === JSON.stringify(canonical(second));
function fields(value: any, names: string[]) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) return fail();
}
function receipt(value: any, userId: string, resourceId: string): PolicyCommandReceipt {
  fields(value, ['schemaVersion','commandId','operationId','deviceId','deviceGeneration','operatorUserId','reference','configurationVersion','configurationHash','publicationVersion','payloadHash','expiresAt','persistence']);
  fields(value.reference, ['resourceKind','resourceId','resourceVersion','publicationId','configurationId']);
  if (value.schemaVersion !== 1 || !uuid(value.commandId) || !uuid(value.operationId) || value.operatorUserId !== userId || !uuid(userId)
    || typeof value.deviceId !== 'string' || !/^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,255}$/.test(value.deviceId)
    || typeof value.deviceGeneration !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.deviceGeneration) || BigInt(value.deviceGeneration) > BigInt('9223372036854775807')
    || value.reference.resourceKind !== 'blueprint' || value.reference.resourceId !== resourceId || !uuid(resourceId) || !uuid(value.reference.publicationId) || !uuid(value.reference.configurationId)
    || !Number.isSafeInteger(value.reference.resourceVersion) || value.reference.resourceVersion < 1 || !Number.isSafeInteger(value.configurationVersion) || value.configurationVersion < 1 || value.configurationVersion > value.reference.resourceVersion
    || !Number.isSafeInteger(value.publicationVersion) || value.publicationVersion < 2 || !hash(value.configurationHash) || !hash(value.payloadHash) || !date(value.expiresAt) || value.persistence !== 'committed') return fail();
  return value;
}
function cancellation(value: any, original: PolicyCommandReceipt): PolicyCancellationReceipt {
  fields(value, ['schemaVersion','commandId','deviceId','operationId','cancelledByUserId','cancelledAt','reason','previouslyOffered','policyReceipt','persistence','furtherOffersStopped','enforcementConfirmed']);
  if (value.schemaVersion !== 1 || value.commandId !== original.commandId || value.deviceId !== original.deviceId || !uuid(value.operationId) || value.cancelledByUserId !== original.operatorUserId
    || !date(value.cancelledAt) || typeof value.reason !== 'string' || value.reason.trim() !== value.reason || value.reason.length < 10 || value.reason.length > 500 || typeof value.previouslyOffered !== 'boolean'
    || !same(value.policyReceipt, original) || value.persistence !== 'committed' || value.furtherOffersStopped !== true || value.enforcementConfirmed !== false) return fail();
  return value;
}
export const policyCommands = {
  async list(resourceId: string, userId: string, offset = 0): Promise<{ commands: OwnedPolicyCommand[]; truncated: boolean }> {
    if (!uuid(resourceId) || !uuid(userId) || !Number.isInteger(offset) || offset < 0 || offset > 1000000) return fail();
    const result = await api.get('/api/devices/policy-commands', { params: { resourceKind: 'blueprint', resourceId, limit: 200, offset } });
    const body = result.data;
    fields(body, ['schemaVersion','contract','userId','resourceKind','resourceId','commands','truncated']);
    if (result.status !== 200 || body.schemaVersion !== 1 || body.contract !== 'owned-policy-cancellation-v1' || body.userId !== userId || body.resourceKind !== 'blueprint' || body.resourceId !== resourceId
      || !Array.isArray(body.commands) || body.commands.length > 200 || typeof body.truncated !== 'boolean') return fail();
    const commands = body.commands.map((row: any): OwnedPolicyCommand => {
      fields(row, ['id','status','policyReceipt','previouslyOffered','cancellationReceipt','enforcementConfirmed']);
      const original = receipt(row.policyReceipt, userId, resourceId);
      if (row.id !== original.commandId || !['pending','expired','cancelled','completed','failed'].includes(row.status) || typeof row.previouslyOffered !== 'boolean' || row.enforcementConfirmed !== false
        || (row.status === 'cancelled') !== (row.cancellationReceipt !== null)) return fail();
      if (row.cancellationReceipt && cancellation(row.cancellationReceipt, original).previouslyOffered !== row.previouslyOffered) return fail();
      return row;
    });
    if (new Set(commands.map((row: OwnedPolicyCommand) => row.id)).size !== commands.length) return fail();
    return { commands, truncated: body.truncated };
  },
  async cancel(original: PolicyCommandReceipt, userId: string, operationId: string, reason: string): Promise<PolicyCancellationReceipt> {
    receipt(original, userId, original?.reference?.resourceId);
    if (!uuid(operationId) || typeof reason !== 'string' || reason.trim() !== reason || reason.length < 10 || reason.length > 500 || /[\u0000-\u001f\u007f]/.test(reason)) return fail();
    const result = await api.post(`/api/devices/${encodeURIComponent(original.deviceId)}/commands/${original.commandId}/cancel`, { policyReceipt: original, reason, acknowledgeScope: true }, { headers: { 'X-OD-Operation-Id': operationId } });
    if (result.status !== 200) return fail(); const retained = cancellation(result.data, original);
    if (retained.operationId !== operationId || retained.reason !== reason) return fail(); return retained;
  },
};
