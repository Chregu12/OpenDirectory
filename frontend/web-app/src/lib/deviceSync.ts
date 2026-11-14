import { z } from 'zod';
import { api } from './api';
import { deviceInventoryError, type Device } from './deviceInventory';
import { agentInventoryFactsSchema } from './agentInventory';
import { deviceComplianceAssessmentSchema, agentSecurityReceiptSchema } from './deviceCompliance';
const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/), time = z.string().datetime({ offset: true });
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => BigInt(value) <= BigInt('9223372036854775807'));
export const syncLabels = { queued: 'Wartet auf Agent', claimed: 'Vom Agenten abgerufen', completed: 'Synchronisiert', cancelled: 'Abgebrochen', expired: 'Auftrag abgelaufen', connection_changed: 'Gerätezugang ersetzt oder ungültig', failed: 'Zustellung ausgeschöpft' };
const inventory = z.object({ schemaVersion: z.literal(1), facts: agentInventoryFactsSchema, receivedAt: time, enrolledAt: time, revision, platform: z.enum(['macos', 'windows', 'linux']), agentVersion: z.string().min(1).max(40) }).strict();
const result = z.object({ agentRevision: revision, receivedAt: time, inventory, security: agentSecurityReceiptSchema, compliance: deviceComplianceAssessmentSchema }).strict().refine(value => value.agentRevision === value.inventory.revision && value.agentRevision === value.security.revision && value.agentRevision === value.compliance.agentRevision && Date.parse(value.receivedAt) === Date.parse(value.inventory.receivedAt) && Date.parse(value.receivedAt) === Date.parse(value.security.receivedAt));
const requestSchema = z.object({ id: uuid, deviceId: uuid, revision, status: z.enum(['queued', 'claimed', 'completed', 'cancelled', 'expired', 'connection_changed', 'failed']), attempts: z.number().int().min(0).max(3), actorUserId: uuid, reason: z.string().min(10).max(500), createdAt: time, expiresAt: time, updatedAt: time, leaseExpiresAt: time.nullable(), completedAt: time.nullable(), result: result.nullable() }).strict().refine(value => Date.parse(value.expiresAt) > Date.parse(value.createdAt) && Date.parse(value.expiresAt) - Date.parse(value.createdAt) <= 300000 && (value.status === 'completed' ? value.completedAt !== null && value.result !== null && value.result.compliance.deviceId === value.deviceId : value.completedAt === null && value.result === null));
export type DeviceSyncRequest = z.infer<typeof requestSchema>;
const pageSchema = z.object({ schemaVersion: z.literal(1), syncProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid, deviceId: uuid, checkedAt: time, connectionEtag: z.string().regex(/^"device-sync-generation-[a-f0-9-]{36}-[a-f0-9]{32}"$/).nullable(), page: z.number().int().min(1).max(1000000), limit: z.literal(10), total: z.number().int().nonnegative().safe(), requests: z.array(requestSchema).max(10) }).strict();
export type DeviceSyncPage = z.infer<typeof pageSchema>;
const historySchema = z.object({ schemaVersion: z.literal(1), syncProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid, deviceId: uuid, requestId: uuid, events: z.array(z.object({ id: uuid, action: z.enum(['queued', 'claimed', 'completed', 'cancelled']), actorUserId: uuid.nullable(), reason: z.string().min(10).max(500).nullable(), correlationId: uuid, createdAt: time }).strict()).min(1).max(6) }).strict();
export type DeviceSyncHistory = z.infer<typeof historySchema>;
function bound<T extends { actorUserId: string; tenantId: string }>(value: T, device: Device, actor: string, signal: AbortSignal) { if (signal.aborted || value.actorUserId !== actor || value.tenantId !== device.tenantId) throw new Error('Unconfirmed sync authority'); return value; }
function own(request: DeviceSyncRequest, device: Device) { return request.deviceId === device.id && (!request.result || request.result.compliance.tenantId === device.tenantId); }
const path = (device: Device) => '/api/devices/' + uuid.parse(device.id) + '/agent/sync';
export async function readDeviceSync(device: Device, actor: string, page: number, signal: AbortSignal) {
 const response = await api.get(path(device), { params: { page }, signal }), data = bound(pageSchema.parse(response.data), device, actor, signal);
 if (response.status !== 200 || data.deviceId !== device.id || data.page !== page || data.connectionEtag && !data.connectionEtag.startsWith('"device-sync-generation-' + device.id + '-') || data.requests.length !== Math.min(10, Math.max(0, data.total - (page - 1) * 10)) || new Set(data.requests.map(row => row.id)).size !== data.requests.length || data.requests.some(row => !own(row, device))) throw new Error('Unconfirmed device sync page'); return data;
}
export async function writeDeviceSync(device: Device, actor: string, previous: DeviceSyncPage, reason: string, signal: AbortSignal, cancel?: DeviceSyncRequest) {
 if (previous.actorUserId !== actor || previous.tenantId !== device.tenantId || previous.deviceId !== device.id || !cancel && !previous.connectionEtag || cancel && (!own(cancel, device) || !['queued', 'claimed'].includes(cancel.status))) throw new Error('Current sync source required');
 const explanation = reason.trim(); if (Array.from(explanation).length < 10 || Array.from(explanation).length > 500 || /[\u0000-\u001f\u007f-\u009f]/.test(explanation)) throw new Error('Confirmed reason required');
 const response = await api.post(path(device) + (cancel ? '/' + cancel.id + '/cancel' : ''), { reason: explanation, confirm: true }, { headers: { 'If-Match': cancel ? `"device-sync-${cancel.id}-${cancel.revision}"` : previous.connectionEtag }, signal });
 const data = bound(z.object({ schemaVersion: z.literal(1), syncProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid, request: requestSchema }).strict().parse(response.data), device, actor, signal);
 if (response.status !== (cancel ? 200 : 201) || !own(data.request, device) || data.request.status !== (cancel ? 'cancelled' : 'queued') || cancel && (data.request.id !== cancel.id || BigInt(data.request.revision) !== BigInt(cancel.revision) + BigInt(1))) throw new Error('Actual sync command unconfirmed'); return data.request;
}
export async function readDeviceSyncHistory(device: Device, actor: string, request: DeviceSyncRequest, signal: AbortSignal) {
 const response = await api.get(path(device) + '/' + uuid.parse(request.id) + '/history', { signal }), data = bound(historySchema.parse(response.data), device, actor, signal);
 if (response.status !== 200 || data.deviceId !== device.id || data.requestId !== request.id || new Set(data.events.map(row => row.id)).size !== data.events.length || data.events[0].action !== 'queued') throw new Error('Unconfirmed sync history'); return data;
}

export function deviceSyncError(error: unknown) { const status = (error as any)?.response?.status; return status === 409 ? 'Der Auftrag oder Gerätezugang hat sich geändert, ist abgelaufen oder es gibt bereits eine laufende Synchronisierung. Bitte neu laden.' : status === 503 ? 'Die Synchronisierungsquelle ist momentan nicht verfügbar. Bitte neu laden.' : deviceInventoryError(error); }
