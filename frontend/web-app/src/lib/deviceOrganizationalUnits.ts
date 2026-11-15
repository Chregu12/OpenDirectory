import { z } from 'zod';
import { api } from './api';
import { type Device, deviceInventoryError } from './deviceInventory';

const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => BigInt(value) <= BigInt('9223372036854775807'));
const time = z.string().datetime({ offset: true });
const name = z.string().min(1).max(510).refine(value => Array.from(value.trim()).length >= 1 && Array.from(value.trim()).length <= 255 && !/[\u0000-\u001f\u007f-\u009f]/.test(value));
const unit = z.object({ id: uuid, generation: revision, revision, name, parentId: uuid.nullable() }).strict().refine(value => value.id !== value.parentId);
export type DeviceOrganizationalUnit = z.infer<typeof unit>;
const assignment = z.object({ revision: z.union([z.literal('0'), revision]), ou: unit.nullable(), updatedAt: time.nullable(), updatedBy: uuid.nullable() }).strict().refine(value => value.revision === '0'
  ? value.ou === null && value.updatedAt === null && value.updatedBy === null : value.updatedAt !== null && value.updatedBy !== null);
const identity = { schemaVersion: z.literal(1), deviceOuProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid };
const current = z.object({ ...identity, deviceId: uuid, deviceRevision: revision, ...assignment.shape }).strict().refine(value => assignment.safeParse({ revision: value.revision, ou: value.ou, updatedAt: value.updatedAt, updatedBy: value.updatedBy }).success);
export type DeviceOuAssignment = z.infer<typeof current>;
const receipt = z.object({ ...current.shape, operationId: uuid, deliveryStatus: z.literal('pending') }).strict();
const choices = z.object({ ...identity, page: z.number().int().min(1).max(1000000), limit: z.literal(25), total: z.number().int().nonnegative().safe(), units: z.array(unit).max(25) }).strict();
export type DeviceOuChoices = z.infer<typeof choices>;
const event = z.object({ id: uuid, actorUserId: uuid, correlationId: uuid, reason: z.string().min(10).max(1000), createdAt: time, before: assignment.nullable(), after: assignment, deliveryStatus: z.literal('pending') }).strict().refine(value => value.after.revision !== '0' && value.after.updatedBy === value.actorUserId && value.after.updatedAt === value.createdAt
  && BigInt(value.after.revision) === BigInt(value.before?.revision || '0') + BigInt(1));
const history = z.object({ ...identity, deviceId: uuid, page: z.number().int().min(1).max(1000000), limit: z.literal(25), total: z.number().int().nonnegative().safe(), events: z.array(event).max(25) }).strict();
export type DeviceOuHistory = z.infer<typeof history>;
const reference = z.object({ id: uuid, generation: revision }).strict();
const status = z.object({ schemaVersion: z.literal(1), deviceOuStatusProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid, deviceId: uuid, deviceRevision: revision,
  revision: z.union([z.literal('0'), revision]), selection: reference.nullable(), state: z.enum(['unassigned', 'current', 'changed', 'not-current']), currentOu: unit.nullable(), checkedAt: time,
  validUntil: z.number().int().positive().safe() }).strict();
export type DeviceOuCurrentStatus = z.infer<typeof status>;
const path = (device: Device) => '/api/devices/' + uuid.parse(device.id) + '/organizational-unit';
function bound<T extends { actorUserId: string; tenantId: string }>(value: T, device: Device, actor: string, signal: AbortSignal) {
  if (signal.aborted || value.actorUserId !== actor || value.tenantId !== device.tenantId) throw new Error('Original device OU context unavailable'); return value;
}
const etag = (value: DeviceOuAssignment) => `"device-ou-${value.deviceId}-${value.deviceRevision}-${value.revision}"`;
const count = (total: number, page: number) => Math.min(25, Math.max(0, total - (page - 1) * 25));
const selected = (value: DeviceOrganizationalUnit | null) => value ? { id: value.id, generation: value.generation, revision: value.revision } : null;

export async function readDeviceOu(device: Device, actor: string, signal: AbortSignal) {
  let response;
  try { response = await api.get(path(device), { signal }); }
  catch (error) { if ((error as any)?.response?.status === 501) return null; throw error; }
  const data = bound(current.parse(response.data), device, actor, signal);
  if (response.status !== 200 || data.deviceId !== device.id || data.deviceRevision !== device.revision || response.headers?.etag !== etag(data)) throw new Error('Current device OU versions unavailable');
  return data;
}
export async function readDeviceOuChoices(device: Device, actor: string, page: number, search: string, signal: AbortSignal) {
  const response = await api.get('/api/devices/organizational-units', { params: { page, search }, signal });
  const data = bound(choices.parse(response.data), device, actor, signal);
  if (response.status !== 200 || data.page !== page || data.units.length !== count(data.total, page) || new Set(data.units.map(value => value.id)).size !== data.units.length) throw new Error('Own organizational unit choices unavailable');
  return data;
}
export async function writeDeviceOu(device: Device, actor: string, previous: DeviceOuAssignment, ou: DeviceOrganizationalUnit | null, reason: string, signal: AbortSignal) {
  bound(previous, device, actor, signal);
  if (previous.deviceId !== device.id || previous.deviceRevision !== device.revision || previous.revision === '9223372036854775807') throw new Error('Current device OU context required');
  const explanation = reason.trim();
  if (Array.from(explanation).length < 10 || Array.from(explanation).length > 500 || /[\u0000-\u001f\u007f-\u009f]/.test(explanation)) throw new Error('Explicit device OU reason required');
  if (ou) unit.parse(ou);
  const response = await api.put(path(device), { ou: selected(ou), reason: explanation, confirm: true }, { headers: { 'If-Match': etag(previous) }, signal });
  const data = bound(receipt.parse(response.data), device, actor, signal);
  if (response.status !== 200 || data.deviceId !== device.id || data.deviceRevision !== device.revision || BigInt(data.revision) !== BigInt(previous.revision) + BigInt(1)
    || JSON.stringify(selected(data.ou)) !== JSON.stringify(selected(ou)) || data.updatedBy !== actor || data.updatedAt === null) throw new Error('Actual device OU change unconfirmed');
  return data;
}
export async function readDeviceOuHistory(device: Device, actor: string, page: number, signal: AbortSignal) {
  const response = await api.get(path(device) + '/history', { params: { page }, signal }), data = bound(history.parse(response.data), device, actor, signal);
  if (response.status !== 200 || data.deviceId !== device.id || data.page !== page || data.events.length !== count(data.total, page) || new Set(data.events.map(value => value.id)).size !== data.events.length) throw new Error('Retained device OU history unconfirmed');
  return data;
}
export async function readDeviceOuStatus(device: Device, actor: string, previous: DeviceOuAssignment, signal: AbortSignal) {
  bound(previous, device, actor, signal);
  if (previous.deviceId !== device.id || previous.deviceRevision !== device.revision) throw new Error('Original device OU context required');
  let response;
  try { response = await api.get(path(device) + '/status', { headers: { 'If-Match': etag(previous) }, signal }); }
  catch (error) { if ((error as any)?.response?.status === 501) return null; throw error; }
  const data = bound(status.parse(response.data), device, actor, signal);
  const sameReference = previous.ou === null ? data.selection === null : data.selection?.id === previous.ou.id && data.selection?.generation === previous.ou.generation;
  const currentReference = data.currentOu === null || data.currentOu.id === data.selection?.id && data.currentOu.generation === data.selection?.generation;
  const expectedState = previous.ou === null ? 'unassigned' : data.currentOu === null ? 'not-current'
    : ['id', 'generation', 'revision', 'name', 'parentId'].every(key => previous.ou![key as keyof DeviceOrganizationalUnit] === data.currentOu![key as keyof DeviceOrganizationalUnit]) ? 'current' : 'changed';
  if (response.status !== 200 || data.deviceId !== device.id || data.deviceRevision !== previous.deviceRevision || data.revision !== previous.revision || !sameReference || !currentReference
    || previous.ou === null && data.currentOu !== null || data.state !== expectedState || data.validUntil * 1000 <= Date.now() || data.validUntil * 1000 > Date.now() + 305000
    || Date.parse(data.checkedAt) > Date.now() + 5000 || Date.parse(data.checkedAt) >= data.validUntil * 1000) throw new Error('Current original OU status unconfirmed');
  return data;
}
export function deviceOuError(error: unknown) {
  return (error as any)?.response?.status === 412 ? 'Das Gerät, die Zuordnung oder die ausgewählte Organisationseinheit hat sich geändert. Bitte neu laden und erneut auswählen.'
    : (error as any)?.response?.status === 409 ? 'Diese Zuordnung wurde bereits geändert oder ist unverändert. Bitte neu laden.' : deviceInventoryError(error);
}
