import { z } from 'zod';
import { api } from './api';
import { directoryUsers, UserPage } from './directoryUsers';

export const deviceClasses = ['smartphone', 'tablet', 'laptop', 'desktop', 'shared', 'kiosk', 'other'] as const;
export const devicePlatforms = ['macos', 'ios', 'ipados', 'windows', 'linux', 'android', 'other'] as const;
export const deviceLifecycles = ['available', 'assigned', 'maintenance', 'retired'] as const;
const filtersSchema = z.object({ platform: z.enum(devicePlatforms).optional(), lifecycle: z.enum(deviceLifecycles).optional(), ownership: z.enum(['corporate', 'byod', 'shared']).optional(), deviceClass: z.enum(deviceClasses).optional(), sort: z.enum(['assetId', 'createdAt', 'updatedAt']).optional(), order: z.enum(['asc', 'desc']).optional() }).strict();
export type DeviceFilters = z.infer<typeof filtersSchema>;
const permissions = ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign'] as const;
const uuid = z.string().length(36).regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => !/\s/.test(value) && BigInt(value) <= BigInt('9223372036854775807'));
const timestamp = z.string().datetime({ offset: true }).refine(value => Number.isFinite(Date.parse(value)));
const date = z.string().refine(value => value === '' || /^\d{4}-\d{2}-\d{2}$/.test(value) && !value.startsWith('0000-')
  && Number.isFinite(Date.parse(value + 'T00:00:00.000Z')) && new Date(value + 'T00:00:00.000Z').toISOString().slice(0, 10) === value);
const text = (maximum: number, required = false) => z.string().refine(value => !/[\u0000-\u001f\u007f-\u009f]/.test(value))
  .transform(value => value.trim()).refine(value => Array.from(value).length <= maximum && (!required || value.length > 0));
const valuesSchema = z.object({
  assetId: text(120, true), serialNumber: text(120, true), manufacturer: text(120, true), model: text(120, true),
  deviceClass: z.enum(deviceClasses), platform: z.enum(devicePlatforms), osVersion: text(120).default(''),
  ownership: z.enum(['corporate', 'byod', 'shared']).default('corporate'), purchaseDate: date.default(''),
  warrantyEnd: date.default(''), description: text(2000).default(''),
}).strict().refine(value => !value.purchaseDate || !value.warrantyEnd || value.warrantyEnd >= value.purchaseDate);
const valueFields = ['assetId', 'serialNumber', 'manufacturer', 'model', 'deviceClass', 'platform', 'osVersion', 'ownership', 'purchaseDate', 'warrantyEnd', 'description'] as const;
const deviceSchema = z.object({
  id: uuid, tenantId: uuid, assetId: z.string(), serialNumber: z.string(), manufacturer: z.string(), model: z.string(),
  deviceClass: z.enum(deviceClasses), platform: z.enum(devicePlatforms), osVersion: z.string(),
  ownership: z.enum(['corporate', 'byod', 'shared']), purchaseDate: date, warrantyEnd: date, description: z.string(),
  revision, lifecycle: z.enum(deviceLifecycles), managementMode: z.literal('inventory-only'),
  enrollmentStatus: z.literal('not-enrolled'), managementProvider: z.null(), complianceStatus: z.literal('unknown'),
  lastSeen: z.null(), assignedUserId: uuid.nullable(), assignmentId: uuid.nullable(), createdAt: timestamp, updatedAt: timestamp,
}).strict().refine(value => {
  const normalized = valuesSchema.safeParse(Object.fromEntries(valueFields.map(field => [field, value[field]])));
  return normalized.success && valueFields.every(field => normalized.data[field] === value[field])
    && (value.lifecycle === 'assigned' ? value.assignedUserId !== null && value.assignmentId !== null : value.assignedUserId === null && value.assignmentId === null)
    && Date.parse(value.updatedAt) >= Date.parse(value.createdAt);
});
const capabilitiesSchema = z.object({
  schemaVersion: z.literal(1), inventoryProtocol: z.union([z.literal(1), z.literal(2)]), userId: uuid, tenantId: uuid,
  permissions: z.array(z.enum(permissions)).refine(values => new Set(values).size === values.length),
  managementMode: z.literal('inventory-only'), supportedActions: z.array(z.never()),
}).strict();
const stateSchema = z.object({ assignedUserId: uuid.nullable(), assignmentId: uuid.nullable(), revision }).strict()
  .refine(value => (value.assignedUserId === null) === (value.assignmentId === null));
const eventSchema = z.object({
  id: uuid, tenantId: uuid, deviceId: uuid, type: z.enum(['device.registered', 'device.assigned', 'device.assignment.released', 'device.updated', 'device.lifecycle.changed']),
  version: z.literal(1), actorUserId: uuid, correlationId: uuid, createdAt: timestamp, before: stateSchema.nullable(),
  after: stateSchema, deliveryStatus: z.literal('pending'), reason: text(500, true).refine(value => Array.from(value).length >= 10).optional(),
  changes: z.array(z.object({ field: z.enum([...valueFields, 'lifecycle']), before: z.string(), after: z.string() }).strict().refine(value => value.before !== value.after)).min(1).max(12).optional(),
}).strict().refine(value => {
  if (value.type === 'device.registered') return value.before === null && value.after.revision === '1' && value.after.assignedUserId === null;
  if (!value.before || BigInt(value.after.revision) !== BigInt(value.before.revision) + BigInt(1)) return false;
  if (['device.updated', 'device.lifecycle.changed'].includes(value.type)) return Boolean(value.reason && value.changes
    && new Set(value.changes.map(change => change.field)).size === value.changes.length
    && value.before.assignedUserId === value.after.assignedUserId && value.before.assignmentId === value.after.assignmentId
    && value.changes.every(change => value.type === 'device.updated' ? change.field !== 'lifecycle' : change.field === 'lifecycle'));
  if (value.reason !== undefined || value.changes !== undefined) return false;
  return value.type === 'device.assigned'
    ? value.after.assignedUserId !== null && value.after.assignmentId !== value.before.assignmentId && value.after.assignedUserId !== value.before.assignedUserId
    : value.before.assignedUserId !== null && value.after.assignedUserId === null;
});

export type Device = z.infer<typeof deviceSchema>;
export type DeviceInput = z.input<typeof valuesSchema>;
export type DeviceCapabilities = z.infer<typeof capabilitiesSchema>;
export type DeviceHistoryEvent = z.infer<typeof eventSchema>;
export interface DevicePage { devices: Device[]; total: number; page: number; limit: number }
export interface DeviceHistoryPage { events: DeviceHistoryEvent[]; total: number; page: number; limit: number }

const unconfirmed = () => new Error('Geräteantwort nicht bestätigt. Bitte neu laden; die Aktion wird nicht automatisch wiederholt.');
export function normalizeDeviceInput(input: DeviceInput) { return valuesSchema.parse(input); }
export function deviceEtag(device: Pick<Device, 'id' | 'revision'>) {
  return `"device-${uuid.parse(device.id)}-${revision.parse(device.revision)}"`;
}
export function deviceInventoryError(error: unknown) {
  const status = (error as { response?: { status?: number }; status?: number })?.response?.status;
  if (status === 401) return 'Die Sitzung ist nicht mehr gültig. Bitte erneut anmelden und neu laden.';
  if (status === 403) return 'Keine Berechtigung für diese Geräteaktion. Bitte neu laden.';
  if (status === 412) return 'Das Gerät wurde zwischenzeitlich geändert. Bitte neu laden; die Aktion wird nicht automatisch wiederholt.';
  if (status === 409) return 'Inventarnummer oder Seriennummer bereits vergeben oder Zuweisung geändert. Bitte neu laden.';
  if (status === 413) return 'Der Export ist zu groß. Bitte auf höchstens 5.000 Geräte eingrenzen.';
  if (status === 400) return 'Die Eingaben wurden abgelehnt. Bitte prüfen und neu laden.';
  if (status === 428) return 'Für das Geräteinventar ist eine höchstens fünf Minuten alte MFA-Anmeldung erforderlich. Richte MFA ein und melde dich mit Passwort und aktuellem Einmalcode erneut an.';
  if (status === 503) return 'Der Gerätedienst kann den Anmeldestatus momentan nicht prüfen. Bitte später neu laden.';
  return unconfirmed().message;
}

function pageNumber(page: number) {
  if (!Number.isSafeInteger(page) || page < 1 || page > 1000000) throw unconfirmed();
  return page;
}
function query(search: string) {
  if (typeof search !== 'string' || Array.from(search).length > 200 || /[\u0000-\u001f\u007f-\u009f]/.test(search)) throw unconfirmed();
  return search.trim();
}
function parsePage(data: unknown, field: 'devices' | 'events', page: number, actor: string, deviceId?: string) {
  const envelope = z.object({
    schemaVersion: z.literal(1), actorUserId: z.literal(actor), total: z.number().int().nonnegative().safe(),
    page: z.literal(page), limit: z.literal(25),
    ...(field === 'devices' ? { devices: z.array(deviceSchema) } : { events: z.array(eventSchema), deviceId: z.literal(deviceId) }),
  }).strict().parse(data);
  const rows = envelope[field] as Array<Device | DeviceHistoryEvent>;
  if (rows.length !== Math.min(25, Math.max(0, envelope.total - (page - 1) * 25)) || new Set(rows.map(row => row.id)).size !== rows.length) throw unconfirmed();
  return envelope;
}

export class DeviceInventoryClient {
  private context: DeviceCapabilities | null = null;
  private generation = 0;
  private controllers = new Set<AbortController>();
  private writing = false;
  private disposed = false;
  private onSessionError = () => this.invalidate();

  constructor() {
    if (typeof window !== 'undefined') window.addEventListener('od:session-error', this.onSessionError);
  }

  invalidate() {
    this.generation += 1;
    this.context = null;
    this.controllers.forEach(controller => controller.abort());
    this.controllers.clear();
  }

  dispose() {
    this.disposed = true;
    this.invalidate();
    if (typeof window !== 'undefined') window.removeEventListener('od:session-error', this.onSessionError);
  }

  private async run<Result>(operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal, write = false): Promise<Result> {
    const generation = this.generation;
    const controller = new AbortController();
    const abort = () => controller.abort();
    const check = () => { if (this.disposed || generation !== this.generation || controller.signal.aborted) throw unconfirmed(); };
    if (signal?.aborted) controller.abort();
    signal?.addEventListener('abort', abort);
    this.controllers.add(controller);
    try {
      check();
      const result = await operation(controller.signal, check);
      check();
      return result;
    } catch (error) {
      if (generation === this.generation && (write || !controller.signal.aborted)) this.invalidate();
      throw error;
    } finally {
      signal?.removeEventListener('abort', abort);
      this.controllers.delete(controller);
    }
  }

  private require(permission: typeof permissions[number]) {
    if (!this.context?.permissions.includes(permission)) throw unconfirmed();
    return this.context;
  }

  private async fresh(context: DeviceCapabilities, permission: typeof permissions[number], signal: AbortSignal, check: () => void) {
    const response = await api.get('/api/devices/capabilities', { signal });
    check();
    const current = capabilitiesSchema.parse(response.data);
    if (response.status !== 200 || current.userId !== context.userId || current.tenantId !== context.tenantId || !current.permissions.includes(permission)) throw unconfirmed();
    this.context = current;
  }

  async reload(signal?: AbortSignal): Promise<DeviceCapabilities> {
    this.invalidate();
    return this.run(async (requestSignal, check) => {
      const response = await api.get('/api/devices/capabilities', { signal: requestSignal });
      check();
      if (response.status !== 200) throw unconfirmed();
      const result = capabilitiesSchema.parse(response.data);
      this.context = result;
      return result;
    }, signal);
  }

  async list(page = 1, search = '', signal?: AbortSignal, filters: DeviceFilters = {}): Promise<DevicePage> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('devices.inventory.read');
      const normalizedSearch = query(search);
      const selected = filtersSchema.parse(filters);
      if (Object.values(selected).some(value => value !== undefined) && context.inventoryProtocol !== 2) throw unconfirmed();
      const response = await api.get('/api/devices', { params: { page: pageNumber(page), limit: 25, ...(normalizedSearch ? { search: normalizedSearch } : {}), ...selected }, signal: requestSignal });
      check();
      if (response.status !== 200) throw unconfirmed();
      const result = parsePage(response.data, 'devices', page, context.userId) as DevicePage;
      if (result.devices.some(device => device.tenantId !== context.tenantId || Object.entries(selected).some(([field, value]) => value !== undefined && !['sort', 'order'].includes(field) && device[field] !== value))) throw unconfirmed();
      return result;
    }, signal);
  }

  async get(deviceId: string, signal?: AbortSignal): Promise<Device> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('devices.inventory.read');
      const response = await api.get('/api/devices/' + uuid.parse(deviceId), { signal: requestSignal });
      check();
      const device = deviceSchema.parse(response.data);
      if (response.status !== 200 || device.id !== deviceId || device.tenantId !== context.tenantId) throw unconfirmed();
      return device;
    }, signal);
  }

  async history(deviceId: string, page = 1, signal?: AbortSignal): Promise<DeviceHistoryPage> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('devices.inventory.read');
      const response = await api.get('/api/devices/' + uuid.parse(deviceId) + '/history', { params: { page: pageNumber(page), limit: 25 }, signal: requestSignal });
      check();
      if (response.status !== 200) throw unconfirmed();
      const result = parsePage(response.data, 'events', page, context.userId, deviceId) as DeviceHistoryPage;
      if (result.events.some(event => event.tenantId !== context.tenantId || event.deviceId !== deviceId)
        || new Set(result.events.map(event => event.after.revision)).size !== result.events.length) throw unconfirmed();
      return result;
    }, signal);
  }

  async users(page = 1, search = '', signal?: AbortSignal): Promise<UserPage | null> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('devices.inventory.assign');
      const access = await directoryUsers.access();
      check();
      if (access.userId !== context.userId || access.demoMode) throw unconfirmed();
      if (!access.permissions.includes('users.read')) return null;
      if (access.directoryReadProtocol !== 1) throw unconfirmed();
      const result = await directoryUsers.list(pageNumber(page), query(search), '', requestSignal);
      check();
      return result;
    }, signal);
  }

  private async write(operation: (signal: AbortSignal, check: () => void) => Promise<Device>, signal?: AbortSignal) {
    if (this.writing) throw unconfirmed();
    this.writing = true;
    try { return await this.run(operation, signal, true); }
    finally { this.writing = false; }
  }

  async create(input: DeviceInput, signal?: AbortSignal): Promise<Device> {
    const values = normalizeDeviceInput(input);
    return this.write(async (requestSignal, check) => {
      const context = this.require('devices.inventory.create');
      await this.fresh(context, 'devices.inventory.create', requestSignal, check);
      check();
      const response = await api.post('/api/devices', values, { signal: requestSignal });
      check();
      const device = deviceSchema.parse(response.data);
      if (response.status !== 201 || device.tenantId !== context.tenantId || device.revision !== '1' || device.lifecycle !== 'available'
        || device.createdAt !== device.updatedAt || valueFields.some(field => device[field] !== values[field])) throw unconfirmed();
      return device;
    }, signal);
  }

  async assign(snapshot: Device, input: { userId: string | null }, signal?: AbortSignal): Promise<Device> {
    const previous = deviceSchema.parse(snapshot);
    const assignment = z.object({ userId: uuid.nullable() }).strict().parse(input);
    if (assignment.userId === previous.assignedUserId || previous.revision === '9223372036854775807') throw unconfirmed();
    return this.write(async (requestSignal, check) => {
      const context = this.require('devices.inventory.assign');
      if (previous.tenantId !== context.tenantId) throw unconfirmed();
      await this.fresh(context, 'devices.inventory.assign', requestSignal, check);
      check();
      const response = await api.put('/api/devices/' + previous.id + '/assignment', assignment, {
        headers: { 'If-Match': deviceEtag(previous) }, signal: requestSignal,
      });
      check();
      const device = deviceSchema.parse(response.data);
      const mutable = ['assignedUserId', 'assignmentId', 'lifecycle', 'revision', 'updatedAt'];
      if (response.status !== 200 || Object.keys(previous).some(field => !mutable.includes(field) && previous[field] !== device[field])
        || device.assignedUserId !== assignment.userId || BigInt(device.revision) !== BigInt(previous.revision) + BigInt(1)
        || Date.parse(device.updatedAt) < Date.parse(previous.updatedAt)
        || assignment.userId !== null && device.assignmentId === previous.assignmentId) throw unconfirmed();
      return device;
    }, signal);
  }

  async exportCsv(search = '', filters: DeviceFilters = {}, signal?: AbortSignal): Promise<Blob> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('devices.inventory.read'); if (context.inventoryProtocol !== 2) throw unconfirmed();
      await this.fresh(context, 'devices.inventory.read', requestSignal, check);
      if (this.context?.inventoryProtocol !== 2) throw unconfirmed();
      const response = await api.get('/api/devices/export', { params: { ...filtersSchema.parse(filters), ...(query(search) ? { search: query(search) } : {}) }, responseType: 'blob', signal: requestSignal });
      check();
      const count = String(response.headers?.['x-inventory-count'] || '');
      if (response.status !== 200 || response.headers?.['x-inventory-tenant'] !== context.tenantId || !/^text\/csv\b/i.test(String(response.headers?.['content-type'] || ''))
        || !/^(0|[1-9][0-9]*)$/.test(count) || Number(count) > 5000 || !(response.data instanceof Blob) || response.data.size > 32 * 1024 * 1024) throw unconfirmed();
      const content = await response.data.text(); check();
      if (content.replace(/^\uFEFF/, '').split('\r\n').length !== Number(count) + 2) throw unconfirmed();
      return response.data;
    }, signal);
  }

  async update(snapshot: Device, input: DeviceInput, reason: string, signal?: AbortSignal): Promise<Device> {
    const values = normalizeDeviceInput(input);
    const explanation = text(500, true).refine(value => Array.from(value).length >= 10).parse(reason);
    if (valueFields.every(field => values[field] === snapshot[field])) throw new Error('Keine Stammdaten geändert.');
    return this.maintain(snapshot, { ...values, reason: explanation, confirm: true }, 'update', signal);
  }

  async lifecycle(snapshot: Device, lifecycle: 'available' | 'maintenance' | 'retired', reason: string, signal?: AbortSignal): Promise<Device> {
    z.enum(['available', 'maintenance', 'retired']).parse(lifecycle);
    const explanation = text(500, true).refine(value => Array.from(value).length >= 10).parse(reason);
    if (snapshot.assignedUserId || snapshot.lifecycle === lifecycle) throw unconfirmed();
    return this.maintain(snapshot, { lifecycle, reason: explanation, confirm: true }, 'lifecycle', signal);
  }

  private async maintain(snapshot: Device, body: Record<string, unknown>, action: 'update' | 'lifecycle', signal?: AbortSignal): Promise<Device> {
    const previous = deviceSchema.parse(snapshot);
    return this.write(async (requestSignal, check) => {
      const context = this.require('devices.inventory.create');
      if (context.inventoryProtocol !== 2 || previous.tenantId !== context.tenantId || previous.revision === '9223372036854775807') throw unconfirmed();
      await this.fresh(context, 'devices.inventory.create', requestSignal, check);
      if (this.context?.inventoryProtocol !== 2) throw unconfirmed();
      const options = { headers: { 'If-Match': deviceEtag(previous) }, signal: requestSignal };
      const response = action === 'update' ? await api.put('/api/devices/' + previous.id, body, options) : await api.post('/api/devices/' + previous.id + '/lifecycle', body, options);
      check(); const device = deviceSchema.parse(response.data);
      const mutable = ['revision', 'updatedAt', ...(action === 'update' ? valueFields : ['lifecycle'])];
      if (response.status !== 200 || Object.keys(previous).some(field => !mutable.includes(field) && previous[field] !== device[field])
        || BigInt(device.revision) !== BigInt(previous.revision) + BigInt(1) || Date.parse(device.updatedAt) < Date.parse(previous.updatedAt)
        || (action === 'update' ? valueFields.some(field => device[field] !== body[field]) : device.lifecycle !== body.lifecycle)) throw unconfirmed();
      return device;
    }, signal);
  }
}
