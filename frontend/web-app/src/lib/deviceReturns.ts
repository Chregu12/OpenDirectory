import { z } from 'zod';
import { api } from './api';

const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => BigInt(value) <= BigInt('9223372036854775807'));
const timestamp = z.string().datetime({ offset: true }).refine(value => Number.isFinite(Date.parse(value)));
const text = z.string().refine(value => !/[\u0000-\u001f\u007f-\u009f]/.test(value));
const reasonSchema = text.transform(value => value.trim()).refine(value => Array.from(value).length >= 10 && Array.from(value).length <= 500);
const retainedReason = text.refine(value => value === value.trim()).pipe(reasonSchema);
const label = text.refine(value => value === value.trim() && value.length > 0 && Array.from(value).length <= 120);
const pageNumber = z.number().int().positive().max(1000000);
const count = z.number().int().nonnegative().safe();
const inventoryPermissions = ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign'] as const;
const permissions = z.array(z.enum(inventoryPermissions)).length(3).refine(values => new Set(values).size === 3);
const envelope = { schemaVersion: z.literal(1), actorUserId: uuid, tenantId: uuid };
const targetSchema = z.object({ enabled: z.literal(false), eligibilityRevision: revision }).strict();
const offboardingEnvelope = { ...envelope, workflowId: uuid, userId: uuid, target: targetSchema };
const capSchema = z.object({ ...envelope, deviceReturnsProtocol: z.literal(1), permissions, managementMode: z.literal('inventory-only') }).strict();
const offboardingCapSchema = z.object({ ...offboardingEnvelope, deviceOffboardingReturnsProtocol: z.literal(1), permissions, managementMode: z.literal('inventory-only') }).strict();
export const deviceReturnStatuses = ['requested', 'returned', 'cancelled', 'assignment_changed'] as const;
const status = z.enum(deviceReturnStatuses);
const requestSchema = z.object({
  id: uuid, tenantId: uuid, workflowId: uuid, userId: uuid, deviceId: uuid, assignmentId: uuid,
  assetId: label, serialNumber: label, revision, deviceRevision: revision, currentDeviceRevision: revision,
  status, reason: retainedReason, actorUserId: uuid, requestedAt: timestamp, eligibilityRevision: revision,
  closedAt: timestamp.nullable(), closedByUserId: uuid.nullable(), operationId: uuid,
  closingOperationId: uuid.nullable(), inventoryOperationId: uuid.nullable(), deliveryStatus: z.literal('pending'),
}).strict().refine(value => {
  if (value.actorUserId === value.userId || BigInt(value.currentDeviceRevision) < BigInt(value.deviceRevision)) return false;
  if (value.status === 'requested') return value.closedAt === null && value.closedByUserId === null
    && value.closingOperationId === null && value.inventoryOperationId === null;
  if (!value.closedAt || !value.closedByUserId || Date.parse(value.closedAt) < Date.parse(value.requestedAt)) return false;
  if (value.status === 'assignment_changed') return value.closingOperationId === null && value.inventoryOperationId !== null
    && BigInt(value.currentDeviceRevision) > BigInt(value.deviceRevision);
  return value.closingOperationId !== null && value.closingOperationId !== value.operationId
    && (value.status === 'returned' ? value.inventoryOperationId !== null && BigInt(value.currentDeviceRevision) > BigInt(value.deviceRevision) : value.inventoryOperationId === null);
});
const rawState = z.object({ revision, status: z.enum(['requested', 'returned', 'cancelled']) }).strict();
const eventSchema = z.object({
  id: uuid, tenantId: uuid, requestId: uuid, deviceId: uuid, assignmentId: uuid,
  type: z.enum(['device.return.requested', 'device.return.confirmed', 'device.return.cancelled']), version: z.literal(1),
  actorUserId: uuid, correlationId: uuid, createdAt: timestamp, before: rawState.nullable(), after: rawState,
  inventoryOperationId: uuid.nullable(), reason: retainedReason, deliveryStatus: z.literal('pending'),
}).strict().refine(value => value.type === 'device.return.requested'
  ? value.before === null && value.after.status === 'requested' && value.after.revision === '1' && value.inventoryOperationId === null
  : value.before?.status === 'requested' && BigInt(value.after.revision) === BigInt(value.before.revision) + BigInt(1)
    && (value.type === 'device.return.confirmed' ? value.after.status === 'returned' && value.inventoryOperationId !== null
      : value.after.status === 'cancelled' && value.inventoryOperationId === null));
const pagination = { total: count, page: pageNumber, limit: z.literal(25) };
const listSchema = z.object({ ...envelope, requests: z.array(requestSchema).max(25), ...pagination }).strict();
const eventPageSchema = z.object({ ...envelope, requestId: uuid, events: z.array(eventSchema).max(25), ...pagination }).strict();
const deviceSchema = z.object({ deviceId: uuid, assetId: label, serialNumber: label, deviceRevision: revision, assignmentId: uuid, openRequestId: uuid.nullable() }).strict();
const previewSchema = z.object({ ...offboardingCapSchema.shape, devices: z.array(deviceSchema).max(25), ...pagination }).strict();
const historySchema = z.object({ ...offboardingEnvelope, requests: z.array(requestSchema).max(25), ...pagination }).strict();
const resultSchema = z.object({
  deviceId: uuid, assignmentId: uuid, requestId: uuid, status: z.enum(['requested', 'already_requested', 'unconfirmed', 'not_attempted']),
  code: z.union([z.literal(200), z.number().int().min(400).max(599)]).nullable(), operationId: uuid.nullable(),
}).strict().refine(value => value.status === 'requested' || value.status === 'already_requested'
  ? value.code === 200 && value.operationId !== null
  : value.operationId === null && (value.status === 'not_attempted' ? value.code === null : value.code !== null && value.code >= 400));
const outcomeSchema = z.object({ ...envelope, workflowId: uuid, userId: uuid, correlationId: uuid, results: z.array(resultSchema).min(1).max(25) }).strict();
const decisionSchema = z.object({ action: z.enum(['returned', 'cancelled']), reason: reasonSchema, confirm: z.literal(true) }).strict();
const decisionResultSchema = z.object({ ...capSchema.pick({ schemaVersion: true, deviceReturnsProtocol: true, actorUserId: true, tenantId: true }).shape,
  request: requestSchema, outcome: z.enum(['returned', 'already_returned', 'cancelled', 'already_cancelled']), operationId: uuid }).strict();

export type DeviceReturnRequest = z.infer<typeof requestSchema>;
export type DeviceReturnPage = z.infer<typeof listSchema>;
export type DeviceReturnHistory = z.infer<typeof eventPageSchema>;
export type DeviceReturnDecisionResult = z.infer<typeof decisionResultSchema>;
export type DeviceReturnStatus = typeof deviceReturnStatuses[number];
export type DeviceReturnCapabilities = z.infer<typeof capSchema>;
export type OffboardingDevicesCapabilities = z.infer<typeof offboardingCapSchema>;
export type OffboardingDevicesPreview = z.infer<typeof previewSchema>;
export type OffboardingDevicesHistory = z.infer<typeof historySchema>;
export type OffboardingDevicesOutcome = z.infer<typeof outcomeSchema>;
export type OffboardingDevicesBinding = { actorUserId: string; tenantId: string; workflowId: string; userId: string; eligibilityRevision: string };
export type DeviceReturnIntent = { request: DeviceReturnRequest; etag: string; body: z.infer<typeof decisionSchema> };
export type OffboardingDevicesIntent = { snapshot: OffboardingDevicesPreview; reason: string; items: Array<{ deviceId: string; deviceRevision: string; assignmentId: string; requestId: string }> };
export const deviceReturnsReason = (value: string) => reasonSchema.parse(value);
export const deviceReturnsIdentifier = (value: string) => uuid.parse(value);
export function deviceReturnEtag(value: Pick<DeviceReturnRequest, 'id' | 'revision' | 'currentDeviceRevision'>) {
  return `"device-return-${uuid.parse(value.id)}-${revision.parse(value.revision)}-${revision.parse(value.currentDeviceRevision)}"`;
}
const unconfirmed = () => new Error('Geräterückgabe nicht bestätigt. Tatsächlichen Arbeitsstand und Historie neu laden; keine automatische Wiederholung.');
export function deviceReturnsError(error: unknown) {
  const failure = z.object({ response: z.object({ status: z.number() }).passthrough() }).passthrough().safeParse(error);
  const code = failure.success ? failure.data.response.status : null;
  if (code === 401) return 'Sitzung ungültig. Erneut anmelden und Arbeitsstand neu laden.';
  if (code === 403) return 'Geräteberechtigung oder aktuelle Quellfreigabe fehlt. Arbeitsstand neu laden.';
  if (code === 428) return 'Frische MFA-Anmeldung erforderlich. Erneut anmelden und Arbeitsstand neu laden.';
  if (code === 404) return 'Gerät, Rückgabeauftrag oder Austrittsnachweis nicht verfügbar. Arbeitsstand neu laden.';
  if (code === 409 || code === 412) return 'Kontogeneration, Auftrag oder Gerätezuweisung geändert. Arbeitsstand und Historie neu laden; keine neue Zuweisung als Ersatz verwenden.';
  if (code === 400) return 'Eingaben abgelehnt. Auswahl und Begründung prüfen und Arbeitsstand neu laden.';
  return unconfirmed().message;
}
function freeze<Value>(value: Value): Value {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function unique(values: string[]) { return new Set(values).size === values.length; }
function page(rows: unknown[], total: number, actual: number, expected: number) {
  if (actual !== expected || rows.length !== Math.min(25, Math.max(0, total - (expected - 1) * 25))) throw unconfirmed();
}
const retainedFields = ['id', 'tenantId', 'workflowId', 'userId', 'deviceId', 'assignmentId', 'assetId', 'serialNumber', 'deviceRevision', 'reason', 'actorUserId', 'requestedAt', 'eligibilityRevision', 'operationId', 'deliveryStatus'] as const;
function sameRequest(before: DeviceReturnRequest, after: DeviceReturnRequest) {
  if (retainedFields.some(field => before[field] !== after[field])) throw unconfirmed();
}

class ReturnsClient {
  protected actor: string;
  protected tenant: string | null;
  protected generation = 0;
  protected writing = false;
  private disposed = false;
  private controllers = new Set<AbortController>();
  protected intents = new WeakMap<object, { attempted: boolean; generation: number }>();
  private sessionError = () => { this.intents = new WeakMap(); this.invalidate(); };
  constructor(actorUserId: string, tenantId?: string) {
    this.actor = uuid.parse(actorUserId); this.tenant = tenantId ? uuid.parse(tenantId) : null;
    if (typeof window !== 'undefined') window.addEventListener('od:session-error', this.sessionError);
  }
  invalidate() {
    this.generation++; this.clearReads(); this.controllers.forEach(controller => controller.abort()); this.controllers.clear();
  }
  protected clearReads() {}
  dispose() {
    this.disposed = true; this.intents = new WeakMap(); this.invalidate();
    if (typeof window !== 'undefined') window.removeEventListener('od:session-error', this.sessionError);
  }
  protected bind(value: Pick<DeviceReturnCapabilities, 'actorUserId' | 'tenantId'>, pin = false) {
    if (value.actorUserId !== this.actor || this.tenant !== null && value.tenantId !== this.tenant) throw unconfirmed();
    if (pin) this.tenant = value.tenantId;
    if (!this.tenant) throw unconfirmed();
  }
  protected async run<Value>(operation: (signal: AbortSignal, check: () => void) => Promise<Value>, signal?: AbortSignal): Promise<Value> {
    const generation = this.generation; const controller = new AbortController();
    const abort = () => controller.abort();
    const check = () => { if (this.disposed || generation !== this.generation || controller.signal.aborted) throw unconfirmed(); };
    if (signal?.aborted) abort(); signal?.addEventListener('abort', abort); this.controllers.add(controller);
    try { check(); const result = await operation(controller.signal, check); check(); return result; }
    catch (error) { if (generation === this.generation) this.invalidate(); throw error; }
    finally { signal?.removeEventListener('abort', abort); this.controllers.delete(controller); }
  }
  protected async write<Value>(operation: (signal: AbortSignal, check: () => void) => Promise<Value>, signal?: AbortSignal) {
    if (this.writing) throw unconfirmed(); this.writing = true;
    try { return await this.run(operation, signal); }
    finally { this.invalidate(); this.writing = false; }
  }
  protected intent(value: object, recovery: boolean) {
    const known = this.intents.get(value);
    if (!known || (recovery ? !known.attempted : known.attempted || known.generation !== this.generation)) throw unconfirmed();
    known.attempted = true;
  }
}

export class DeviceReturnsClient extends ReturnsClient {
  private access: DeviceReturnCapabilities | null = null;
  private detail: DeviceReturnRequest | null = null;
  private historyReady = false;
  protected clearReads() { this.access = null; this.detail = null; this.historyReady = false; }
  async capabilities(signal?: AbortSignal): Promise<DeviceReturnCapabilities> {
    if (this.writing) throw unconfirmed(); this.invalidate();
    return this.run(async (requestSignal, check) => {
      const response = await api.get('/api/devices/returns/capabilities', { signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = capSchema.parse(response.data); this.bind(value, true); this.access = freeze(value); return value;
    }, signal);
  }
  async list(requestedPage = 1, filter?: DeviceReturnStatus, signal?: AbortSignal): Promise<DeviceReturnPage> {
    if (this.writing || !this.access) throw unconfirmed();
    return this.run(async (requestSignal, check) => {
      const response = await api.get('/api/devices/returns', { params: { page: pageNumber.parse(requestedPage), limit: 25, ...(filter ? { status: status.parse(filter) } : {}) }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = listSchema.parse(response.data); this.bind(value); page(value.requests, value.total, value.page, requestedPage);
      if (!unique(value.requests.map(row => row.id)) || value.requests.some(row => row.tenantId !== this.tenant || filter && row.status !== filter)) throw unconfirmed();
      return freeze(value);
    }, signal);
  }
  async get(requestId: string, signal?: AbortSignal): Promise<DeviceReturnRequest> {
    if (this.writing || !this.access) throw unconfirmed(); this.detail = null; this.historyReady = false;
    return this.run(async (requestSignal, check) => {
      const response = await api.get('/api/devices/returns/' + uuid.parse(requestId), { signal: requestSignal }); check();
      const value = requestSchema.parse(response.data);
      if (response.status !== 200 || value.id !== requestId || value.tenantId !== this.tenant || response.headers?.etag !== deviceReturnEtag(value)) throw unconfirmed();
      this.detail = freeze(value); return value;
    }, signal);
  }
  async history(requestId: string, requestedPage = 1, signal?: AbortSignal): Promise<DeviceReturnHistory> {
    if (this.writing || !this.access || this.detail?.id !== requestId) throw unconfirmed(); this.historyReady = false;
    return this.run(async (requestSignal, check) => {
      const response = await api.get('/api/devices/returns/' + uuid.parse(requestId) + '/history', { params: { page: pageNumber.parse(requestedPage), limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = eventPageSchema.parse(response.data); this.bind(value); page(value.events, value.total, value.page, requestedPage);
      const detail = this.detail;
      if (!detail || value.requestId !== requestId || !unique(value.events.map(event => event.id)) || !unique(value.events.map(event => event.after.revision))
        || value.events.some(event => event.tenantId !== this.tenant || event.requestId !== requestId || event.deviceId !== detail.deviceId || event.assignmentId !== detail.assignmentId
          || BigInt(event.after.revision) > BigInt(detail.revision)
          || (event.type === 'device.return.requested' ? event.id !== detail.operationId || event.reason !== detail.reason || event.actorUserId !== detail.actorUserId || event.createdAt !== detail.requestedAt
            : event.id !== detail.closingOperationId || event.actorUserId !== detail.closedByUserId || event.createdAt !== detail.closedAt || event.after.status !== detail.status || event.inventoryOperationId !== detail.inventoryOperationId))) throw unconfirmed();
      this.historyReady = true; return freeze(value);
    }, signal);
  }
  capture(snapshot: DeviceReturnRequest, input: z.input<typeof decisionSchema>): DeviceReturnIntent {
    if (this.writing || !this.access || !this.historyReady || snapshot !== this.detail || snapshot.status !== 'requested') throw unconfirmed();
    const value = freeze({ request: snapshot, etag: deviceReturnEtag(snapshot), body: decisionSchema.parse(input) });
    this.intents.set(value, { attempted: false, generation: this.generation }); return value;
  }
  canRecover(intent: DeviceReturnIntent) {
    return !!this.access && !!this.historyReady && this.detail?.id === intent.request.id
      && (this.detail.status === 'requested' || this.detail.status === intent.body.action)
      && this.intents.get(intent)?.attempted === true;
  }
  async decide(intent: DeviceReturnIntent, recovery = false, signal?: AbortSignal): Promise<DeviceReturnDecisionResult> {
    if (!this.access || !this.historyReady || !this.detail || recovery && !this.canRecover(intent) || !recovery && this.detail !== intent.request) throw unconfirmed();
    sameRequest(intent.request, this.detail); this.intent(intent, recovery);
    return this.write(async (requestSignal, check) => {
      const authority = await api.get('/api/devices/returns/capabilities', { signal: requestSignal }); check();
      if (authority.status !== 200) throw unconfirmed(); this.bind(capSchema.parse(authority.data));
      const response = await api.post('/api/devices/returns/' + intent.request.id + '/decision', intent.body, { headers: { 'If-Match': intent.etag }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = decisionResultSchema.parse(response.data); this.bind(value); sameRequest(intent.request, value.request);
      if (value.request.status !== intent.body.action || ![intent.body.action, 'already_' + intent.body.action].includes(value.outcome)
        || value.operationId !== value.request.closingOperationId
        || BigInt(value.request.revision) !== BigInt(intent.request.revision) + BigInt(1)
        || response.headers?.etag !== deviceReturnEtag(value.request)
        || value.outcome === intent.body.action && (value.request.closedByUserId !== this.actor
          || BigInt(value.request.currentDeviceRevision) !== BigInt(intent.request.currentDeviceRevision) + (intent.body.action === 'returned' ? BigInt(1) : BigInt(0)))) throw unconfirmed();
      return freeze(value);
    }, signal);
  }
}

export class CompanyOffboardingDevicesClient extends ReturnsClient {
  private expected: OffboardingDevicesBinding;
  private base: string;
  private access: OffboardingDevicesCapabilities | null = null;
  private snapshot: OffboardingDevicesPreview | null = null;
  private historyReady = false;
  constructor(binding: OffboardingDevicesBinding) {
    const expected = { actorUserId: uuid.parse(binding.actorUserId), tenantId: uuid.parse(binding.tenantId), workflowId: uuid.parse(binding.workflowId), userId: uuid.parse(binding.userId), eligibilityRevision: revision.parse(binding.eligibilityRevision) };
    if (expected.actorUserId === expected.userId) throw unconfirmed();
    super(expected.actorUserId, expected.tenantId);
    this.expected = freeze(expected);
    this.base = '/api/devices/users/' + this.expected.userId + '/offboarding-returns';
  }
  protected clearReads() { this.access = null; this.snapshot = null; this.historyReady = false; }
  private bound(value: z.infer<typeof offboardingEnvelopeSchema>) {
    this.bind(value);
    if (value.workflowId !== this.expected.workflowId || value.userId !== this.expected.userId || value.target.eligibilityRevision !== this.expected.eligibilityRevision) throw unconfirmed();
  }
  async capabilities(signal?: AbortSignal): Promise<OffboardingDevicesCapabilities> {
    if (this.writing) throw unconfirmed(); this.invalidate();
    return this.run(async (requestSignal, check) => {
      const response = await api.get(this.base + '/capabilities', { params: { workflowId: this.expected.workflowId }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = offboardingCapSchema.parse(response.data); this.bound(value); this.access = freeze(value); return value;
    }, signal);
  }
  async preview(requestedPage = 1, signal?: AbortSignal): Promise<OffboardingDevicesPreview> {
    if (this.writing || !this.access) throw unconfirmed(); this.snapshot = null; this.historyReady = false;
    return this.run(async (requestSignal, check) => {
      const response = await api.get(this.base, { params: { workflowId: this.expected.workflowId, page: pageNumber.parse(requestedPage), limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = previewSchema.parse(response.data); this.bound(value); page(value.devices, value.total, value.page, requestedPage);
      if (['deviceId', 'assignmentId'].some(field => !unique(value.devices.map(device => device[field])))
        || !unique(value.devices.flatMap(device => device.openRequestId ? [device.openRequestId] : []))) throw unconfirmed();
      this.snapshot = freeze(value); return value;
    }, signal);
  }
  async history(requestedPage = 1, signal?: AbortSignal): Promise<OffboardingDevicesHistory> {
    if (this.writing || !this.access) throw unconfirmed(); this.historyReady = false;
    return this.run(async (requestSignal, check) => {
      const response = await api.get(this.base + '/history', { params: { workflowId: this.expected.workflowId, page: pageNumber.parse(requestedPage), limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = historySchema.parse(response.data); this.bound(value); page(value.requests, value.total, value.page, requestedPage);
      if (!unique(value.requests.map(row => row.id)) || value.requests.some(row => row.tenantId !== this.tenant || row.workflowId !== this.expected.workflowId || row.userId !== this.expected.userId || row.eligibilityRevision !== this.expected.eligibilityRevision)) throw unconfirmed();
      this.historyReady = true; return freeze(value);
    }, signal);
  }
  capture(snapshot: OffboardingDevicesPreview, deviceIds: string[], input: { reason: string; confirm: true }): OffboardingDevicesIntent {
    const confirmation = z.object({ reason: reasonSchema, confirm: z.literal(true) }).strict().parse(input);
    if (this.writing || !this.access || snapshot !== this.snapshot || !this.historyReady || !deviceIds.length || deviceIds.length > 25 || !unique(deviceIds)) throw unconfirmed();
    const devices = snapshot.devices.filter(device => deviceIds.includes(device.deviceId));
    if (devices.length !== deviceIds.length || devices.some(device => device.openRequestId !== null)) throw unconfirmed();
    const items = devices.map(device => ({ deviceId: device.deviceId, deviceRevision: device.deviceRevision, assignmentId: device.assignmentId, requestId: uuid.parse(crypto.randomUUID()) }));
    if (!unique(items.map(item => item.requestId))) throw unconfirmed();
    const value = freeze({ snapshot, reason: confirmation.reason, items });
    this.intents.set(value, { attempted: false, generation: this.generation }); return value;
  }
  canRecover(intent: OffboardingDevicesIntent) {
    return !!this.access && !!this.snapshot && this.historyReady && this.intents.get(intent)?.attempted === true;
  }
  async request(intent: OffboardingDevicesIntent, recovery = false, signal?: AbortSignal): Promise<OffboardingDevicesOutcome> {
    if (!this.access || !this.snapshot || !this.historyReady || recovery && !this.canRecover(intent) || !recovery && this.snapshot !== intent.snapshot) throw unconfirmed();
    this.intent(intent, recovery);
    return this.write(async (requestSignal, check) => {
      const authority = await api.get(this.base + '/capabilities', { params: { workflowId: this.expected.workflowId }, signal: requestSignal }); check();
      if (authority.status !== 200) throw unconfirmed(); this.bound(offboardingCapSchema.parse(authority.data));
      const response = await api.post(this.base, { workflowId: this.expected.workflowId, eligibilityRevision: this.expected.eligibilityRevision, reason: intent.reason, confirm: true, items: intent.items }, { signal: requestSignal }); check();
      if (response.status !== 200 && response.status !== 207) throw unconfirmed();
      const value = outcomeSchema.parse(response.data); this.bind(value);
      if (value.workflowId !== this.expected.workflowId || value.userId !== this.expected.userId || value.results.length !== intent.items.length
        || !unique(value.results.flatMap(result => result.operationId ? [result.operationId] : []))) throw unconfirmed();
      let stopped = false;
      value.results.forEach((result, index) => {
        const item = intent.items[index];
        if (result.deviceId !== item.deviceId || result.assignmentId !== item.assignmentId || result.requestId !== item.requestId) throw unconfirmed();
        if (stopped) { if (result.status !== 'not_attempted') throw unconfirmed(); }
        else if (result.status === 'unconfirmed') stopped = true;
        else if (result.status !== 'requested' && result.status !== 'already_requested') throw unconfirmed();
      });
      if ((response.status === 207) !== stopped) throw unconfirmed();
      return freeze(value);
    }, signal);
  }
}
const offboardingEnvelopeSchema = z.object(offboardingEnvelope).strict();
