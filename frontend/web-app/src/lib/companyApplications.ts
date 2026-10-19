import { z } from 'zod';
import { api } from './api';
import { directoryUsers, UserPage } from './directoryUsers';

const base = '/api/licenses/company';
const permissions = ['company.apps.read', 'company.apps.create', 'company.apps.assign'] as const;
const uuid = z.string().length(36).regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => !/\s/.test(value) && BigInt(value) <= BigInt('9223372036854775807'));
const timestamp = z.string().datetime({ offset: true }).refine(value => Number.isFinite(Date.parse(value)));
const text = (minimum: number, maximum: number) => z.string().refine(value => !/[\u0000-\u001f\u007f-\u009f]/.test(value))
  .transform(value => value.trim()).refine(value => Array.from(value).length >= minimum && Array.from(value).length <= maximum);
const reasonSchema = text(10, 500);
const fieldsSchema = z.object({ name: text(1, 160), vendor: text(1, 160), description: text(0, 2000), totalSeats: z.number().int().min(1).max(10000) }).strict();
const inputSchema = fieldsSchema.extend({ reason: reasonSchema }).strict();
const editInputSchema = inputSchema.extend({ confirm: z.literal(true) }).strict();
const poolSchema = fieldsSchema.extend({
  name: z.string().refine(value => value === value.trim()).pipe(text(1, 160)),
  vendor: z.string().refine(value => value === value.trim()).pipe(text(1, 160)),
  description: z.string().refine(value => value === value.trim()).pipe(text(0, 2000)),
  id: uuid, tenantId: uuid, revision, usedSeats: z.number().int().nonnegative(), availableSeats: z.number().int().nonnegative(),
  licenseType: z.literal('per_user'), allocationMode: z.literal('local-only'), createdAt: timestamp, updatedAt: timestamp,
}).strict().refine(value => value.usedSeats + value.availableSeats === value.totalSeats && Date.parse(value.updatedAt) >= Date.parse(value.createdAt));
const capabilitiesSchema = z.object({
  schemaVersion: z.literal(1), companyLicenseProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid,
  permissions: z.array(z.enum(permissions)).refine(values => new Set(values).size === values.length),
  allocationMode: z.literal('local-only'), supportedTargets: z.tuple([z.literal('user')]),
}).strict();
const editCapabilitiesSchema = z.object({
  schemaVersion: z.literal(1), companyPoolEditProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid, poolId: uuid, poolRevision: revision,
}).strict();
const assignmentSchema = z.object({ id: uuid, userId: uuid, assignedAt: timestamp, assignedBy: uuid, grantId: uuid }).strict();
const changeSchema = z.object({ userId: uuid, reason: reasonSchema, confirm: z.literal(true) }).strict();
const returnAssignmentSchema = z.object({
  id: uuid, poolId: uuid, poolRevision: revision,
  name: z.string().refine(value => value === value.trim()).pipe(text(1, 160)),
  vendor: z.string().refine(value => value === value.trim()).pipe(text(1, 160)),
  grantId: uuid, assignedAt: timestamp,
}).strict();
const returnTargetSchema = z.object({ enabled: z.boolean(), deleted: z.boolean(), eligibilityRevision: revision }).strict().refine(value => !value.deleted || !value.enabled);
const returnResultSchema = z.discriminatedUnion('status', [
  z.object({ poolId: uuid, assignmentId: uuid, status: z.literal('released'), code: z.literal(200) }).strict(),
  z.object({ poolId: uuid, assignmentId: uuid, status: z.literal('unconfirmed'), code: z.number().int().min(400).max(599) }).strict(),
  z.object({ poolId: uuid, assignmentId: uuid, status: z.literal('not_attempted'), code: z.null() }).strict(),
]);
const returnInputSchema = z.object({ reason: reasonSchema, confirm: z.literal(true) }).strict();
const eventSchema = z.object({
  id: uuid, type: z.enum(['app.license.pool.created', 'app.license.pool.updated', 'app.license.assigned', 'app.license.released']), version: z.literal(1),
  actorUserId: uuid, userId: uuid.nullable(), correlationId: uuid, createdAt: timestamp,
  beforeRevision: revision.nullable(), afterRevision: revision, deliveryStatus: z.literal('pending'),
}).strict().refine(value => value.type === 'app.license.pool.created'
  ? value.beforeRevision === null && value.afterRevision === '1' && value.userId === null
  : value.beforeRevision !== null && (value.type === 'app.license.pool.updated' ? value.userId === null : value.userId !== null)
    && BigInt(value.afterRevision) === BigInt(value.beforeRevision) + BigInt(1));

export type CompanyPool = Required<z.infer<typeof poolSchema>>;
export type CompanyPoolInput = Required<z.input<typeof inputSchema>>;
export type CompanyApplicationsCapabilities = Required<z.infer<typeof capabilitiesSchema>>;
export type CompanyAssignment = Required<z.infer<typeof assignmentSchema>>;
export type CompanyLicenseEvent = Required<z.infer<typeof eventSchema>>;
type CompanyAssignmentInput = Required<z.infer<typeof changeSchema>>;
export interface CompanyPoolPage { pools: CompanyPool[]; total: number; page: number; limit: number }
export interface CompanyAssignmentPage { assignments: CompanyAssignment[]; total: number; page: number; limit: number }
export interface CompanyHistoryPage { events: CompanyLicenseEvent[]; total: number; page: number; limit: number }
export type CompanyLicenseReturnAssignment = Required<z.infer<typeof returnAssignmentSchema>>;
export interface CompanyLicenseReturnPreview {
  schemaVersion: 1; actorUserId: string; tenantId: string; userId: string;
  target: Required<z.infer<typeof returnTargetSchema>>;
  assignments: CompanyLicenseReturnAssignment[]; total: number; page: number; limit: 25;
}
export interface CompanyLicenseReturnReceipt {
  schemaVersion: 1; actorUserId: string; tenantId: string; userId: string; correlationId: string;
  results: Required<z.infer<typeof returnResultSchema>>[];
}

function valueFields(value: { name: string; vendor: string; description: string; totalSeats: number }) {
  return { name: value.name, vendor: value.vendor, description: value.description, totalSeats: value.totalSeats };
}
const unconfirmed = () => new Error('Lizenzantwort nicht bestätigt. Bitte neu laden; die Aktion wird nicht automatisch wiederholt.');
export function normalizeCompanyPoolInput(input: CompanyPoolInput) { return inputSchema.parse(input) as CompanyPoolInput; }
export function normalizeCompanyLicenseReason(reason: string) { return reasonSchema.parse(reason); }
export function companyPoolEtag(pool: Pick<CompanyPool, 'id' | 'revision'>) { return `"company-pool-${uuid.parse(pool.id)}-${revision.parse(pool.revision)}"`; }
export function companyApplicationsError(error: unknown) {
  const status = (error as { response?: { status?: number } })?.response?.status;
  if (status === 401) return 'Die Sitzung ist nicht mehr gültig. Bitte erneut anmelden und neu laden.';
  if (status === 403) return 'Keine Berechtigung für diese Lizenzaktion oder dieses Benutzerziel. Bitte neu laden.';
  if (status === 409) return 'Lizenzbestand oder Zuweisung steht im Konflikt. Bitte neu laden; die Aktion wird nicht automatisch wiederholt.';
  if (status === 412) return 'Der Lizenzpool wurde zwischenzeitlich geändert. Bitte neu laden; die Aktion wird nicht automatisch wiederholt.';
  if (status === 428) return 'Eine aktuelle zusätzliche Anmeldung ist erforderlich. Bitte erneut anmelden und neu laden.';
  if (status === 503) return 'Der Lizenzdienst ist nicht verfügbar. Ergebnis nicht bestätigt; bitte neu laden. Nicht automatisch wiederholen.';
  if (status === 400) return 'Die Eingaben wurden abgelehnt. Bitte prüfen und neu laden.';
  if (status === 404) return 'Der Lizenzpool oder die Zuweisung ist nicht verfügbar. Bitte neu laden.';
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
function envelope(context: CompanyApplicationsCapabilities, page: number) {
  return z.object({ schemaVersion: z.literal(1), actorUserId: z.literal(context.actorUserId), tenantId: z.literal(context.tenantId),
    total: z.number().int().nonnegative().safe(), page: z.literal(pageNumber(page)), limit: z.literal(25) }).strict();
}
function validateRows(rows: { id: string }[], total: number, page: number) {
  if (rows.length !== Math.min(25, Math.max(0, total - (page - 1) * 25)) || new Set(rows.map(row => row.id)).size !== rows.length) throw unconfirmed();
}

export class CompanyApplicationsClient {
  private context: CompanyApplicationsCapabilities | null = null;
  private generation = 0;
  private controllers = new Set<AbortController>();
  private pools = new Map<string, CompanyPool>();
  private snapshots = new WeakMap<CompanyPool, number>();
  private editablePool: CompanyPool | null = null;
  private editCapabilityVersion = 0;
  private assignments = new WeakMap<CompanyAssignment, { poolId: string; generation: number }>();
  private returnPreview: CompanyLicenseReturnPreview | null = null;
  private returnPreviewVersion = 0;
  private writing = false;
  private disposed = false;
  private onSessionError = () => this.invalidate();

  constructor() { if (typeof window !== 'undefined') window.addEventListener('od:session-error', this.onSessionError); }
  invalidate() {
    this.generation += 1; this.context = null; this.pools.clear(); this.returnPreview = null; this.editablePool = null; this.editCapabilityVersion += 1;
    this.controllers.forEach(controller => controller.abort()); this.controllers.clear();
  }
  dispose() {
    this.disposed = true; this.invalidate();
    if (typeof window !== 'undefined') window.removeEventListener('od:session-error', this.onSessionError);
  }
  private async run<Result>(operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal, invalidateOnAbort = false): Promise<Result> {
    const generation = this.generation;
    const controller = new AbortController();
    const abort = () => { controller.abort(); if (invalidateOnAbort && generation === this.generation) this.invalidate(); };
    const check = () => { if (this.disposed || generation !== this.generation || controller.signal.aborted) throw unconfirmed(); };
    if (signal?.aborted) abort();
    signal?.addEventListener('abort', abort); this.controllers.add(controller);
    try { check(); const result = await operation(controller.signal, check); check(); return result; }
    catch (error) { if (generation === this.generation && (invalidateOnAbort || !controller.signal.aborted)) this.invalidate(); throw error; }
    finally { signal?.removeEventListener('abort', abort); this.controllers.delete(controller); }
  }
  private require(permission: typeof permissions[number]) {
    if (!this.context?.permissions.includes(permission)) throw unconfirmed();
    return this.context;
  }
  private async fresh(context: CompanyApplicationsCapabilities, permission: typeof permissions[number], signal: AbortSignal, check: () => void) {
    const response = await api.get(base + '/capabilities', { signal }); check();
    const current = capabilitiesSchema.parse(response.data) as CompanyApplicationsCapabilities;
    if (response.status !== 200 || current.actorUserId !== context.actorUserId || current.tenantId !== context.tenantId || !current.permissions.includes(permission)) throw unconfirmed();
    this.context = current;
  }
  private remember(pool: CompanyPool, context: CompanyApplicationsCapabilities) {
    const known = this.pools.get(pool.id);
    if (pool.tenantId !== context.tenantId || known && (BigInt(known.revision) > BigInt(pool.revision)
      || known.revision === pool.revision && Object.keys(known).some(field => known[field] !== pool[field]))) throw unconfirmed();
    Object.freeze(pool); this.pools.set(pool.id, pool); this.snapshots.set(pool, this.generation); return pool;
  }
  async reload(signal?: AbortSignal): Promise<CompanyApplicationsCapabilities> {
    this.invalidate();
    return this.run(async (requestSignal, check) => {
      const response = await api.get(base + '/capabilities', { signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      this.context = capabilitiesSchema.parse(response.data) as CompanyApplicationsCapabilities;
      return { ...this.context, permissions: [...this.context.permissions], supportedTargets: [...this.context.supportedTargets] };
    }, signal);
  }
  async list(page = 1, search = '', signal?: AbortSignal): Promise<CompanyPoolPage> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('company.apps.read'); const normalized = query(search);
      const response = await api.get(base + '/pools', { params: { page: pageNumber(page), limit: 25, ...(normalized ? { search: normalized } : {}) }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const result = envelope(context, page).extend({ pools: z.array(poolSchema) }).strict().parse(response.data) as CompanyPoolPage;
      validateRows(result.pools, result.total, page);
      await this.fresh(context, 'company.apps.read', requestSignal, check);
      result.pools.forEach(pool => this.remember(pool, context)); return result;
    }, signal);
  }
  async get(poolId: string, signal?: AbortSignal): Promise<CompanyPool> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('company.apps.read');
      const response = await api.get(base + '/pools/' + uuid.parse(poolId), { signal: requestSignal }); check();
      const pool = poolSchema.parse(response.data) as CompanyPool;
      if (response.status !== 200 || pool.id !== poolId || response.headers?.etag !== companyPoolEtag(pool)) throw unconfirmed();
      await this.fresh(context, 'company.apps.read', requestSignal, check);
      return this.remember(pool, context);
    }, signal);
  }
  private requireEditSnapshot(snapshot: CompanyPool) {
    const context = this.require('company.apps.create'); this.require('company.apps.read');
    if (!snapshot || this.snapshots.get(snapshot) !== this.generation || this.pools.get(snapshot.id)?.revision !== snapshot.revision
      || snapshot.tenantId !== context.tenantId || snapshot.revision === '9223372036854775807') throw unconfirmed();
    return context;
  }
  private async checkEditCapabilities(snapshot: CompanyPool, context: CompanyApplicationsCapabilities, signal: AbortSignal, check: () => void) {
    const response = await api.get(base + '/pools/' + snapshot.id + '/edit-capabilities', { signal }); check();
    const result = editCapabilitiesSchema.parse(response.data);
    this.requireEditSnapshot(snapshot);
    if (response.status !== 200 || response.headers?.['cache-control'] !== 'no-store' || result.actorUserId !== context.actorUserId
      || result.tenantId !== context.tenantId || result.poolId !== snapshot.id || result.poolRevision !== snapshot.revision) throw unconfirmed();
    return result;
  }
  async editCapabilities(snapshot: CompanyPool, signal?: AbortSignal) {
    const version = ++this.editCapabilityVersion; this.editablePool = null;
    return this.run(async (requestSignal, check) => {
      const context = this.requireEditSnapshot(snapshot);
      if (this.writing) throw unconfirmed();
      await this.fresh(context, 'company.apps.create', requestSignal, check);
      this.requireEditSnapshot(snapshot);
      const result = await this.checkEditCapabilities(snapshot, context, requestSignal, check);
      await this.fresh(context, 'company.apps.create', requestSignal, check);
      this.requireEditSnapshot(snapshot);
      if (version !== this.editCapabilityVersion || this.writing) throw unconfirmed();
      this.editablePool = snapshot; return result;
    }, signal, true);
  }
  async listAssignments(poolId: string, page = 1, signal?: AbortSignal): Promise<CompanyAssignmentPage> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('company.apps.read'); uuid.parse(poolId);
      const response = await api.get(base + '/pools/' + poolId + '/assignments', { params: { page: pageNumber(page), limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const result = envelope(context, page).extend({ poolId: z.literal(poolId), assignments: z.array(assignmentSchema) }).strict().parse(response.data) as CompanyAssignmentPage;
      validateRows(result.assignments, result.total, page);
      if (new Set(result.assignments.map(row => row.userId)).size !== result.assignments.length || new Set(result.assignments.map(row => row.grantId)).size !== result.assignments.length) throw unconfirmed();
      await this.fresh(context, 'company.apps.read', requestSignal, check);
      result.assignments.forEach(assignment => { Object.freeze(assignment); this.assignments.set(assignment, { poolId, generation: this.generation }); }); return result;
    }, signal);
  }
  async history(poolId: string, page = 1, signal?: AbortSignal): Promise<CompanyHistoryPage> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('company.apps.read'); uuid.parse(poolId);
      const response = await api.get(base + '/pools/' + poolId + '/history', { params: { page: pageNumber(page), limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const result = envelope(context, page).extend({ poolId: z.literal(poolId), events: z.array(eventSchema) }).strict().parse(response.data) as CompanyHistoryPage;
      validateRows(result.events, result.total, page);
      if (new Set(result.events.map(event => event.afterRevision)).size !== result.events.length) throw unconfirmed();
      await this.fresh(context, 'company.apps.read', requestSignal, check); return result;
    }, signal);
  }
  async users(page = 1, search = '', signal?: AbortSignal): Promise<UserPage | null> {
    return this.run(async (requestSignal, check) => {
      const context = this.require('company.apps.assign'); pageNumber(page); const normalized = query(search);
      const access = await directoryUsers.access(); check();
      if (access.userId !== context.actorUserId || access.demoMode) throw unconfirmed();
      if (!access.permissions.includes('users.read')) { await this.fresh(context, 'company.apps.assign', requestSignal, check); return null; }
      if (access.directoryReadProtocol !== 1) throw unconfirmed();
      const result = await directoryUsers.list(page, normalized, 'true', requestSignal); check();
      validateRows(result.users, result.total, page);
      if (result.users.some(user => !user.enabled)) throw unconfirmed();
      const current = await directoryUsers.access(); check();
      if (current.userId !== context.actorUserId || current.demoMode || current.directoryReadProtocol !== 1 || !current.permissions.includes('users.read')) throw unconfirmed();
      await this.fresh(context, 'company.apps.assign', requestSignal, check); return result;
    }, signal);
  }
  async previewLicenseReturns(userId: string, page = 1, signal?: AbortSignal): Promise<CompanyLicenseReturnPreview> {
    const version = ++this.returnPreviewVersion; this.returnPreview = null;
    return this.run(async (requestSignal, check) => {
      const context = this.require('company.apps.assign'); uuid.parse(userId); pageNumber(page);
      if (this.writing) throw unconfirmed();
      await this.fresh(context, 'company.apps.assign', requestSignal, check);
      const response = await api.get(base + '/users/' + userId + '/license-returns', { params: { page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const result = envelope(context, page).extend({ userId: z.literal(userId), target: returnTargetSchema, assignments: z.array(returnAssignmentSchema).max(25) }).strict().parse(response.data) as CompanyLicenseReturnPreview;
      validateRows(result.assignments, result.total, page);
      if (new Set(result.assignments.map(row => row.poolId)).size !== result.assignments.length
        || new Set(result.assignments.map(row => row.grantId)).size !== result.assignments.length) throw unconfirmed();
      await this.fresh(context, 'company.apps.assign', requestSignal, check);
      if (version !== this.returnPreviewVersion || this.writing) throw unconfirmed();
      result.assignments.forEach(row => Object.freeze(row)); Object.freeze(result.assignments); Object.freeze(result.target); Object.freeze(result);
      this.returnPreview = result; return result;
    }, signal, true);
  }
  async returnLicenses(snapshot: CompanyLicenseReturnPreview, input: { reason: string; confirm: true }, signal?: AbortSignal): Promise<CompanyLicenseReturnReceipt> {
    const values = returnInputSchema.parse(input);
    const receipt = await this.write(async (requestSignal, check) => {
      const context = this.require('company.apps.assign');
      if (!snapshot || this.returnPreview !== snapshot || snapshot.actorUserId !== context.actorUserId || snapshot.tenantId !== context.tenantId
        || snapshot.target.enabled || !snapshot.assignments.length || snapshot.assignments.length > 25
        || snapshot.assignments.some(row => { const known = this.pools.get(row.poolId); return known && BigInt(known.revision) > BigInt(row.poolRevision); })) throw unconfirmed();
      await this.fresh(context, 'company.apps.assign', requestSignal, check); check();
      if (this.returnPreview !== snapshot) throw unconfirmed();
      this.returnPreview = null;
      const assignments = snapshot.assignments.map(row => ({ poolId: row.poolId, assignmentId: row.id, poolRevision: row.poolRevision }));
      const response = await api.post(base + '/users/' + snapshot.userId + '/license-returns', { ...values, assignments }, { signal: requestSignal }); check();
      const result = z.object({ schemaVersion: z.literal(1), actorUserId: z.literal(context.actorUserId), tenantId: z.literal(context.tenantId),
        userId: z.literal(snapshot.userId), correlationId: uuid, results: z.array(returnResultSchema).length(assignments.length) }).strict().parse(response.data) as CompanyLicenseReturnReceipt;
      let stopped = false;
      result.results.forEach((row, index) => {
        if (row.poolId !== assignments[index].poolId || row.assignmentId !== assignments[index].assignmentId
          || (stopped ? row.status !== 'not_attempted' : row.status === 'not_attempted')) throw unconfirmed();
        if (row.status === 'unconfirmed') stopped = true;
      });
      if (response.status !== (stopped ? 207 : 200)) throw unconfirmed();
      await this.fresh(context, 'company.apps.assign', requestSignal, check); return result;
    }, signal);
    this.invalidate(); return receipt;
  }
  private async write<Result>(operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal) {
    if (this.writing) throw unconfirmed();
    this.writing = true; this.editCapabilityVersion += 1;
    try { return await this.run(operation, signal, true); } finally { this.writing = false; this.returnPreview = null; this.editablePool = null; }
  }
  async create(input: CompanyPoolInput, signal?: AbortSignal): Promise<CompanyPool> {
    const values = normalizeCompanyPoolInput(input);
    return this.write(async (requestSignal, check) => {
      const context = this.require('company.apps.create');
      await this.fresh(context, 'company.apps.create', requestSignal, check); check();
      const response = await api.post(base + '/pools', values, { signal: requestSignal }); check();
      const pool = poolSchema.parse(response.data) as CompanyPool;
      if (response.status !== 201 || pool.revision !== '1' || pool.usedSeats !== 0 || pool.createdAt !== pool.updatedAt
        || Object.keys(valueFields(values)).some(field => pool[field] !== values[field])) throw unconfirmed();
      await this.fresh(context, 'company.apps.create', requestSignal, check); return this.remember(pool, context);
    }, signal);
  }
  async edit(snapshot: CompanyPool, input: CompanyPoolInput & { confirm: true }, signal?: AbortSignal): Promise<CompanyPool> {
    const parsed = editInputSchema.parse(input);
    const values = { name: parsed.name, vendor: parsed.vendor, description: parsed.description, totalSeats: parsed.totalSeats, reason: parsed.reason, confirm: parsed.confirm };
    return this.write(async (requestSignal, check) => {
      const context = this.requireEditSnapshot(snapshot);
      if (this.editablePool !== snapshot || values.totalSeats < snapshot.usedSeats
        || Object.keys(valueFields(values)).every(field => values[field] === snapshot[field])) throw unconfirmed();
      await this.fresh(context, 'company.apps.create', requestSignal, check);
      this.requireEditSnapshot(snapshot);
      await this.checkEditCapabilities(snapshot, context, requestSignal, check);
      this.requireEditSnapshot(snapshot);
      if (this.editablePool !== snapshot) throw unconfirmed();
      this.editablePool = null;
      const response = await api.patch(base + '/pools/' + snapshot.id, values,
        { headers: { 'If-Match': companyPoolEtag(snapshot) }, signal: requestSignal }); check();
      const pool = poolSchema.parse(response.data) as CompanyPool;
      if (response.status !== 200 || response.headers?.etag !== companyPoolEtag(pool)
        || Object.keys(valueFields(values)).some(field => pool[field] !== values[field])
        || Object.keys(snapshot).some(field => !['name', 'vendor', 'description', 'totalSeats', 'availableSeats', 'revision', 'updatedAt'].includes(field) && snapshot[field] !== pool[field])
        || BigInt(pool.revision) !== BigInt(snapshot.revision) + BigInt(1) || Date.parse(pool.updatedAt) < Date.parse(snapshot.updatedAt)) throw unconfirmed();
      await this.fresh(context, 'company.apps.create', requestSignal, check);
      this.requireEditSnapshot(snapshot);
      return this.remember(pool, context);
    }, signal);
  }
  async assign(snapshot: CompanyPool, input: { userId: string; reason: string; confirm: true }, signal?: AbortSignal): Promise<CompanyPool> {
    const change = changeSchema.parse(input) as CompanyAssignmentInput;
    return this.change(snapshot, change, null, signal);
  }
  async revoke(snapshot: CompanyPool, assignment: CompanyAssignment, input: { userId: string; reason: string; confirm: true }, signal?: AbortSignal): Promise<CompanyPool> {
    const change = changeSchema.parse(input) as CompanyAssignmentInput;
    const origin = this.assignments.get(assignment);
    if (!origin || origin.poolId !== snapshot.id || origin.generation !== this.generation || assignment.userId !== change.userId) throw unconfirmed();
    return this.change(snapshot, change, assignment, signal);
  }
  private async change(snapshot: CompanyPool, input: CompanyAssignmentInput, assignment: CompanyAssignment | null, signal?: AbortSignal) {
    return this.write(async (requestSignal, check) => {
      const context = this.require('company.apps.assign');
      const previous = poolSchema.parse(snapshot) as CompanyPool;
      if (this.snapshots.get(snapshot) !== this.generation || this.pools.get(previous.id)?.revision !== previous.revision || previous.tenantId !== context.tenantId || previous.revision === '9223372036854775807'
        || (assignment ? previous.usedSeats === 0 : previous.availableSeats === 0)) throw unconfirmed();
      await this.fresh(context, 'company.apps.assign', requestSignal, check); check();
      const response = await api.post(base + '/pools/' + previous.id + '/assignments' + (assignment ? '/' + assignment.id + '/revoke' : ''), input,
        { headers: { 'If-Match': companyPoolEtag(previous) }, signal: requestSignal }); check();
      const pool = poolSchema.parse(response.data) as CompanyPool;
      if (response.status !== (assignment ? 200 : 201) || Object.keys(previous).some(field => !['usedSeats', 'availableSeats', 'revision', 'updatedAt'].includes(field) && previous[field] !== pool[field])
        || BigInt(pool.revision) !== BigInt(previous.revision) + BigInt(1) || pool.usedSeats !== previous.usedSeats + (assignment ? -1 : 1)
        || Date.parse(pool.updatedAt) < Date.parse(previous.updatedAt)) throw unconfirmed();
      await this.fresh(context, 'company.apps.assign', requestSignal, check);
      if (assignment) this.assignments.delete(assignment);
      return this.remember(pool, context);
    }, signal);
  }
}
