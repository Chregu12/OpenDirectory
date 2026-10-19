import { z } from 'zod';
import { api } from './api';

const base = '/api/licenses/company';
const jobs = base + '/offboarding-workflows';
const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => BigInt(value) <= BigInt('9223372036854775807'));
const timestamp = z.string().datetime({ offset: true }).refine(value => Number.isFinite(Date.parse(value)));
const count = z.number().int().nonnegative().safe();
const text = z.string().refine(value => !/[\u0000-\u001f\u007f-\u009f]/.test(value));
const reason = text.transform(value => value.trim()).refine(value => Array.from(value).length >= 10 && Array.from(value).length <= 500);
const phase = z.enum(['pending', 'licenses', 'paused', 'completed_local']);
const failure = z.object({ code: z.number().int().min(400).max(599), step: z.enum(['account', 'capture', 'licenses', 'verify']) }).strict();
const contextFields = { schemaVersion: z.literal(1), actorUserId: uuid, tenantId: uuid };
const capabilities = z.object({ ...contextFields, companyOffboardingProtocol: z.literal(1), scope: z.literal('account-and-local-licenses'), requiresFreshMfa: z.literal(true) }).strict();
const previewSchema = z.object({ ...contextFields, user: z.object({ id: uuid, name: text.refine(value => !!value.trim()), userRevision: revision, eligibilityRevision: revision, enabled: z.boolean() }).strict(), licenseCount: count }).strict();
const receiptSchema = z.object({
  schemaVersion: z.literal(1), workflowId: uuid, tenantId: uuid, userId: uuid, actorUserId: uuid, operationId: uuid.nullable(),
  action: z.enum(['disabled', 'already_disabled']), beforeRevision: revision, afterRevision: revision,
  beforeEligibilityRevision: revision, afterEligibilityRevision: revision, createdAt: timestamp, deliveryStatus: z.literal('pending'),
}).strict().refine(value => value.action === 'disabled'
  ? value.operationId !== null && BigInt(value.afterRevision) > BigInt(value.beforeRevision) && BigInt(value.afterEligibilityRevision) > BigInt(value.beforeEligibilityRevision)
  : value.operationId === null && value.beforeRevision === value.afterRevision && value.beforeEligibilityRevision === value.afterEligibilityRevision);
const itemSchema = z.object({ poolId: uuid, assignmentId: uuid, grantId: uuid, poolRevision: revision, name: text.refine(value => !!value.trim()), vendor: text.refine(value => !!value.trim()) }).strict();
const summarySchema = z.object({
  id: uuid, userId: uuid, createdBy: uuid, revision, reason: text.refine(value => value === value.trim()).pipe(reason), phase,
  totalLicenses: count.nullable(), completedLicenses: count, failure: failure.nullable(), createdAt: timestamp, updatedAt: timestamp,
}).strict();
const workflowSchema = summarySchema.extend({ requestedRevision: revision, checkpoint: receiptSchema.nullable(), nextAssignments: z.array(itemSchema).max(25), reviewAssignments: z.array(itemSchema).max(25) }).strict();
const jobSchema = z.object({ ...contextFields, workflow: workflowSchema, currentTarget: z.object({ enabled: z.boolean(), deleted: z.boolean(), eligibilityRevision: revision }).strict() }).strict();
const eventSchema = z.object({ id: uuid, revision, phase, actorUserId: uuid, createdAt: timestamp, deliveryStatus: z.literal('pending'), failure: failure.nullable(), completedLicenses: count, totalLicenses: count.nullable() }).strict();
const confirmation = z.object({ reason, confirm: z.literal(true) }).strict();

export type OffboardingContext = { actorUserId: string; tenantId: string };
export type OffboardingPreview = Required<z.infer<typeof previewSchema>> & { user: Required<z.infer<typeof previewSchema>['user']> };
export type OffboardingSummary = Required<z.infer<typeof summarySchema>>;
export type OffboardingItem = Required<z.infer<typeof itemSchema>>;
export type OffboardingJob = Required<z.infer<typeof jobSchema>> & { workflow: OffboardingSummary & { requestedRevision: string; checkpoint: Required<z.infer<typeof receiptSchema>> | null; nextAssignments: OffboardingItem[]; reviewAssignments: OffboardingItem[] }; currentTarget: { enabled: boolean; deleted: boolean; eligibilityRevision: string } };
export type OffboardingEvent = Required<z.infer<typeof eventSchema>>;
export interface OffboardingPage { workflows: OffboardingSummary[]; total: number; page: number; limit: number }
export interface OffboardingHistory { events: OffboardingEvent[]; total: number; page: number; limit: number }

const unconfirmed = () => new Error('Ergebnis nicht bestätigt. Arbeitsstand ausdrücklich neu laden; keine automatische Wiederholung.');
export const offboardingReason = (value: string) => reason.parse(value);
export const offboardingUserId = (value: string) => uuid.parse(value);
export const offboardingEtag = (workflow: Pick<OffboardingSummary, 'id' | 'revision'>) => `"company-offboarding-${uuid.parse(workflow.id)}-${revision.parse(workflow.revision)}"`;
export const needsOffboardingPreview = (job: OffboardingJob) => !job.workflow.checkpoint && job.workflow.failure?.code === 412 && job.workflow.failure.step === 'account';
export const offboardingTargetChanged = (job: OffboardingJob) => job.currentTarget.deleted || (job.workflow.checkpoint
  ? job.currentTarget.enabled || job.currentTarget.eligibilityRevision !== job.workflow.checkpoint.afterEligibilityRevision
  : job.workflow.failure?.code === 409 && ['account', 'verify'].includes(job.workflow.failure.step));
export function offboardingError(error: unknown) {
  const status = (error as { response?: { status?: number } })?.response?.status;
  if (status === 401) return 'Sitzung ungültig. Erneut anmelden und Arbeitsstand neu laden.';
  if (status === 403) return 'Berechtigung fehlt oder eigenes Konto ausgewählt. Arbeitsstand neu laden.';
  if (status === 404) return 'Mitarbeiter oder Vorgang in dieser Firma nicht verfügbar. Arbeitsstand neu laden.';
  if (status === 409) return 'Ziel oder Vorgang im Konflikt. Bei geänderter Kontogeneration ist ein neuer Vorgang erforderlich. Arbeitsstand neu laden.';
  if (status === 412) return 'Datensatz oder Lizenzbestand geändert. Arbeitsstand ausdrücklich neu laden und erneut prüfen.';
  if (status === 428) return 'Frische MFA-Anmeldung erforderlich. Erneut anmelden und Arbeitsstand neu laden.';
  if (status === 400) return 'Eingaben abgelehnt. Arbeitsstand neu laden und Angaben prüfen.';
  if (status === 503) return 'Dienst nicht verfügbar; Teilschritte können bereits wirksam sein. Arbeitsstand neu laden.';
  return unconfirmed().message;
}
function freeze<Value>(value: Value): Value {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function validCounts(value: { phase?: string; totalLicenses?: number | null; completedLicenses?: number; failure?: unknown }) {
  return (value.totalLicenses === null ? value.completedLicenses === 0 : value.completedLicenses <= value.totalLicenses)
    && (value.phase !== 'completed_local' || value.totalLicenses !== null && value.completedLicenses === value.totalLicenses && value.failure === null)
    && (value.phase !== 'licenses' || value.failure === null)
    && (value.phase !== 'pending' || value.totalLicenses === null && value.failure === null)
    && (value.phase !== 'paused' || value.failure !== null);
}
function validateSummary(value: OffboardingSummary) {
  if (!validCounts(value) || value.createdBy === value.userId || Date.parse(value.updatedAt) < Date.parse(value.createdAt)) throw unconfirmed();
}
function pageNumber(value: number) { return z.number().int().min(1).max(1000000).parse(value); }
function validateRows(rows: { id?: string }[], total: number, page: number) {
  if (rows.length !== Math.min(25, Math.max(0, total - (page - 1) * 25)) || new Set(rows.map(row => row.id)).size !== rows.length) throw unconfirmed();
}

export class CompanyOffboardingClient {
  private context: OffboardingContext | null = null;
  private generation = 0;
  private disposed = false;
  private writing = false;
  private controllers = new Set<AbortController>();
  private snapshots = new Map<string, OffboardingJob>();
  private knownJobs = new Map<string, OffboardingJob>();
  private previews = new Map<string, OffboardingPreview>();
  private known = new Map<string, OffboardingSummary>();
  private recoveryId: string | null = null;
  private recoveryKey: string;
  private expected: OffboardingContext;
  private onSessionError = () => this.invalidate();

  constructor(expected: OffboardingContext) {
    this.expected = freeze({ actorUserId: uuid.parse(expected.actorUserId), tenantId: uuid.parse(expected.tenantId) });
    this.recoveryKey = `od:company-offboarding:${this.expected.tenantId}:${this.expected.actorUserId}`;
    if (typeof window !== 'undefined') {
      try { const saved = window.localStorage.getItem(this.recoveryKey); if (saved && uuid.safeParse(saved).success) this.recoveryId = saved; } catch {}
      window.addEventListener('od:session-error', this.onSessionError);
    }
  }
  get knownIdRecovery() { return this.recoveryId; }
  invalidate() {
    this.generation += 1; this.context = null; this.snapshots.clear(); this.previews.clear();
    this.controllers.forEach(controller => controller.abort()); this.controllers.clear();
  }
  dispose() { this.disposed = true; this.invalidate(); if (typeof window !== 'undefined') window.removeEventListener('od:session-error', this.onSessionError); }
  private async run<Result>(operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal): Promise<Result> {
    const generation = this.generation; const controller = new AbortController();
    const abort = () => controller.abort();
    const check = () => { if (this.disposed || generation !== this.generation || controller.signal.aborted) throw unconfirmed(); };
    if (signal?.aborted) abort(); signal?.addEventListener('abort', abort); this.controllers.add(controller);
    try { check(); const result = await operation(controller.signal, check); check(); return result; }
    catch (error) { if (generation === this.generation) this.invalidate(); throw error; }
    finally { signal?.removeEventListener('abort', abort); this.controllers.delete(controller); }
  }
  private require() { if (!this.context) throw unconfirmed(); return this.context; }
  private bind(value: OffboardingContext) {
    if (value.actorUserId !== this.expected.actorUserId || value.tenantId !== this.expected.tenantId) throw unconfirmed();
  }
  private async fresh(signal: AbortSignal, check: () => void) {
    const response = await api.get(jobs + '/capabilities', { signal }); check();
    if (response.status !== 200) throw unconfirmed();
    const value = capabilities.parse(response.data) as OffboardingContext; this.bind(value); this.context = value;
    return value;
  }
  async reload(signal?: AbortSignal) { this.invalidate(); return this.run((requestSignal, check) => this.fresh(requestSignal, check), signal); }
  private clearRecovery(id: string) {
    if (this.recoveryId !== id) return;
    try { window.localStorage.removeItem(this.recoveryKey); this.recoveryId = null; } catch {}
  }
  private retainRecovery(id: string) {
    if (this.recoveryId && this.recoveryId !== id) throw unconfirmed();
    window.localStorage.setItem(this.recoveryKey, id); this.recoveryId = id;
  }
  private remember(summary: OffboardingSummary) {
    validateSummary(summary);
    const prior = this.known.get(summary.id);
    if (prior && (prior.userId !== summary.userId || prior.createdBy !== summary.createdBy || prior.reason !== summary.reason || prior.createdAt !== summary.createdAt
      || BigInt(prior.revision) > BigInt(summary.revision) || prior.completedLicenses > summary.completedLicenses
      || prior.totalLicenses !== null && prior.totalLicenses !== summary.totalLicenses
      || Date.parse(prior.updatedAt) > Date.parse(summary.updatedAt)
      || prior.revision === summary.revision && Object.keys(summarySchema.shape).some(field => JSON.stringify(prior[field]) !== JSON.stringify(summary[field])))) throw unconfirmed();
    if (prior && prior.revision !== summary.revision) this.snapshots.delete(summary.id);
    this.known.set(summary.id, freeze(summary));
  }
  private parseJob(data: unknown, id: string, userId?: string): OffboardingJob {
    const value = jobSchema.parse(data) as OffboardingJob; this.bind(value);
    const workflow = value.workflow; const checkpoint = workflow.checkpoint;
    validateSummary(workflow);
    if (workflow.id !== id || workflow.userId === value.actorUserId || userId && workflow.userId !== userId || value.currentTarget.deleted && value.currentTarget.enabled) throw unconfirmed();
    if (checkpoint && (checkpoint.workflowId !== id || checkpoint.tenantId !== value.tenantId || checkpoint.userId !== workflow.userId || checkpoint.actorUserId === workflow.userId
      || checkpoint.beforeRevision !== workflow.requestedRevision || Date.parse(checkpoint.createdAt) < Date.parse(workflow.createdAt)
      || Date.parse(checkpoint.createdAt) > Date.parse(workflow.updatedAt))) throw unconfirmed();
    if (!checkpoint && (workflow.totalLicenses !== null || workflow.completedLicenses !== 0 || workflow.nextAssignments.length || workflow.reviewAssignments.length)
      || workflow.phase === 'pending' && checkpoint || ['licenses', 'completed_local'].includes(workflow.phase) && !checkpoint) throw unconfirmed();
    for (const rows of [workflow.nextAssignments, workflow.reviewAssignments]) {
      if (['poolId', 'assignmentId', 'grantId'].some(field => new Set(rows.map(row => row[field])).size !== rows.length)
        || workflow.totalLicenses !== null && rows.length > workflow.totalLicenses - workflow.completedLicenses) throw unconfirmed();
    }
    if (workflow.phase === 'licenses' && workflow.nextAssignments.length !== Math.min(25, workflow.totalLicenses - workflow.completedLicenses)
      || workflow.phase === 'completed_local' && (workflow.nextAssignments.length || workflow.reviewAssignments.length)
      || workflow.reviewAssignments.length && (workflow.phase !== 'paused' || workflow.failure?.step !== 'licenses' || !checkpoint || offboardingTargetChanged(value) || workflow.reviewAssignments.length !== workflow.nextAssignments.length
        || workflow.reviewAssignments.some((row, index) => {
          const captured = workflow.nextAssignments[index];
          return captured.poolId !== row.poolId || captured.assignmentId !== row.assignmentId || captured.grantId !== row.grantId || captured.name !== row.name || captured.vendor !== row.vendor || BigInt(row.poolRevision) < BigInt(captured.poolRevision);
        }))) throw unconfirmed();
    const prior = this.knownJobs.get(id)?.workflow;
    if (prior) {
      if (prior.checkpoint && JSON.stringify(prior.checkpoint) !== JSON.stringify(checkpoint)
        || prior.requestedRevision !== workflow.requestedRevision && (prior.checkpoint || prior.failure?.code !== 412 || prior.failure?.step !== 'account')
        || prior.revision === workflow.revision && (prior.requestedRevision !== workflow.requestedRevision || JSON.stringify(prior.checkpoint) !== JSON.stringify(checkpoint))) throw unconfirmed();
      const progress = workflow.completedLicenses - prior.completedLicenses;
      if (progress < 0 || prior.nextAssignments.slice(progress).some((captured, index) => JSON.stringify(captured) !== JSON.stringify(workflow.nextAssignments[index]))) throw unconfirmed();
    }
    this.remember(summarySchema.parse(Object.fromEntries(Object.keys(summarySchema.shape).map(field => [field, workflow[field]]))) as OffboardingSummary);
    this.knownJobs.set(id, value);
    return freeze(value);
  }
  async preview(userId: string, signal?: AbortSignal): Promise<OffboardingPreview> {
    uuid.parse(userId); this.previews.delete(userId);
    return this.run(async (requestSignal, check) => {
      this.require(); if (userId === this.expected.actorUserId) throw unconfirmed();
      const response = await api.get(base + '/users/' + userId + '/offboarding-preview', { signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = previewSchema.parse(response.data) as OffboardingPreview; this.bind(value);
      if (value.user.id !== userId) throw unconfirmed();
      await this.fresh(requestSignal, check); freeze(value); this.previews.set(userId, value); return value;
    }, signal);
  }
  async get(id: string, signal?: AbortSignal): Promise<OffboardingJob> {
    uuid.parse(id); this.snapshots.delete(id);
    return this.run(async (requestSignal, check) => {
      this.require(); const response = await api.get(jobs + '/' + id, { signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = this.parseJob(response.data, id);
      if (response.headers?.etag !== offboardingEtag(value.workflow)) throw unconfirmed();
      await this.fresh(requestSignal, check); this.snapshots.set(id, value); this.clearRecovery(id); return value;
    }, signal);
  }
  async list(page = 1, signal?: AbortSignal): Promise<OffboardingPage> {
    pageNumber(page);
    return this.run(async (requestSignal, check) => {
      this.require(); const response = await api.get(jobs, { params: { page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = z.object({ ...contextFields, workflows: z.array(summarySchema).max(25), total: count, page: z.literal(page), limit: z.literal(25) }).strict().parse(response.data);
      this.bind(value as OffboardingContext); validateRows(value.workflows, value.total, page);
      if (value.workflows.some(row => row.userId === this.expected.actorUserId)) throw unconfirmed();
      value.workflows.forEach(row => this.remember(row as OffboardingSummary));
      await this.fresh(requestSignal, check); return freeze(value) as OffboardingPage;
    }, signal);
  }
  async history(id: string, page = 1, signal?: AbortSignal): Promise<OffboardingHistory> {
    uuid.parse(id); pageNumber(page);
    return this.run(async (requestSignal, check) => {
      this.require(); const workflow = this.known.get(id); if (!workflow) throw unconfirmed();
      const response = await api.get(jobs + '/' + id + '/history', { params: { page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = z.object({ ...contextFields, workflowId: z.literal(id), events: z.array(eventSchema).max(25), total: count, page: z.literal(page), limit: z.literal(25) }).strict().parse(response.data);
      this.bind(value as OffboardingContext); validateRows(value.events, value.total, page);
      if (new Set(value.events.map(event => event.revision)).size !== value.events.length || value.events.some(event => !validCounts(event)
        || BigInt(event.revision) > BigInt(workflow.revision) || event.completedLicenses > workflow.completedLicenses
        || event.totalLicenses !== null && event.totalLicenses !== workflow.totalLicenses
        || Date.parse(event.createdAt) < Date.parse(workflow.createdAt) || Date.parse(event.createdAt) > Date.parse(workflow.updatedAt))) throw unconfirmed();
      await this.fresh(requestSignal, check); return freeze(value) as OffboardingHistory;
    }, signal);
  }
  private async write<Result>(operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal) {
    if (this.writing) throw unconfirmed(); this.writing = true;
    try { return await this.run(operation, signal); } finally { this.writing = false; }
  }
  async create(preview: OffboardingPreview, input: { reason: string; confirm: true }, signal?: AbortSignal): Promise<OffboardingJob> {
    const values = confirmation.parse(input);
    return this.write(async (requestSignal, check) => {
      this.require(); if (this.recoveryId || this.previews.get(preview?.user.id) !== preview) throw unconfirmed();
      await this.fresh(requestSignal, check);
      if (this.previews.get(preview.user.id) !== preview) throw unconfirmed();
      const id = uuid.parse(window.crypto.randomUUID()); this.retainRecovery(id);
      this.previews.delete(preview.user.id); this.snapshots.clear();
      const response = await api.post(jobs, { workflowId: id, userId: preview.user.id, userRevision: preview.user.userRevision, eligibilityRevision: preview.user.eligibilityRevision, ...values }, { signal: requestSignal }); check();
      if (![200, 201].includes(response.status)) throw unconfirmed();
      const value = this.parseJob(response.data, id, preview.user.id);
      if (value.workflow.createdBy !== this.expected.actorUserId || value.workflow.reason !== values.reason || value.workflow.requestedRevision !== preview.user.userRevision
        || value.workflow.checkpoint && value.workflow.checkpoint.beforeEligibilityRevision !== preview.user.eligibilityRevision) throw unconfirmed();
      await this.fresh(requestSignal, check); this.clearRecovery(id); return value;
    }, signal);
  }
  async continue(job: OffboardingJob, input: { reason: string; confirm: true }, preview?: OffboardingPreview, signal?: AbortSignal): Promise<OffboardingJob> {
    const values = confirmation.parse(input);
    return this.write(async (requestSignal, check) => {
      this.require(); const workflow = job.workflow;
      if (values.reason !== workflow.reason || this.snapshots.get(workflow.id) !== job || workflow.phase === 'completed_local' || offboardingTargetChanged(job) || workflow.failure?.code === 409 && workflow.failure.step === 'verify') throw unconfirmed();
      const needsPreview = needsOffboardingPreview(job);
      if (needsPreview ? !preview || this.previews.get(workflow.userId) !== preview || preview.user.id !== workflow.userId
        || preview.user.eligibilityRevision !== job.currentTarget.eligibilityRevision || preview.user.enabled !== job.currentTarget.enabled : !!preview) throw unconfirmed();
      const rows = workflow.phase === 'paused' ? workflow.reviewAssignments : workflow.nextAssignments;
      if (workflow.phase === 'paused' && workflow.nextAssignments.length && !rows.length) throw unconfirmed();
      await this.fresh(requestSignal, check);
      if (this.snapshots.get(workflow.id) !== job || needsPreview && this.previews.get(workflow.userId) !== preview) throw unconfirmed();
      this.retainRecovery(workflow.id);
      this.snapshots.delete(workflow.id); this.previews.delete(workflow.userId);
      const response = await api.post(jobs + '/' + workflow.id + '/continue', { ...values, userRevision: needsPreview ? preview.user.userRevision : workflow.requestedRevision,
        assignments: rows.map(row => ({ poolId: row.poolId, assignmentId: row.assignmentId, poolRevision: row.poolRevision })) }, { headers: { 'If-Match': offboardingEtag(workflow) }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = this.parseJob(response.data, workflow.id, workflow.userId);
      if (BigInt(value.workflow.revision) <= BigInt(workflow.revision) || value.workflow.requestedRevision !== (needsPreview ? preview.user.userRevision : workflow.requestedRevision)
        || workflow.checkpoint && JSON.stringify(workflow.checkpoint) !== JSON.stringify(value.workflow.checkpoint)) throw unconfirmed();
      await this.fresh(requestSignal, check); this.clearRecovery(workflow.id); return value;
    }, signal);
  }
}
