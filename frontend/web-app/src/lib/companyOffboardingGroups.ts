import { z } from 'zod';
import { api } from './api';
import type { OffboardingContext } from './companyOffboarding';

const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => BigInt(value) <= BigInt('9223372036854775807'));
const text = z.string().refine(value => !/[\u0000-\u001f\u007f-\u009f]/.test(value));
const reason = text.transform(value => value.trim()).refine(value => Array.from(value).length >= 10 && Array.from(value).length <= 500);
const count = z.number().int().nonnegative().safe();
const pageNumber = z.number().int().positive().safe();
const targetSchema = z.object({ enabled: z.literal(false), eligibilityRevision: revision }).strict();
const bindingFields = { schemaVersion: z.literal(1), actorUserId: uuid, tenantId: uuid, workflowId: uuid, userId: uuid };
const groupSchema = z.object({ groupId: uuid, name: text.refine(value => !!value.trim()), groupRevision: revision, membershipId: uuid }).strict();
const previewSchema = z.object({
  ...bindingFields, companyOffboardingGroupsProtocol: z.literal(1), target: targetSchema,
  groups: z.array(groupSchema).max(25), total: count, page: pageNumber, limit: z.literal(25),
}).strict();
const receiptSchema = z.object({
  id: uuid, groupId: uuid, name: text.refine(value => !!value.trim()), membershipId: uuid, operationId: uuid,
  beforeGroupRevision: revision, afterGroupRevision: revision, actorUserId: uuid,
  reason: text.refine(value => value === value.trim()).pipe(reason),
  createdAt: z.string().datetime({ offset: true }).refine(value => Number.isFinite(Date.parse(value))), deliveryStatus: z.literal('pending'),
}).strict().refine(value => BigInt(value.afterGroupRevision) > BigInt(value.beforeGroupRevision));
const historySchema = z.object({
  ...bindingFields, target: targetSchema, receipts: z.array(receiptSchema).max(25), total: count, page: pageNumber, limit: z.literal(25),
}).strict();
const resultSchema = z.object({
  groupId: uuid, membershipId: uuid, status: z.enum(['removed', 'already_removed', 'unconfirmed', 'not_attempted']),
  code: z.union([z.literal(200), z.number().int().min(400).max(599)]).nullable(), operationId: uuid.nullable(),
}).strict().refine(value => value.status === 'removed' || value.status === 'already_removed'
  ? value.code === 200 && value.operationId !== null
  : value.operationId === null && (value.status === 'not_attempted' ? value.code === null : value.code !== null && value.code >= 400));
const outcomeSchema = z.object({ ...bindingFields, correlationId: uuid, results: z.array(resultSchema).min(1).max(25) }).strict();
const confirmationSchema = z.object({ reason, confirm: z.literal(true) }).strict();

export type OffboardingGroupsBinding = OffboardingContext & { workflowId: string; userId: string; eligibilityRevision: string };
export type OffboardingGroupsPreview = z.infer<typeof previewSchema>;
export type OffboardingGroupsHistory = z.infer<typeof historySchema>;
export type OffboardingGroupsOutcome = z.infer<typeof outcomeSchema>;
export const offboardingGroupsReason = (value: string) => reason.parse(value);
const unconfirmed = () => new Error('Ergebnis nicht bestätigt. Gruppenvorschau und Historie ausdrücklich neu laden; keine automatische Wiederholung.');

export function offboardingGroupsError(error: unknown) {
  const failure = z.object({ response: z.object({ status: z.number() }).passthrough() }).passthrough().safeParse(error);
  const status = failure.success ? failure.data.response.status : null;
  if (status === 401) return 'Sitzung ungültig. Erneut anmelden und Gruppenvorschau und Historie neu laden.';
  if (status === 403) return 'Berechtigung oder aktuelle Quellfreigabe fehlt. Gruppenvorschau und Historie neu laden.';
  if (status === 404) return 'Mitarbeiter, Gruppen oder verknüpfter Austrittsvorgang nicht verfügbar. Arbeitsstand neu laden.';
  if (status === 409) return 'Kontogeneration oder Gruppenmitgliedschaft geändert. Übergeordneten Arbeitsstand neu laden und prüfen.';
  if (status === 412) return 'Gruppenversion geändert. Gruppenvorschau und Historie ausdrücklich neu laden.';
  if (status === 428) return 'Frische MFA-Anmeldung erforderlich. Erneut anmelden und Gruppenvorschau und Historie neu laden.';
  if (status === 400) return 'Eingaben abgelehnt. Gruppenvorschau und Historie neu laden und Begründung prüfen.';
  if (status === 503) return 'Dienst nicht verfügbar. Teilschritte können bereits wirksam sein. Gruppenvorschau und Historie neu laden; nicht automatisch wiederholen.';
  return unconfirmed().message;
}

function freeze<Value>(value: Value): Value {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function validatePage(rows: unknown[], total: number, actual: number, expected: number) {
  if (actual !== expected || rows.length !== Math.min(25, Math.max(0, total - (expected - 1) * 25))) throw unconfirmed();
}
function unique(values: string[]) { return new Set(values).size === values.length; }

export class CompanyOffboardingGroupsClient {
  private expected: OffboardingGroupsBinding;
  private base: string;
  private generation = 0;
  private disposed = false;
  private writing = false;
  private controllers = new Set<AbortController>();
  private snapshot: OffboardingGroupsPreview | null = null;
  private historyReady = false;
  private receipts = new Map<string, string>();
  private onSessionError = () => this.invalidate();

  constructor(binding: OffboardingGroupsBinding) {
    this.expected = freeze({
      actorUserId: uuid.parse(binding.actorUserId), tenantId: uuid.parse(binding.tenantId), workflowId: uuid.parse(binding.workflowId),
      userId: uuid.parse(binding.userId), eligibilityRevision: revision.parse(binding.eligibilityRevision),
    });
    if (this.expected.actorUserId === this.expected.userId) throw unconfirmed();
    this.base = '/api/users/' + this.expected.userId + '/company-offboarding-groups';
    if (typeof window !== 'undefined') window.addEventListener('od:session-error', this.onSessionError);
  }
  invalidate() {
    this.generation += 1; this.snapshot = null; this.historyReady = false;
    this.controllers.forEach(controller => controller.abort()); this.controllers.clear();
  }
  dispose() {
    this.disposed = true; this.invalidate();
    if (typeof window !== 'undefined') window.removeEventListener('od:session-error', this.onSessionError);
  }
  private bind(value: z.infer<typeof outcomeSchema> | OffboardingGroupsPreview | OffboardingGroupsHistory) {
    if (value.actorUserId !== this.expected.actorUserId || value.tenantId !== this.expected.tenantId
      || value.workflowId !== this.expected.workflowId || value.userId !== this.expected.userId) throw unconfirmed();
  }
  private target(value: z.infer<typeof targetSchema>) {
    if (value.eligibilityRevision !== this.expected.eligibilityRevision) throw unconfirmed();
  }
  private async run<Result>(operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal): Promise<Result> {
    const generation = this.generation; const controller = new AbortController();
    const abort = () => controller.abort();
    const check = () => { if (this.disposed || generation !== this.generation || controller.signal.aborted) throw unconfirmed(); };
    if (signal?.aborted) abort(); signal?.addEventListener('abort', abort); this.controllers.add(controller);
    try { check(); const value = await operation(controller.signal, check); check(); return value; }
    catch (error) { if (generation === this.generation) this.invalidate(); throw error; }
    finally { signal?.removeEventListener('abort', abort); this.controllers.delete(controller); }
  }
  async preview(page = 1, signal?: AbortSignal): Promise<OffboardingGroupsPreview> {
    if (this.writing) throw unconfirmed();
    this.invalidate();
    return this.run(async (requestSignal, check) => {
      pageNumber.parse(page);
      const response = await api.get(this.base, { params: { workflowId: this.expected.workflowId, page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = previewSchema.parse(response.data); this.bind(value); this.target(value.target);
      validatePage(value.groups, value.total, value.page, page);
      if (!unique(value.groups.map(group => group.groupId)) || !unique(value.groups.map(group => group.membershipId))) throw unconfirmed();
      this.snapshot = freeze(value); return value;
    }, signal);
  }
  async history(page = 1, signal?: AbortSignal): Promise<OffboardingGroupsHistory> {
    if (this.writing) throw unconfirmed();
    this.historyReady = false;
    return this.run(async (requestSignal, check) => {
      pageNumber.parse(page);
      const response = await api.get(this.base + '/history', { params: { workflowId: this.expected.workflowId, page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = historySchema.parse(response.data); this.bind(value); this.target(value.target);
      validatePage(value.receipts, value.total, value.page, page);
      if (['id', 'membershipId', 'operationId'].some(field => !unique(value.receipts.map(receipt => receipt[field])))
        || value.receipts.some(receipt => receipt.actorUserId === this.expected.userId
          || this.receipts.has(receipt.id) && this.receipts.get(receipt.id) !== JSON.stringify(receipt))) throw unconfirmed();
      value.receipts.forEach(receipt => this.receipts.set(receipt.id, JSON.stringify(receipt)));
      this.historyReady = true; return freeze(value);
    }, signal);
  }
  async remove(snapshot: OffboardingGroupsPreview, confirmation: { reason: string; confirm: true }, signal?: AbortSignal): Promise<OffboardingGroupsOutcome> {
    if (this.writing) throw unconfirmed();
    this.writing = true;
    try {
      return await this.run(async (requestSignal, check) => {
        const values = confirmationSchema.parse(confirmation);
        if (!snapshot || snapshot !== this.snapshot || !this.historyReady || snapshot.groups.length < 1) throw unconfirmed();
        this.snapshot = null; this.historyReady = false;
        const memberships = snapshot.groups.map(group => ({ groupId: group.groupId, groupRevision: group.groupRevision, membershipId: group.membershipId }));
        const response = await api.post(this.base, { workflowId: this.expected.workflowId, eligibilityRevision: this.expected.eligibilityRevision, ...values, memberships }, { signal: requestSignal }); check();
        if (response.status !== 200 && response.status !== 207) throw unconfirmed();
        const value = outcomeSchema.parse(response.data); this.bind(value);
        if (value.results.length !== memberships.length || !unique(value.results.filter(result => result.operationId !== null).map(result => result.operationId))) throw unconfirmed();
        let stopped = false;
        value.results.forEach((result, index) => {
          const original = memberships[index];
          if (result.groupId !== original.groupId || result.membershipId !== original.membershipId) throw unconfirmed();
          if (stopped) { if (result.status !== 'not_attempted') throw unconfirmed(); }
          else if (result.status === 'unconfirmed') stopped = true;
          else if (result.status !== 'removed' && result.status !== 'already_removed') throw unconfirmed();
        });
        if ((response.status === 207) !== stopped) throw unconfirmed();
        return freeze(value);
      }, signal);
    } finally { this.invalidate(); this.writing = false; }
  }
}
