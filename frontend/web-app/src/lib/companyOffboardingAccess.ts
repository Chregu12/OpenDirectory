import { z } from 'zod';
import { ROLES, PROTECTED } from '../../../../packages/directory-role-contract';
import { api } from './api';

const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => BigInt(value) <= BigInt('9223372036854775807'));
const version = z.string().regex(/^[a-f0-9]{64}$/);
const timestamp = z.string().datetime({ offset: true }).refine(value => Number.isFinite(Date.parse(value)));
const role = z.string().refine(value => ROLES.includes(value));
const reason = z.string().refine(value => !/[\u0000-\u001f\u007f-\u009f]/.test(value)).transform(value => value.trim())
  .refine(value => Array.from(value).length >= 10 && Array.from(value).length <= 500);
const kind = z.enum(['role', 'eligibility']);
const permission = z.enum(['identities.roles.read', 'identities.roles.manage', 'pim.eligibilities.read', 'pim.eligibilities.manage']);
const pageNumber = z.number().int().positive().max(1000000);
const count = z.number().int().nonnegative().safe();
const target = z.object({ enabled: z.literal(false), eligibilityRevision: revision }).strict();
const binding = { schemaVersion: z.literal(1), actorUserId: uuid, tenantId: uuid, workflowId: uuid, userId: uuid };
const capabilitiesSchema = z.object({
  ...binding, companyOffboardingAccessProtocol: z.literal(1), target,
  permissions: z.array(permission).max(4), supportedKinds: z.array(kind).min(1).max(2),
}).strict();
const itemSchema = z.object({
  id: uuid, role, version, createdAt: timestamp, expiresAt: timestamp.nullable(), canRevoke: z.boolean(),
  blockedReason: z.enum(['permission_required', 'protected_role']).nullable(),
}).strict().refine(value => value.expiresAt === null || Date.parse(value.expiresAt) > Date.parse(value.createdAt));
const previewSchema = z.object({
  ...binding, companyOffboardingAccessProtocol: z.literal(1), target, kind, canRevoke: z.boolean(),
  items: z.array(itemSchema).max(25), total: count, page: pageNumber, limit: z.literal(25),
}).strict();
const receiptSchema = z.object({
  id: uuid, resourceId: uuid, role, version, kind, checkpointId: uuid, actorUserId: uuid, correlationId: uuid,
  reason: z.string().refine(value => value === value.trim()).pipe(reason), createdAt: timestamp, deliveryStatus: z.literal('pending'),
}).strict();
const historySchema = z.object({
  ...binding, target, kind, receipts: z.array(receiptSchema).max(25), total: count, page: pageNumber, limit: z.literal(25),
}).strict();
const resultSchema = z.object({
  id: uuid, status: z.enum(['revoked', 'already_revoked', 'unconfirmed', 'not_attempted']),
  code: z.union([z.literal(200), z.number().int().min(400).max(599)]).nullable(), checkpointId: uuid.nullable(),
}).strict().refine(value => value.status === 'revoked' || value.status === 'already_revoked'
  ? value.code === 200 && value.checkpointId !== null
  : value.checkpointId === null && (value.status === 'not_attempted' ? value.code === null : value.code !== null && value.code >= 400));
const outcomeSchema = z.object({ ...binding, kind, correlationId: uuid, results: z.array(resultSchema).min(1).max(25) }).strict();

export type OffboardingAccessKind = z.infer<typeof kind>;
export type OffboardingAccessBinding = { expectedActorUserId: string; tenantId?: string; userId: string; workflowId: string; eligibilityRevision?: string };
export type OffboardingAccessCapabilities = z.infer<typeof capabilitiesSchema>;
export type OffboardingAccessPreview = z.infer<typeof previewSchema>;
export type OffboardingAccessHistory = z.infer<typeof historySchema>;
export type OffboardingAccessOutcome = z.infer<typeof outcomeSchema>;
export type OffboardingAccessIntent = Readonly<{ snapshot: OffboardingAccessPreview; items: OffboardingAccessPreview['items']; reason: string }>;
export const offboardingAccessIdentifier = (value: string) => uuid.parse(value);
export const offboardingAccessReason = (value: string) => reason.parse(value);
const duties = { role: ['identities.roles.read', 'identities.roles.manage'], eligibility: ['pim.eligibilities.read', 'pim.eligibilities.manage'] } as const;
const unconfirmed = () => new Error('Ergebnis nicht bestätigt. Vorschau und Historie ausdrücklich neu laden; keine automatische Wiederholung.');

export function offboardingAccessError(error: unknown) {
  const failure = z.object({ response: z.object({ status: z.number() }).passthrough() }).passthrough().safeParse(error);
  const status = failure.success ? failure.data.response.status : null;
  if (status === 401) return 'Sitzung ungültig. Erneut anmelden und Arbeitsstand ausdrücklich neu laden.';
  if (status === 403) return 'Separate Rollen- oder PIM-Berechtigung erforderlich. Firmen-Ownership verleiht keine globalen Adminrechte.';
  if (status === 404) return 'Ziel oder verknüpfter Kontosperrnachweis nicht verfügbar. Arbeitsstand ausdrücklich neu laden.';
  if (status === 409) return 'Konto oder Berechtigungsverknüpfung geändert. Kontosperrnachweis und Arbeitsstand prüfen.';
  if (status === 412) return 'Ursprüngliche Zuweisung geändert. Arbeitsstand ausdrücklich neu laden; keine neue Zuweisung als Ersatz verwenden.';
  if (status === 428) return 'Frische MFA-Anmeldung erforderlich (höchstens 300 Sekunden). Erneut anmelden und Arbeitsstand neu laden.';
  if (status === 400) return 'Eingaben abgelehnt. Begründung und ursprüngliche Auswahl prüfen; Arbeitsstand neu laden.';
  if (status === 503) return 'Dienst nicht verfügbar. Teilschritte können wirksam sein. Vorschau und Historie ausdrücklich neu laden; nicht automatisch wiederholen.';
  return unconfirmed().message;
}
function freeze<Value>(value: Value): Value {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function unique(values: string[]) { return new Set(values).size === values.length; }
function validatePage(rows: unknown[], total: number, actual: number, expected: number) {
  if (actual !== expected || rows.length !== Math.min(25, Math.max(0, total - (expected - 1) * 25))) throw unconfirmed();
}
function chronological(rows: { createdAt?: string }[]) {
  return rows.every((row, index) => index === 0 || Date.parse(rows[index - 1].createdAt) <= Date.parse(row.createdAt));
}

export class CompanyOffboardingAccessClient {
  private expected: OffboardingAccessBinding;
  private pinned: { tenantId: string; eligibilityRevision: string } | null = null;
  private base: string;
  private generation = 0;
  private disposed = false;
  private writing = false;
  private controllers = new Set<AbortController>();
  private capabilitiesValue: OffboardingAccessCapabilities | null = null;
  private snapshot: OffboardingAccessPreview | null = null;
  private historyKind: OffboardingAccessKind | null = null;
  private receipts = new Map<string, string>();
  private resources = new Map<string, z.infer<typeof receiptSchema>>();
  private checkpoints = new Map<string, string>();
  private intents = new WeakMap<OffboardingAccessIntent, 'new' | 'uncertain' | 'complete'>();
  private onSessionError = () => { this.intents = new WeakMap(); this.invalidate(); };

  constructor(values: OffboardingAccessBinding) {
    this.expected = freeze({ expectedActorUserId: uuid.parse(values.expectedActorUserId), userId: uuid.parse(values.userId), workflowId: uuid.parse(values.workflowId),
      ...(values.tenantId !== undefined ? { tenantId: uuid.parse(values.tenantId) } : {}),
      ...(values.eligibilityRevision !== undefined ? { eligibilityRevision: revision.parse(values.eligibilityRevision) } : {}) });
    if (this.expected.expectedActorUserId === this.expected.userId) throw unconfirmed();
    this.base = '/api/users/' + this.expected.userId + '/company-offboarding-access';
    if (typeof window !== 'undefined') window.addEventListener('od:session-error', this.onSessionError);
  }
  private cancelRequests() {
    this.generation += 1;
    this.controllers.forEach(controller => controller.abort()); this.controllers.clear();
  }
  invalidate() {
    this.cancelRequests(); this.capabilitiesValue = null; this.snapshot = null; this.historyKind = null;
  }
  dispose() {
    this.disposed = true; this.intents = new WeakMap(); this.invalidate();
    if (typeof window !== 'undefined') window.removeEventListener('od:session-error', this.onSessionError);
  }
  private bind(value: z.infer<typeof outcomeSchema> | OffboardingAccessCapabilities | OffboardingAccessPreview | OffboardingAccessHistory) {
    if (value.actorUserId !== this.expected.expectedActorUserId || value.workflowId !== this.expected.workflowId || value.userId !== this.expected.userId
      || (this.expected.tenantId !== undefined && value.tenantId !== this.expected.tenantId)
      || (this.pinned !== null && value.tenantId !== this.pinned.tenantId)) throw unconfirmed();
  }
  private target(value: z.infer<typeof target>) {
    if ((this.expected.eligibilityRevision !== undefined && value.eligibilityRevision !== this.expected.eligibilityRevision)
      || (this.pinned !== null && value.eligibilityRevision !== this.pinned.eligibilityRevision)) throw unconfirmed();
  }
  private require(selectedKind: OffboardingAccessKind, write = false) {
    kind.parse(selectedKind);
    const value = this.capabilitiesValue;
    if (!value || !value.supportedKinds.includes(selectedKind) || !value.permissions.includes(duties[selectedKind][write ? 1 : 0])) throw unconfirmed();
    return value;
  }
  private async run<Result>(operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal): Promise<Result> {
    const generation = this.generation; const controller = new AbortController(); const abort = () => controller.abort();
    const check = () => { if (this.disposed || generation !== this.generation || controller.signal.aborted) throw unconfirmed(); };
    if (signal?.aborted) abort(); signal?.addEventListener('abort', abort); this.controllers.add(controller);
    try { check(); const value = await operation(controller.signal, check); check(); return value; }
    catch (error) { if (generation === this.generation) this.invalidate(); throw error; }
    finally { signal?.removeEventListener('abort', abort); this.controllers.delete(controller); }
  }
  async capabilities(signal?: AbortSignal): Promise<OffboardingAccessCapabilities> {
    if (this.writing) throw unconfirmed();
    this.invalidate();
    return this.run(async (requestSignal, check) => {
      const response = await api.get(this.base + '/capabilities', { params: { workflowId: this.expected.workflowId }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = capabilitiesSchema.parse(response.data); this.bind(value); this.target(value.target);
      if (!unique(value.permissions) || !unique(value.supportedKinds)
        || (['role', 'eligibility'] as const).some(candidate => value.supportedKinds.includes(candidate) !== value.permissions.includes(duties[candidate][0]))) throw unconfirmed();
      this.pinned = freeze({ tenantId: value.tenantId, eligibilityRevision: value.target.eligibilityRevision });
      this.capabilitiesValue = freeze(value); return value;
    }, signal);
  }
  async preview(selectedKind: OffboardingAccessKind, page = 1, signal?: AbortSignal): Promise<OffboardingAccessPreview> {
    if (this.writing) throw unconfirmed();
    this.cancelRequests(); this.snapshot = null; this.historyKind = null;
    return this.run(async (requestSignal, check) => {
      const access = this.require(selectedKind); pageNumber.parse(page);
      const response = await api.get(this.base, { params: { workflowId: this.expected.workflowId, kind: selectedKind, page: String(page), limit: '25' }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = previewSchema.parse(response.data); this.bind(value); this.target(value.target);
      validatePage(value.items, value.total, value.page, page);
      if (value.kind !== selectedKind || value.canRevoke !== access.permissions.includes(duties[selectedKind][1]) || !unique(value.items.map(item => item.id)) || !chronological(value.items)
        || value.items.some(item => item.canRevoke !== (value.canRevoke && item.blockedReason === null)
          || (!value.canRevoke && item.blockedReason !== 'permission_required')
          || (value.canRevoke && item.blockedReason === 'permission_required')
          || (item.blockedReason === 'protected_role' && !PROTECTED.includes(item.role)))) throw unconfirmed();
      this.snapshot = freeze(value); return value;
    }, signal);
  }
  async history(selectedKind: OffboardingAccessKind, page = 1, signal?: AbortSignal): Promise<OffboardingAccessHistory> {
    if (this.writing) throw unconfirmed();
    this.cancelRequests(); this.historyKind = null;
    return this.run(async (requestSignal, check) => {
      this.require(selectedKind); pageNumber.parse(page);
      const response = await api.get(this.base + '/history', { params: { workflowId: this.expected.workflowId, kind: selectedKind, page: String(page), limit: '25' }, signal: requestSignal }); check();
      if (response.status !== 200) throw unconfirmed();
      const value = historySchema.parse(response.data); this.bind(value); this.target(value.target);
      validatePage(value.receipts, value.total, value.page, page);
      if (value.kind !== selectedKind || !chronological(value.receipts) || ['id', 'resourceId', 'checkpointId'].some(field => !unique(value.receipts.map(receipt => receipt[field])))
        || value.receipts.some(receipt => receipt.kind !== selectedKind || receipt.actorUserId === this.expected.userId
          || (this.receipts.has(receipt.id) && this.receipts.get(receipt.id) !== JSON.stringify(receipt))
          || (this.checkpoints.has(receipt.checkpointId) && this.checkpoints.get(receipt.checkpointId) !== receipt.id)
          || (this.resources.has(selectedKind + ':' + receipt.resourceId) && this.resources.get(selectedKind + ':' + receipt.resourceId).id !== receipt.id))) throw unconfirmed();
      value.receipts.forEach(receipt => {
        this.receipts.set(receipt.id, JSON.stringify(receipt)); this.resources.set(selectedKind + ':' + receipt.resourceId, receipt); this.checkpoints.set(receipt.checkpointId, receipt.id);
      });
      this.historyKind = selectedKind; return freeze(value);
    }, signal);
  }
  capture(snapshot: OffboardingAccessPreview, identifiers: string[], values: { reason: string; confirm: true }): OffboardingAccessIntent {
    const confirmation = z.object({ reason, confirm: z.literal(true) }).strict().parse(values);
    if (this.writing || !snapshot || snapshot !== this.snapshot || this.historyKind !== snapshot.kind) throw unconfirmed();
    this.require(snapshot.kind, true);
    z.array(uuid).min(1).max(25).parse(identifiers);
    const items = snapshot.items.filter(item => identifiers.includes(item.id));
    if (!unique(identifiers) || items.length !== identifiers.length || items.some((item, index) => !item.canRevoke || item.id !== identifiers[index])) throw unconfirmed();
    const intent = freeze({ snapshot, items, reason: confirmation.reason }); this.intents.set(intent, 'new'); return intent;
  }
  async revoke(intent: OffboardingAccessIntent, recovery = false, signal?: AbortSignal): Promise<OffboardingAccessOutcome> {
    if (this.writing) throw unconfirmed();
    this.writing = true;
    try {
      return await this.run(async (requestSignal, check) => {
        const state = this.intents.get(intent);
        if (!intent || (recovery ? state !== 'uncertain' : state !== 'new' || intent.snapshot !== this.snapshot)
          || this.historyKind !== intent.snapshot.kind) throw unconfirmed();
        this.require(intent.snapshot.kind, true);
        this.intents.set(intent, 'uncertain'); this.snapshot = null; this.historyKind = null;
        const response = await api.post(this.base, { workflowId: this.expected.workflowId, eligibilityRevision: this.pinned.eligibilityRevision,
          kind: intent.snapshot.kind, reason: intent.reason, confirm: true, items: intent.items.map(item => ({ id: item.id, version: item.version })) }, { signal: requestSignal }); check();
        if (response.status !== 200 && response.status !== 207) throw unconfirmed();
        const value = outcomeSchema.parse(response.data); this.bind(value);
        if (value.kind !== intent.snapshot.kind || value.results.length !== intent.items.length
          || !unique(value.results.filter(result => result.checkpointId !== null).map(result => result.checkpointId))) throw unconfirmed();
        let stopped = false;
        value.results.forEach((result, index) => {
          const original = intent.items[index]; const known = this.resources.get(value.kind + ':' + original.id);
          if (result.id !== original.id || (result.checkpointId !== null && known && (known.version !== original.version || known.checkpointId !== result.checkpointId))) throw unconfirmed();
          if (stopped) { if (result.status !== 'not_attempted') throw unconfirmed(); }
          else if (result.status === 'unconfirmed') stopped = true;
          else if (result.status !== 'revoked' && result.status !== 'already_revoked') throw unconfirmed();
        });
        if ((response.status === 207) !== stopped) throw unconfirmed();
        this.intents.set(intent, stopped ? 'uncertain' : 'complete'); return freeze(value);
      }, signal);
    } finally { this.invalidate(); this.writing = false; }
  }
}
