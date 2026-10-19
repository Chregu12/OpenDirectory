import { z } from 'zod';
import { api } from './api';

const base = '/api/company-blueprints';
const rights = ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish'] as const;
const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => BigInt(value) <= BigInt('9223372036854775807'));
const ordinal = z.number().int().min(1).max(2147483647);
const timestamp = z.string().datetime().refine(value => Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value);
const text = (minimum: number, maximum: number) => z.string().refine(value => value === value.trim()
  && !/[\u0000-\u001f\u007f-\u009f]/.test(value) && Array.from(value).length >= minimum && Array.from(value).length <= maximum);
const platform = z.enum(['all', 'windows', 'macos', 'linux']);
const configType = z.enum(['screen_lock', 'filevault', 'software_update']);
const payloadSchemas = {
  screen_lock: z.object({ minutes: z.number().int().min(1).max(1440), requirePassword: z.boolean() }).strict(),
  filevault: z.object({ enabled: z.boolean() }).strict(),
  software_update: z.object({ automatic: z.boolean(), deferralDays: z.number().int().min(0).max(365) }).strict(),
};
export type CompanyBlueprintConfigType = 'screen_lock' | 'filevault' | 'software_update';
export interface CompanyBlueprintConfiguration { id: string; type: CompanyBlueprintConfigType; name: string; payloadJson: string }
export interface CompanyBlueprintDraft { name: string; description: string; platform: 'all' | 'windows' | 'macos' | 'linux'; configurations: CompanyBlueprintConfiguration[]; appPoolIds: string[] }
export interface CompanyBlueprintAccess {
  schemaVersion: 1; companyBlueprintProtocol: 1; actorUserId: string; tenantId: string; permissions: typeof rights[number][];
  configurationMode: 'local-only'; maxConfigurations: 25; maxApplications: 25;
}
export interface CompanyBlueprintSummary {
  id: string; tenantId: string; name: string; platform: CompanyBlueprintDraft['platform']; revision: string; publishedVersion: number | null;
  draftChanged: boolean; configurationCount: number; appCount: number; createdAt: string; updatedAt: string;
}
export interface CompanyBlueprintSource { blueprintId: string; configurationId: string }
export interface CompanyBlueprintVariant { payloadJson: string; sources: CompanyBlueprintSource[] }
export interface CompanyBlueprintPreview {
  configurationCount: number; hasConflicts: boolean; effectiveConfigurations: (CompanyBlueprintVariant & { configType: CompanyBlueprintConfigType })[];
  conflicts: { configType: CompanyBlueprintConfigType; variants: CompanyBlueprintVariant[] }[];
}
export interface CompanyBlueprintDetail {
  id: string; tenantId: string; revision: string; publishedVersion: number | null; draftChanged: boolean; draft: CompanyBlueprintDraft;
  createdAt: string; updatedAt: string; preview: CompanyBlueprintPreview;
}
export interface CompanyBlueprintVersion {
  version: number; sourceRevision: string; publishedRevision: string; actorUserId: string; operationId: string; createdAt: string;
}
export interface CompanyBlueprintVersionDetail extends CompanyBlueprintVersion {
  draft: CompanyBlueprintDraft; apps: { id: string; name: string; vendor: string; revision: string }[];
}
export interface CompanyBlueprintEvent {
  id: string; tenantId: string; type: 'blueprint.created' | 'blueprint.draft.updated' | 'blueprint.published' | 'blueprint.draft.restored'; version: 1;
  blueprintId: string; actorUserId: string; correlationId: string; createdAt: string; beforeRevision: string | null; afterRevision: string;
  releasedVersion: number | null; restoredFrom: number | null; reason: string; deliveryStatus: 'pending';
}
export interface CompanyBlueprintPage<Row> { total: number; page: number; limit: 25; rows: Row[] }
export interface CompanyBlueprintReceipt {
  schemaVersion: 1; actorUserId: string; tenantId: string; operationId: string; blueprintId: string; revision: string; publishedVersion: number | null;
  action: 'created' | 'updated' | 'published' | 'restored'; outcome: 'applied' | 'already_applied'; deliveryStatus: 'pending';
}
export interface CompanyBlueprintIntent {
  readonly operationId: string; readonly blueprintId: string; readonly action: CompanyBlueprintReceipt['action']; readonly etag: string | null;
  readonly body: { id?: string; draft?: CompanyBlueprintDraft; version?: number; reason: string; confirm: true };
}
class UnconfirmedBlueprint extends Error {
  constructor(readonly unsafe = false) { super('Blueprint-Antwort nicht bestätigt. Bitte Berechtigung und aktuellen Stand ausdrücklich neu prüfen.'); }
}
const fail = (unsafe = false): never => { throw new UnconfirmedBlueprint(unsafe); };
export function companyBlueprintsUnsafe(error: unknown) {
  return error instanceof UnconfirmedBlueprint && error.unsafe || [401, 403, 428].includes((error as { response?: { status?: number } })?.response?.status);
}
export function companyBlueprintsError(error: unknown) {
  const status = (error as { response?: { status?: number } })?.response?.status;
  if (status === 401) return 'Sitzung nicht mehr gültig. Bitte erneut anmelden.';
  if (status === 403) return 'Firmen-Blueprint-Berechtigung fehlt. Bitte Zugriff erneut prüfen.';
  if (status === 428) return 'Eine aktuelle zusätzliche Anmeldung ist erforderlich. Bitte erneut anmelden.';
  if (status === 412) return 'Der Entwurf wurde inzwischen geändert. Aktuellen Stand ausdrücklich neu laden; keine automatische Wiederholung.';
  if (status === 409) return 'Konflikt: Konfiguration, Freigabe oder ursprünglicher Änderungsversuch ist nicht mehr zulässig. Bitte aktuellen Stand prüfen.';
  if (status === 404) return 'Blueprint oder Version nicht verfügbar. Bitte aktuellen Stand neu laden.';
  if (status === 400) return 'Eingaben wurden abgelehnt. Bitte Felder und Begründung prüfen.';
  return 'Ergebnis nicht bestätigt. Die Änderung könnte bereits gespeichert sein. Nur den ursprünglichen Versuch ausdrücklich wiederaufnehmen oder den aktuellen Stand prüfen.';
}
export function companyBlueprintId() { return uuid.parse(crypto.randomUUID()); }
export function companyBlueprintEtag(value: Pick<CompanyBlueprintDetail, 'id' | 'revision'>) {
  return `"company-blueprint-${uuid.parse(value.id)}-${revision.parse(value.revision)}"`;
}
export function companyBlueprintPayload(type: CompanyBlueprintConfigType, payloadJson: string): Record<string, number | boolean> {
  configType.parse(type);
  if (typeof payloadJson !== 'string' || payloadJson.length > 65536 || /[0-9][.eE]/.test(payloadJson)) return fail();
  const payload = JSON.parse(payloadJson);
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || (payloadJson.match(/"\s*:/g) || []).length !== Object.keys(payload).length) return fail();
  return payloadSchemas[type].parse(payload) as Record<string, number | boolean>;
}
const configurationSchema = z.object({ id: uuid, type: configType, name: text(1, 160), payloadJson: z.string() }).strict()
  .refine(value => { try { companyBlueprintPayload(value.type, value.payloadJson); return true; } catch { return false; } });
const draftSchema = z.object({ name: text(1, 160), description: text(0, 2000), platform,
  configurations: z.array(configurationSchema).max(25).refine(values => new Set(values.map(value => value.id)).size === values.length),
  appPoolIds: z.array(uuid).max(25).refine(values => new Set(values).size === values.length),
}).strict().refine(value => value.configurations.reduce((total, config) => total + config.payloadJson.length, 0) <= 262144);
export function normalizeCompanyBlueprintDraft(draft: CompanyBlueprintDraft): CompanyBlueprintDraft {
  return draftSchema.parse({ ...draft, name: draft.name.trim(), description: draft.description.trim(),
    configurations: draft.configurations.map(config => ({ ...config, name: config.name.trim() })) }) as CompanyBlueprintDraft;
}
export function normalizeCompanyBlueprintReason(reason: string) { return text(10, 500).parse(reason.trim()); }
const capabilitiesSchema = z.object({ schemaVersion: z.literal(1), companyBlueprintProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid,
  permissions: z.tuple([z.literal(rights[0]), z.literal(rights[1]), z.literal(rights[2])]), configurationMode: z.literal('local-only'),
  maxConfigurations: z.literal(25), maxApplications: z.literal(25),
}).strict();
const summarySchema = z.object({ id: uuid, tenantId: uuid, name: text(1, 160), platform, revision, publishedVersion: ordinal.nullable(),
  draftChanged: z.boolean(), configurationCount: z.number().int().min(0).max(25), appCount: z.number().int().min(0).max(25), createdAt: timestamp, updatedAt: timestamp,
}).strict().refine(value => Date.parse(value.updatedAt) >= Date.parse(value.createdAt) && (value.publishedVersion === null || BigInt(value.publishedVersion) <= BigInt(value.revision)));
const sourceSchema = z.object({ blueprintId: uuid, configurationId: uuid }).strict();
const variantSchema = z.object({ payloadJson: z.string(), sources: z.array(sourceSchema).min(1).max(25) }).strict();
const previewSchema = z.object({ configurationCount: z.number().int().min(0).max(25), hasConflicts: z.boolean(),
  effectiveConfigurations: z.array(variantSchema.extend({ configType }).strict()).max(3),
  conflicts: z.array(z.object({ configType, variants: z.array(variantSchema).min(2).max(25) }).strict()).max(3),
}).strict();
const detailSchema = z.object({ id: uuid, tenantId: uuid, revision, publishedVersion: ordinal.nullable(), draftChanged: z.boolean(), draft: draftSchema,
  createdAt: timestamp, updatedAt: timestamp, preview: previewSchema,
}).strict().refine(value => Date.parse(value.updatedAt) >= Date.parse(value.createdAt) && (value.publishedVersion === null || BigInt(value.publishedVersion) <= BigInt(value.revision)));
const versionSchema = z.object({ version: ordinal, sourceRevision: revision, publishedRevision: revision, actorUserId: uuid, operationId: uuid, createdAt: timestamp }).strict()
  .refine(value => BigInt(value.publishedRevision) === BigInt(value.sourceRevision) + BigInt(1) && BigInt(value.version) <= BigInt(value.publishedRevision));
const versionDetailSchema = z.object({ version: ordinal, sourceRevision: revision, publishedRevision: revision, actorUserId: uuid, operationId: uuid, createdAt: timestamp,
  draft: draftSchema, apps: z.array(z.object({ id: uuid, name: text(1, 160), vendor: text(1, 160), revision }).strict()).max(25),
}).strict().refine(value => BigInt(value.publishedRevision) === BigInt(value.sourceRevision) + BigInt(1) && BigInt(value.version) <= BigInt(value.publishedRevision)
  && value.apps.length === value.draft.appPoolIds.length && new Set(value.apps.map(app => app.id)).size === value.apps.length
  && value.apps.every(app => value.draft.appPoolIds.includes(app.id)));
const eventSchema = z.object({ id: uuid, tenantId: uuid, type: z.enum(['blueprint.created', 'blueprint.draft.updated', 'blueprint.published', 'blueprint.draft.restored']),
  version: z.literal(1), blueprintId: uuid, actorUserId: uuid, correlationId: uuid, createdAt: timestamp, beforeRevision: revision.nullable(), afterRevision: revision,
  releasedVersion: ordinal.nullable(), restoredFrom: ordinal.nullable(), reason: text(10, 500), deliveryStatus: z.literal('pending'),
}).strict().refine(value => (value.type === 'blueprint.created' ? value.beforeRevision === null && value.afterRevision === '1'
  : value.beforeRevision !== null && BigInt(value.afterRevision) === BigInt(value.beforeRevision) + BigInt(1))
  && (value.type === 'blueprint.published' ? value.releasedVersion !== null : value.releasedVersion === null)
  && (value.type === 'blueprint.draft.restored' ? value.restoredFrom !== null : value.restoredFrom === null));
function freeze<Value>(value: Value): Value {
  if (value && typeof value === 'object') { Object.values(value).forEach(child => freeze(child)); Object.freeze(value); }
  return value;
}
function pageNumber(page: number) { return z.number().int().min(1).max(1000000).parse(page); }
function pageSchema(context: CompanyBlueprintAccess, page: number) {
  return z.object({ schemaVersion: z.literal(1), actorUserId: z.literal(context.actorUserId), tenantId: z.literal(context.tenantId),
    total: z.number().int().nonnegative().safe(), page: z.literal(pageNumber(page)), limit: z.literal(25) }).strict();
}
function verifyContext(value: unknown, context: CompanyBlueprintAccess) {
  if (!value || typeof value !== 'object' || value['actorUserId'] !== context.actorUserId || value['tenantId'] !== context.tenantId) fail(true);
}
function verifyPage(rows: unknown[], total: number, page: number, keys: (string | number)[]) {
  if (rows.length !== Math.min(25, Math.max(0, total - (page - 1) * 25)) || new Set(keys).size !== keys.length) fail();
}
function payloadKey(type: CompanyBlueprintConfigType, payloadJson: string) {
  const payload = companyBlueprintPayload(type, payloadJson);
  return JSON.stringify(Object.keys(payload).sort().map(key => [key, payload[key]]));
}
function verifyPreview(detail: CompanyBlueprintDetail) {
  const { preview, draft } = detail; const seen = new Set<string>(); const types = new Set<string>();
  if (preview.configurationCount !== draft.configurations.length || preview.hasConflicts !== (preview.conflicts.length > 0)) fail();
  const verify = (type: CompanyBlueprintConfigType, variants: CompanyBlueprintVariant[]) => {
    if (types.has(type)) fail(); types.add(type); const payloads = new Set<string>();
    variants.forEach(variant => {
      const key = payloadKey(type, variant.payloadJson); if (payloads.has(key)) fail(); payloads.add(key);
      variant.sources.forEach(source => {
        const config = draft.configurations.find(candidate => candidate.id === source.configurationId);
        if (source.blueprintId !== detail.id || seen.has(source.configurationId) || !config || config.type !== type || payloadKey(type, config.payloadJson) !== key) fail();
        seen.add(source.configurationId);
      });
    });
  };
  preview.effectiveConfigurations.forEach(config => verify(config.configType, [config]));
  preview.conflicts.forEach(conflict => verify(conflict.configType, conflict.variants));
  if (seen.size !== draft.configurations.length) fail();
}

export class CompanyBlueprintsClient {
  private context: CompanyBlueprintAccess | null = null;
  private generation = 0;
  private disposed = false;
  private writing = false;
  private controllers = new Set<AbortController>();
  private snapshots = new WeakMap<CompanyBlueprintDetail, number>();
  private intents = new WeakMap<CompanyBlueprintIntent, { generation: number; revision: string | null; publishedVersion: number | null }>();
  private onSessionError = () => this.invalidate();
  constructor() { if (typeof window !== 'undefined') window.addEventListener('od:session-error', this.onSessionError); }
  invalidate() { this.generation++; this.context = null; this.controllers.forEach(controller => controller.abort()); this.controllers.clear(); }
  dispose() { this.disposed = true; this.invalidate(); if (typeof window !== 'undefined') window.removeEventListener('od:session-error', this.onSessionError); }
  private async run<Result>(operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal): Promise<Result> {
    const generation = this.generation; const controller = new AbortController();
    const abort = () => controller.abort(); const check = () => { if (this.disposed || generation !== this.generation || controller.signal.aborted) fail(true); };
    signal?.addEventListener('abort', abort); if (signal?.aborted) abort(); this.controllers.add(controller);
    try { check(); const result = await operation(controller.signal, check); check(); return result; }
    catch (error) { if (generation === this.generation && companyBlueprintsUnsafe(error)) this.invalidate(); throw error; }
    finally { signal?.removeEventListener('abort', abort); this.controllers.delete(controller); }
  }
  private require() { if (!this.context || this.disposed) return fail(true); return this.context; }
  private async fresh(signal: AbortSignal, check: () => void, expected = this.context): Promise<CompanyBlueprintAccess> {
    const response = await api.get(base + '/capabilities', { signal }); check();
    const result = capabilitiesSchema.safeParse(response.data);
    if (response.status !== 200 || !result.success) return fail(true);
    const access = result.data as CompanyBlueprintAccess;
    if (expected && (access.actorUserId !== expected.actorUserId || access.tenantId !== expected.tenantId)) return fail(true);
    this.context = freeze(access); return access;
  }
  access(signal?: AbortSignal) { return this.run((requestSignal, check) => this.fresh(requestSignal, check), signal); }
  async list(page = 1, search = '', signal?: AbortSignal): Promise<CompanyBlueprintPage<CompanyBlueprintSummary>> {
    pageNumber(page); const query = text(0, 100).parse(search.trim());
    return this.run(async (requestSignal, check) => {
      const context = this.require();
      const response = await api.get(base, { params: { page, limit: 25, ...(query ? { search: query } : {}) }, signal: requestSignal }); check();
      if (response.status !== 200) return fail();
      verifyContext(response.data, context);
      const result = pageSchema(context, page).extend({ blueprints: z.array(summarySchema).max(25) }).strict().parse(response.data);
      verifyPage(result.blueprints, result.total, page, result.blueprints.map(row => row.id));
      if (result.blueprints.some(row => row.tenantId !== context.tenantId)) return fail(true);
      await this.fresh(requestSignal, check, context);
      return freeze({ rows: result.blueprints as CompanyBlueprintSummary[], total: result.total, page, limit: 25 as const });
    }, signal);
  }
  async get(id: string, signal?: AbortSignal): Promise<CompanyBlueprintDetail> {
    uuid.parse(id);
    return this.run(async (requestSignal, check) => {
      const context = this.require(); const response = await api.get(base + '/' + id, { signal: requestSignal }); check();
      if (response.status !== 200) return fail();
      verifyContext(response.data, context);
      const result = z.object({ schemaVersion: z.literal(1), actorUserId: z.literal(context.actorUserId), tenantId: z.literal(context.tenantId), blueprint: detailSchema }).strict().parse(response.data);
      const detail = result.blueprint as CompanyBlueprintDetail;
      if (detail.id !== id || detail.tenantId !== context.tenantId || response.headers?.etag !== companyBlueprintEtag(detail)) return fail();
      verifyPreview(detail); await this.fresh(requestSignal, check, context);
      freeze(detail); this.snapshots.set(detail, this.generation); return detail;
    }, signal);
  }
  private async rows<Row>(id: string, kind: 'versions' | 'history', page: number, schema: z.ZodTypeAny, key: (row: Row) => string | number, signal?: AbortSignal): Promise<CompanyBlueprintPage<Row>> {
    uuid.parse(id); pageNumber(page);
    return this.run(async (requestSignal, check) => {
      const context = this.require(); const response = await api.get(base + '/' + id + '/' + kind, { params: { page, limit: 25 }, signal: requestSignal }); check();
      if (response.status !== 200) return fail();
      verifyContext(response.data, context);
      const field = kind === 'versions' ? 'versions' : 'events';
      const result = pageSchema(context, page).extend({ blueprintId: z.literal(id), [field]: z.array(schema).max(25) }).strict().parse(response.data) as Record<string, unknown> & { total: number };
      const rows = result[field] as Row[]; verifyPage(rows, result.total, page, rows.map(key));
      if (kind === 'history' && (rows as CompanyBlueprintEvent[]).some(row => row.tenantId !== context.tenantId || row.blueprintId !== id)) return fail(true);
      await this.fresh(requestSignal, check, context); return freeze({ rows, total: result.total, page, limit: 25 as const });
    }, signal);
  }
  versions(id: string, page = 1, signal?: AbortSignal) { return this.rows<CompanyBlueprintVersion>(id, 'versions', page, versionSchema, row => row.version, signal); }
  history(id: string, page = 1, signal?: AbortSignal) { return this.rows<CompanyBlueprintEvent>(id, 'history', page, eventSchema, row => row.id, signal); }
  async version(id: string, version: number, signal?: AbortSignal): Promise<CompanyBlueprintVersionDetail> {
    uuid.parse(id); ordinal.parse(version);
    return this.run(async (requestSignal, check) => {
      const context = this.require(); const response = await api.get(base + '/' + id + '/versions/' + version, { signal: requestSignal }); check();
      if (response.status !== 200) return fail();
      verifyContext(response.data, context);
      const result = z.object({ schemaVersion: z.literal(1), actorUserId: z.literal(context.actorUserId), tenantId: z.literal(context.tenantId), blueprintId: z.literal(id), version: versionDetailSchema }).strict().parse(response.data);
      if (result.version.version !== version) return fail();
      await this.fresh(requestSignal, check, context); return freeze(result.version as CompanyBlueprintVersionDetail);
    }, signal);
  }
  capture(action: CompanyBlueprintReceipt['action'], detail: CompanyBlueprintDetail | null, reason: string, value?: CompanyBlueprintDraft | number): CompanyBlueprintIntent {
    this.require();
    if (this.writing || !['created', 'updated', 'published', 'restored'].includes(action)) return fail();
    if (action === 'created' ? detail !== null : !detail || this.snapshots.get(detail) !== this.generation || detail.tenantId !== this.context.tenantId || detail.revision === '9223372036854775807') return fail();
    if (action === 'published' && (detail.preview.hasConflicts || !detail.draft.configurations.length && !detail.draft.appPoolIds.length)) return fail();
    const body: CompanyBlueprintIntent['body'] = { reason: normalizeCompanyBlueprintReason(reason), confirm: true };
    const blueprintId = action === 'created' ? companyBlueprintId() : detail.id;
    if (action === 'created' || action === 'updated') body.draft = normalizeCompanyBlueprintDraft(value as CompanyBlueprintDraft);
    if (action === 'created') body.id = blueprintId;
    if (action === 'restored') body.version = ordinal.parse(value);
    const intent = freeze({ operationId: companyBlueprintId(), blueprintId, action, etag: detail ? companyBlueprintEtag(detail) : null, body });
    this.intents.set(intent, { generation: this.generation, revision: detail?.revision || null, publishedVersion: detail?.publishedVersion ?? null });
    return intent;
  }
  canRetry(intent: CompanyBlueprintIntent) { return !this.disposed && !!this.context && this.intents.get(intent)?.generation === this.generation; }
  async write(intent: CompanyBlueprintIntent, signal?: AbortSignal): Promise<CompanyBlueprintReceipt> {
    if (!this.canRetry(intent) || this.writing) return fail();
    const original = this.intents.get(intent); this.writing = true;
    try {
      return await this.run(async (requestSignal, check) => {
        const context = this.require(); await this.fresh(requestSignal, check, context);
        if (!this.canRetry(intent)) return fail(true);
        const path = intent.action === 'created' ? base : base + '/' + intent.blueprintId + (intent.action === 'published' ? '/publish' : intent.action === 'restored' ? '/restore' : '');
        const options = { headers: { 'Idempotency-Key': intent.operationId, ...(intent.etag ? { 'If-Match': intent.etag } : {}) }, signal: requestSignal };
        const response = intent.action === 'updated' ? await api.put(path, intent.body, options) : await api.post(path, intent.body, options); check();
        verifyContext(response.data, context);
        const result = z.object({ schemaVersion: z.literal(1), actorUserId: z.literal(context.actorUserId), tenantId: z.literal(context.tenantId),
          operationId: z.literal(intent.operationId), blueprintId: z.literal(intent.blueprintId), revision, publishedVersion: ordinal.nullable(),
          action: z.literal(intent.action), outcome: z.enum(['applied', 'already_applied']), deliveryStatus: z.literal('pending'),
        }).strict().parse(response.data) as CompanyBlueprintReceipt;
        const expectedRevision = original.revision === null ? '1' : String(BigInt(original.revision) + BigInt(1));
        const expectedPublished = intent.action === 'published' ? (original.publishedVersion || 0) + 1 : original.publishedVersion;
        if (result.revision !== expectedRevision || result.publishedVersion !== expectedPublished
          || response.status !== (intent.action === 'created' && result.outcome === 'applied' ? 201 : 200)) return fail();
        await this.fresh(requestSignal, check, context); this.intents.delete(intent); return freeze(result);
      }, signal);
    } catch (error) {
      if ([400, 404, 409, 412].includes((error as { response?: { status?: number } })?.response?.status)) this.intents.delete(intent);
      throw error;
    } finally { this.writing = false; }
  }
}
