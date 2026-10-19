import { z } from 'zod';
import { api } from './api';

export const companyUuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
export const companyRevision = z.string().regex(/^[1-9][0-9]{0,18}$/).refine(value => /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= BigInt('9223372036854775807'));
export const companyTimestamp = z.string().datetime({ offset: true }).refine(value => Number.isFinite(Date.parse(value)));
export const companyCount = z.number().int().nonnegative().safe();
export const companyText = (minimum: number, maximum: number) => z.string().refine(value => value === value.trim()
  && !/[\u0000-\u001f\u007f-\u009f]/.test(value) && Array.from(value).length >= minimum && Array.from(value).length <= maximum);
export const companyReason = (value: string) => companyText(10, 500).parse(value.trim());
export const companySourceSchema = z.discriminatedUnion('sourceType', [
  z.object({ sourceType: z.literal('direct'), sourceId: z.literal('direct'), grantId: companyUuid }).strict(),
  z.object({ sourceType: z.literal('blueprint'), sourceId: companyUuid, grantId: companyUuid }).strict(),
]);
export const companySourcesSchema = z.array(companySourceSchema).min(1).max(10000).refine(values => new Set(values.map(value => value.grantId)).size === values.length
  && values.every((value, index) => !index || `${values[index - 1].sourceType}:${values[index - 1].sourceId}` < `${value.sourceType}:${value.sourceId}`));
export type CompanyLicenseSource = Required<z.infer<typeof companySourceSchema>>;
export type CompanyWire<Value> = Value extends (infer Item)[] ? CompanyWire<Item>[] : Value extends object ? { [Field in keyof Value]-?: CompanyWire<Value[Field]> } : Value;
export interface CompanyWorkflowContext { actorUserId: string; tenantId: string }
export const companyV2Context = { schemaVersion: z.literal(2), companyLicenseProtocol: z.literal(2), actorUserId: companyUuid, tenantId: companyUuid };
export const companyTargetSchema = z.object({ enabled: z.boolean(), deleted: z.boolean(), eligibilityRevision: companyRevision }).strict()
  .refine(value => !value.deleted || !value.enabled);
export function companyFreeze<Value>(value: Value): Value {
  if (value && typeof value === 'object') { Object.values(value).forEach(companyFreeze); Object.freeze(value); }
  return value;
}
class UnconfirmedCompanyWorkflow extends Error {
  constructor(readonly unsafe = false) { super('Ergebnis nicht bestätigt. Ursprünglichen Versuch ausdrücklich prüfen oder aktuellen Stand neu laden. Keine automatische Wiederholung.'); }
}
export const companyUnconfirmed = (unsafe = false): never => { throw new UnconfirmedCompanyWorkflow(unsafe); };
export function companyWorkflowUnsafe(error: unknown) {
  return error instanceof UnconfirmedCompanyWorkflow && error.unsafe || [401, 403, 428].includes((error as { response?: { status?: number } })?.response?.status);
}
export function companyWorkflowError(error: unknown) {
  const status = (error as { response?: { status?: number } })?.response?.status;
  if (status === 401) return 'Sitzung ungültig. Bitte erneut anmelden und Berechtigungen neu prüfen.';
  if (status === 403) return 'Berechtigung für diesen Firmenvorgang fehlt. Bitte Zugriff neu prüfen.';
  if (status === 428) return 'Frische zusätzliche Anmeldung erforderlich. Bitte erneut anmelden.';
  if (status === 409) return 'Zuweisung, Kontogeneration oder Lizenzbestand im Konflikt. Aktuellen Stand ausdrücklich prüfen; keine automatische Wiederholung.';
  if (status === 412) return 'Erfasster Stand wurde geändert. Aktuellen Stand ausdrücklich neu laden und erneut prüfen.';
  if (status === 404) return 'Vorgang oder Ziel in dieser Firma nicht verfügbar. Aktuellen Stand neu laden.';
  if (status === 400) return 'Eingaben abgelehnt. Felder und Begründung prüfen.';
  return new UnconfirmedCompanyWorkflow().message;
}
export function companyPage(page: number) { return z.number().int().min(1).max(1000000).parse(page); }
export function companyCheckPage(rows: unknown[], total: number, page: number, ids: string[]) {
  if (rows.length !== Math.min(25, Math.max(0, total - (page - 1) * 25)) || new Set(ids).size !== ids.length) companyUnconfirmed();
}

export class CompanyWorkflowSession<Access extends CompanyWorkflowContext> {
  private context: Access | null = null;
  private generation = 0;
  private disposed = false;
  private writing = false;
  private controllers = new Set<AbortController>();
  private captures = new WeakMap<object, number>();
  private onSessionError = () => this.invalidate();
  constructor(private capabilitiesUrl: string, private capabilitiesSchema: z.ZodTypeAny, private expected?: CompanyWorkflowContext) {
    if (expected) { companyUuid.parse(expected.actorUserId); companyUuid.parse(expected.tenantId); }
    if (typeof window !== 'undefined') window.addEventListener('od:session-error', this.onSessionError);
  }
  invalidate() { this.generation++; this.context = null; this.controllers.forEach(controller => controller.abort()); this.controllers.clear(); }
  dispose() { this.disposed = true; this.invalidate(); if (typeof window !== 'undefined') window.removeEventListener('od:session-error', this.onSessionError); }
  require() { if (!this.context || this.disposed) return companyUnconfirmed(true); return this.context; }
  bind(value: CompanyWorkflowContext, expected = this.require()) {
    if (value.actorUserId !== expected.actorUserId || value.tenantId !== expected.tenantId) companyUnconfirmed(true);
  }
  own<Value extends object>(value: Value): Value { companyFreeze(value); this.captures.set(value, this.generation); return value; }
  captured(value: object) { return !this.disposed && !!this.context && this.captures.get(value) === this.generation; }
  async fresh(signal: AbortSignal, check: () => void) {
    const response = await api.get(this.capabilitiesUrl, { signal }); check();
    const result = this.capabilitiesSchema.safeParse(response.data);
    if (response.status !== 200 || !result.success) return companyUnconfirmed(true);
    const access = result.data as Access;
    if (this.expected) this.bind(access, this.expected as Access);
    if (this.context) this.bind(access);
    this.context = companyFreeze(access); return access;
  }
  access(signal?: AbortSignal) { return this.run((requestSignal, check) => this.fresh(requestSignal, check), signal); }
  async run<Result>(operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal): Promise<Result> {
    const generation = this.generation; const controller = new AbortController(); const abort = () => controller.abort();
    const check = () => { if (this.disposed || generation !== this.generation || controller.signal.aborted) companyUnconfirmed(true); };
    if (signal?.aborted) abort(); signal?.addEventListener('abort', abort); this.controllers.add(controller);
    try { check(); const result = await operation(controller.signal, check); check(); return result; }
    catch (error) { if (generation === this.generation && companyWorkflowUnsafe(error)) this.invalidate(); throw error; }
    finally { signal?.removeEventListener('abort', abort); this.controllers.delete(controller); }
  }
  async write<Result>(intent: object, operation: (signal: AbortSignal, check: () => void) => Promise<Result>, signal?: AbortSignal) {
    if (this.writing || !this.captured(intent)) return companyUnconfirmed();
    this.writing = true;
    try { return await this.run(async (requestSignal, check) => {
      await this.fresh(requestSignal, check);
      if (!this.captured(intent)) companyUnconfirmed(true);
      const result = await operation(requestSignal, check); check();
      await this.fresh(requestSignal, check); return companyFreeze(result);
    }, signal); } finally { this.writing = false; }
  }
}
