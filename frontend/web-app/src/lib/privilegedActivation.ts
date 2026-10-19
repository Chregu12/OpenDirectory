import { api } from './api';
import { canonicalRoleUser, CatalogRole } from './directoryRoles';

export interface Eligibility { id: string; userId: string; role: string; reason: string; maxDurationSeconds: number; createdAt: string; expiresAt: string; revokedAt: string | null; status: 'eligible' | 'expired' | 'revoked' }
export interface ActivationRequest { id: string; eligibilityId: string; userId: string; role: string; reason: string; durationSeconds: number; createdAt: string; deadlineAt: string; status: 'pending' | 'approved' | 'active' | 'denied' | 'cancelled' | 'revoked' | 'expired' | 'stale'; decidedAt: string | null; decidedBy: string | null; approvalExpiresAt: string | null; assignmentId: string | null; expiresAt: string | null }
export interface PIMSelf { userId: string; eligibilities: Eligibility[]; requests: ActivationRequest[]; truncated: boolean }
export type PIMAction = 'approve' | 'deny' | 'activate' | 'cancel' | 'revoke';
export interface PIMCatalogRole extends CatalogRole { reviewable: boolean; activationRequired: boolean; maxDurationSeconds: number }
const base = '/api/identity/pim';
function invalid(): never { throw new Error('PIM-Ergebnis nicht bestätigt. Aktuellen Stand neu laden; Aktionen werden nicht automatisch wiederholt.'); }
const date = (value: unknown) => typeof value === 'string' && Number.isFinite(Date.parse(value));
function common(value: any) {
  canonicalRoleUser(value?.id); canonicalRoleUser(value?.userId);
  if (typeof value.role !== 'string' || !/^[a-z][a-z-]{0,63}$/.test(value.role) || typeof value.reason !== 'string' || !date(value.createdAt)) invalid();
}
function eligibility(value: any): Eligibility {
  common(value);
  if (!Number.isInteger(value.maxDurationSeconds) || value.maxDurationSeconds < 60 || value.maxDurationSeconds > 28800 || !date(value.expiresAt)
    || !['eligible', 'expired', 'revoked'].includes(value.status) || (value.revokedAt !== null && !date(value.revokedAt))
    || ((value.status === 'revoked') !== (value.revokedAt !== null))) return invalid();
  return value;
}
function request(value: any): ActivationRequest {
  common(value); canonicalRoleUser(value.eligibilityId);
  if (!Number.isInteger(value.durationSeconds) || value.durationSeconds < 60 || value.durationSeconds > 28800 || !date(value.deadlineAt)
    || !['pending', 'approved', 'active', 'denied', 'cancelled', 'revoked', 'expired', 'stale'].includes(value.status)
    || ['decidedAt', 'approvalExpiresAt', 'expiresAt'].some(key => value[key] !== null && !date(value[key]))) return invalid();
  for (const key of ['decidedBy', 'assignmentId']) if (value[key] !== null) canonicalRoleUser(value[key]);
  if (['approved', 'active'].includes(value.status) && (!value.decidedBy || canonicalRoleUser(value.decidedBy) === canonicalRoleUser(value.userId) || !value.approvalExpiresAt || !value.decidedAt)) return invalid();
  if (value.status === 'active' && (!value.assignmentId || !value.expiresAt)) return invalid();
  return value;
}
function list<Value>(items: any, parse: (item: any) => Value): Value[] {
  if (!Array.isArray(items) || items.length > 100 || new Set(items.map((item: any) => item?.id)).size !== items.length) return invalid();
  return items.map(parse);
}
export function pimError(error: any) {
  if (error?.response?.status === 428) return 'Für die Aktivierung bitte neu anmelden. Eine Token-Erneuerung ersetzt keine frische Anmeldung.';
  if (error?.response?.status === 403) return 'Keine Berechtigung oder unabhängige Entscheidung erforderlich.';
  if (error?.response?.status === 409) return 'PIM-Zustand oder Berechtigung hat sich geändert. Neu laden und gegebenenfalls einen neuen Antrag stellen.';
  if (error?.response?.status === 400) return 'Angaben prüfen: bekannte Rolle, gültige Verzeichnis-ID, begrenzte Dauer und Begründung erforderlich.';
  if (error?.response?.status === 404) return 'Berechtigung oder eigener Antrag nicht vorhanden.';
  return 'PIM-Ergebnis nicht bestätigt. Vor einem weiteren Versuch den aktuellen Stand neu laden.';
}
export const privilegedActivation = {
  async catalog(signal?: AbortSignal): Promise<PIMCatalogRole[]> {
    const { data } = await api.get(base + '/catalog', { signal });
    if (!Array.isArray(data?.roles) || data.roles.length > 100 || data.minDurationSeconds !== 60 || data.maxDurationSeconds !== 28800 || data.maxEligibilitySeconds !== 2592000 || data.approvalWindowSeconds !== 300
      || data.roles.some((item: any) => typeof item.role !== 'string' || typeof item.protected !== 'boolean' || typeof item.assignable !== 'boolean' || typeof item.reviewable !== 'boolean'
        || typeof item.activationRequired !== 'boolean' || !Number.isInteger(item.maxDurationSeconds) || item.maxDurationSeconds < 60 || item.maxDurationSeconds > 28800)) return invalid();
    return data.roles;
  },
  async self(signal?: AbortSignal): Promise<PIMSelf> {
    const { data } = await api.get(base + '/self', { signal }); canonicalRoleUser(data?.userId);
    const eligibilities = list(data.eligibilities, eligibility); const requests = list(data.requests, request);
    if (typeof data.truncated !== 'boolean' || [...eligibilities, ...requests].some(item => item.userId !== data.userId)) return invalid();
    return { userId: data.userId, eligibilities, requests, truncated: data.truncated };
  },
  async queue(signal?: AbortSignal): Promise<ActivationRequest[]> {
    const { data } = await api.get(base + '/requests', { signal }); if (typeof data?.truncated !== 'boolean') return invalid(); return list(data.requests, request);
  },
  async eligibilities(userId: string, signal?: AbortSignal): Promise<Eligibility[]> {
    const target = canonicalRoleUser(userId); const { data } = await api.get(base + '/eligibilities', { params: { userId: target }, signal });
    if (data?.userId !== target || typeof data.truncated !== 'boolean') return invalid();
    const rows = list(data.eligibilities, eligibility); if (rows.some(item => item.userId !== target)) return invalid(); return rows;
  },
  async grantEligibility(body: { userId: string; role: string; maxDurationSeconds: number; validForSeconds: number; reason: string }) {
    const response = await api.post(base + '/eligibilities', body); const created = eligibility(response.data);
    const lifetime = (Date.parse(created.expiresAt) - Date.parse(created.createdAt)) / 1000;
    if (response.status !== 201 || created.userId !== body.userId || created.role !== body.role || created.status !== 'eligible' || created.maxDurationSeconds !== body.maxDurationSeconds
      || created.reason !== body.reason.trim() || Math.abs(lifetime - body.validForSeconds) > 5) return invalid(); return created;
  },
  async revokeEligibility(id: string) {
    const response = await api.delete(base + '/eligibilities/' + canonicalRoleUser(id));
    if (response.status !== 200 || response.data?.id !== id || response.data.revoked !== true) return invalid();
  },
  async request(body: { id: string; eligibilityId: string; durationSeconds: number; reason: string }) {
    const response = await api.post(base + '/requests', body); const created = request(response.data);
    if (response.status !== 200 || created.id !== body.id || created.eligibilityId !== body.eligibilityId || created.durationSeconds !== body.durationSeconds || created.reason !== body.reason.trim()) return invalid(); return created;
  },
  async change(id: string, action: PIMAction) {
    const response = await api.post(`${base}/requests/${canonicalRoleUser(id)}/${action}`, {}); const changed = request(response.data);
    const expected = { approve: ['approved'], deny: ['denied'], activate: ['active'], cancel: ['cancelled', 'revoked'], revoke: ['cancelled', 'revoked'] };
    if (response.status !== 200 || changed.id !== id || !expected[action].includes(changed.status)) return invalid(); return changed;
  },
};
