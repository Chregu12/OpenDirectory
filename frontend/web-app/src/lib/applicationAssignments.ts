import { api } from './api';
import { canonicalRoleUser } from './directoryRoles';

export interface ApplicationAssignment { id: string; clientId: string; targetType: 'user' | 'group'; targetId: string; targetRevision: string; reason: string; durationSeconds: number; createdAt: string; expiresAt: string; revokedAt: string | null; status: 'active' | 'expired' | 'revoked' }
export interface ApplicationAssignmentPage { clientId: string; name: string; protected: boolean; assignmentRequired: true; canManage: boolean; assignments: ApplicationAssignment[]; truncated: boolean }
export interface ApplicationGrant { requestId: string; targetType: 'user' | 'group'; targetId: string; reason: string; durationSeconds: number }
function invalid(): never { throw new Error('Anwendungszuweisung nicht bestätigt. Aktuellen Stand prüfen; keine automatische Wiederholung.'); }
function clientId(value: string) { if (typeof value !== 'string' || !/^[A-Za-z0-9._~-]{1,255}$/.test(value) || value.trim() !== value) return invalid(); return value; }
const date = (value: unknown) => typeof value === 'string' && Number.isFinite(Date.parse(value));
function assignment(value: any): ApplicationAssignment {
  canonicalRoleUser(value?.id); canonicalRoleUser(value?.targetId); clientId(value?.clientId);
  if (!['user','group'].includes(value.targetType) || typeof value.targetRevision !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.targetRevision)
    || BigInt(value.targetRevision).toString() !== value.targetRevision || BigInt(value.targetRevision) > BigInt('9223372036854775807')
    || typeof value.reason !== 'string' || value.reason.trim().length < 10 || value.reason.length > 500 || !Number.isInteger(value.durationSeconds) || value.durationSeconds < 60 || value.durationSeconds > 2592000
    || !date(value.createdAt) || !date(value.expiresAt) || (value.revokedAt !== null && !date(value.revokedAt))
    || !['active','expired','revoked'].includes(value.status) || ((value.status === 'revoked') !== (value.revokedAt !== null))) return invalid();
  const lifetime = (Date.parse(value.expiresAt) - Date.parse(value.createdAt)) / 1000;
  if (Math.abs(lifetime - value.durationSeconds) > 1) return invalid();
  return value;
}
export function assignmentRequestId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16)); bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
  const value = Array.from(bytes, byte => byte.toString(16).padStart(2,'0')).join('');
  return `${value.slice(0,8)}-${value.slice(8,12)}-${value.slice(12,16)}-${value.slice(16,20)}-${value.slice(20)}`;
}
export const applicationAssignments = {
  async list(identifier: string, signal?: AbortSignal): Promise<ApplicationAssignmentPage> {
    const target = clientId(identifier); const { data } = await api.get(`/api/clients/${encodeURIComponent(target)}/assignments`,{ signal });
    if (data?.clientId !== target || typeof data.name !== 'string' || typeof data.protected !== 'boolean' || data.assignmentRequired !== true || typeof data.canManage !== 'boolean'
      || typeof data.truncated !== 'boolean' || !Array.isArray(data.assignments) || data.assignments.length > 100) return invalid();
    const assignments = data.assignments.map(assignment);
    if (assignments.some((row: ApplicationAssignment) => row.clientId !== target) || new Set(assignments.map((row: ApplicationAssignment) => row.id)).size !== assignments.length) return invalid();
    return { ...data,assignments };
  },
  async grant(identifier: string, input: ApplicationGrant) {
    const target = clientId(identifier); canonicalRoleUser(input.requestId); canonicalRoleUser(input.targetId);
    const { data,status } = await api.post(`/api/clients/${encodeURIComponent(target)}/assignments`,input);
    if (![200,201].includes(status) || typeof data?.reused !== 'boolean' || (status === 200) !== data.reused) return invalid();
    const created = assignment(data.assignment);
    if (created.clientId !== target || created.id !== input.requestId || created.targetType !== input.targetType || created.targetId !== input.targetId.toLowerCase()
      || created.reason !== input.reason.trim() || created.durationSeconds !== input.durationSeconds || created.status !== 'active' || created.revokedAt !== null) return invalid();
    return created;
  },
  async revoke(identifier: string, row: ApplicationAssignment) {
    const target = clientId(identifier); const id = canonicalRoleUser(row.id);
    const { data,status } = await api.delete(`/api/clients/${encodeURIComponent(target)}/assignments/${id}`);
    if (status !== 200) return invalid(); const result = assignment(data?.assignment);
    if (result.id !== row.id || result.clientId !== target || result.targetId !== row.targetId || result.targetType !== row.targetType || result.status !== 'revoked'
      || result.targetRevision !== row.targetRevision || result.reason !== row.reason || result.durationSeconds !== row.durationSeconds || result.createdAt !== row.createdAt || result.expiresAt !== row.expiresAt) return invalid();
  },
};
