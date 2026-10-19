import { api } from './api';
import { requireDirectoryRead } from './directoryUsers';

export interface CatalogRole { role: string; protected: boolean; assignable: boolean }
export interface RoleAssignment { id: string; userId: string; role: string; reason: string; createdAt: string; expiresAt: string | null; revokedAt: string | null; status: 'active' | 'expired' | 'revoked' | 'policy_changed' | 'review_expired' }
export interface RolePage { userId: string; assignments: RoleAssignment[]; truncated: boolean }
export function canonicalRoleUser(value: string) {
  if (typeof value !== 'string' || value.length !== 36 || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value)) throw new Error('Kanonische Verzeichnis-ID erforderlich.');
  return value.toLowerCase();
}
function unconfirmed(): never { throw new Error('Rollenänderung oder Daten nicht bestätigt. Vor einem weiteren Versuch neu laden.'); }
function timestamp(value: unknown) { return typeof value === 'string' && Number.isFinite(Date.parse(value)); }
function assignment(value: any): RoleAssignment {
  canonicalRoleUser(value?.id); canonicalRoleUser(value?.userId);
  if (typeof value.role !== 'string' || !/^[a-z][a-z-]{0,63}$/.test(value.role) || typeof value.reason !== 'string'
    || !timestamp(value.createdAt) || (value.expiresAt !== null && !timestamp(value.expiresAt)) || (value.revokedAt !== null && !timestamp(value.revokedAt))
    || !['active', 'expired', 'revoked', 'policy_changed', 'review_expired'].includes(value.status) || ((value.status === 'revoked') !== (value.revokedAt !== null))
    || (value.status === 'expired' && value.expiresAt === null)
    || (value.expiresAt !== null && Date.parse(value.expiresAt) <= Date.parse(value.createdAt))
    || (value.revokedAt !== null && Date.parse(value.revokedAt) < Date.parse(value.createdAt))) return unconfirmed();
  return { id: value.id, userId: value.userId, role: value.role, reason: value.reason, createdAt: value.createdAt, expiresAt: value.expiresAt, revokedAt: value.revokedAt, status: value.status };
}
export const directoryRoles = {
  async catalog(signal?: AbortSignal): Promise<CatalogRole[]> {
    const { data } = await api.get('/api/identity/roles/catalog', { signal });
    if (!Array.isArray(data?.roles) || !data.roles.length || data.roles.length > 100 || data.minDurationSeconds !== 60 || data.maxDurationSeconds !== 28800
      || data.roles.some((item: any) => typeof item.role !== 'string' || !/^[a-z][a-z-]{0,63}$/.test(item.role) || typeof item.protected !== 'boolean' || typeof item.assignable !== 'boolean')
      || new Set(data.roles.map((item: CatalogRole) => item.role)).size !== data.roles.length) return unconfirmed();
    return data.roles.map((item: CatalogRole) => ({ role: item.role, protected: item.protected, assignable: item.assignable }));
  },
  async list(userId: string, signal?: AbortSignal): Promise<RolePage> {
    const target = canonicalRoleUser(userId); await requireDirectoryRead(); const { data } = await api.get(`/api/users/${target}/roles`, { signal });
    if (data?.userId !== target || !Array.isArray(data.assignments) || data.assignments.length > 100 || typeof data.truncated !== 'boolean') return unconfirmed();
    const assignments = data.assignments.map(assignment);
    if (assignments.some((item: RoleAssignment) => item.userId !== target) || new Set(assignments.map((item: RoleAssignment) => item.id)).size !== assignments.length) return unconfirmed();
    return { userId: target, assignments, truncated: data.truncated };
  },
  async grant(userId: string, role: string, durationSeconds: number, reason: string) {
    const target = canonicalRoleUser(userId); const response = await api.post(`/api/users/${target}/roles`, { role, durationSeconds, reason });
    const created = assignment(response.data);
    if (response.status !== 201 || created.userId !== target || created.role !== role || created.status !== 'active' || created.expiresAt === null || created.revokedAt !== null) return unconfirmed();
    const lifetime = (Date.parse(created.expiresAt) - Date.parse(created.createdAt)) / 1000;
    if (created.reason !== reason.trim() || lifetime < durationSeconds - 5 || lifetime > durationSeconds + 5) return unconfirmed();
    return created;
  },
  async revoke(userId: string, assignmentId: string) {
    const target = canonicalRoleUser(userId); const identifier = canonicalRoleUser(assignmentId);
    const { data, status } = await api.delete(`/api/users/${target}/roles/${identifier}`);
    if (status !== 200 || data?.id !== identifier || data.userId !== target || data.revoked !== true) return unconfirmed();
  },
};
