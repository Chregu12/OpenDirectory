import { api } from './api';

const permissions = ['policies.read', 'policies.preview', 'policies.audit.read', 'policies.manage', 'policies.deploy', 'policies.publication.request', 'policies.publication.review'];
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
export interface PolicyAccess { schemaVersion: 4; subject: string; userId: string; permissions: string[]; freshMfa: boolean; writeAuthenticationMaxAgeSeconds: 300 }
export interface CanonicalPolicy { id: string; name: string; type: string; platform: string; status: string; version: number; settings: Record<string, unknown>; created_by: string | null }
export interface PolicyDraft { name: string; type: string; platform: string; settings: Record<string, unknown> }
export const policyTag = (row: CanonicalPolicy) => `"od-policy:${row.id}:${row.version}"`;
function unconfirmed(): never { throw new Error('Richtlinienänderung nicht bestätigt. Berechtigungen und Daten neu laden; nicht blind wiederholen.'); }
export function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).sort(([first], [second]) => first.localeCompare(second)).map(([key, item]) => [key, canonical(item)]));
  return value;
}
function parse(row: CanonicalPolicy): CanonicalPolicy {
  if (!row || !uuid.test(row.id) || typeof row.name !== 'string' || !row.name || typeof row.type !== 'string' || !row.type
    || typeof row.platform !== 'string' || !['draft', 'active', 'inactive', 'archived'].includes(row.status) || !Number.isSafeInteger(row.version) || row.version < 1
    || !row.settings || typeof row.settings !== 'object' || Array.isArray(row.settings) || row.created_by !== null && typeof row.created_by !== 'string') return unconfirmed();
  return { id: row.id, name: row.name, type: row.type, platform: row.platform, status: row.status, version: row.version, settings: row.settings, created_by: row.created_by };
}
export const policyGovernance = {
  async access(signal?: AbortSignal): Promise<PolicyAccess> {
    const result = await api.get('/api/policies/access', { signal }); const row = result.data;
    if (result.status !== 200 || !row || Object.keys(row).length !== 6 || row.schemaVersion !== 4 || typeof row.subject !== 'string' || !row.subject
      || !uuid.test(row.userId) || typeof row.freshMfa !== 'boolean' || row.writeAuthenticationMaxAgeSeconds !== 300 || !Array.isArray(row.permissions)
      || row.permissions.some((permission: unknown) => typeof permission !== 'string' || !permissions.includes(permission))
      || new Set(row.permissions).size !== row.permissions.length) return unconfirmed();
    return row;
  },
  async list(signal?: AbortSignal): Promise<{ policies: CanonicalPolicy[]; total: number }> {
    const result = await api.get('/api/policies', { params: { page: 1, limit: 50 }, signal }); const row = result.data;
    if (result.status !== 200 || !row || !Array.isArray(row.policies) || row.policies.length > 50 || !Number.isSafeInteger(row.total) || row.total < row.policies.length || row.page !== 1 || row.limit !== 50) return unconfirmed();
    const policies: CanonicalPolicy[] = row.policies.map(parse);
    if (new Set(policies.map(policy => policy.id)).size !== policies.length) return unconfirmed();
    return { policies, total: row.total };
  },
  async create(draft: PolicyDraft, userId: string, reason: string): Promise<CanonicalPolicy> {
    const result = await api.post('/api/policies', { ...draft, reason, acknowledgeScope: true }); const row = parse(result.data);
    if (result.status !== 201 || row.name !== draft.name || row.type !== draft.type || row.platform !== draft.platform || row.status !== 'draft'
      || row.created_by !== userId || row.version !== 1 || result.headers?.etag !== policyTag(row) || JSON.stringify(canonical(row.settings)) !== JSON.stringify(canonical(draft.settings))) return unconfirmed();
    return row;
  },
  async transition(current: CanonicalPolicy, action: 'activate' | 'deactivate', reason: string, publicationId?: string): Promise<CanonicalPolicy> {
    if (!uuid.test(current.id) || action === 'activate' && (!publicationId || !uuid.test(publicationId))) return unconfirmed();
    const result = await api.post(`/api/policies/${current.id}/${action}`, { reason, acknowledgeScope: true, ...(action === 'activate' ? { publicationId } : {}) }, { headers: { 'If-Match': policyTag(current) } }); const row = parse(result.data);
    if (result.status !== 200 || row.id !== current.id || row.version !== current.version + 1 || result.headers?.etag !== policyTag(row) || row.name !== current.name || row.type !== current.type
      || JSON.stringify(canonical(row.settings)) !== JSON.stringify(canonical(current.settings)) || row.status !== (action === 'activate' ? 'active' : 'inactive')) return unconfirmed();
    return row;
  },
};
