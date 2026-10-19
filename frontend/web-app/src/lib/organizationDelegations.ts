import { api } from './api';
import { getAccessToken } from './auth';

export interface OrganizationDelegation {
  id: string; userId: string; username: string; name: string; expiresAt: string; createdAt: string; status: 'active' | 'expired' | 'revoked' | 'inactive';
}
export interface OrganizationDelegationsPage {
  schemaVersion: 1; actorUserId: string; tenantId: string; permissions: string[]; canManage: boolean; truncated: boolean; grants: OrganizationDelegation[];
}
const identifier = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
function fail(): never { throw new Error('Organisationsberechtigung nicht bestätigt. Bitte neu laden; nicht automatisch erneut senden.'); }
function unchanged(token: string | null) { if (token && getAccessToken() !== token) fail(); }
function pageFor(value: any, actorUserId: string, tenantId: string): OrganizationDelegationsPage {
  if (value?.schemaVersion !== 1 || !identifier(actorUserId) || !identifier(tenantId) || value.actorUserId !== actorUserId || value.tenantId !== tenantId
    || JSON.stringify(value.permissions) !== JSON.stringify(['organization.read', 'organization.manage']) || typeof value.canManage !== 'boolean' || typeof value.truncated !== 'boolean'
    || !Array.isArray(value.grants) || value.grants.length > 100 || new Set(value.grants.map((grant: any) => grant?.id)).size !== value.grants.length) fail();
  for (const grant of value.grants) {
    if (!identifier(grant?.id) || !identifier(grant.userId) || typeof grant.username !== 'string' || typeof grant.name !== 'string' || !['active', 'expired', 'revoked', 'inactive'].includes(grant.status)
      || !['expiresAt', 'createdAt'].every(field => typeof grant[field] === 'string' && Number.isFinite(Date.parse(grant[field]))) || Date.parse(grant.expiresAt) <= Date.parse(grant.createdAt)) fail();
  }
  return value;
}
export const organizationDelegations = {
  async load(actorUserId: string, tenantId: string, signal?: AbortSignal): Promise<OrganizationDelegationsPage> {
    const token = getAccessToken(); const response = await api.get('/api/identity/organization/delegations', { signal });
    unchanged(token); return pageFor(response.data, actorUserId, tenantId);
  },
  async change(previous: OrganizationDelegationsPage, operation: { userId: string; durationSeconds: number } | { grantId: string }, reason: string): Promise<OrganizationDelegationsPage> {
    const grant = 'userId' in operation;
    if (!previous.canManage || reason.trim().length < 10 || reason.length > 500 || /[\u0000-\u001f\u007f]/.test(reason)
      || grant && (!identifier(operation.userId) || operation.userId === previous.actorUserId || !Number.isInteger(operation.durationSeconds) || operation.durationSeconds < 60 || operation.durationSeconds > 28800)
      || !grant && !previous.grants.some(row => row.id === operation.grantId && row.status !== 'revoked')) fail();
    const token = getAccessToken(); const current = await organizationDelegations.load(previous.actorUserId, previous.tenantId);
    if (!current.canManage) fail(); unchanged(token);
    const response = await api.post(grant ? '/api/identity/organization/delegations' : `/api/identity/organization/delegations/${operation.grantId}/revoke`,
      grant ? { ...operation, reason: reason.trim() } : { reason: reason.trim() });
    unchanged(token); const result = response.data;
    if (result?.schemaVersion !== 1 || result.actorUserId !== previous.actorUserId || result.tenantId !== previous.tenantId || !identifier(result.eventId) || !identifier(result.grantId)
      || !identifier(result.userId) || result.action !== (grant ? 'granted' : 'revoked') || typeof result.expiresAt !== 'string' || !Number.isFinite(Date.parse(result.expiresAt))
      || grant && (result.userId !== operation.userId || result.grantId !== result.eventId) || !grant && result.grantId !== operation.grantId) fail();
    const confirmed = await organizationDelegations.load(previous.actorUserId, previous.tenantId); unchanged(token);
    const row = confirmed.grants.find(entry => entry.id === result.grantId);
    if (!row || row.userId !== result.userId || row.expiresAt !== result.expiresAt || row.status !== (grant ? 'active' : 'revoked')
      || grant && Date.parse(row.expiresAt) - Date.parse(row.createdAt) !== operation.durationSeconds * 1000) fail();
    return confirmed;
  },
};
