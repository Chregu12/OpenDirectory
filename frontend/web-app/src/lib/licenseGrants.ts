import { api } from './api';

export interface LicenseGrant {
  id: string;
  licenseId: string;
  kind: 'direct' | 'group';
  recipientId: string;
  version: string;
  origin: 'observed' | 'allocated';
  createdAt: string;
  expiresAt: string | null;
  state: 'active' | 'expired' | 'revoked' | 'deleted';
  sourceUsers: number;
}

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const invalid = () => { throw new Error('Ungültige Antwort zur Lizenzquelle. Neu laden, nicht blind wiederholen.'); };
const etag = (grant: LicenseGrant) => `"od-license-grant:${grant.id}:${grant.version}"`;
const count = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;

export function parseLicenseGrant(value: unknown, licenseId: string, grantId: string): LicenseGrant {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const grant = value as LicenseGrant;
  if (Object.keys(grant).length !== 10 || grant.id !== grantId || grant.licenseId !== licenseId
    || !['direct', 'group'].includes(grant.kind) || !['observed', 'allocated'].includes(grant.origin)
    || !['active', 'expired', 'revoked', 'deleted'].includes(grant.state) || typeof grant.recipientId !== 'string' || !grant.recipientId.trim()
    || typeof grant.version !== 'string' || !/^[1-9]\d{0,18}$/.test(grant.version) || BigInt(grant.version) > BigInt('9223372036854775807')
    || typeof grant.createdAt !== 'string' || !Number.isFinite(Date.parse(grant.createdAt))
    || grant.expiresAt !== null && (typeof grant.expiresAt !== 'string' || !Number.isFinite(Date.parse(grant.expiresAt))) || !count(grant.sourceUsers)) return invalid();
  return grant;
}

export async function readLicenseGrant(licenseId: string, grantId: string): Promise<LicenseGrant> {
  if (!UUID.test(licenseId) || !UUID.test(grantId)) return invalid();
  const result = await api.get(`/api/licenses/${licenseId}/grants/${grantId}`);
  const grant = parseLicenseGrant(result.data, licenseId, grantId);
  if (result.status !== 200 || result.headers?.etag !== etag(grant)) return invalid();
  return grant;
}

export async function revokeLicenseGrant(grant: LicenseGrant, reason: string, scoped = false) {
  const prefix = scoped ? `/api/licenses/scoped/pools/${grant.licenseId}` : `/api/licenses/${grant.licenseId}`;
  const result = await api.post(`${prefix}/grants/${grant.id}/revoke`, { confirm: true, reason: reason.trim() }, { headers: { 'If-Match': etag(grant) } });
  const receipt = result.data;
  if (!receipt || Object.keys(receipt).length !== 4 || receipt.localOnly !== true || !count(receipt.sourcesRemoved)
    || !count(receipt.usersRetainingAssignment) || receipt.sourcesRemoved !== grant.sourceUsers || receipt.usersRetainingAssignment > receipt.sourcesRemoved) return invalid();
  const current = parseLicenseGrant(receipt.grant, grant.licenseId, grant.id);
  if (result.status !== 200 || result.headers?.etag !== etag(current) || current.state !== 'revoked' || current.sourceUsers !== 0
    || BigInt(current.version) <= BigInt(grant.version) || current.kind !== grant.kind || current.recipientId !== grant.recipientId
    || current.origin !== grant.origin || current.createdAt !== grant.createdAt || current.expiresAt !== grant.expiresAt) return invalid();
  return { usersRetainingAssignment: receipt.usersRetainingAssignment as number };
}
