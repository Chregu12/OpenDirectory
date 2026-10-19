import { api } from './api';
import { LicenseGrant, parseLicenseGrant } from './licenseGrants';
export interface LicenseDelegation { id: string; licenseId: string; userId: string; duty: 'reader' | 'allocator' | 'approver'; version: string; createdAt: string; expiresAt: string; revokedAt: string | null; state: 'active' | 'expired' | 'revoked' }
export interface ScopedPool { id: string; name: string; vendor: string | null; licenseType: string; totalSeats: number; usedSeats: number }
export interface ScopedRequest { id: string; assigneeType: string; assigneeId: string; requesterId: string; identityBound: boolean; justification: string | null; requestedAt: string }
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const bad = () => { throw new Error('Unbestätigte Delegationsantwort. Neu laden, nicht blind wiederholen.'); };
const version = (value: unknown): value is string => typeof value === 'string' && /^[1-9]\d{0,18}$/.test(value) && BigInt(value) <= BigInt('9223372036854775807');
const date = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value));
const id = (value: string) => UUID.test(value) ? value : bad();
const tag = (row: LicenseDelegation) => `"od-license-delegation:${row.id}:${row.version}"`;
function parse(value: unknown): LicenseDelegation {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return bad(); const row = value as LicenseDelegation;
  if (Object.keys(row).length !== 9 || [row.id,row.licenseId,row.userId].some(value => !UUID.test(value)) || !version(row.version)
    || !['reader','allocator','approver'].includes(row.duty) || !date(row.createdAt) || !date(row.expiresAt) || Date.parse(row.createdAt) >= Date.parse(row.expiresAt)
    || row.revokedAt !== null && !date(row.revokedAt) || !['active','expired','revoked'].includes(row.state) || (row.revokedAt !== null) !== (row.state === 'revoked')) return bad();
  return row;
}
function accepted(result: { status: number; headers?: Record<string, unknown> }, expected = 200, expectedTag?: string) { if (result.status !== expected || expectedTag && result.headers?.etag !== expectedTag) bad(); }
function page(rows: { id: string }[], hasMore: boolean, nextAfter: unknown) { if (hasMore ? rows.length !== 100 || nextAfter !== rows[99].id : nextAfter !== null) bad(); }
const base = '/api/licenses/delegations'; const poolPath = (licenseId: string) => `/api/licenses/scoped/pools/${id(licenseId)}`;
export const licenseDelegations = {
  async self(userId: string) { const result = await api.get(base + '/self'); accepted(result);
    if (!result.data || Object.keys(result.data).length !== 3 || result.data.userId !== id(userId) || !Array.isArray(result.data.delegations) || result.data.delegations.length > 100 || typeof result.data.truncated !== 'boolean') return bad();
    const rows = result.data.delegations.map(parse) as LicenseDelegation[]; if (rows.some(row => row.userId !== userId || row.state !== 'active') || new Set(rows.map(row => row.id)).size !== rows.length) return bad();
    return { delegations: rows, truncated: result.data.truncated as boolean }; },
  async list(licenseId: string) { const result = await api.get(`${base}/pools/${id(licenseId)}`); accepted(result); const value = result.data;
    if (!value || Object.keys(value).length !== 4 || value.licenseId !== licenseId || !Array.isArray(value.delegations) || value.delegations.length > 100 || typeof value.hasMore !== 'boolean' || value.nextAfter !== null && !UUID.test(value.nextAfter)) return bad();
    const rows = value.delegations.map(parse) as LicenseDelegation[]; if (rows.some(row => row.licenseId !== licenseId) || new Set(rows.map(row => row.id)).size !== rows.length) return bad();
    page(rows,value.hasMore,value.nextAfter); return { delegations: rows, hasMore: value.hasMore as boolean }; },
  async create(body: { licenseId: string; userId: string; duty: string; durationSeconds: number; reason: string; confirm: true }) {
    const result = await api.post(base, body); const row = parse(result.data); accepted(result, 201, tag(row));
    if (row.licenseId !== body.licenseId || row.userId !== body.userId || row.duty !== body.duty || row.version !== '1' || row.state !== 'active') return bad(); return row; },
  async revoke(row: LicenseDelegation, reason: string) { const result = await api.post(`${base}/${row.id}/revoke`, { reason, confirm: true }, { headers: { 'If-Match': tag(row) } }); const current = parse(result.data); accepted(result, 200, tag(current));
    if (current.id !== row.id || current.licenseId !== row.licenseId || current.userId !== row.userId || current.duty !== row.duty || current.expiresAt !== row.expiresAt || current.createdAt !== row.createdAt || current.state !== 'revoked' || BigInt(current.version) !== BigInt(row.version) + BigInt(1)) return bad(); return current; },
  async pool(licenseId: string) { const result = await api.get(poolPath(licenseId)); accepted(result); const row = result.data as ScopedPool;
    if (!row || Object.keys(row).length !== 6 || row.id !== licenseId || typeof row.name !== 'string' || row.vendor !== null && typeof row.vendor !== 'string' || !['per_user','subscription'].includes(row.licenseType)
      || !Number.isSafeInteger(row.totalSeats) || row.totalSeats < 0 || !Number.isSafeInteger(row.usedSeats) || row.usedSeats < 0) return bad(); return row; },
  async grants(licenseId: string) { const result = await api.get(poolPath(licenseId) + '/grants'); accepted(result); const value = result.data;
    if (!value || Object.keys(value).length !== 3 || !Array.isArray(value.grants) || value.grants.length > 100 || typeof value.hasMore !== 'boolean' || value.nextAfter !== null && !UUID.test(value.nextAfter)) return bad();
    const rows = value.grants.map((row: LicenseGrant) => { if (!row || !UUID.test(row.id)) return bad(); return parseLicenseGrant(row, licenseId, row.id); }); if (new Set(rows.map((row: LicenseGrant) => row.id)).size !== rows.length) return bad();
    page(rows,value.hasMore,value.nextAfter);
    return { grants: rows as LicenseGrant[], hasMore: value.hasMore as boolean }; },
  async assign(licenseId: string, assigneeType: string, assigneeId: string, reason: string) { const result = await api.post(poolPath(licenseId) + '/assign', { assigneeType, assigneeId: id(assigneeId), expiresAt: null, reason, confirm: true }); accepted(result, 201); const value = result.data;
    if (!value || Object.keys(value).length !== 5 || value.licenseId !== licenseId || value.assigneeType !== assigneeType || value.assigneeId !== assigneeId || value.localOnly !== true || !(assigneeType==='user'?['assigned']:assigneeType==='group'?['active','capacity-blocked']:[]).includes(value.status)) return bad(); return value.status as string; },
  async requests(licenseId: string) { const result = await api.get(poolPath(licenseId) + '/requests'); accepted(result); const value = result.data;
    if (!value || Object.keys(value).length !== 4 || value.licenseId !== licenseId || !Array.isArray(value.requests) || value.requests.length > 100 || typeof value.hasMore !== 'boolean' || value.nextAfter !== null && !UUID.test(value.nextAfter)) return bad();
    for (const row of value.requests) if (!row || Object.keys(row).length !== 7 || !UUID.test(row.id) || !['user','group','device'].includes(row.assigneeType) || typeof row.assigneeId !== 'string' || typeof row.requesterId !== 'string' || typeof row.identityBound !== 'boolean' || row.identityBound && (!UUID.test(row.requesterId)||row.assigneeType!=='device'&&!UUID.test(row.assigneeId)) || row.justification !== null && typeof row.justification !== 'string' || !date(row.requestedAt)) return bad();
    if (new Set(value.requests.map((row: ScopedRequest) => row.id)).size !== value.requests.length) return bad();
    page(value.requests,value.hasMore,value.nextAfter);
    return { requests: value.requests as ScopedRequest[], hasMore: value.hasMore as boolean }; },
  async review(licenseId: string, request: ScopedRequest, decision: 'approved' | 'denied', reason: string) { const result = await api.post(poolPath(licenseId) + `/requests/${request.id}/decisions`, { decision, reason, confirm: true }); accepted(result); const value = result.data;
    if (!value || Object.keys(value).length !== 5 || value.id !== request.id || value.licenseId !== licenseId || value.status !== decision || value.localOnly !== true || value.allocationStatus !== null && (decision==='denied'||!['active','capacity-blocked'].includes(value.allocationStatus))) return bad(); return value.allocationStatus as string | null; },
};
