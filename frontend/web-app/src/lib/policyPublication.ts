import { api } from './api';
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const hash = /^[a-f0-9]{64}$/;
const identifier = (value: unknown): value is string => typeof value === 'string' && uuid.test(value);
const digest = (value: unknown): value is string => typeof value === 'string' && hash.test(value);
export type PublicationKind = 'policy' | 'blueprint';
export interface Publication { id: string; resourceKind: PublicationKind; resourceId: string; resourceVersion: number; configurationVersion: number; configurationHash: string; requestedBy: string; reviewerUserId: string; state: 'pending' | 'approved' | 'denied' | 'withdrawn'; version: number; expiresAt: string; decidedBy: string | null; current: boolean }
export interface PublicationFrame { schemaVersion: 1; resourceKind: PublicationKind; resourceId: string; resourceVersion: number; configurationVersion: number; configurationHash: string; frame: { resource: Record<string, unknown>; configurationVersion: number; assignments: unknown[]; children: unknown[] }; verifiedOrigin: boolean; contributors: string[]; publications: Publication[]; total: number; limit: 50 }
const fail = (): never => { throw new Error('Richtlinienfreigabe nicht bestätigt. Daten und Rechte neu laden; keinen Schreibzugriff automatisch wiederholen.'); };
const root = (kind: PublicationKind, id: string) => { if (!['policy', 'blueprint'].includes(kind) || !identifier(id)) return fail(); return `/api/${kind === 'policy' ? 'policies' : 'blueprints'}/${id}/publications`; };
export const publicationTag = (row: Publication) => `"od-policy-publication:${row.id}:${row.version}"`;
function parse(row: Publication, kind: PublicationKind, id: string): Publication {
  if (!row || !identifier(row.id) || row.resourceKind !== kind || row.resourceId !== id || !Number.isSafeInteger(row.resourceVersion) || row.resourceVersion < 1
    || !Number.isSafeInteger(row.configurationVersion) || row.configurationVersion < 1 || row.configurationVersion > row.resourceVersion || !digest(row.configurationHash)
    || !identifier(row.requestedBy) || !identifier(row.reviewerUserId) || row.requestedBy === row.reviewerUserId || !['pending', 'approved', 'denied', 'withdrawn'].includes(row.state)
    || !Number.isSafeInteger(row.version) || row.version < 1 || typeof row.current !== 'boolean' || row.current && row.state !== 'approved' || row.decidedBy !== null && !identifier(row.decidedBy)
    || typeof row.expiresAt !== 'string' || !Number.isFinite(Date.parse(row.expiresAt)) || new Date(row.expiresAt).toISOString() !== row.expiresAt) return fail();
  return row;
}
export const policyPublication = {
  async get(kind: PublicationKind, id: string, version: number, signal?: AbortSignal): Promise<PublicationFrame> {
    const result = await api.get(root(kind, id), { signal }); const row = result.data as PublicationFrame;
    if (result.status !== 200 || !row || row.schemaVersion !== 1 || row.resourceKind !== kind || row.resourceId !== id || row.resourceVersion !== version
      || !Number.isSafeInteger(row.configurationVersion) || row.configurationVersion < 1 || row.configurationVersion > version || !digest(row.configurationHash) || typeof row.verifiedOrigin !== 'boolean'
      || !row.frame || !row.frame.resource || row.frame.resource.id !== id || row.frame.configurationVersion !== row.configurationVersion || !Array.isArray(row.frame.assignments) || !Array.isArray(row.frame.children)
      || row.frame.assignments.length + row.frame.children.length > 2000 || !Array.isArray(row.contributors) || row.contributors.length > 1000 || row.contributors.some(value => !identifier(value))
      || new Set(row.contributors).size !== row.contributors.length || !Array.isArray(row.publications) || row.publications.length > 50 || row.limit !== 50 || !Number.isSafeInteger(row.total) || row.total < row.publications.length) return fail();
    row.publications.forEach(item => parse(item, kind, id)); if (new Set(row.publications.map(item => item.id)).size !== row.publications.length) return fail(); return row;
  },
  async request(frame: PublicationFrame, reviewerUserId: string, validitySeconds: number, reason: string, userId: string): Promise<Publication> {
    if (!identifier(reviewerUserId) || reviewerUserId === userId || frame.contributors.includes(reviewerUserId) || !frame.verifiedOrigin || !Number.isInteger(validitySeconds) || validitySeconds < 300 || validitySeconds > 28800) return fail();
    const result = await api.post(root(frame.resourceKind, frame.resourceId), { reviewerUserId, validitySeconds, configurationHash: frame.configurationHash, reason, acknowledgeScope: true },
      { headers: { 'If-Match': `"od-${frame.resourceKind}:${frame.resourceId}:${frame.resourceVersion}"` } });
    const row = parse(result.data, frame.resourceKind, frame.resourceId);
    if (result.status !== 201 || result.headers?.etag !== publicationTag(row) || row.version !== 1 || row.state !== 'pending' || row.requestedBy !== userId || row.reviewerUserId !== reviewerUserId
      || row.resourceVersion !== frame.resourceVersion || row.configurationVersion !== frame.configurationVersion || row.configurationHash !== frame.configurationHash || row.current || row.decidedBy !== null) return fail(); return row;
  },
  async decide(frame: PublicationFrame, current: Publication, decision: 'approved' | 'denied' | 'withdrawn', reason: string, userId: string): Promise<Publication> {
    parse(current, frame.resourceKind, frame.resourceId);
    const result = await api.post(`${root(frame.resourceKind, frame.resourceId)}/${current.id}/decisions`, { decision, resourceVersion: frame.resourceVersion, configurationHash: current.configurationHash, reason, acknowledgeScope: true },
      { headers: { 'If-Match': publicationTag(current) } });
    const row = parse(result.data, frame.resourceKind, frame.resourceId);
    if (result.status !== 200 || result.headers?.etag !== publicationTag(row) || row.id !== current.id || row.version !== current.version + 1 || row.state !== decision
      || row.resourceVersion !== current.resourceVersion || row.configurationVersion !== current.configurationVersion || row.configurationHash !== current.configurationHash
      || row.requestedBy !== current.requestedBy || row.reviewerUserId !== current.reviewerUserId || row.expiresAt !== current.expiresAt || row.decidedBy !== userId) return fail(); return row;
  },
};
