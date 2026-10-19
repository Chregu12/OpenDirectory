import { api } from './api';

export interface LicenseReviewPolicy {
  id: string; licenseId: string; version: string; intervalSeconds: number; windowSeconds: number;
  reviewerUserIds: string[]; createdAt: string; retiredAt: string | null;
}
export interface LicenseReview {
  id: string; policyId: string; licenseId: string; grantId: string; kind: 'direct' | 'group'; recipientId: string;
  version: string; policyVersion: string; sourceVersion: string; cycle: string; dueAt: string | null; deadlineAt: string | null; baseExpiresAt: string | null;
  state: 'pending' | 'scheduled' | 'expired' | 'exempt' | 'denied' | 'obsolete'; policyRetired: boolean; canDecide: boolean; requiresFreshMfa: boolean; selfReview: boolean;
}
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const version = (value: unknown): value is string => typeof value === 'string' && /^[1-9]\d{0,18}$/.test(value) && BigInt(value) <= BigInt('9223372036854775807');
const date = (value: unknown) => value === null || typeof value === 'string' && Number.isFinite(Date.parse(value));
const invalid = () => { throw new Error('Ungültige Prüfungsantwort. Neu laden, nicht blind wiederholen.'); };
const identifier = (value: string) => { if (!UUID.test(value)) return invalid(); return value; };
const policyTag = (row: LicenseReviewPolicy) => `"od-license-review-policy:${row.id}:${row.version}"`;
const reviewTag = (row: LicenseReview) => `"od-license-review:${row.id}:${row.version}:${row.policyVersion}:${row.sourceVersion}"`;
function policy(value: unknown): LicenseReviewPolicy {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const row = value as LicenseReviewPolicy;
  if (Object.keys(row).length !== 8 || !UUID.test(row.id) || !UUID.test(row.licenseId) || !version(row.version)
    || !Number.isInteger(row.intervalSeconds) || row.intervalSeconds < 3600 || row.intervalSeconds > 31536000
    || !Number.isInteger(row.windowSeconds) || row.windowSeconds < 60 || row.windowSeconds > 604800 || row.windowSeconds >= row.intervalSeconds
    || !Array.isArray(row.reviewerUserIds) || !row.reviewerUserIds.length || row.reviewerUserIds.length > 20
    || row.reviewerUserIds.some((value, index) => !UUID.test(value) || index > 0 && row.reviewerUserIds[index - 1] >= value)
    || !date(row.createdAt) || row.createdAt === null || !date(row.retiredAt)) return invalid();
  return row;
}
function review(value: unknown): LicenseReview {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const row = value as LicenseReview;
  if (Object.keys(row).length !== 18 || [row.id, row.policyId, row.licenseId, row.grantId, row.recipientId].some(value => !UUID.test(value))
    || !['direct', 'group'].includes(row.kind) || [row.version, row.policyVersion, row.sourceVersion, row.cycle].some(value => !version(value))
    || [row.dueAt, row.deadlineAt, row.baseExpiresAt].some(value => !date(value)) || (row.dueAt === null) !== (row.deadlineAt === null)
    || row.dueAt && row.deadlineAt && Date.parse(row.dueAt) >= Date.parse(row.deadlineAt)
    || !['pending', 'scheduled', 'expired', 'exempt', 'denied', 'obsolete'].includes(row.state)
    || ['pending', 'scheduled', 'expired'].includes(row.state) && (!row.dueAt || !row.deadlineAt)
    || [row.policyRetired, row.canDecide, row.requiresFreshMfa, row.selfReview].some(value => typeof value !== 'boolean')
    || row.canDecide && (row.requiresFreshMfa || row.selfReview || row.state !== 'pending')
    || row.requiresFreshMfa && (row.selfReview || row.state !== 'pending')
    || row.state === 'exempt' && (!row.policyRetired || row.dueAt !== null || row.deadlineAt !== null)) return invalid();
  return row;
}
function envelope(result: { status: number; headers?: Record<string, unknown> }, status: number, tag?: string) {
  if (result.status !== status || tag && result.headers?.etag !== tag) invalid();
}
const base = '/api/licenses/reviews';
export const licenseReviews = {
  async policy(licenseId: string) {
    const result = await api.get(`${base}/policies/${identifier(licenseId)}`); envelope(result, 200);
    if (!result.data || Object.keys(result.data).length !== 2 || result.data.licenseId !== licenseId) return invalid();
    const row = result.data.policy === null ? null : policy(result.data.policy);
    if (row) { if (row.licenseId !== licenseId) return invalid(); envelope(result, 200, policyTag(row)); }
    return row;
  },
  async create(body: { licenseId: string; intervalSeconds: number; windowSeconds: number; reviewerUserIds: string[]; reason: string; acknowledgeDeadlines: true }) {
    const result = await api.post(`${base}/policies`, body); const row = policy(result.data); envelope(result, 201, policyTag(row));
    if (row.licenseId !== body.licenseId || row.retiredAt !== null || row.version !== '1' || row.intervalSeconds !== body.intervalSeconds || row.windowSeconds !== body.windowSeconds
      || JSON.stringify(row.reviewerUserIds) !== JSON.stringify(body.reviewerUserIds)) return invalid(); return row;
  },
  async retire(row: LicenseReviewPolicy, reason: string) {
    const result = await api.post(`${base}/policies/${row.id}/retire`, { reason, acknowledgeDeadlines: true }, { headers: { 'If-Match': policyTag(row) } });
    const changed = policy(result.data); envelope(result, 200, policyTag(changed));
    if (changed.id !== row.id || changed.licenseId !== row.licenseId || !changed.retiredAt || BigInt(changed.version) !== BigInt(row.version) + BigInt(1)
      || changed.createdAt !== row.createdAt || changed.intervalSeconds !== row.intervalSeconds || changed.windowSeconds !== row.windowSeconds
      || JSON.stringify(changed.reviewerUserIds) !== JSON.stringify(row.reviewerUserIds)) return invalid(); return changed;
  },
  async get(id: string) {
    const result = await api.get(`${base}/${identifier(id)}`); const row = review(result.data); envelope(result, 200, reviewTag(row));
    if (row.id !== id) return invalid(); return row;
  },
  async self(userId: string) {
    const result = await api.get(`${base}/self`); envelope(result, 200);
    if (!result.data || Object.keys(result.data).length !== 3 || result.data.userId !== identifier(userId) || !Array.isArray(result.data.reviews)
      || result.data.reviews.length > 100 || typeof result.data.truncated !== 'boolean') return invalid();
    const rows = result.data.reviews.map(review) as LicenseReview[];
    if (new Set(rows.map(row => row.id)).size !== rows.length) return invalid();
    return { userId: result.data.userId as string, reviews: rows, truncated: result.data.truncated as boolean };
  },
  async decide(row: LicenseReview, decision: 'retain' | 'deny', reason: string) {
    const result = await api.post(`${base}/${row.id}/decisions`, { decision, reason, acknowledgeScope: true }, { headers: { 'If-Match': reviewTag(row) } });
    const changed = review(result.data); envelope(result, 200, reviewTag(changed));
    if (changed.id !== row.id || changed.grantId !== row.grantId || changed.policyId !== row.policyId || changed.policyVersion !== row.policyVersion
      || changed.licenseId !== row.licenseId || changed.recipientId !== row.recipientId || changed.kind !== row.kind || changed.baseExpiresAt !== row.baseExpiresAt
      || BigInt(changed.version) !== BigInt(row.version) + BigInt(1) || changed.canDecide || changed.policyRetired !== row.policyRetired
      || decision === 'retain' && (changed.sourceVersion !== row.sourceVersion || BigInt(changed.cycle) !== BigInt(row.cycle) + BigInt(1))
      || decision === 'deny' && (BigInt(changed.sourceVersion) <= BigInt(row.sourceVersion) || changed.cycle !== row.cycle)
      || decision === 'deny' && changed.state !== 'denied' || decision === 'retain' && changed.state !== (row.policyRetired ? 'exempt' : 'scheduled')) return invalid();
    return changed;
  },
};
