import { api } from './api';
import { getAccessToken } from './auth';
import { identifier, normalizeReview, CompanyReviewInput } from '../../../../packages/company-registration-contract';
import { normalizeProfile, OrganizationProfile } from '../../../../packages/organization-profile-contract';

export type ReviewStatus = 'pending-verification' | 'pending-activation' | 'rejected' | 'active' | 'suspended';
export interface RegistrationReview {
  schemaVersion: 1; actorUserId: string; registrationId: string; tenantId: string; administratorId: string;
  principal: { username: string; email: string; displayName: string }; profile: OrganizationProfile; createdAt: string;
  status: ReviewStatus; etag: string; canReview: boolean; activationSupported: false;
  review: null | { id: string; decision: 'approved' | 'rejected'; reviewedAt: string; reason: string; reviewerUserId: string };
}
export interface RegistrationQueue { schemaVersion: 1; actorUserId: string; page: number; limit: number; status: ReviewStatus | 'all'; total: number; registrations: RegistrationReview[] }
const path = '/api/identity/company-registrations';
function fail(): never { throw new Error('Firmenprüfung nicht bestätigt. Status neu laden; nicht automatisch erneut senden.'); }
function unchanged(token: string | null) { if (token && token !== getAccessToken()) fail(); }
function detail(value: any, actor: string): RegistrationReview {
  if (value?.schemaVersion !== 1 || !identifier(actor) || value.actorUserId !== actor || !identifier(value.registrationId) || !identifier(value.tenantId) || !identifier(value.administratorId)
    || !['pending-verification', 'pending-activation', 'rejected', 'active', 'suspended'].includes(value.status) || value.activationSupported !== false || typeof value.canReview !== 'boolean'
    || typeof value.createdAt !== 'string' || !Number.isFinite(Date.parse(value.createdAt)) || !['username', 'email', 'displayName'].every(key => typeof value.principal?.[key] === 'string' && value.principal[key].length > 0)) fail();
  normalizeProfile(value.profile);
  const review = value.review;
  if (review === null) { if (value.status !== 'pending-verification' || value.canReview && value.administratorId === actor) fail(); }
  else if (!identifier(review?.id) || !identifier(review.reviewerUserId) || typeof review.reason !== 'string' || review.reason.trim().length < 10 || review.reason.length > 500
    || typeof review.reviewedAt !== 'string' || !Number.isFinite(Date.parse(review.reviewedAt)) || Date.parse(review.reviewedAt) < Date.parse(value.createdAt)
    || !['approved', 'rejected'].includes(review.decision) || value.canReview || (review.decision === 'approved' ? !['pending-activation', 'active', 'suspended'].includes(value.status) : value.status !== 'rejected')) fail();
  const etag = `^"company-review-${value.registrationId}-[a-f0-9]{64}-${review?.id || 'pending'}${['active', 'suspended'].includes(value.status) ? '-' + value.status : ''}"$`;
  if (typeof value.etag !== 'string' || !new RegExp(etag).test(value.etag)) fail(); return value;
}
export function companyReviewError(error: any) {
  return ({ 403: 'Nur ausdrücklich bestellte Plattformprüfer dürfen Firmenanträge einsehen.', 428: 'Eine frische MFA-Anmeldung und die aktuelle Version sind erforderlich.',
    409: 'Dieser Antrag wurde bereits abschliessend geprüft.', 412: 'Der Antrag wurde inzwischen geändert. Bitte neu laden.' } as Record<number, string>)[error?.response?.status]
    || 'Firmenprüfung nicht bestätigt. Status neu laden; nicht automatisch erneut senden.';
}
export const companyRegistrationReviews = {
  async list(actor: string, page = 1, status: ReviewStatus | 'all' = 'pending-verification', signal?: AbortSignal): Promise<RegistrationQueue> {
    if (!identifier(actor) || !Number.isInteger(page) || page < 1 || page > 10000 || !['pending-verification', 'pending-activation', 'rejected', 'active', 'suspended', 'all'].includes(status)) fail();
    const token = getAccessToken(); const result = (await api.get(path, { params: { page, limit: 20, status }, signal })).data; unchanged(token);
    if (result?.schemaVersion !== 1 || result.actorUserId !== actor || result.page !== page || result.limit !== 20 || result.status !== status || !Number.isInteger(result.total) || result.total < 0
      || !Array.isArray(result.registrations) || result.registrations.length > 20 || result.registrations.length > result.total
      || new Set(result.registrations.map((row: any) => row?.registrationId)).size !== result.registrations.length) fail();
    for (const row of result.registrations) { detail(row, actor); if (status !== 'all' && row.status !== status) fail(); } return result;
  },
  async load(id: string, actor: string, signal?: AbortSignal): Promise<RegistrationReview> {
    if (!identifier(id)) fail(); const token = getAccessToken(); const response = await api.get(path + '/' + id, { signal }); unchanged(token);
    const result = detail(response.data, actor); if (result.registrationId !== id || response.headers.etag !== result.etag) fail(); return result;
  },
  async decide(previous: RegistrationReview, input: CompanyReviewInput): Promise<RegistrationReview> {
    const body = normalizeReview(input); if (!previous.canReview || previous.status !== 'pending-verification') fail();
    const token = getAccessToken(); const current = await companyRegistrationReviews.load(previous.registrationId, previous.actorUserId);
    if (!current.canReview || current.etag !== previous.etag) fail(); unchanged(token);
    const response = await api.post(path + '/' + previous.registrationId + '/review', body, { headers: { 'If-Match': previous.etag } }); unchanged(token);
    const saved = detail(response.data, previous.actorUserId);
    if (saved.registrationId !== previous.registrationId || saved.review?.decision !== body.decision || saved.review.reason !== body.reason || saved.review.reviewerUserId !== previous.actorUserId
      || response.headers.etag !== saved.etag) fail();
    const confirmed = await companyRegistrationReviews.load(previous.registrationId, previous.actorUserId); unchanged(token);
    if (confirmed.review?.id !== saved.review.id || confirmed.etag !== saved.etag) fail(); return confirmed;
  },
};
