import { api } from '@/lib/api';
import { getAccessToken } from '@/lib/auth';
import { companyRegistrationReviews } from '@/lib/companyRegistrationReviews';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
jest.mock('@/lib/auth', () => ({ getAccessToken: jest.fn() }));
const actor = '11111111-1111-4111-8111-111111111111'; const id = '22222222-2222-4222-8222-222222222222'; const eventId = '44444444-4444-4444-8444-444444444444';
const profile = { name: 'Actual Company', legalForm: '', registrationNumber: '', taxId: '', addressLine1: 'Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
const pending: any = { schemaVersion: 1, actorUserId: actor, registrationId: id, tenantId: '33333333-3333-4333-8333-333333333333', administratorId: '55555555-5555-4555-8555-555555555555',
  principal: { username: 'requestor', email: 'person@example.invalid', displayName: 'Requestor' }, profile, createdAt: '2026-10-19T00:00:00Z', status: 'pending-verification',
  etag: `"company-review-${id}-${'a'.repeat(64)}-pending"`, activationSupported: false, canReview: true, review: null };
const body = { decision: 'approved' as const, reason: 'Independent real company review', confirm: true as const };
const saved: any = { ...pending, status: 'pending-activation', canReview: false, etag: `"company-review-${id}-${'a'.repeat(64)}-${eventId}"`,
  review: { id: eventId, decision: 'approved', reason: body.reason, reviewerUserId: actor, reviewedAt: '2026-10-19T01:00:00Z' } };
const response = (data: any) => ({ data, headers: { etag: data.etag } });
beforeEach(() => { jest.resetAllMocks(); (getAccessToken as jest.Mock).mockReturnValue('original'); });
test('queue accepts only an actor-bound paginated real result and passes the filter to the server', async () => {
  const queue = { schemaVersion: 1, actorUserId: actor, page: 1, limit: 20, status: 'pending-verification', total: 1, registrations: [pending] }; (api.get as jest.Mock).mockResolvedValue(response(queue));
  expect(await companyRegistrationReviews.list(actor)).toEqual(queue); expect(api.get).toHaveBeenCalledWith('/api/identity/company-registrations', expect.objectContaining({ params: { page: 1, limit: 20, status: 'pending-verification' } }));
});
test.each([{ ...pending, actorUserId: id }, { ...pending, activationSupported: true }, { ...pending, etag: 'invented' }, { ...pending, profile: { ...profile, website: 'javascript:invalid' } }, { ...saved, canReview: true }])('foreign or unsupported detail is not a success %#', async value => {
  (api.get as jest.Mock).mockResolvedValue(response(value)); await expect(companyRegistrationReviews.load(id, actor)).rejects.toThrow();
});
test('a confirmed decision requires current ETag, exact command receipt and actual readback, never optimistic activation', async () => {
  (api.get as jest.Mock).mockResolvedValueOnce(response(pending)).mockResolvedValueOnce(response(saved)); (api.post as jest.Mock).mockResolvedValue(response(saved));
  expect(await companyRegistrationReviews.decide(pending, body)).toEqual(saved); expect(api.post).toHaveBeenCalledWith('/api/identity/company-registrations/' + id + '/review', body, { headers: { 'If-Match': pending.etag } }); expect(api.get).toHaveBeenCalledTimes(2);
});
test('changed state and changed session stop the command before POST', async () => {
  (api.get as jest.Mock).mockResolvedValue(response(saved)); await expect(companyRegistrationReviews.decide(pending, body)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
  (api.get as jest.Mock).mockResolvedValue(response(pending)); (getAccessToken as jest.Mock).mockReturnValueOnce('original').mockReturnValueOnce('other'); await expect(companyRegistrationReviews.load(id, actor)).rejects.toThrow();
});
test('lost acknowledgement or failed readback never retries or returns an invented success', async () => {
  (api.get as jest.Mock).mockResolvedValue(response(pending)); (api.post as jest.Mock).mockRejectedValue(new Error('lost')); await expect(companyRegistrationReviews.decide(pending, body)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
  (api.get as jest.Mock).mockResolvedValueOnce(response(pending)).mockRejectedValueOnce(new Error('read unavailable')); (api.post as jest.Mock).mockResolvedValue(response(saved)); await expect(companyRegistrationReviews.decide(pending, body)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(2);
});
