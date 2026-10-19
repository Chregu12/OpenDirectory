import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CompanyRegistrationReviewsView from '@/components/views/CompanyRegistrationReviewsView';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { companyRegistrationReviews } from '@/lib/companyRegistrationReviews';
jest.mock('@/hooks/useIdentityAccess');
jest.mock('@/lib/companyRegistrationReviews', () => ({ ...jest.requireActual('@/lib/companyRegistrationReviews'), companyRegistrationReviews: { list: jest.fn(), load: jest.fn(), decide: jest.fn() } }));
const actor = '11111111-1111-4111-8111-111111111111'; const id = '22222222-2222-4222-8222-222222222222';
const pending: any = { schemaVersion: 1, actorUserId: actor, registrationId: id, tenantId: '33333333-3333-4333-8333-333333333333', administratorId: '55555555-5555-4555-8555-555555555555',
  principal: { username: 'requestor', email: 'person@example.invalid', displayName: 'Actual Requestor' },
  profile: { name: 'Actual Company', legalForm: '', registrationNumber: '', taxId: '', addressLine1: 'Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' },
  createdAt: '2026-10-19T00:00:00Z', status: 'pending-verification', etag: 'actual-etag', activationSupported: false, canReview: true, review: null };
beforeEach(() => {
  jest.clearAllMocks(); (useIdentityAccess as jest.Mock).mockReturnValue({ access: { userId: actor, permissions: ['company.registrations.review'], companyRegistrationReviewProtocol: 1, demoMode: false }, unavailable: false, reload: jest.fn() });
  (companyRegistrationReviews.list as jest.Mock).mockResolvedValue({ schemaVersion: 1, actorUserId: actor, page: 1, limit: 20, status: 'pending-verification', total: 1, registrations: [pending] });
  (companyRegistrationReviews.load as jest.Mock).mockResolvedValue(pending);
});
test('ordinary administrator sees no queue or review controls', async () => {
  (useIdentityAccess as jest.Mock).mockReturnValue({ access: { userId: actor, permissions: ['organization.manage'], companyRegistrationReviewProtocol: 1 }, reload: jest.fn() }); render(<CompanyRegistrationReviewsView />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Eine normale Administratorrolle genügt nicht'); expect(companyRegistrationReviews.list).not.toHaveBeenCalled();
});
test('real detail requires an explicit decision, reason and confirmation and reports no activation after success', async () => {
  (companyRegistrationReviews.decide as jest.Mock).mockResolvedValue({ ...pending, status: 'pending-activation', canReview: false, review: { id, decision: 'approved', reason: 'Independently reviewed company', reviewerUserId: actor, reviewedAt: '2026-10-19T01:00:00Z' } });
  render(<CompanyRegistrationReviewsView />); fireEvent.click(await screen.findByRole('button', { name: 'Antrag öffnen: Actual Company' }));
  const save = await screen.findByRole('button', { name: 'Prüfentscheidung speichern' }); expect(save).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Entscheidung'), { target: { value: 'approved' } }); fireEvent.change(screen.getByLabelText('Prüfbegründung'), { target: { value: 'Independently reviewed company' } }); expect(save).toBeDisabled(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(save);
  expect(await screen.findByText('Prüfentscheidung bestätigt. Mandant und Administrator bleiben gesperrt.')).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Prüfentscheidung speichern' })).not.toBeInTheDocument(); expect(companyRegistrationReviews.decide).toHaveBeenCalledTimes(1);
});
test('an unconfirmed decision clears details and asks for actual status instead of retrying', async () => {
  (companyRegistrationReviews.decide as jest.Mock).mockRejectedValue(new Error('lost')); render(<CompanyRegistrationReviewsView />); fireEvent.click(await screen.findByRole('button', { name: 'Antrag öffnen: Actual Company' }));
  const save = await screen.findByRole('button', { name: 'Prüfentscheidung speichern' }); fireEvent.change(screen.getByLabelText('Entscheidung'), { target: { value: 'rejected' } }); fireEvent.change(screen.getByLabelText('Prüfbegründung'), { target: { value: 'Independently rejected company' } }); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(save);
  expect(await screen.findByRole('alert')).toHaveTextContent('nicht bestätigt'); expect(screen.queryByLabelText('Prüfbegründung')).not.toBeInTheDocument(); await waitFor(() => expect(companyRegistrationReviews.decide).toHaveBeenCalledTimes(1));
});
