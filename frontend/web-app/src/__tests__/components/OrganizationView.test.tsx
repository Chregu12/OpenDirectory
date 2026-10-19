import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import OrganizationView from '@/components/views/OrganizationView';
import { organizationProfile } from '@/lib/organizationProfile';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
jest.mock('@/hooks/useIdentityAccess');
jest.mock('@/lib/organizationProfile', () => ({ ...jest.requireActual('@/lib/organizationProfile'), organizationProfile: { load: jest.fn(), save: jest.fn() } }));
const actor = '11111111-1111-4111-8111-111111111111';
const access = { subject: 'actual', userId: actor, permissions: ['organization.read', 'organization.manage'], demoMode: false, organizationProfileProtocol: 1 };
const profile = { name: 'Actual Company', legalForm: '', registrationNumber: '', taxId: '', addressLine1: 'Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
const page = { schemaVersion: 1 as const, actorUserId: actor, tenant: { id: '22222222-2222-4222-8222-222222222222', name: 'Actual Company', version: '1', generation: '1' },
  organization: { ...profile, id: '33333333-3333-4333-8333-333333333333', version: '1', createdAt: '2026-10-19T00:00:00Z', updatedAt: '2026-10-19T00:00:00Z' }, etag: 'actual-etag', canManage: true, requiresFreshMfa: false, verificationSupported: false as const };
beforeEach(() => {
  jest.clearAllMocks(); (useIdentityAccess as jest.Mock).mockReturnValue({ access, unavailable: false, reload: jest.fn() }); (organizationProfile.load as jest.Mock).mockResolvedValue(page);
});
test('renders real profile fields and confirms only an actual server save', async () => {
  const updated = { ...page, organization: { ...page.organization, version: '2', city: 'Bern' } }; (organizationProfile.save as jest.Mock).mockResolvedValue(updated);
  render(<OrganizationView />); expect(await screen.findByDisplayValue('Actual Company')).toBeInTheDocument(); fireEvent.change(screen.getByLabelText('Ort *'), { target: { value: 'Bern' } });
  fireEvent.change(screen.getByLabelText('Begründung der Änderung'), { target: { value: 'Actual requested company profile update' } }); fireEvent.click(screen.getByRole('button', { name: 'Organisationsprofil speichern' }));
  expect(await screen.findByText('Organisationsprofil gespeichert. Version 2.')).toBeInTheDocument(); expect(organizationProfile.save).toHaveBeenCalledWith(page, { ...profile, city: 'Bern' }, 'Actual requested company profile update');
});
test('stale MFA leaves the profile visible but prevents all writes', async () => {
  (organizationProfile.load as jest.Mock).mockResolvedValue({ ...page, canManage: false, requiresFreshMfa: true }); render(<OrganizationView />); await screen.findByDisplayValue('Actual Company');
  expect(screen.getByRole('button', { name: 'Organisationsprofil speichern' })).toBeDisabled(); expect(screen.getByLabelText('Firmenname *')).toBeDisabled(); expect(screen.getByRole('alert')).toHaveTextContent('frische MFA');
});
test('missing permissions or an old protocol cannot fetch or invent organization data', async () => {
  (useIdentityAccess as jest.Mock).mockReturnValue({ access: { ...access, permissions: [] }, unavailable: false, reload: jest.fn() }); render(<OrganizationView />);
  expect(screen.getByRole('alert')).toHaveTextContent('Keine Berechtigung'); expect(organizationProfile.load).not.toHaveBeenCalled(); expect(screen.queryByLabelText('Firmenname *')).not.toBeInTheDocument();
});
test('a lost receipt clears the captured form and does not claim a successful save', async () => {
  (organizationProfile.save as jest.Mock).mockRejectedValue(new Error('lost confirmation')); render(<OrganizationView />); await screen.findByDisplayValue('Actual Company');
  fireEvent.change(screen.getByLabelText('Begründung der Änderung'), { target: { value: 'Actual requested company profile update' } }); fireEvent.click(screen.getByRole('button', { name: 'Organisationsprofil speichern' }));
  await waitFor(() => expect(screen.queryByLabelText('Firmenname *')).not.toBeInTheDocument()); expect(screen.getByRole('alert')).toHaveTextContent('nicht bestätigt'); expect(organizationProfile.save).toHaveBeenCalledTimes(1);
});
test('a late former-session response cannot restore profile data after session loss', async () => {
  let resolve: (value: any) => void; (organizationProfile.load as jest.Mock).mockReturnValue(new Promise(value => { resolve = value; })); render(<OrganizationView />);
  await act(async () => { window.dispatchEvent(new Event('od:session-error')); resolve!(page); }); expect(screen.queryByLabelText('Firmenname *')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Sitzung');
});
