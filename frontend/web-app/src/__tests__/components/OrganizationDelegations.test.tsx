import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import OrganizationDelegations from '@/components/OrganizationDelegations';
import { organizationDelegations } from '@/lib/organizationDelegations';
jest.mock('@/lib/organizationDelegations', () => ({ organizationDelegations: { load: jest.fn(), change: jest.fn() } }));
const actor = '11111111-1111-4111-8111-111111111111'; const tenant = '22222222-2222-4222-8222-222222222222'; const recipient = '33333333-3333-4333-8333-333333333333';
const row = { id: '44444444-4444-4444-8444-444444444444', userId: recipient, username: 'actual-person', name: 'Actual Person', expiresAt: '2026-10-19T13:00:00Z', createdAt: '2026-10-19T12:00:00Z', status: 'active' };
const page = { schemaVersion: 1, actorUserId: actor, tenantId: tenant, permissions: ['organization.read', 'organization.manage'], canManage: true, truncated: false, grants: [] };
beforeEach(() => { jest.clearAllMocks(); (organizationDelegations.load as jest.Mock).mockResolvedValue(page); });
test('grants only a scoped actual profile permission after explicit recipient, lifetime and reason', async () => {
  (organizationDelegations.change as jest.Mock).mockResolvedValue({ ...page, grants: [row] }); render(<OrganizationDelegations actorUserId={actor} tenantId={tenant} />);
  const input = await screen.findByLabelText('Kanonische Benutzer-ID (UUID, aus Personen)'); fireEvent.change(input, { target: { value: recipient } }); fireEvent.change(screen.getByLabelText('Begründung der Berechtigung'), { target: { value: 'Actual requested profile delegation' } });
  fireEvent.click(screen.getByRole('button', { name: 'Profilberechtigung erteilen' })); await screen.findByText('Actual Person');
  expect(organizationDelegations.change).toHaveBeenCalledWith(page, { userId: recipient, durationSeconds: 3600 }, 'Actual requested profile delegation'); expect(screen.getByRole('status')).toHaveTextContent('tatsächlicher Bestand bestätigt');
});
test('a revoke must be selected, reasoned and separately confirmed', async () => {
  const loaded = { ...page, grants: [row] }; (organizationDelegations.load as jest.Mock).mockResolvedValue(loaded); (organizationDelegations.change as jest.Mock).mockResolvedValue({ ...loaded, grants: [{ ...row, status: 'revoked' }] });
  render(<OrganizationDelegations actorUserId={actor} tenantId={tenant} />); fireEvent.click(await screen.findByRole('button', { name: 'Widerruf vorbereiten: Actual Person' })); expect(organizationDelegations.change).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Begründung der Berechtigung'), { target: { value: 'Actual independently confirmed revocation' } }); fireEvent.click(screen.getByRole('button', { name: 'Widerruf bestätigen' }));
  await screen.findByText('Widerrufen'); expect(organizationDelegations.change).toHaveBeenCalledWith(loaded, { grantId: row.id }, 'Actual independently confirmed revocation');
});
test('stale MFA disables management without inventing data', async () => {
  (organizationDelegations.load as jest.Mock).mockResolvedValue({ ...page, canManage: false }); render(<OrganizationDelegations actorUserId={actor} tenantId={tenant} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('mit MFA'); expect(screen.getByRole('button', { name: 'Profilberechtigung erteilen' })).toBeDisabled(); expect(screen.getByLabelText('Kanonische Benutzer-ID (UUID, aus Personen)')).toBeDisabled();
});
test('unconfirmed writes remove the captured command until an explicit reload', async () => {
  (organizationDelegations.change as jest.Mock).mockRejectedValue(new Error('receipt missing')); render(<OrganizationDelegations actorUserId={actor} tenantId={tenant} />);
  fireEvent.change(await screen.findByLabelText('Kanonische Benutzer-ID (UUID, aus Personen)'), { target: { value: recipient } }); fireEvent.change(screen.getByLabelText('Begründung der Berechtigung'), { target: { value: 'Actual requested profile delegation' } }); fireEvent.click(screen.getByRole('button', { name: 'Profilberechtigung erteilen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('nicht bestätigt'); expect(screen.queryByLabelText('Kanonische Benutzer-ID (UUID, aus Personen)')).not.toBeInTheDocument(); expect(organizationDelegations.change).toHaveBeenCalledTimes(1);
});
test('late responses cannot restore previous-session persons or commands', async () => {
  let resolve: (value: any) => void; (organizationDelegations.load as jest.Mock).mockReturnValue(new Promise(value => { resolve = value; })); render(<OrganizationDelegations actorUserId={actor} tenantId={tenant} />);
  await act(async () => { window.dispatchEvent(new Event('od:session-error')); resolve!({ ...page, grants: [row] }); }); await waitFor(() => expect(screen.queryByText('Actual Person')).not.toBeInTheDocument()); expect(screen.getByRole('alert')).toHaveTextContent('Sitzung');
});
