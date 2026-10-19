import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import RegisterCompanyPage from '@/app/register/page';
import { companyRegistration } from '@/lib/companyRegistration';
jest.mock('@/lib/companyRegistration', () => ({ ...jest.requireActual('@/lib/companyRegistration'), companyRegistration: { capabilities: jest.fn(), submit: jest.fn(), status: jest.fn(), activate: jest.fn() } }));
const registrationId = '11111111-1111-4111-8111-111111111111';
const receipt = { schemaVersion: 1, registrationId, tenantId: '22222222-2222-4222-8222-222222222222', administratorId: '33333333-3333-4333-8333-333333333333', createdAt: '2026-10-19T00:00:00Z', status: 'pending-verification', tenantEnabled: false, administratorEnabled: false, profileSaved: false, activationSupported: false, replayed: false };
beforeEach(() => { jest.clearAllMocks(); sessionStorage.clear(); Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: () => registrationId }); (companyRegistration.capabilities as jest.Mock).mockResolvedValue({ enabled: true }); });
test('disabled registration has no decorative submit form or invented company', async () => {
  (companyRegistration.capabilities as jest.Mock).mockResolvedValue({ enabled: false }); render(<RegisterCompanyPage />); expect(await screen.findByText('Die Firmenregistrierung ist durch den Betreiber nicht aktiviert.')).toBeInTheDocument(); expect(screen.queryByLabelText('Benutzername')).not.toBeInTheDocument(); expect(companyRegistration.submit).not.toHaveBeenCalled();
});
test('a successful actual receipt is explicitly pending, does not log in and stores only the registration key', async () => {
  (companyRegistration.submit as jest.Mock).mockResolvedValue(receipt); render(<RegisterCompanyPage />); fireEvent.change(await screen.findByLabelText('Benutzername'), { target: { value: 'verified' } }); fireEvent.change(screen.getByLabelText('Aktuelles Passwort'), { target: { value: 'disposable-provider-password' } });
  fireEvent.click(screen.getByRole('checkbox')); fireEvent.submit(screen.getByRole('button', { name: 'Unternehmen zur Prüfung anmelden' }).closest('form')!);
  await screen.findByText('Zur Prüfung vorgemerkt'); expect(screen.getByRole('status')).toHaveTextContent('nicht aktiviert'); expect(screen.getByLabelText('Aktuelles Passwort')).toHaveValue('');
  expect(sessionStorage.length).toBe(1); expect(sessionStorage.getItem('od_company_registration_id')).toBe(registrationId); expect(JSON.stringify(sessionStorage)).not.toContain('disposable-provider-password');
});
test('an unconfirmed submit clears credentials, keeps the recovery key and never retries or invents success', async () => {
  (companyRegistration.submit as jest.Mock).mockRejectedValue(new Error('lost acknowledgement')); render(<RegisterCompanyPage />); fireEvent.change(await screen.findByLabelText('Benutzername'), { target: { value: 'verified' } }); fireEvent.change(screen.getByLabelText('Aktuelles Passwort'), { target: { value: 'disposable-provider-password' } });
  fireEvent.click(screen.getByRole('checkbox')); fireEvent.submit(screen.getByRole('button', { name: 'Unternehmen zur Prüfung anmelden' }).closest('form')!); expect(await screen.findByRole('alert')).toHaveTextContent('nicht bestätigt'); expect(screen.getByLabelText('Aktuelles Passwort')).toHaveValue(''); expect(companyRegistration.submit).toHaveBeenCalledTimes(1); expect(companyRegistration.status).not.toHaveBeenCalled();
});
test('explicit status checking needs credentials but not a resubmitted company profile', async () => {
  (companyRegistration.status as jest.Mock).mockResolvedValue({ ...receipt, replayed: true }); render(<RegisterCompanyPage />); fireEvent.change(await screen.findByLabelText('Benutzername'), { target: { value: 'verified' } }); fireEvent.change(screen.getByLabelText('Aktuelles Passwort'), { target: { value: 'disposable-provider-password' } }); fireEvent.click(screen.getByRole('button', { name: 'Bestehenden Status prüfen' }));
  await screen.findByText('Bestehende Registrierung bestätigt; kein zweiter Mandant angelegt.'); expect(companyRegistration.status).toHaveBeenCalledWith({ registrationId, username: 'verified', password: 'disposable-provider-password', mfaCode: '' }); expect(companyRegistration.submit).not.toHaveBeenCalled();
});
test('a late capabilities response after leaving the anonymous registration page cannot recreate a form', async () => {
  let resolve: (value: any) => void; (companyRegistration.capabilities as jest.Mock).mockReturnValue(new Promise(value => { resolve = value; })); const rendered = render(<RegisterCompanyPage />); rendered.unmount(); await act(async () => { resolve!({ enabled: true }); }); await waitFor(() => expect(screen.queryByLabelText('Benutzername')).not.toBeInTheDocument());
});
test.each([['pending-activation', 'Freigegeben – Aktivierung ausstehend'], ['rejected', 'Antrag abgelehnt']])('actual decided status %s does not grant first-administrator access', async (status, heading) => {
  (companyRegistration.status as jest.Mock).mockResolvedValue({ ...receipt, schemaVersion: 2, replayed: true, status, reviewedAt: '2026-10-19T01:00:00Z' }); render(<RegisterCompanyPage />);
  fireEvent.change(await screen.findByLabelText('Benutzername'), { target: { value: 'verified' } }); fireEvent.change(screen.getByLabelText('Aktuelles Passwort'), { target: { value: 'disposable-provider-password' } }); fireEvent.click(screen.getByRole('button', { name: 'Bestehenden Status prüfen' }));
  expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument(); expect(screen.getByLabelText('Aktuelles Passwort')).toHaveValue(''); expect(screen.getByRole('status')).toHaveTextContent('nicht aktiviert');
});
test('approved own activation requires fresh credentials and explicit confirmation, then offers MFA without creating a session', async () => {
  (companyRegistration.capabilities as jest.Mock).mockResolvedValue({ enabled: true, activationSupported: true }); (companyRegistration.status as jest.Mock).mockResolvedValue({ ...receipt, schemaVersion: 2, status: 'pending-activation', replayed: true, reviewedAt: '2026-10-19T01:00:00Z' });
  (companyRegistration.activate as jest.Mock).mockResolvedValue({ ...receipt, schemaVersion: 3, status: 'active', tenantEnabled: true, administratorEnabled: true, profileSaved: true, activationSupported: true, reviewedAt: '2026-10-19T01:00:00Z', activatedAt: '2026-10-19T02:00:00Z', consoleClientId: 'web-app', mfaRequired: true });
  render(<RegisterCompanyPage />); fireEvent.change(await screen.findByLabelText('Benutzername'), { target: { value: 'verified' } }); fireEvent.change(screen.getByLabelText('Aktuelles Passwort'), { target: { value: 'fixture-password' } }); fireEvent.click(screen.getByRole('button', { name: 'Bestehenden Status prüfen' }));
  const activate = await screen.findByRole('button', { name: 'Freigegebene Firma aktivieren' }); expect(activate).toBeDisabled(); fireEvent.change(screen.getByLabelText('Aktuelles Passwort'), { target: { value: 'fixture-password' } });
  fireEvent.click(screen.getByLabelText('Ich bestätige die Aktivierung meiner freigegebenen Firma mit Pflicht-MFA und ohne globale Adminrechte.')); fireEvent.click(activate);
  expect(await screen.findByRole('heading', { name: 'Unternehmen aktiviert – MFA erforderlich' })).toBeInTheDocument(); expect(screen.getByRole('link', { name: 'Pflicht-MFA einrichten' })).toHaveAttribute('href', '/auth/mfa-enroll'); expect(screen.getByLabelText('Aktuelles Passwort')).toHaveValue(''); expect(companyRegistration.activate).toHaveBeenCalledTimes(1);
});
