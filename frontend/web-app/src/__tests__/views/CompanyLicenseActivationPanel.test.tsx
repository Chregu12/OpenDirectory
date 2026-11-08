import React from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import Panel from '@/components/views/CompanyLicenseActivationPanel';
import { companyLicenseActivation } from '@/lib/companyLicenseActivation';
import { ensureSession } from '@/lib/auth';
jest.mock('@/lib/companyLicenseActivation', () => ({ companyLicenseActivation: { status: jest.fn(), change: jest.fn() } }));
jest.mock('@/lib/auth', () => ({ ensureSession: jest.fn() }));
const tenant = { id: '11111111-1111-4111-8111-111111111111', version: '1', generation: '1' };
const status = { schemaVersion: 1, scope: 'company-licenses', tenant, durations: [900, 3600, 7200, 14400, 28800, 36000], requiresFreshMfa: false, activation: null };
beforeEach(() => { jest.resetAllMocks(); (companyLicenseActivation.status as jest.Mock).mockResolvedValue(status); (ensureSession as jest.Mock).mockResolvedValue({}); });
test('ten hours require a reason and confirmation, then refresh the session before reloading private data', async () => {
  const changed = jest.fn(); render(<Panel onAccessChanged={changed} />);
  const select = await screen.findByLabelText('Aktivierungsdauer'); fireEvent.change(select, { target: { value: '36000' } });
  expect(screen.getByRole('button', { name: 'Berechtigung aktivieren' })).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Begründung'), { target: { value: 'Lizenzinventar bearbeiten' } });
  fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Berechtigung aktivieren' }));
  await waitFor(() => expect(changed).toHaveBeenLastCalledWith(true));
  expect(companyLicenseActivation.change).toHaveBeenCalledWith({ durationSeconds: 36000, reason: 'Lizenzinventar bearbeiten', confirm: true });
  expect(changed.mock.calls).toEqual([[false], [true]]); expect(ensureSession).toHaveBeenCalledWith(true, { rotate: true });
});
test('old MFA leads to personal reauthentication without sending an activation', async () => {
  (companyLicenseActivation.status as jest.Mock).mockResolvedValue({ ...status, requiresFreshMfa: true }); render(<Panel onAccessChanged={jest.fn()} />);
  expect(await screen.findByRole('link', { name: 'Anmeldung für Aktivierung bestätigen' })).toHaveAttribute('href', '/api/auth/oidc/login?returnTo=%2Fapplications');
  expect(screen.queryByRole('button', { name: 'Berechtigung aktivieren' })).not.toBeInTheDocument(); expect(companyLicenseActivation.change).not.toHaveBeenCalled();
});
test('uncertain writes clear private access and require status readback without retry', async () => {
  const changed = jest.fn(); (companyLicenseActivation.change as jest.Mock).mockRejectedValue(new Error('network'));
  render(<Panel onAccessChanged={changed} />); await screen.findByLabelText('Aktivierungsdauer');
  fireEvent.change(screen.getByLabelText('Begründung'), { target: { value: 'Lizenzinventar bearbeiten' } }); fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Berechtigung aktivieren' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('zuerst den Status prüfen'); expect(companyLicenseActivation.change).toHaveBeenCalledTimes(1);
  expect(changed.mock.calls).toEqual([[false]]); expect(ensureSession).not.toHaveBeenCalled();
});
test('an activation ends by immutable ID', async () => {
  const activation = { schemaVersion: 1, scope: 'company-licenses', id: '22222222-2222-4222-8222-222222222222', tenant, expiresAt: Math.floor(Date.now() / 1000) + 5 };
  (companyLicenseActivation.status as jest.Mock).mockResolvedValue({ ...status, activation });
  const changed = jest.fn(); render(<Panel onAccessChanged={changed} />); expect(await screen.findByRole('status')).toHaveTextContent('Aktiv bis');
  fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Aktivierung beenden' }));
  await waitFor(() => expect(ensureSession).toHaveBeenCalled()); expect(companyLicenseActivation.change).toHaveBeenCalledWith({ activationId: activation.id, confirm: true });
});
test('an existing activation is recovered by session refresh without repeating the write', async () => {
  const activation = { schemaVersion: 1, scope: 'company-licenses', id: '22222222-2222-4222-8222-222222222222', tenant, expiresAt: Math.floor(Date.now() / 1000) + 3600 };
  (companyLicenseActivation.status as jest.Mock).mockResolvedValue({ ...status, activation }); const changed = jest.fn();
  render(<Panel onAccessChanged={changed} />); fireEvent.click(await screen.findByRole('button', { name: 'Aktivierung übernehmen' }));
  await waitFor(() => expect(changed).toHaveBeenLastCalledWith(true)); expect(ensureSession).toHaveBeenCalledWith(true, { rotate: true }); expect(companyLicenseActivation.change).not.toHaveBeenCalled();
});
test('expiry clears private access without issuing a write', async () => {
  jest.useFakeTimers();
  try {
    const activation = { schemaVersion: 1, scope: 'company-licenses', id: '22222222-2222-4222-8222-222222222222', tenant, expiresAt: Math.floor(Date.now() / 1000) + 10 };
    (companyLicenseActivation.status as jest.Mock).mockResolvedValueOnce({ ...status, activation }).mockResolvedValue(status); const changed = jest.fn();
    render(<Panel onAccessChanged={changed} />); await act(async () => {});
    await act(async () => { jest.advanceTimersByTime(11000); });
    expect(changed).toHaveBeenCalledWith(true); expect(companyLicenseActivation.change).not.toHaveBeenCalled();
  } finally { jest.useRealTimers(); }
});
