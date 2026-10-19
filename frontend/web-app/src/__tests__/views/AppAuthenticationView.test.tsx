import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import AppAuthenticationView from '../../components/views/AppAuthenticationView';
import { applicationAuthentication } from '../../lib/applicationAuthentication';
import { api } from '../../lib/api';

jest.mock('../../lib/auth', () => ({ startLogin: jest.fn() }));
const access = { permissions: ['applications.authentication.read','applications.authentication.manage'], subject: 'operator', userId: '11111111-1111-4111-8111-111111111111', clientId: 'control', demoMode: false };
const row = (extra = {}) => ({ clientId: 'policy-app', name: 'Actual policy target', version: '1', required: false, maxAgeSeconds: 3600, protected: false, canManage: true, requiresFreshMfa: false, ...extra });
beforeEach(() => {
  jest.clearAllMocks(); (api.get as jest.Mock).mockResolvedValue({ status: 200, data: row() });
  (api.put as jest.Mock).mockImplementation(async (_url: string, body: any) => ({ status: 200, data: row({ version: '2', required: body.required, maxAgeSeconds: body.maxAgeSeconds }) }));
});
async function form() {
  const user = userEvent.setup(); await user.click(screen.getByLabelText('MFA für Benutzeranmeldungen verlangen'));
  const age = screen.getByLabelText('Maximales Anmeldealter in Sekunden'); await user.clear(age); await user.type(age, '300');
  await user.type(screen.getByLabelText('Begründung der Anmelderichtlinie'), 'Reviewed application MFA requirement'); await user.click(screen.getByRole('button', { name: 'Anmelderichtlinie prüfen' })); return user;
}
test('authentication staff uses only a known client policy and does not enumerate registrations or directory profiles', async () => {
  render(<AppAuthenticationView access={access} selectedClientId="policy-app" />); await screen.findByText('Actual policy target');
  expect(api.get).toHaveBeenCalledWith('/api/clients/policy-app/authentication', expect.objectContaining({ signal: expect.any(AbortSignal) })); expect(api.get).toHaveBeenCalledTimes(1);
  expect(screen.queryByLabelText('Redirect-URIs')).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
});
test('an explicit conditional write confirms the exact required state, maximum age and newer client generation', async () => {
  render(<AppAuthenticationView access={access} selectedClientId="policy-app" />); await screen.findByText('Actual policy target'); const user = await form();
  expect(api.put).not.toHaveBeenCalled(); await user.click(screen.getByRole('button', { name: 'Richtlinie verbindlich speichern' })); await screen.findByText(/Anmelderichtlinie bestätigt für policy-app/);
  expect(api.put).toHaveBeenCalledWith('/api/clients/policy-app/authentication', { required: true, maxAgeSeconds: 300, reason: 'Reviewed application MFA requirement' }, { headers: { 'If-Match': '"od-client:policy-app:1"' } });
  expect(screen.getByText('MFA verbindlich; Anmeldung höchstens 300 Sekunden alt.')).toBeInTheDocument();
});
test('a stale write stays visibly unconfirmed and cannot be automatically retried', async () => {
  (api.put as jest.Mock).mockRejectedValue({ response: { status: 412 } }); render(<AppAuthenticationView access={access} selectedClientId="policy-app" />); await screen.findByText('Actual policy target'); const user = await form();
  await user.click(screen.getByRole('button', { name: 'Richtlinie verbindlich speichern' })); await screen.findByRole('alert');
  expect(screen.getByRole('button', { name: 'Richtlinie verbindlich speichern' })).toBeDisabled(); expect(api.put).toHaveBeenCalledTimes(1); expect(screen.queryByText(/Anmelderichtlinie bestätigt/)).not.toBeInTheDocument();
});
test('a genuine fresh-MFA requirement is not displayed as a successful or editable policy grant', async () => {
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data: row({ canManage: false, requiresFreshMfa: true }) }); render(<AppAuthenticationView access={access} selectedClientId="policy-app" />);
  await screen.findByText('Actual policy target'); expect(screen.queryByLabelText('MFA für Benutzeranmeldungen verlangen')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Für Richtlinienänderung neu anmelden' })).toBeInTheDocument();
});
test('a protected policy reader never sees a mutation form or a misleading fresh-login workaround', async () => {
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data: row({ protected: true, canManage: false }) }); render(<AppAuthenticationView access={{ ...access, permissions: ['applications.authentication.read'] }} selectedClientId="policy-app" />);
  await screen.findByText('Actual policy target'); expect(screen.queryByRole('button', { name: 'Anmelderichtlinie prüfen' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Für Richtlinienänderung neu anmelden' })).not.toBeInTheDocument();
});
test('losing the independent management capability closes an old confirmation even if a stale response still advertises manageability', async () => {
  const view = render(<AppAuthenticationView access={access} selectedClientId="policy-app" />); await screen.findByText('Actual policy target'); await form();
  view.rerender(<AppAuthenticationView access={{ ...access, permissions: ['applications.authentication.read'] }} selectedClientId="policy-app" />);
  await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
  expect(screen.queryByLabelText('MFA für Benutzeranmeldungen verlangen')).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
});
test.each([{}, { ...row(), maxAgeSeconds: 299 }, { ...row(), required: 'true' }, { ...row(), requiresFreshMfa: true }, { ...row(), clientSecret: 'forbidden' }])('malformed policy %j never becomes a confirmed configuration', async data => {
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data }); render(<AppAuthenticationView access={access} selectedClientId="policy-app" />); await screen.findByRole('alert'); expect(screen.queryByLabelText('MFA für Benutzeranmeldungen verlangen')).not.toBeInTheDocument();
});
test('changing the selected application closes stale confirmation without issuing a write', async () => {
  const view = render(<AppAuthenticationView access={access} selectedClientId="policy-app" />); await screen.findByText('Actual policy target'); await form();
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data: row({ clientId: 'second-app', name: 'Second policy' }) }); view.rerender(<AppAuthenticationView access={access} selectedClientId="second-app" />);
  await screen.findByText('Second policy'); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
});
test.each([{ status: 207, data: row({ version: '2', required: true, maxAgeSeconds: 300 }) }, { status: 200, data: row({ required: true, maxAgeSeconds: 300 }) }, { status: 200, data: row({ version: '2', required: false, maxAgeSeconds: 300 }) }])('a partial, unchanged or mismatched write %j cannot be success', async response => {
  (api.put as jest.Mock).mockResolvedValue(response); await expect(applicationAuthentication.change(row(), { required: true, maxAgeSeconds: 300, reason: 'Reviewed actual policy change' })).rejects.toThrow(); expect(api.put).toHaveBeenCalledTimes(1);
});
