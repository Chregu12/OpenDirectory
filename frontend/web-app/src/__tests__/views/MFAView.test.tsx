import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import MFAView from '../../components/views/MFAView';
import { api } from '../../lib/api';
import { startLogin } from '../../lib/auth';
import { verifiedMfa } from '../../lib/verifiedMfa';

jest.mock('../../lib/auth', () => ({ startLogin: jest.fn() }));
const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const userId = '11111111-1111-4111-8111-111111111111';
const setup = { secret, otpauthUri: `otpauth://totp/OpenDirectory:${userId}?secret=${secret}&issuer=OpenDirectory&algorithm=SHA1&digits=6&period=30`, expiresAt: '2026-10-18T20:10:00.000Z' };
let enabled: boolean;
beforeEach(() => {
  jest.clearAllMocks(); enabled = false;
  (api.get as jest.Mock).mockResolvedValue({ data: { enabled: false, pending: false, pendingOwned: false, method: 'totp', reauthenticationRequiredAfterChange: true } });
  (api.post as jest.Mock).mockImplementation(async (route: string) => route.endsWith('/enroll') ? { data: setup } : { data: { enabled: !enabled, reauthenticationRequired: true } });
});
async function credentials() {
  const user = userEvent.setup(); await user.type(screen.getByLabelText('Eigener Benutzername'), 'owner'); await user.type(screen.getByLabelText('Aktuelles Passwort'), 'current-password'); return user;
}
test('only a confirmed own factor is shown, without prototype users, policy toggles or aggregate statistics', async () => {
  render(<MFAView />); await screen.findByText('TOTP nicht eingerichtet');
  expect(api.get).toHaveBeenCalledWith('/api/mfa', expect.objectContaining({ signal: expect.any(AbortSignal) }));
  expect(api.get).toHaveBeenCalledTimes(1); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});
test('enrollment rechecks credentials, confirms the actual secret once, clears it and requires reauthentication', async () => {
  render(<MFAView />); await screen.findByText('TOTP nicht eingerichtet'); const user = await credentials();
  await user.click(screen.getByRole('button', { name: 'TOTP einrichten' })); await screen.findByText(secret);
  expect(api.post).toHaveBeenCalledWith('/api/mfa/enroll', { username: 'owner', password: 'current-password' });
  await user.type(screen.getByLabelText('Neuer OpenDirectory-Einmalcode'), '123456'); await user.click(screen.getByRole('button', { name: 'Einrichtung bestätigen' }));
  await screen.findByText(/Änderung bestätigt. Alle bisherigen Tokens/); expect(api.post).toHaveBeenCalledWith('/api/mfa/confirm', { code: '123456' });
  expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(screen.queryByLabelText('Aktuelles Passwort')).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Erneut anmelden und Status prüfen' })); expect(startLogin).toHaveBeenCalledTimes(1);
});
test('an unconfirmed or lost write does not fabricate activation or retry', async () => {
  (api.post as jest.Mock).mockResolvedValue({ data: { success: true } }); render(<MFAView />); await screen.findByText('TOTP nicht eingerichtet'); const user = await credentials();
  await user.click(screen.getByRole('button', { name: 'TOTP einrichten' })); await screen.findByRole('alert');
  expect(screen.queryByText(/Änderung bestätigt/)).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('button', { name: 'TOTP einrichten' })).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Erneut anmelden und Status prüfen' })).toBeInTheDocument();
});
test('disabling is explicit and submits the fresh password and separate unused OpenDirectory code', async () => {
  enabled = true; (api.get as jest.Mock).mockResolvedValue({ data: { enabled: true, pending: false, pendingOwned: false, method: 'totp', reauthenticationRequiredAfterChange: true } });
  render(<MFAView />); await screen.findByText('TOTP aktiviert'); const user = userEvent.setup();
  expect(screen.queryByLabelText('Aktuelles Passwort')).not.toBeInTheDocument(); await user.click(screen.getByRole('button', { name: 'Deaktivierung vorbereiten' }));
  await credentials(); await user.type(screen.getByLabelText('Neuer OpenDirectory-Einmalcode'), '654321'); await user.click(screen.getByRole('button', { name: 'TOTP endgültig deaktivieren' }));
  await screen.findByText(/Änderung bestätigt/); expect(api.post).toHaveBeenCalledWith('/api/mfa/disable', { username: 'owner', password: 'current-password', code: '654321' });
});
test.each([{}, [], { enabled: true }, { enabled: true, pending: true, pendingOwned: true, method: 'totp', reauthenticationRequiredAfterChange: true }])('malformed status %j cannot become an enabled badge or editable form', async value => {
  (api.get as jest.Mock).mockResolvedValue({ data: value }); render(<MFAView />); await screen.findByRole('alert'); expect(screen.queryByLabelText('Aktuelles Passwort')).not.toBeInTheDocument();
});
test.each([{ enabled: false }, { enabled: true, reauthenticationRequired: false }, { enabled: true, reauthenticationRequired: true, secret }])('malformed confirmation %j is not success', async value => {
  (api.post as jest.Mock).mockResolvedValue({ data: value }); await expect(verifiedMfa.confirm('123456')).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('a failed replay is visible, clears the submitted code, and never automatically repeats it', async () => {
  render(<MFAView />); await screen.findByText('TOTP nicht eingerichtet'); const user = await credentials(); await user.click(screen.getByRole('button', { name: 'TOTP einrichten' })); await screen.findByText(secret);
  (api.post as jest.Mock).mockRejectedValue({ response: { status: 401, data: { error: 'invalid_otp' } } });
  await user.type(screen.getByLabelText('Neuer OpenDirectory-Einmalcode'), '123456'); await user.click(screen.getByRole('button', { name: 'Einrichtung bestätigen' }));
  await screen.findByText(/Code ungültig oder bereits verwendet/); await waitFor(() => expect(screen.getByLabelText('Neuer OpenDirectory-Einmalcode')).toHaveValue('')); expect(api.post).toHaveBeenCalledTimes(2);
});
