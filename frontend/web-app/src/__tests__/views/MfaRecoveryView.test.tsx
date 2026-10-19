import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import MfaRecoveryView from '../../components/views/MfaRecoveryView';
import MfaRecoveryCodesView from '../../components/views/MfaRecoveryCodesView';
import { mfaRecovery } from '../../lib/mfaRecovery';
import { api } from '../../lib/api';

jest.mock('../../lib/auth', () => ({ startLogin: jest.fn() }));
const originalFetch = global.fetch;
const codes = Array.from({ length: 8 }, (_unused, index) => String(index + 1).padStart(8, '0') + '-11223344-55667788-99aabbcc');
const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; const userId = '11111111-1111-4111-8111-111111111111';
const setup = { challenge: userId + '.' + 'A'.repeat(43), secret, otpauthUri: `otpauth://totp/OpenDirectory:${userId}?secret=${secret}&issuer=OpenDirectory&algorithm=SHA1&digits=6&period=30`, expiresAt: '2026-10-18T20:10:00.000Z' };
const response = (data: any, status = 200) => ({ ok: status >= 200 && status < 300, status, headers: { get: () => 'application/json' }, json: async () => data }) as unknown as Response;
beforeEach(() => {
  jest.clearAllMocks(); global.fetch = jest.fn(async (_url, options: any) => response(JSON.parse(options.body).challenge ? { enabled: true, reauthenticationRequired: true } : setup));
  (api.get as jest.Mock).mockResolvedValue({ data: { remaining: 0 } }); (api.post as jest.Mock).mockResolvedValue({ data: { recoveryCodes: codes, remaining: 8 } });
});
afterEach(() => { global.fetch = originalFetch; });
async function begin() {
  const user = userEvent.setup(); await user.type(screen.getByLabelText('Eigener Benutzername'), 'owner'); await user.type(screen.getByLabelText('Aktuelles Passwort'), 'password');
  await user.type(screen.getByLabelText('Gespeicherter Notfallcode'), codes[0]); await user.click(screen.getByRole('button', { name: 'Notfallcode verbrauchen und Faktor vorbereiten' })); return user;
}
test('public recovery uses no browser session, API bearer or storage and finishes only after the new real factor receipt', async () => {
  const storage = jest.spyOn(Storage.prototype, 'setItem'); render(<MfaRecoveryView />); const user = await begin(); await screen.findByText(secret);
  expect(global.fetch).toHaveBeenCalledWith('/api/auth/oidc/recovery/start', expect.objectContaining({ credentials: 'omit', cache: 'no-store', redirect: 'error', headers: { 'Content-Type': 'application/json', 'X-OD-Recovery': '1' } }));
  await user.type(screen.getByLabelText('Einmalcode des neuen Authenticators'), '123456'); await user.click(screen.getByRole('button', { name: 'Neuen Faktor bestätigen' }));
  await screen.findByText(/Faktorwechsel bestätigt/); expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(api.get).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled(); expect(storage).not.toHaveBeenCalled(); storage.mockRestore();
  expect(screen.getByRole('link', { name: 'Zur normalen Anmeldung' })).toHaveAttribute('href', '/login'); expect(global.fetch).toHaveBeenCalledTimes(2);
});
test('an ambiguous public start never fabricates a secret or automatically consumes another code', async () => {
  (global.fetch as jest.Mock).mockRejectedValue(new Error('network lost')); render(<MfaRecoveryView />); await begin(); await screen.findByRole('alert');
  expect(screen.queryByLabelText('Neuer MFA-Schlüssel')).not.toBeInTheDocument(); expect(screen.queryByLabelText('Aktuelles Passwort')).not.toBeInTheDocument(); expect(global.fetch).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: 'Mit anderem Notfallcode neu beginnen' })).toBeInTheDocument();
});
test('an unconfirmed completion does not become success or preserve the new secret', async () => {
  render(<MfaRecoveryView />); const user = await begin(); await screen.findByText(secret); (global.fetch as jest.Mock).mockResolvedValue(response({ success: true }));
  await user.type(screen.getByLabelText('Einmalcode des neuen Authenticators'), '123456'); await user.click(screen.getByRole('button', { name: 'Neuen Faktor bestätigen' })); await screen.findByRole('alert');
  expect(screen.queryByText(/Faktorwechsel bestätigt/)).not.toBeInTheDocument(); expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(global.fetch).toHaveBeenCalledTimes(2);
});
test('a rejected unused backup is visible, clears both credentials and permits only an explicit new attempt', async () => {
  (global.fetch as jest.Mock).mockResolvedValue(response({ error: 'invalid_recovery_code' }, 401)); render(<MfaRecoveryView />); await begin(); await screen.findByText(/Notfallcode nicht gültig/);
  expect(screen.getByLabelText('Aktuelles Passwort')).toHaveValue(''); expect(screen.getByLabelText('Gespeicherter Notfallcode')).toHaveValue(''); expect(global.fetch).toHaveBeenCalledTimes(1);
});
test('the owner sees only a verified backup count until explicit password-plus-OTP generation, then can discard the one-time display', async () => {
  render(<MfaRecoveryCodesView />); await screen.findByText('Verfügbare Notfallcodes: 0'); const user = userEvent.setup(); expect(api.post).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Notfallcodes vorbereiten' })); await user.type(screen.getByLabelText('Benutzername für Notfallcodes'), 'owner'); await user.type(screen.getByLabelText('Passwort für Notfallcodes'), 'password');
  await user.type(screen.getByLabelText('Neuer Einmalcode für Notfallcodes'), '123456'); await user.click(screen.getByRole('button', { name: 'Bisherige Codes ersetzen und neue erzeugen' }));
  await screen.findByText(codes[0]); expect(api.post).toHaveBeenCalledWith('/api/mfa/recovery-codes', { username: 'owner', password: 'password', code: '123456' }); expect(screen.getByText('Verfügbare Notfallcodes: 8')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Codes ausblenden' })); expect(screen.queryByText(codes[0])).not.toBeInTheDocument(); expect(api.get).toHaveBeenCalledTimes(1);
});
test.each([{}, { remaining: '8' }, { remaining: 9 }, { remaining: -1 }, { remaining: 8, recoveryCodes: codes }])('invalid backup status %j is not a fabricated eight-code inventory', async data => {
  (api.get as jest.Mock).mockResolvedValue({ data }); render(<MfaRecoveryCodesView />); await screen.findByRole('alert'); expect(screen.queryByRole('button', { name: 'Notfallcodes vorbereiten' })).not.toBeInTheDocument();
});
test.each([{ remaining: 8, recoveryCodes: [codes[0]] }, { remaining: 8, recoveryCodes: Array(8).fill(codes[0]) }, { remaining: 8, recoveryCodes: codes, access_token: 'not-a-recovery-result' }])('unverified generation %j cannot disclose a supposedly usable backup family', async data => {
  (api.post as jest.Mock).mockResolvedValue({ data }); await expect(mfaRecovery.rotate({ username: 'owner', password: 'password' }, '123456')).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('a write with a lost generation receipt cannot be blindly repeated', async () => {
  (api.post as jest.Mock).mockRejectedValue(new Error('lost response')); render(<MfaRecoveryCodesView />); await screen.findByText('Verfügbare Notfallcodes: 0'); const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Notfallcodes vorbereiten' })); await user.type(screen.getByLabelText('Benutzername für Notfallcodes'), 'owner'); await user.type(screen.getByLabelText('Passwort für Notfallcodes'), 'password');
  await user.type(screen.getByLabelText('Neuer Einmalcode für Notfallcodes'), '123456'); await user.click(screen.getByRole('button', { name: 'Bisherige Codes ersetzen und neue erzeugen' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Vor weiteren Änderungen neu anmelden' })).toBeInTheDocument()); expect(screen.queryByText(codes[0])).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('initial enrollment is a separate purpose with an assigned client selector and no backup, session or storage use', async () => {
  render(<MfaRecoveryView enrollment />); const user = userEvent.setup(); await user.type(screen.getByLabelText('Eigener Benutzername'), 'owner'); await user.type(screen.getByLabelText('Aktuelles Passwort'), 'password');
  await user.clear(screen.getByLabelText('Anwendungs-ID für Ersteinrichtung')); await user.type(screen.getByLabelText('Anwendungs-ID für Ersteinrichtung'), 'assigned-app');
  expect(screen.queryByLabelText('Gespeicherter Notfallcode')).not.toBeInTheDocument(); await user.click(screen.getByRole('button', { name: 'Ersteinrichtung vorbereiten' })); await screen.findByText(secret);
  expect(global.fetch).toHaveBeenCalledWith('/api/auth/oidc/enrollment/start', expect.objectContaining({ credentials: 'omit', headers: { 'Content-Type': 'application/json', 'X-OD-Enrollment': '1' }, body: JSON.stringify({ clientId: 'assigned-app', username: 'owner', password: 'password' }) }));
  await user.type(screen.getByLabelText('Einmalcode des neuen Authenticators'), '123456'); await user.click(screen.getByRole('button', { name: 'Neuen Faktor bestätigen' })); await screen.findByText(/Ersteinrichtung bestätigt/); expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled(); expect(global.fetch).toHaveBeenCalledTimes(2);
});
test('an existing factor or missing assignment cannot become a registration success', async () => {
  (global.fetch as jest.Mock).mockResolvedValue(response({ error: 'mfa_already_enabled' }, 409)); render(<MfaRecoveryView enrollment />); const user = userEvent.setup(); await user.type(screen.getByLabelText('Eigener Benutzername'), 'owner'); await user.type(screen.getByLabelText('Aktuelles Passwort'), 'password');
  await user.click(screen.getByRole('button', { name: 'Ersteinrichtung vorbereiten' })); await screen.findByText(/Ein Faktor ist bereits eingerichtet/); expect(screen.queryByLabelText('Neuer MFA-Schlüssel')).not.toBeInTheDocument(); expect(global.fetch).toHaveBeenCalledTimes(1);
});
