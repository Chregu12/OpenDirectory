import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import AppRegistrationsView from '../../components/views/AppRegistrationsView';
import { registeredClients } from '../../lib/registeredClients';
import { api } from '../../lib/api';

const entry = (extra = {}) => ({ clientId: 'canonical-app', name: 'Canonical application', enabled: false, publicClient: false, version: '1', protected: false,
  scopes: ['openid','profile','email'], grantTypes: ['authorization_code','refresh_token'], redirectUris: ['https://app.test/callback'],
  createdAt: '2026-10-18T10:00:00.000Z', updatedAt: '2026-10-18T10:00:00.000Z', ...extra });
const secret = 's'.repeat(43);
let permissions: string[]; let rows: ReturnType<typeof entry>[];
beforeEach(() => {
  jest.clearAllMocks(); permissions = ['applications.read','applications.create','applications.update','applications.delete','applications.credentials.rotate']; rows = [entry()];
  (api.get as jest.Mock).mockImplementation(async (url: string) => ({ data: url.endsWith('/access') ? { permissions, subject: 'verified-actor', userId: '11111111-1111-4111-8111-111111111111', clientId: 'console', demoMode: false } : { clients: rows, truncated: false } }));
  (api.post as jest.Mock).mockImplementation(async (url: string, body: any) => {
    if (url.endsWith('/rotate-secret')) { rows = [entry({ version: '2' })]; return { status: 200, data: { ...rows[0], clientSecret: secret } }; }
    rows = [entry({ ...body, clientId: 'new-canonical-app' })]; return { status: 201, data: { ...rows[0], clientSecret: body.publicClient ? null : secret } };
  });
  (api.put as jest.Mock).mockImplementation(async (_url: string, body: any) => { rows = [entry({ ...body, version: '2' })]; return { status: 200, data: rows[0] }; });
  (api.delete as jest.Mock).mockImplementation(async () => { rows = []; return { status: 204 }; });
});
async function creation() {
  render(<AppRegistrationsView />); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name: 'Anwendung registrieren' }));
  await user.type(screen.getByLabelText('Name'), 'New canonical app'); await user.type(screen.getByLabelText('Redirect-URIs, eine pro Zeile'), 'https://new-app.test/callback'); return user;
}
test('the direct app-account flow needs only a name and leaves identity scopes and redirect URIs empty', async () => {
  render(<AppRegistrationsView />); const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'App-Konto erstellen' }));
  expect(screen.getByRole('dialog', { name: 'Neues App-Konto' })).toBeInTheDocument();
  expect(screen.queryByLabelText('Redirect-URIs, eine pro Zeile')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Scopes, durch Leerzeichen getrennt')).toHaveValue('');
  await user.type(screen.getByLabelText('Name'), 'Nightly job');
  await user.click(screen.getByRole('button', { name: 'Verbindlich speichern' }));
  await screen.findByTestId('client-secret');
  expect(api.post).toHaveBeenCalledWith('/api/clients', { name: 'Nightly job', redirectUris: [], scopes: [], grantTypes: ['client_credentials'], publicClient: false, enabled: false });
  expect(screen.getByText(/node scripts\/od.mjs check/)).toBeInTheDocument();
  expect(api.put).not.toHaveBeenCalled();
});
test('switching a web registration to an app account clears inappropriate login scopes', async () => {
  const user = await creation();
  await user.selectOptions(screen.getByLabelText('Client-Typ'), 'workload');
  expect(screen.getByLabelText('Scopes, durch Leerzeichen getrennt')).toHaveValue('');
  expect(screen.queryByLabelText('Redirect-URIs, eine pro Zeile')).not.toBeInTheDocument();
});
test('editing an existing app account cannot reintroduce default login scopes', async () => {
  rows = [entry({ scopes: [], grantTypes: ['client_credentials'], redirectUris: [] })];
  render(<AppRegistrationsView />); const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Konfiguration bearbeiten' }));
  expect(screen.getByLabelText('Scopes, durch Leerzeichen getrennt')).toHaveValue('');
  await user.click(screen.getByRole('button', { name: 'Verbindlich speichern' }));
  await screen.findByText(/Konfiguration gespeichert/);
  expect((api.put as jest.Mock).mock.calls[0][1].scopes).toEqual([]);
});
test('ordinary users do not read a registration list or see sample administrators', async () => {
  permissions = []; render(<AppRegistrationsView />); await screen.findByText('Keine Leseberechtigung für das Anwendungsregister.');
  expect(api.get).toHaveBeenCalledTimes(1); expect(screen.queryByText('Grafana Dashboard')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Anwendung registrieren' })).not.toBeInTheDocument();
});
test('readers see actual disabled state and never mutation or credential controls', async () => {
  permissions = ['applications.read']; render(<AppRegistrationsView />); await screen.findByRole('article', { name: 'Canonical application' });
  expect(screen.getByText(/Deaktiviert/)).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Aktivieren' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Geheimnis ersetzen' })).not.toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.every(([url]) => ['/api/clients/access','/api/clients'].includes(url))).toBe(true);
});
test('creation defaults disabled, sends canonical metadata and shows then discards the only secret receipt', async () => {
  const user = await creation(); await user.click(screen.getByRole('button', { name: 'Verbindlich speichern' })); await screen.findByTestId('client-secret');
  expect(api.post).toHaveBeenCalledWith('/api/clients', { name: 'New canonical app', redirectUris: ['https://new-app.test/callback'], scopes: ['openid','profile','email'], grantTypes: ['authorization_code','refresh_token'], publicClient: false, enabled: false });
  expect(screen.getByTestId('client-secret')).toHaveTextContent(secret); await user.click(screen.getByRole('button', { name: 'Zugangsdaten schließen' }));
  expect(screen.queryByText(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});
test('public registration receives no invented secret or workload grant', async () => {
  const user = await creation(); await user.selectOptions(screen.getByLabelText('Client-Typ'), 'public'); await user.click(screen.getByRole('button', { name: 'Verbindlich speichern' }));
  await screen.findByText('Öffentlicher Client: kein Geheimnis, S256 PKCE erforderlich.'); expect(screen.queryByTestId('client-secret')).not.toBeInTheDocument();
  expect((api.post as jest.Mock).mock.calls[0][1].publicClient).toBe(true);
});
test('activation needs confirmation and sends only editable fields with the exact observed version', async () => {
  render(<AppRegistrationsView />); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name: 'Aktivieren' })); expect(api.put).not.toHaveBeenCalled();
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Änderung bestätigen' })); await screen.findByText(/Änderung bestätigt/);
  expect(api.put).toHaveBeenCalledWith('/api/clients/canonical-app', { name: 'Canonical application', enabled: true, publicClient: false,
    scopes: ['openid','profile','email'], grantTypes: ['authorization_code','refresh_token'], redirectUris: ['https://app.test/callback'] }, { headers: { 'If-Match': '"od-client:canonical-app:1"' } });
});
test.each(['Geheimnis ersetzen','Registrierung löschen'])('%s cannot dispatch without confirmation', async label => {
  render(<AppRegistrationsView />); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name: label })); expect(api.post).not.toHaveBeenCalled(); expect(api.delete).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Abbrechen und Stand prüfen' })); expect(api.post).not.toHaveBeenCalled(); expect(api.delete).not.toHaveBeenCalled();
});
test('privileged and current issuing clients have no delegated takeover controls', async () => {
  rows = [entry({ protected: true, scopes: ['roles'] }), entry({ clientId: 'console', name: 'Own console' })]; render(<AppRegistrationsView />);
  await screen.findByText('Privilegierte Scopes: nur globale Administration.'); expect(screen.queryByRole('button', { name: 'Geheimnis ersetzen' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Konfiguration bearbeiten' })).not.toBeInTheDocument();
});
test.each([503,412])('an uncertain/conflicting write (%s) stays unconfirmed and is never automatically retried', async status => {
  (api.post as jest.Mock).mockRejectedValue({ response: { status } }); const user = await creation(); await user.click(screen.getByRole('button', { name: 'Verbindlich speichern' }));
  await within(screen.getByRole('dialog')).findByRole('alert'); expect(api.post).toHaveBeenCalledTimes(1); expect(screen.getByRole('button', { name: 'Verbindlich speichern' })).toBeDisabled(); expect(screen.queryByTestId('client-secret')).not.toBeInTheDocument();
});
test.each([200,207])('HTTP %s is not confirmed registration even when a secret-shaped field is present', async status => {
  (api.post as jest.Mock).mockResolvedValue({ status, data: { ...entry(), clientSecret: secret } }); const user = await creation(); await user.click(screen.getByRole('button', { name: 'Verbindlich speichern' }));
  await within(screen.getByRole('dialog')).findByRole('alert'); expect(screen.queryByTestId('client-secret')).not.toBeInTheDocument();
});
test('a malformed or credential-bearing read is an error, never an empty successful registry', async () => {
  rows = [entry({ clientSecret: secret })]; render(<AppRegistrationsView />); await screen.findByRole('alert');
  expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.queryByText('Keine Registrierungen bestätigt.')).not.toBeInTheDocument();
});
test.each([{ clientSecret: '' }, { clientSecretHash: 'a'.repeat(64) }, { version: '9' }, { enabled: true }])('unconfirmed create receipts cannot display credentials: %j', async changed => {
  (api.post as jest.Mock).mockResolvedValue({ status: 201, data: { ...entry({ name: 'New canonical app', redirectUris: ['https://new-app.test/callback'] }), clientSecret: secret, ...changed } });
  const user = await creation(); await user.click(screen.getByRole('button', { name: 'Verbindlich speichern' })); await within(screen.getByRole('dialog')).findByRole('alert'); expect(screen.queryByTestId('client-secret')).not.toBeInTheDocument();
});
test('rotation replaces a version and shows the confirmed secret without fetching it from a list', async () => {
  render(<AppRegistrationsView />); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name: 'Geheimnis ersetzen' })); await user.click(screen.getByRole('button', { name: 'Änderung bestätigen' }));
  await screen.findByTestId('client-secret'); expect(api.post).toHaveBeenCalledWith('/api/clients/canonical-app/rotate-secret', {}, { headers: { 'If-Match': '"od-client:canonical-app:1"' } });
});
test('failed read authority clears rows instead of retaining an old positive display', async () => {
  render(<AppRegistrationsView />); const user = userEvent.setup(); await screen.findByRole('article'); (api.get as jest.Mock).mockRejectedValue({ response: { status: 503 } }); await user.click(screen.getByRole('button', { name: 'Register neu laden' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('article')).not.toBeInTheDocument();
});
test('a missing confirmed metadata change cannot be represented as a successful update', async () => {
  (api.put as jest.Mock).mockResolvedValue({ status: 200, data: entry({ version: '2' }) });
  await expect(registeredClients.update(entry(), { ...entry(), enabled: true })).rejects.toThrow('nicht bestätigt');
  await waitFor(() => expect(api.put).toHaveBeenCalledTimes(1));
});
