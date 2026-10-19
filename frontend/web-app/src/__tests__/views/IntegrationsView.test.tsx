import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import IntegrationsView from '../../components/views/IntegrationsView';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;
function backend(permissions: string[] = []) {
  mockedApi.get = jest.fn((url: string) => {
    if (url === '/api/gateway/access') return Promise.resolve({ data: { subject: 'operator', permissions, keyIssuanceEnabled: false } });
    if (url === '/api/gateway/api-keys') return Promise.resolve({ data: [{ id: 'old-key', name: 'Legacy Record', permissions: ['read'], active: true }] });
    if (url === '/api/gateway/webhooks') return Promise.resolve({ data: [{ id: 'hook', name: 'Hook', url: 'https://example.test/hook', events: [], active: true }] });
    return Promise.resolve({ data: [] });
  }) as any;
  mockedApi.post = jest.fn().mockResolvedValue({ data: {} });
}
beforeEach(() => { jest.clearAllMocks(); });

test('ordinary identities cannot fetch administrative lists or open mutation dialogs', async () => {
  backend(); render(<IntegrationsView />);
  expect(await screen.findByText(/Gateway-API-Schlüssel sind stillgelegt/)).toBeInTheDocument();
  expect(mockedApi.get).not.toHaveBeenCalledWith('/api/gateway/api-keys');
  expect(mockedApi.get).not.toHaveBeenCalledWith('/api/gateway/webhooks');
  expect(screen.queryByRole('button', { name: /API-Schlüssel erstellen/ })).not.toBeInTheDocument();
  await userEvent.setup().click(screen.getByRole('button', { name: 'Webhooks' }));
  expect(screen.queryByRole('button', { name: 'Webhook hinzufügen' })).not.toBeInTheDocument();
});
test('read-only webhook permission never enables test delivery or writes', async () => {
  backend(['gateway.webhooks.read']); render(<IntegrationsView />);
  await screen.findByText(/Gateway-API-Schlüssel sind stillgelegt/);
  await userEvent.setup().click(screen.getByRole('button', { name: 'Webhooks' }));
  expect(await screen.findByText('Hook')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Test senden' })).toBeDisabled();
  expect(screen.queryByRole('button', { name: 'Webhook hinzufügen' })).not.toBeInTheDocument();
});
test('retired credentials are not advertised as active and no new master key can be minted in the UI', async () => {
  backend(['gateway.keys.read', 'gateway.keys.manage']); render(<IntegrationsView />);
  expect(await screen.findByText('Legacy Record')).toBeInTheDocument();
  expect(screen.getByText('Stillgelegt')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /erstellen/i })).not.toBeInTheDocument();
});
test('an unavailable capability source clears privileges instead of pretending administrative lists are empty', async () => {
  mockedApi.get = jest.fn().mockRejectedValue(new Error('authority unavailable'));
  render(<IntegrationsView />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Gateway-Anmeldung oder Berechtigungen sind nicht verfügbar.');
  expect(mockedApi.get).toHaveBeenCalledTimes(1);
});
