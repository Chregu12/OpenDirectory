import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import toast from 'react-hot-toast';
import PolicyCreationWizard from '../../components/setup/PolicyCreationWizard';
import SecuritySetupWizard from '../../components/setup/SecuritySetupWizard';
import { api } from '../../lib/api';

jest.mock('../../lib/api', () => ({ api: { get: jest.fn(), post: jest.fn(), patch: jest.fn() } }));

beforeEach(() => { jest.clearAllMocks(); window.localStorage.clear(); });

test.each([
  ['policy', PolicyCreationWizard, 'od_policy_created'],
  ['security', SecuritySetupWizard, 'od_security_setup'],
] as const)('%s setup reports unsupported instead of sending unknown configuration or saving a false success', async (_name, Component, storageKey) => {
  const onClose = jest.fn(); const user = userEvent.setup();
  const storage = jest.spyOn(Storage.prototype, 'setItem');
  try {
    render(<Component onClose={onClose} />);
    expect(screen.getByRole('status')).toHaveTextContent('nicht');
    expect(screen.getByText('Nicht verfügbar')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Weiter' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Schliessen' }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(api.get).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled(); expect(api.patch).not.toHaveBeenCalled();
    expect(storage).not.toHaveBeenCalled(); expect(window.localStorage.getItem(storageKey)).toBeNull();
    expect(toast.success).not.toHaveBeenCalled();
  } finally { storage.mockRestore(); }
});

test('the policy notice links to the existing governed editor rather than invented domain or group targets', () => {
  render(<PolicyCreationWizard onClose={jest.fn()} />);
  expect(screen.getByRole('link', { name: 'Zum Richtlinieneditor' })).toHaveAttribute('href', '/policies');
  expect(screen.getByRole('status')).toHaveTextContent('keine bestätigte Gerätebereitstellung');
  expect(screen.queryByText('Standard-Benutzer')).not.toBeInTheDocument();
});

test('security setup does not present missing observations as zero threats or a compliance score', async () => {
  const onClose = jest.fn(); const user = userEvent.setup(); render(<SecuritySetupWizard onClose={onClose} />);
  expect(screen.getByRole('status')).toHaveTextContent('Fehlende Sicherheitsdaten');
  expect(screen.queryByText('0 Bedrohungen')).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Assistent schliessen' }));
  expect(onClose).toHaveBeenCalledTimes(1); expect(toast.success).not.toHaveBeenCalled();
});
