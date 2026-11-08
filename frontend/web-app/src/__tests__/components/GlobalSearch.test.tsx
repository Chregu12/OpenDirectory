import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import GlobalSearch from '@/components/layout/GlobalSearch';
import { VIEWS } from '@/lib/views';
import { directoryUsers } from '@/lib/directoryUsers';
const mockPush = jest.fn();
jest.mock('next/navigation', () => ({ useRouter: () => ({ push: mockPush }) }));
jest.mock('@/lib/directoryUsers', () => ({ directoryUsers: { access: jest.fn(), list: jest.fn() } }));
jest.mock('@/lib/deviceInventory', () => ({ DeviceInventoryClient: jest.fn().mockImplementation(() => ({ reload: jest.fn().mockRejectedValue({ response: { status: 428 } }), dispose: jest.fn() })), deviceInventoryError: () => 'Frische MFA erforderlich.' }));
const id = '22222222-2222-4222-8222-222222222222';
beforeEach(() => {
  jest.clearAllMocks();
  (directoryUsers.access as jest.Mock).mockResolvedValue({ userId: id, permissions: ['users.read'], directoryReadProtocol: 1, demoMode: false });
  (directoryUsers.list as jest.Mock).mockResolvedValue({ users: [{ id, username: 'langername', displayName: 'Testperson' }] });
});
test('opens the exact found person and restores focus', async () => {
  render(<GlobalSearch views={VIEWS.filter(view => ['users', 'devices'].includes(view.id))} />);
  const trigger = screen.getByRole('button', { name: 'Globale Suche öffnen' });
  await userEvent.click(trigger); await userEvent.type(screen.getByRole('combobox'), 'Testperson');
  await userEvent.click(await screen.findByRole('option', { name: 'Person Testperson' }));
  expect(mockPush).toHaveBeenCalledWith('/users?selected=' + id);
  await waitFor(() => expect(trigger).toHaveFocus());
});
test('keeps source failures distinct from no matches', async () => {
  (directoryUsers.list as jest.Mock).mockRejectedValue(new Error('unavailable'));
  render(<GlobalSearch views={VIEWS.filter(view => ['users', 'devices'].includes(view.id))} />);
  await userEvent.click(screen.getByRole('button', { name: 'Globale Suche öffnen' }));
  await userEvent.type(screen.getByRole('combobox'), 'nirgends');
  expect(await screen.findByText(/Personensuche nicht verfügbar/)).toBeInTheDocument();
  expect(screen.getByText(/Frische MFA erforderlich/)).toBeInTheDocument();
});
test('ignores late responses for a previous search', async () => {
  let finish!: (value: unknown) => void;
  (directoryUsers.list as jest.Mock).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })).mockResolvedValue({ users: [] });
  render(<GlobalSearch views={VIEWS.filter(view => view.id === 'users')} />);
  await userEvent.click(screen.getByRole('button', { name: 'Globale Suche öffnen' }));
  const input = screen.getByRole('combobox'); await userEvent.type(input, 'alt');
  await waitFor(() => expect(directoryUsers.list).toHaveBeenCalled());
  await userEvent.clear(input); await userEvent.type(input, 'neu');
  await waitFor(() => expect(screen.getByText('Keine bestätigten Treffer. Suchbegriff anpassen.')).toBeInTheDocument());
  await act(async () => finish({ users: [{ id, username: 'alt' }] }));
  expect(screen.queryByRole('option', { name: 'Person alt' })).not.toBeInTheDocument();
});
test('opens the exact canonical device with the device context in its deep link', async () => {
  const { DeviceInventoryClient } = require('@/lib/deviceInventory');
  DeviceInventoryClient.mockImplementation(() => ({ reload: jest.fn().mockResolvedValue({ permissions: ['devices.inventory.read'] }), list: jest.fn().mockResolvedValue({ devices: [{ id, assetId: 'INV-TEST', model: 'Testgerät' }] }), dispose: jest.fn() }));
  render(<GlobalSearch views={VIEWS.filter(view => view.id === 'devices')} />);
  await userEvent.click(screen.getByRole('button', { name: 'Globale Suche öffnen' }));
  await userEvent.type(screen.getByRole('combobox'), 'INV-TEST');
  await userEvent.click(await screen.findByRole('option', { name: 'Gerät INV-TEST · Testgerät' }));
  expect(mockPush).toHaveBeenCalledWith('/devices?selected=' + id);
});

test('the combobox opens its active option with ArrowDown and Enter', async () => {
  render(<GlobalSearch views={VIEWS.filter(view => view.id === 'users')} />);
  await userEvent.click(screen.getByRole('button', { name: 'Globale Suche öffnen' }));
  await userEvent.type(screen.getByRole('combobox'), 'Testperson');
  await screen.findByRole('option', { name: 'Person Testperson' });
  await userEvent.keyboard('{ArrowDown}{Enter}');
  expect(mockPush).toHaveBeenCalledWith('/users?selected=' + id);
});
