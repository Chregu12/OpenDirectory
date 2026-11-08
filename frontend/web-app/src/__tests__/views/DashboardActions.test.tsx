jest.mock('../../components/views/PIMGroupsPanel', () => () => null);
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import DashboardView from '@/components/views/DashboardView';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

const mockPush = jest.fn();
jest.mock('next/navigation', () => ({ useRouter: () => ({ push: mockPush }) }));

test('dashboard actions open their actual workflow without a fabricated success', async () => {
  (api.get as jest.Mock).mockImplementation(async (url: string) => ({ data: url === '/api/platform/capabilities' ? { configuredServices: ['identity-service'] } : {} }));
  render(<DashboardView />);
  fireEvent.click(await screen.findByRole('button', { name: 'Nutzer hinzufügen' }));
  expect(mockPush).toHaveBeenLastCalledWith('/users?create=1');
  fireEvent.click(screen.getByRole('button', { name: 'Gerät erfassen' }));
  expect(mockPush).toHaveBeenLastCalledWith('/devices?create=1');
  fireEvent.click(screen.getByRole('button', { name: 'App verbinden' }));
  expect(mockPush).toHaveBeenLastCalledWith('/identity');
  fireEvent.click(screen.getByRole('button', { name: 'Richtlinien verwalten' }));
  expect(mockPush).toHaveBeenLastCalledWith('/policies');
  expect(toast.success).not.toHaveBeenCalled();
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/auth/audit/login-history?limit=8'));
});
