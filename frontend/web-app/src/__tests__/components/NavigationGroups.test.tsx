import { fireEvent, render, screen } from '@testing-library/react';
import UnifiLayout from '@/components/layout/UnifiLayout';
import { api } from '@/lib/api';

jest.mock('next/navigation', () => ({ useRouter: () => ({ replace: jest.fn(), push: jest.fn() }) }));
const user = { name: 'Test Operator', role: 'admin', roles: ['admin'] };
beforeEach(() => {
  window.matchMedia = jest.fn().mockReturnValue({ matches: false, addEventListener: jest.fn(), removeEventListener: jest.fn() });
  (api.get as jest.Mock).mockImplementation(async (url: string) => ({ data: url === '/api/platform/capabilities' ? { configuredServices: ['app-store'] } : { subject: 'operator', userId: '11111111-1111-4111-8111-111111111111', permissions: ['users.read', 'licenses.users.read'], demoMode: false, history: [] } }));
});
test('keeps the active chapter open and unavailable extensions out of navigation', async () => {
  render(<UnifiLayout activeView="users" currentUser={user} onViewChange={jest.fn()}>Content</UnifiLayout>);
  expect((await screen.findByText('Unternehmen & Personen')).closest('details')).toHaveAttribute('open');
  expect(screen.queryByText('Apps & Lizenzen', { selector: 'summary' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'People' })).toHaveAttribute('aria-current','true');
  expect(screen.queryByRole('button', { name: 'Antivirus' })).not.toBeInTheDocument();
});
test('opening a chapter survives header updates and links navigate', async () => {
  const navigate = jest.fn();
  render(<UnifiLayout activeView="dashboard" currentUser={user} onViewChange={navigate}>Content</UnifiLayout>);
  fireEvent.click(await screen.findByRole('button',{name:'Apps & Services'}));
  const summary = await screen.findByText('Apps & Lizenzen', { selector: 'summary' });
  fireEvent.click(summary); fireEvent.click(summary);
  expect(summary.closest('details')).toHaveAttribute('open');
  fireEvent.click(screen.getByRole('button', { name: 'Benutzermenü' }));
  expect(screen.getByText('Apps & Lizenzen', { selector: 'summary' }).closest('details')).toBe(summary.closest('details'));
  expect(summary.closest('details')).toHaveAttribute('open');
  fireEvent.click(screen.getByRole('button', { name: 'Lizenzverwaltung' }));
  expect(navigate).toHaveBeenCalledWith('licenses');
});
test('failed notification queries never announce healthy services', async () => {
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url === '/api/auth/audit/login-history?limit=5') throw new Error('Unavailable');
    return { data: url === '/api/platform/capabilities' ? { configuredServices: [] } : { subject: 'test', userId: null, permissions: [], demoMode: false } };
  });
  render(<UnifiLayout activeView="dashboard" currentUser={user} onViewChange={jest.fn()}>Content</UnifiLayout>);
  fireEvent.click(screen.getByRole('button', { name: 'Benachrichtigungen' }));
  expect(await screen.findByText(/Anmeldehistorie nicht verfügbar/)).toBeInTheDocument();
  expect(screen.queryByText(/Alle Dienste laufen normal|System betriebsbereit/)).not.toBeInTheDocument();
});

test('main areas and contextual dropdowns preserve the currently authorized task set', async()=>{
 const navigate=jest.fn();const {rerender}=render(<UnifiLayout activeView="users" currentUser={user} onViewChange={navigate}>Content</UnifiLayout>);
 await screen.findByRole('button',{name:'Apps & Services'});
 expect(screen.queryByRole('button',{name:'Brands'})).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Ads'})).not.toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Devices'}));expect(await screen.findByText('Geräte',{selector:'summary'})).toBeInTheDocument();expect(screen.queryByRole('button',{name:'Mitarbeitende'})).not.toBeInTheDocument();
 rerender(<UnifiLayout activeView="devices" currentUser={user} onViewChange={navigate}>Content</UnifiLayout>);
 fireEvent.click(screen.getByRole('button',{name:'People'}));expect(navigate).toHaveBeenLastCalledWith('users');expect(screen.getByRole('button',{name:'Mitarbeitende'})).toBeInTheDocument();
});
