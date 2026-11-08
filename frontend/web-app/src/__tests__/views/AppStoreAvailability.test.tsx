import { render, screen } from '@testing-library/react';
import AppStoreView from '@/components/views/AppStoreView';
import { api } from '@/lib/api';
jest.mock('@/lib/ui-mode', () => ({ useUiMode: () => ({ isSimple: true }) }));
beforeEach(() => { jest.clearAllMocks(); });
test('shows catalog failure as an error without sample data or success', async () => {
  (api.get as jest.Mock).mockRejectedValue(new Error('Unavailable'));
  render(<AppStoreView />);
  expect(await screen.findByRole('alert')).toHaveTextContent('App-Katalog konnte nicht geladen');
  expect(screen.queryByText(/Demo-Modus/)).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Erneut laden' })).toBeInTheDocument();
});
test('a confirmed catalog does not enable remote install on an invented device', async () => {
  (api.get as jest.Mock).mockImplementation(async (url: string) => ({ data: url.includes('/catalog') ? { apps: [{ id: 'fixture-app', name: 'test', display_name: 'Test App', category: 'tools', publisher: 'Test', description: 'Testdaten', version: '1', platforms: ['macos'], tags: [], packages: {}, enabled: true }], total: 1, page: 1, totalPages: 1 } : url.endsWith('/stats') ? { apps: { total: 1, enabled: 1 }, installations: { installed: 0, pending: 0, failed: 0 }, categories: [], licenses: {} } : [] }));
  render(<AppStoreView />);
  expect(await screen.findByText('Test App')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Install' })).not.toBeInTheDocument();
  expect(screen.getByText(/Gerätegebundene Installation benötigt einen verbundenen Agenten/)).toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => String(url).includes('self-service'))).toBe(false);
});

test('a provider version is hidden when it belongs to a previous package binding', async () => {
 (api.get as jest.Mock).mockResolvedValue({data:{apps:[{id:'a',display_name:'Source Test',publisher:'Fixture',platforms:['macos'],packages:{macos:{type:'brew',id:'new-package'}},metadata:{catalogReleases:{macos:{packageId:'old-package',version:'987.1',provider:'Homebrew',status:'confirmed',checkedAt:'2026-11-02T12:00:00Z'}}}}],page:1,total:1,totalPages:1}});
 render(<AppStoreView/>);await screen.findByText('Source Test');expect(screen.queryByText(/987.1/)).not.toBeInTheDocument();expect(screen.getByText(/Version nicht bestätigt/)).toBeInTheDocument();
});
