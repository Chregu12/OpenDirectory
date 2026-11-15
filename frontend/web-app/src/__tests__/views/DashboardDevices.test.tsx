import { act, render, screen, waitFor, within } from '@testing-library/react';
import DashboardView from '@/components/views/DashboardView';
import { api } from '@/lib/api';

jest.mock('@/components/views/PIMGroupsPanel', () => () => null);
jest.mock('next/navigation', () => ({ useRouter: () => ({ push: jest.fn() }) }));

const actor = '11111111-1111-4111-8111-111111111111', tenant = '22222222-2222-4222-8222-222222222222';
const checkedAt = '2026-11-15T10:00:00.000Z';
const devices = Array.from({ length: 25 }, (_, index) => ({
  id: `33333333-3333-4333-8333-${String(index).padStart(12, '0')}`, tenantId: tenant,
  assetId: `INV-${index}`, serialNumber: `SER-${index}`, manufacturer: 'Test', model: 'Laptop', deviceClass: 'laptop',
  platform: 'linux', osVersion: '', ownership: 'corporate', purchaseDate: '', warrantyEnd: '', description: '',
  revision: '1', lifecycle: 'available', managementMode: 'inventory-only', enrollmentStatus: 'not-enrolled',
  managementProvider: null, complianceStatus: 'unknown', lastSeen: null, assignedUserId: null, assignmentId: null,
  createdAt: checkedAt, updatedAt: checkedAt,
}));
const fleet = { schemaVersion: 1, actorUserId: actor, devices, total: 40, page: 1, limit: 25, fleet: {
  protocol: 1, tenantId: tenant, checkedAt,
  counts: { total: 40, connected: 8, offline: 3, pending: 2, 'not-enrolled': 27, expired: 0, revoked: 0 },
  connections: devices.map(device => ({ deviceId: device.id, status: 'not-enrolled', enrolledAt: null, lastSeen: null, credentialExpiresAt: null, enrollmentExpiresAt: null, report: null })),
} };
const compliance = { schemaVersion: 1, actorUserId: actor, tenantId: tenant, checkedAt, page: 1, limit: 25, total: 40,
  counts: { total: 40, compliant: 10, 'non-compliant': 8, unknown: 4, 'not-configured': 6, pending: 5, stale: 4, historical: 3 },
  devices: devices.map((device, index) => ({ deviceId: device.id, assetId: device.assetId, platform: device.platform, status: index < 10 ? 'compliant' : index < 18 ? 'non-compliant' : index < 22 ? 'unknown' : 'pending', policyRevision: '1', evaluatedAt: checkedAt })),
};
let denyInventory = false, denyCompliance = false;
function response(url: string) {
  if (url === '/api/devices/capabilities') return { schemaVersion: 1, inventoryProtocol: 2, userId: actor, tenantId: tenant, permissions: ['devices.inventory.read'], managementMode: 'inventory-only', supportedActions: [] };
  if (url === '/api/devices/fleet') { if (denyInventory) throw { response: { status: 428 } }; return fleet; }
  if (url === '/api/devices/compliance/capabilities') { if (denyCompliance) throw { response: { status: 403 } }; return { schemaVersion: 1, complianceProtocol: 1, actorUserId: actor, tenantId: tenant, permissions: ['devices.compliance.read'] }; }
  if (url === '/api/devices/compliance') return compliance;
  if (url === '/api/platform/capabilities') return { configuredServices: [] };
  return {};
}
const card = () => within(screen.getByRole('group', { name: 'Geräte', exact: true }));
beforeEach(() => {
  denyInventory = false; denyCompliance = false;
  (api.get as jest.Mock).mockImplementation(async (url: string) => ({ status: 200, data: response(url) }));
});
afterEach(() => { jest.useRealTimers(); });

test('dashboard uses full fleet and actual compliance counts beyond the first inventory page', async () => {
  render(<DashboardView />);
  await screen.findByText('29 ohne aktive Verbindung');
  expect(card().getByText('40')).toBeVisible();
  expect(card().getByText('3 offline')).toBeVisible();
  expect(card().getAllByText('8 online')).toHaveLength(2);
  expect(screen.getByText('Erste 25 von 40 Geräten.')).toBeInTheDocument();
  const assessment = screen.getByRole('region', { name: 'Geräte-Compliance' });
  expect(within(assessment).getByText('Konform').nextSibling).toHaveTextContent('10');
  expect(within(assessment).getByText('Meldung abgelaufen').nextSibling).toHaveTextContent('4');
  expect(within(assessment).getByText('40')).toBeVisible();
  expect(screen.queryByText(/Score [≥<]/)).not.toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/devices')).toBe(false);
});

test('independent compliance denial does not erase authorized inventory or invent a compliance score', async () => {
  denyCompliance = true;
  render(<DashboardView />);
  await screen.findByText(/tatsächliche Compliance-Berechtigung/);
  expect(card().getByText('40')).toBeVisible();
  expect(within(screen.getByRole('region', { name: 'Geräte-Compliance' })).queryByText('Konform')).toBeNull();
});

test('a denied refresh removes old fleet and compliance data', async () => {
  jest.useFakeTimers();
  render(<DashboardView />);
  await screen.findByText('29 ohne aktive Verbindung');
  denyInventory = true; denyCompliance = true;
  await act(async () => { jest.advanceTimersByTime(30000); });
  await screen.findByText(/höchstens fünf Minuten alte MFA-Anmeldung/);
  expect(card().getByText('—')).toBeVisible();
  expect(screen.queryByText('29 ohne aktive Verbindung')).toBeNull();
  expect(screen.queryByText('Erste 25 von 40 Geräten.')).toBeNull();
  expect(within(screen.getByRole('region', { name: 'Geräte-Compliance' })).queryByText('Konform')).toBeNull();
});

test('session invalidation prevents an already pending fleet response from restoring device data', async () => {
  let finish!: (value: unknown) => void;
  (api.get as jest.Mock).mockImplementation((url: string) => url === '/api/devices/fleet'
    ? new Promise(resolve => { finish = resolve; }) : Promise.resolve({ status: 200, data: response(url) }));
  render(<DashboardView />);
  await waitFor(() => expect(finish).toBeDefined());
  act(() => { window.dispatchEvent(new Event('od:session-error')); });
  await act(async () => { finish({ status: 200, data: fleet }); });
  expect(card().getByText('—')).toBeVisible();
  expect(screen.queryByText('29 ohne aktive Verbindung')).toBeNull();
  expect(screen.queryByText('Erste 25 von 40 Geräten.')).toBeNull();
});
