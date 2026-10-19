import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LicenseKioskView from '../../components/views/LicenseKioskView';
import { api } from '../../lib/api';
import toast from 'react-hot-toast';

const mockedApi = api as jest.Mocked<typeof api>;
test.each([['directory-unobserved','Verzeichnisnachweis fehlt'],['directory-stale','Verzeichnisnachweis abgelaufen'],['membership-expired','Mitgliedschaftsfrist abgelaufen']])('group lease status %s remains truthful even when its last directory poll failed',async(status,label)=>{
 mockBackend(['licenses.assignments.read']);const get=mockedApi.get;
 mockedApi.get=jest.fn((url:string)=>url==='/api/licenses/groups'?Promise.resolve({data:{groups:[{license_id:'office',group_id:'engineering',group_name:'Engineering',license_name:'Office Suite',status,last_error:'Owned directory outage',assigned_users:0,desired_users:1,directory_valid_until:'2026-10-18T12:00:00.000Z',membership_valid_until:'2026-10-18T11:59:00.000Z'}]}}):get(url)) as any;
 render(<LicenseKioskView/>);expect(await screen.findByText(label)).toBeInTheDocument();expect(screen.getByText('Owned directory outage')).toBeInTheDocument();expect(screen.getByText(/Ohne rechtzeitigen manuellen Abgleich/)).toBeInTheDocument();expect(screen.getByText(/Verzeichnis gültig bis:/)).toBeInTheDocument();expect(screen.getByText(/Früheste Mitgliedschaftsfrist:/)).toBeInTheDocument();expect(mockedApi.post).not.toHaveBeenCalled();
});
const license = {
  id: 'office', name: 'Office Suite', vendor: 'Vendor', category: 'Productivity',
  license_type: 'per_user', total_seats: 10, used_seats: 3, auto_approve: false,
};
const requests = [
  { id: 'own', license_id: 'office', license_name: 'Own Request', requester_id: 'alice', requester_name: 'Alice', assignee_type: 'user', assignee_id: 'alice', status: 'pending' },
  { id: 'other', license_id: 'office', license_name: 'Other Request', requester_id: 'bob', requester_name: 'Bob', assignee_type: 'user', assignee_id: 'bob', status: 'pending' },
  { id: 'beneficiary', license_id: 'office', license_name: 'Delegated Request', requester_id: 'manager', requester_name: 'Manager', assignee_type: 'user', assignee_id: 'alice', status: 'pending' },
  { id: 'cancelled', license_id: 'office', license_name: 'Cancelled Request', requester_id: 'alice', requester_name: 'Alice', assignee_type: 'user', assignee_id: 'alice', status: 'cancelled' },
];

function mockBackend(permissions: string[] = [], demoMode = false) {
  mockedApi.get = jest.fn((url: string) => {
    if (url === '/api/licenses/access') return Promise.resolve({ data: { subject: 'alice', identityState: 'active', permissions, demoMode } });
    if (url === '/api/licenses') return Promise.resolve({ data: { licenses: [{ ...license, cost_per_seat: '12.50', currency: 'CHF' }], total: 1 } });
    if (url === '/api/licenses/kiosk') return Promise.resolve({ data: { licenses: [license], total: 1 } });
    if (url === '/api/licenses/requests') return Promise.resolve({ data: { requests: requests.map(request => ({ ...request, identity_bound: true })), total: requests.length } });
    if (url === '/api/licenses/groups') return Promise.resolve({ data: { groups: [{ license_id: 'office', group_id: 'engineering', group_name: 'Engineering', license_name: 'Office Suite', status: 'capacity-blocked', assigned_users: 1, desired_users: 3, source_revision: '42' }] } });
    if (url === '/api/licenses/users') return Promise.resolve({ data: { users: [{ user_id: 'canonical-user', disabled: false, directory_revision: '43', directory_enabled: false, directory_deleted: false, directory_error: 'source unavailable' }] } });
    return Promise.reject(new Error(`Unexpected URL: ${url}`));
  }) as any;
  mockedApi.post = jest.fn().mockResolvedValue({ data: { status: 'pending' } });
}

beforeEach(() => {
  jest.clearAllMocks();
});

test.each([
  ['unlinked', /keiner Verzeichnis-Identität zugeordnet/],
  ['disabled', /Verzeichnis-Identität ist deaktiviert/],
  ['unavailable', /Identitätsquelle ist nicht verfügbar/],
])('shows the kiosk without private reads or actions for identity state %s', async (identityState, message) => {
  mockBackend(['licenses.catalog.manage', 'licenses.catalog.read', 'licenses.requests.review']);
  const get = mockedApi.get;
  mockedApi.get = jest.fn((url: string) => url === '/api/licenses/access'
    ? Promise.resolve({ data: { identityState, subject: null, permissions: ['licenses.catalog.manage', 'licenses.catalog.read', 'licenses.requests.review'] } }) : get(url)) as any;
  render(<LicenseKioskView />);
  expect(await screen.findByText(message)).toBeInTheDocument();
  expect(await screen.findByText('Office Suite')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Bestellen' })).toBeDisabled();
  expect(screen.queryByRole('button', { name: 'Verwaltung' })).not.toBeInTheDocument();
  expect(mockedApi.get).not.toHaveBeenCalledWith('/api/licenses/requests');
  expect(mockedApi.get).not.toHaveBeenCalledWith('/api/licenses');
});

test('legacy pending requests remain visible to reviewers but cannot be approved or denied', async () => {
  mockBackend(['licenses.requests.read', 'licenses.requests.review']);
  const get = mockedApi.get;
  mockedApi.get = jest.fn((url: string) => url === '/api/licenses/requests'
    ? Promise.resolve({ data: { requests: [{ ...requests[1], identity_bound: false }] } }) : get(url)) as any;
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await screen.findByText('Office Suite');
  await user.click(screen.getByRole('button', { name: /Anfragen/ }));
  expect(screen.getByText('Other Request')).toBeInTheDocument();
  expect(screen.getByText('Identität ungeklärt – Anfrage neu erstellen')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Genehmigen' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Ablehnen' })).not.toBeInTheDocument();
});

test('group rules report blocked capacity without pretending all members were assigned', async () => {
  mockBackend(['licenses.catalog.read', 'licenses.assignments.read']);
  render(<LicenseKioskView />);
  expect(await screen.findByText('Kapazität fehlt')).toBeInTheDocument();
  expect(screen.getByText('1 / 3 Mitglieder')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Abgleichen' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Gruppenquelle entziehen' })).not.toBeInTheDocument();
});

test('group managers can request reconciliation without supplying a membership list', async () => {
  mockBackend(['licenses.catalog.read', 'licenses.assignments.read', 'licenses.assignments.manage']);
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await user.click(await screen.findByRole('button', { name: 'Abgleichen' }));
  expect(mockedApi.post).toHaveBeenCalledWith('/api/licenses/office/groups/engineering/reconcile');
});

test('read-only assignment access shows last confirmed eligibility and source errors without mutation controls', async () => {
  mockBackend(['licenses.assignments.read']);
  render(<LicenseKioskView />);
  expect(await screen.findByText('Im Verzeichnis deaktiviert')).toBeInTheDocument();
  expect(screen.getByText('Abgleichfehler: source unavailable')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Kontostand abgleichen' })).not.toBeInTheDocument();
});

test('an assignment manager can reconcile the authoritative user state without submitting eligibility flags', async () => {
  mockBackend(['licenses.assignments.read', 'licenses.assignments.manage']);
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await user.click(await screen.findByRole('button', { name: 'Kontostand abgleichen' }));
  expect(mockedApi.post).toHaveBeenCalledWith('/api/licenses/users/canonical-user/reconcile');
});

test('a rejected review reloads server-side cancellation instead of displaying stale pending actions', async () => {
  mockBackend(['licenses.requests.read', 'licenses.requests.review']);
  let cancelled = false; const get = mockedApi.get;
  mockedApi.get = jest.fn((url: string) => url === '/api/licenses/requests'
    ? Promise.resolve({ data: { requests: [{ ...requests[1], identity_bound: true, status: cancelled ? 'cancelled' : 'pending' }] } }) : get(url)) as any;
  mockedApi.post = jest.fn().mockImplementation(async () => { cancelled = true; throw new Error('beneficiary disabled'); });
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await screen.findByText('Office Suite');
  await user.click(screen.getByRole('button', { name: /Anfragen/ }));
  await user.click(screen.getByRole('button', { name: 'Genehmigen' }));
  expect(await screen.findByText('Zurückgezogen')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Genehmigen' })).not.toBeInTheDocument();
  expect(toast.error).toHaveBeenCalledWith('Anfrage konnte nicht genehmigt werden');
});

test('approval and group provisioning are distinct statuses in request history', async () => {
  mockBackend(['licenses.requests.read']);
  const get = mockedApi.get;
  mockedApi.get = jest.fn((url: string) => url === '/api/licenses/requests'
    ? Promise.resolve({ data: { requests: [{ ...requests[0], assignee_type: 'group', status: 'approved', allocation_status: 'capacity-blocked' }] } }) : get(url)) as any;
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await screen.findByText('Office Suite');
  await user.click(screen.getByRole('button', { name: /Anfragen/ }));
  expect(screen.getByText('Genehmigt · Kapazität fehlt')).toBeInTheDocument();
});

test('uses the self-service catalog and real response envelopes without admin privileges', async () => {
  mockBackend();
  render(<LicenseKioskView />);
  expect(await screen.findByText('Office Suite')).toBeInTheDocument();
  expect(mockedApi.get).toHaveBeenCalledWith('/api/licenses/kiosk');
  expect(mockedApi.get).not.toHaveBeenCalledWith('/api/licenses');
  expect(screen.queryByRole('button', { name: 'Verwaltung' })).not.toBeInTheDocument();
  expect(screen.queryByText('Kosten der Zuweisungen')).not.toBeInTheDocument();
  expect(screen.queryByText(/CHF/)).not.toBeInTheDocument();
});

test('submits a request for the signed-in identity without placeholder or delegated identity fields', async () => {
  mockBackend();
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await screen.findByText('Office Suite');
  await user.click(screen.getByRole('button', { name: 'Bestellen' }));
  expect(screen.getByText(/für dein angemeldetes Benutzerkonto/)).toBeInTheDocument();
  expect(screen.queryByPlaceholderText('user123')).not.toBeInTheDocument();
  await user.type(screen.getByPlaceholderText('Warum wird diese Lizenz benötigt?'), 'Für die Arbeit');
  await user.click(screen.getAllByRole('button', { name: 'Bestellen' })[1]);
  await waitFor(() => expect(mockedApi.post).toHaveBeenCalledWith('/api/licenses/office/request', { justification: 'Für die Arbeit' }));
  expect(toast.success).toHaveBeenCalledWith('Anfrage eingereicht — wartet auf Genehmigung');
});

test('shows request status without review actions to ordinary users', async () => {
  mockBackend();
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await screen.findByText('Office Suite');
  await user.click(screen.getByRole('button', { name: /Anfragen/ }));
  expect(screen.getByText('Own Request')).toBeInTheDocument();
  expect(screen.getByText('Zurückgezogen')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Genehmigen' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Ablehnen' })).not.toBeInTheDocument();
});

test('limits approval actions to requests by and for other users', async () => {
  mockBackend(['licenses.requests.read', 'licenses.requests.review']);
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await screen.findByText('Office Suite');
  await user.click(screen.getByRole('button', { name: /Anfragen/ }));
  expect(screen.getAllByRole('button', { name: 'Genehmigen' })).toHaveLength(1);
  await user.click(screen.getByRole('button', { name: 'Genehmigen' }));
  expect(mockedApi.post).toHaveBeenCalledWith('/api/licenses/requests/other/approve');
  expect(mockedApi.get).not.toHaveBeenCalledWith('/api/licenses');
});

test('lets readers view private catalog data but hides catalog changes', async () => {
  mockBackend(['licenses.catalog.read']);
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await screen.findByText('Office Suite');
  expect(screen.getByText('CHF 12.50')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Verwaltung' }));
  expect(screen.queryByRole('button', { name: /Lizenz hinzufügen/ })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /bearbeiten|entfernen/ })).not.toBeInTheDocument();
});

test('shows management controls only for the corresponding permission', async () => {
  mockBackend(['licenses.catalog.read', 'licenses.catalog.manage']);
  const user = userEvent.setup();
  render(<LicenseKioskView />);
  await screen.findByText('Office Suite');
  await user.click(screen.getByRole('button', { name: 'Verwaltung' }));
  expect(screen.getByRole('button', { name: /Lizenz hinzufügen/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Lizenz Office Suite bearbeiten' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Lizenz Office Suite entfernen' })).toBeInTheDocument();
});

test('shows an error and no privileged controls when capabilities cannot be loaded', async () => {
  mockedApi.get = jest.fn().mockRejectedValue(new Error('Unauthorized'));
  render(<LicenseKioskView />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Lizenzdaten konnten nicht geladen werden');
  expect(screen.queryByRole('button', { name: 'Verwaltung' })).not.toBeInTheDocument();
  expect(mockedApi.get).toHaveBeenCalledTimes(1);
});

test('explicitly identifies development fallback mode', async () => {
  mockBackend([], true);
  render(<LicenseKioskView />);
  expect(await screen.findByRole('status')).toHaveTextContent('Demo-Modus');
});
