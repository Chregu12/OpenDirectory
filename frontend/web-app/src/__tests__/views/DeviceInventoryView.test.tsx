import React from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DeviceInventoryView from '@/components/views/DeviceInventoryView';
import { api } from '@/lib/api';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn(), put: jest.fn() } }));

const actorId = '11111111-1111-4111-8111-111111111111';
const tenantId = '22222222-2222-4222-8222-222222222222';
const deviceId = '33333333-3333-4333-8333-333333333333';
const recipientId = '44444444-4444-4444-8444-444444444444';
const assignmentId = '55555555-5555-4555-8555-555555555555';
const otherId = '66666666-6666-4666-8666-666666666666';
const device = (changes = {}) => ({ id: deviceId, tenantId, assetId: 'INV-001', serialNumber: 'SER-001', manufacturer: 'Framework', model: 'Laptop 13', deviceClass: 'laptop', platform: 'linux', osVersion: '', ownership: 'corporate', purchaseDate: '', warrantyEnd: '', description: '',
  revision: '1', lifecycle: 'available', managementMode: 'inventory-only', enrollmentStatus: 'not-enrolled', managementProvider: null, complianceStatus: 'unknown', lastSeen: null, assignedUserId: null, assignmentId: null,
  createdAt: '2026-10-19T10:00:00.000Z', updatedAt: '2026-10-19T10:00:00.000Z', ...changes });
const capabilities = (changes = {}) => ({ schemaVersion: 1, inventoryProtocol: 1, userId: actorId, tenantId, permissions: ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign'], managementMode: 'inventory-only', supportedActions: [], ...changes });
const identifier = (value: number) => '77777777-7777-4777-8777-' + String(value).padStart(12, '0');
const event = (version = 1) => {
  const assigned = version % 2 === 0;
  return { id: identifier(version), tenantId, deviceId, type: version === 1 ? 'device.registered' : assigned ? 'device.assigned' : 'device.assignment.released', version: 1, actorUserId: actorId, correlationId: otherId, createdAt: device().createdAt,
    before: version === 1 ? null : { assignedUserId: assigned ? null : recipientId, assignmentId: assigned ? null : identifier(version - 1), revision: String(version - 1) },
    after: { assignedUserId: assigned ? recipientId : null, assignmentId: assigned ? identifier(version) : null, revision: String(version) }, deliveryStatus: 'pending' };
};
let rows: any[];
let access: any;
let directoryAccess: any;
let events: any[];
let directoryRows: any[];
let requestedSearch: string;

function testUser() {
  const user = userEvent.setup();
  return {
    click: (target: HTMLElement) => act(async () => { await user.click(target); }),
    type: (target: HTMLElement, content: string) => act(async () => { await user.type(target, content); }),
    selectOptions: (target: HTMLElement, value: string) => act(async () => { await user.selectOptions(target, value); }),
  };
}

function deferred<Result>() {
  let resolve: (result: Result) => void;
  const promise = new Promise<Result>(complete => { resolve = complete; });
  return { promise, resolve: (result: Result) => resolve(result) };
}
async function getResponse(url: string, config?: any) {
  if (url === '/api/devices/capabilities') return { status: 200, data: access };
  if (url === '/api/devices') {
    requestedSearch = config?.params?.search || '';
    const page = config.params.page;
    return { status: 200, data: { schemaVersion: 1, actorUserId: actorId, devices: rows.slice((page - 1) * 25, page * 25), total: rows.length, page, limit: 25 } };
  }
  if (url === '/api/devices/' + deviceId) return { status: 200, data: rows.find(row => row.id === deviceId) };
  if (url === '/api/devices/' + deviceId + '/history') {
    const page = config.params.page;
    return { status: 200, data: { schemaVersion: 1, actorUserId: actorId, deviceId, events: events.slice((page - 1) * 25, page * 25), total: events.length, page, limit: 25 } };
  }
  if (url === '/api/identity/access') return { status: 200, data: directoryAccess };
  if (url === '/api/users') {
    if (!directoryAccess.permissions.includes('users.read')) throw new Error('Profile privacy boundary violated');
    const page = config.params.page;
    return { status: 200, data: { users: directoryRows.slice((page - 1) * 25, page * 25), total: directoryRows.length, page, limit: 25 } };
  }
  throw new Error('Unexpected HTTP read: ' + url);
}
beforeEach(() => {
  jest.resetAllMocks(); rows = [device()]; access = capabilities(); requestedSearch = ''; events = [event()]; directoryRows = [];
  directoryAccess = { subject: 'verified-human', userId: actorId, permissions: [], demoMode: false, directoryReadProtocol: 1 };
  (api.get as jest.Mock).mockImplementation(getResponse);
  (api.post as jest.Mock).mockImplementation(async (_url: string, input: any) => {
    const created = device({ ...input, id: otherId }); rows = [...rows, created]; return { status: 201, data: created };
  });
  (api.put as jest.Mock).mockImplementation(async (_url: string, input: any) => {
    const updated = { ...rows[0], assignedUserId: input.userId, assignmentId: input.userId ? otherId : null, lifecycle: input.userId ? 'assigned' : 'available', revision: String(BigInt(rows[0].revision) + BigInt(1)) };
    rows = [updated]; events = [...events, event(Number(updated.revision))]; return { status: 200, data: updated };
  });
});

async function openDevice() {
  render(<DeviceInventoryView />); const user = testUser();
  await user.click(await screen.findByRole('button', { name: 'INV-001' }));
  await screen.findByRole('article', { name: 'Gerätedetails' }); return user;
}
async function creationForm() {
  render(<DeviceInventoryView />); const user = testUser();
  await user.click(await screen.findByRole('button', { name: 'Gerät erfassen' }));
  const dialog = within(screen.getByRole('dialog', { name: 'Gerät erfassen' }));
  for(const name of ['Geräteklasse','Plattform','Eigentum'])expect(dialog.getByRole('combobox',{name})).toBeInTheDocument();
  for (const [label, value] of [['Inventarnummer', '  INV-NEW  '], ['Seriennummer', 'SER-NEW'], ['Hersteller', 'Dell'], ['Modell', 'Latitude']]) {
    await user.type(dialog.getByLabelText(label), value);
  }
  return { user, dialog };
}

test('renders actual inventory and audit records without provider controls or invented telemetry', async () => {
  await openDevice(); const details = within(screen.getByRole('article', { name: 'Gerätedetails' }));
  expect(details.getByText(deviceId)).toBeInTheDocument(); expect(details.getByText('SER-001')).toBeInTheDocument(); expect(details.getByText('Keine Telemetrie')).toBeInTheDocument();
  await details.findByText('Gerät erfasst'); expect(details.getByText(/Korrelations-ID:/)).toHaveTextContent(otherId);
  expect(screen.getByText(/Nur Inventar · Nicht registriert · Compliance unbekannt/)).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /enroll|wipe|remote|intune|jamf|registrieren/i })).not.toBeInTheDocument();
});

test('a read-only actor sees records and history but cannot create, assign or fetch user profiles', async () => {
  access = capabilities({ permissions: ['devices.inventory.read'] }); await openDevice(); await screen.findByText('Gerät erfasst');
  expect(screen.queryByRole('button', { name: 'Gerät erfassen' })).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Benutzerzuweisung' })).not.toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/identity/access' || url === '/api/users')).toBe(false);
});

test('missing inventory read permission does not load device data, histories or directories', async () => {
  access = capabilities({ permissions: [] }); render(<DeviceInventoryView />); await screen.findByText('Keine Berechtigung zum Lesen des Geräteinventars.');
  expect(api.get).toHaveBeenCalledTimes(1); expect(screen.queryByRole('button', { name: 'Gerät erfassen' })).not.toBeInTheDocument();
});

test.each([{ inventoryProtocol: 0 }, { schemaVersion: 2 }, { tenantId: null }, { supportedActions: ['wipe'] }])('legacy or unsafe capabilities fail closed without demo fallback: %j', async changes => {
  access = capabilities(changes); render(<DeviceInventoryView />); await screen.findByRole('alert');
  expect(api.get).toHaveBeenCalledTimes(1); expect(screen.queryByRole('button', { name: 'INV-001' })).not.toBeInTheDocument(); expect(screen.queryByText('Keine Geräte gefunden.')).not.toBeInTheDocument();
});

test('a server outage clears inventory and never masquerades as an empty successful read', async () => {
  (api.get as jest.Mock).mockImplementation((url, config) => url === '/api/devices' ? Promise.reject({ response: { status: 503 } }) : getResponse(url, config));
  render(<DeviceInventoryView />); await screen.findByRole('alert'); expect(screen.queryByText('Keine Geräte gefunden.')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Gerät erfassen' })).not.toBeInTheDocument();
});

test('server totals, pages and submitted search drive the inventory table', async () => {
  rows = Array.from({ length: 26 }, (_value, index) => device({ id: identifier(index + 1), assetId: 'INV-' + String(index + 1).padStart(3, '0') }));
  render(<DeviceInventoryView />); const user = testUser(); await screen.findByText('Seite 1 von 2 · 26 Einträge');
  await user.click(screen.getByRole('button', { name: 'Nächste Geräteseite' })); await screen.findByRole('button', { name: 'INV-026' });
  expect(api.get).toHaveBeenCalledWith('/api/devices', { params: { page: 2, limit: 25 }, signal: expect.any(AbortSignal) });
  await user.type(screen.getByLabelText('Geräte suchen'), '  Latitude  '); expect(requestedSearch).toBe('');
  await user.click(screen.getByRole('button', { name: 'Suchen' })); await waitFor(() => expect(requestedSearch).toBe('Latitude'));
  expect(api.get).toHaveBeenCalledWith('/api/devices', { params: { page: 1, limit: 25, search: 'Latitude' }, signal: expect.any(AbortSignal) });
});

test('create form submits only normalized real inventory fields and confirms only the HTTP receipt', async () => {
  const { user, dialog } = await creationForm(); expect(dialog.getAllByRole('textbox')).toHaveLength(6);
  expect(dialog.queryByLabelText(/password|token|enrollment|provider/i)).not.toBeInTheDocument();
  await user.click(dialog.getByRole('button', { name: 'Im Inventar speichern' })); await screen.findByText('Gerät INV-NEW im Inventar erfasst.');
  expect(api.post).toHaveBeenCalledWith('/api/devices', { assetId: 'INV-NEW', serialNumber: 'SER-NEW', manufacturer: 'Dell', model: 'Latitude', deviceClass: 'laptop', platform: 'other', ownership: 'corporate', osVersion: '', purchaseDate: '', warrantyEnd: '', description: '' }, { signal: expect.any(AbortSignal) });
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect((api.get as jest.Mock).mock.calls.filter(([url]) => url === '/api/devices/capabilities')).toHaveLength(2);
});

test('create cancellation never calls a write endpoint', async () => {
  const { user, dialog } = await creationForm(); await user.click(dialog.getByRole('button', { name: 'Abbrechen' })); expect(api.post).not.toHaveBeenCalled();
});

test('lost create authority is rechecked before a request can be sent', async () => {
  const { user, dialog } = await creationForm(); access = capabilities({ permissions: ['devices.inventory.read'] });
  await user.click(dialog.getByRole('button', { name: 'Im Inventar speichern' })); await screen.findByRole('alert'); expect(api.post).not.toHaveBeenCalled();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Gerät erfassen' })).not.toBeInTheDocument();
});

test('users.read absence uses only a canonical UUID input and never lists user metadata', async () => {
  const user = await openDevice(); const input = await screen.findByLabelText('Kanonische Benutzer-ID');
  expect(screen.queryByLabelText('Benutzer auswählen')).not.toBeInTheDocument(); expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false);
  await user.type(input, 'invalid-user'); await user.click(screen.getByRole('button', { name: 'Benutzer zuweisen' })); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
});

test.each([true,false])('the picker shows actual directory users only after separate users.read access verification, enabled=%s', async enabled => {
  directoryAccess.permissions = ['users.read']; directoryRows = [{ id: recipientId, username: 'actual-recipient', email: 'private@example.test', displayName: 'Actual Recipient', enabled, revision: '1', createdAt: device().createdAt }];
  const user = await openDevice(); await user.selectOptions(await screen.findByLabelText('Benutzer auswählen'), recipientId);
  expect(screen.getByRole('option', { name: 'Actual Recipient · actual-recipient'+(enabled?'':' · Gesperrter Verzeichniseintrag') })).toBeInTheDocument(); expect(screen.queryByLabelText('Kanonische Benutzer-ID')).not.toBeInTheDocument();
  const calls = (api.get as jest.Mock).mock.calls.map(([url]) => url); expect(calls.indexOf('/api/identity/access')).toBeLessThan(calls.indexOf('/api/users'));
  await user.click(screen.getByRole('button', { name: 'Benutzer zuweisen' })); expect(api.put).not.toHaveBeenCalled();
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await screen.findByText('Inventarzuweisung gespeichert.');
  expect(api.put).toHaveBeenCalledWith('/api/devices/' + deviceId + '/assignment', { userId: recipientId }, { headers: { 'If-Match': '"device-' + deviceId + '-1"' }, signal: expect.any(AbortSignal) });
});

test.each(['replace', 'release'])('%s of an existing active assignment requires the existing confirmation dialog', async action => {
  rows = [device({ lifecycle: 'assigned', assignedUserId: recipientId, assignmentId })]; const user = await openDevice();
  if (action === 'replace') { await user.type(await screen.findByLabelText('Kanonische Benutzer-ID'), otherId); await user.click(screen.getByRole('button', { name: 'Benutzer neu zuweisen' })); }
  else await user.click(await screen.findByRole('button', { name: 'Zuweisung aufheben' }));
  const dialog = within(screen.getByRole('alertdialog')); expect(dialog.getByText(/Die bisherige aktive Zuweisung/)).toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
  await user.click(dialog.getByRole('button', { name: 'Bestätigen' })); await screen.findByText(action === 'replace' ? 'Inventarzuweisung gespeichert.' : 'Zuweisung aufgehoben.');
  expect(api.put).toHaveBeenCalledWith('/api/devices/' + deviceId + '/assignment', { userId: action === 'replace' ? otherId : null }, { headers: { 'If-Match': '"device-' + deviceId + '-1"' }, signal: expect.any(AbortSignal) });
});

test('cancelling a reassignment leaves the canonical assignment untouched', async () => {
  rows = [device({ lifecycle: 'assigned', assignedUserId: recipientId, assignmentId })]; const user = await openDevice();
  await user.click(await screen.findByRole('button', { name: 'Zuweisung aufheben' })); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Abbrechen' }));
  expect(api.put).not.toHaveBeenCalled(); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
});

test.each([412, 503])('HTTP %s clears stale actions and requires explicit reload without automatic replay', async status => {
  (api.put as jest.Mock).mockRejectedValue({ response: { status } }); const user = await openDevice();
  await user.type(await screen.findByLabelText('Kanonische Benutzer-ID'), recipientId); await user.click(screen.getByRole('button', { name: 'Benutzer zuweisen' }));
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await screen.findByRole('alert');
  expect(api.put).toHaveBeenCalledTimes(1); expect(screen.queryByRole('article', { name: 'Gerätedetails' })).not.toBeInTheDocument(); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  expect(screen.queryByText('Inventarzuweisung gespeichert.')).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Neu laden' })); await screen.findByRole('button', { name: 'INV-001' }); expect(api.put).toHaveBeenCalledTimes(1);
});

test('a malformed successful HTTP receipt cannot change inventory attributes or show a success notice', async () => {
  (api.put as jest.Mock).mockResolvedValue({ status: 200, data: device({ assetId: 'Unrelated device', revision: '2', lifecycle: 'assigned', assignedUserId: recipientId, assignmentId }) });
  const user = await openDevice(); await user.type(await screen.findByLabelText('Kanonische Benutzer-ID'), recipientId); await user.click(screen.getByRole('button', { name: 'Benutzer zuweisen' }));
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await screen.findByRole('alert');
  expect(screen.queryByText('Inventarzuweisung gespeichert.')).not.toBeInTheDocument(); expect(screen.queryByText('Unrelated device')).not.toBeInTheDocument();
});

test('history has its own server pagination and never invents provider-delivery success', async () => {
  events = Array.from({ length: 26 }, (_value, index) => event(index + 1)); const user = await openDevice();
  const audit = within(screen.getByRole('region', { name: 'Gerätehistorie' })); await audit.findByText('Seite 1 von 2 · 26 Einträge');
  expect(audit.getAllByRole('listitem')).toHaveLength(25); await user.click(audit.getByRole('button', { name: 'Nächste Historienseite' }));
  await audit.findByText(/Version 26/); expect(audit.getAllByRole('listitem')).toHaveLength(1); expect(audit.getByText('Ereigniszustellung ausstehend')).toBeInTheDocument();
  expect(api.get).toHaveBeenCalledWith('/api/devices/' + deviceId + '/history', { params: { page: 2, limit: 25 }, signal: expect.any(AbortSignal) });
});

test('a deferred initial capability receipt cannot restore inventory after a session error', async () => {
  const pending = deferred<any>(); (api.get as jest.Mock).mockReturnValue(pending.promise); render(<DeviceInventoryView />);
  const signal = (api.get as jest.Mock).mock.calls[0][1].signal;
  act(() => window.dispatchEvent(new CustomEvent('od:session-error'))); expect(signal.aborted).toBe(true); await screen.findByRole('alert');
  await act(async () => pending.resolve({ status: 200, data: capabilities() }));
  expect(api.get).toHaveBeenCalledTimes(1); expect(screen.queryByRole('button', { name: 'Gerät erfassen' })).not.toBeInTheDocument();
});

test('deferred user profiles are aborted and cannot appear after session invalidation', async () => {
  directoryAccess.permissions = ['users.read']; const pending = deferred<any>();
  (api.get as jest.Mock).mockImplementation((url, config) => url === '/api/users' ? pending.promise : getResponse(url, config));
  await openDevice(); await waitFor(() => expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(true));
  const signal = (api.get as jest.Mock).mock.calls.find(([url]) => url === '/api/users')[1].signal;
  act(() => window.dispatchEvent(new CustomEvent('od:session-error'))); expect(signal.aborted).toBe(true);
  await act(async () => pending.resolve({ status: 200, data: { users: [{ id: recipientId, username: 'Late Secret Profile', email: 'secret@example.test', enabled: true, revision: '1', createdAt: device().createdAt }], total: 1, page: 1, limit: 25 } }));
  expect(screen.queryByText(/Late Secret Profile/)).not.toBeInTheDocument(); expect(screen.queryByLabelText('Benutzer auswählen')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toBeInTheDocument();
});

test('a late create receipt cannot announce success or restore write controls after a session error', async () => {
  const pending = deferred<any>(); (api.post as jest.Mock).mockReturnValue(pending.promise); const { user, dialog } = await creationForm();
  await user.click(dialog.getByRole('button', { name: 'Im Inventar speichern' })); await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1));
  const signal = (api.post as jest.Mock).mock.calls[0][2].signal;
  act(() => window.dispatchEvent(new CustomEvent('od:session-error'))); expect(signal.aborted).toBe(true);
  await act(async () => pending.resolve({ status: 201, data: device({ assetId: 'INV-NEW', serialNumber: 'SER-NEW', manufacturer: 'Dell', model: 'Latitude', platform: 'other' }) }));
  expect(screen.queryByText('Gerät INV-NEW im Inventar erfasst.')).not.toBeInTheDocument(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Gerät erfassen' })).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
});

test('a 401 history response also discards a deferred detail response from the same session', async () => {
  const pending = deferred<any>();
  (api.get as jest.Mock).mockImplementation((url, config) => {
    if (url === '/api/devices/' + deviceId) return pending.promise;
    if (url.endsWith('/history')) return Promise.reject({ response: { status: 401 } });
    return getResponse(url, config);
  });
  render(<DeviceInventoryView />); fireEvent.click(await screen.findByRole('button', { name: 'INV-001' })); await screen.findByRole('alert');
  await act(async () => pending.resolve({ status: 200, data: device() })); expect(screen.queryByRole('article', { name: 'Gerätedetails' })).not.toBeInTheDocument(); expect(screen.queryByLabelText('Kanonische Benutzer-ID')).not.toBeInTheDocument();
});
