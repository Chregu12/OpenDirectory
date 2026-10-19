import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import DeviceReturnsView from '@/components/views/DeviceReturnsView';
import { deviceReturnEtag } from '@/lib/deviceReturns';

const mockGet = jest.fn(); const mockPost = jest.fn(); const mockAccess = jest.fn();
jest.mock('@/lib/api', () => ({ api: { get: (...args: unknown[]) => mockGet(...args), post: (...args: unknown[]) => mockPost(...args) } }));
jest.mock('@/lib/directoryUsers', () => ({ directoryUsers: { access: (...args: unknown[]) => mockAccess(...args) } }));
const id = (number: number) => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const actorUserId = id(1); const tenantId = id(2); const userId = id(3); const workflowId = id(4);
const requestId = id(7); const deviceId = id(5); const assignmentId = id(6); const operationId = id(8);
const base = '/api/devices/returns'; const date = '2026-10-19T10:00:00.000Z';
const reason = 'Physische Übergabe am Empfang bestätigt';
const envelope = { schemaVersion: 1, actorUserId, tenantId };
const cap = () => ({ ...envelope, deviceReturnsProtocol: 1, permissions: ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign'], managementMode: 'inventory-only' });
const requested = (changes = {}) => ({ id: requestId, tenantId, workflowId, userId, deviceId, assignmentId, assetId: 'ASSET-1', serialNumber: 'SN-1', revision: '1', deviceRevision: '9007199254740993', currentDeviceRevision: '9007199254740993', status: 'requested', reason: 'Austritt mit Rückgabeauftrag erfasst', actorUserId, requestedAt: date, eligibilityRevision: '8', closedAt: null, closedByUserId: null, operationId, closingOperationId: null, inventoryOperationId: null, deliveryStatus: 'pending', ...changes });
const event = (changes = {}) => ({ id: operationId, tenantId, requestId, deviceId, assignmentId, type: 'device.return.requested', version: 1, actorUserId, correlationId: id(9), createdAt: date, before: null, after: { revision: '1', status: 'requested' }, inventoryOperationId: null, reason: 'Austritt mit Rückgabeauftrag erfasst', deliveryStatus: 'pending', ...changes });
const terminal = (action = 'returned', changes = {}) => requested({ status: action, revision: '2', currentDeviceRevision: action === 'returned' ? '9007199254740994' : '9007199254740993', closedAt: date, closedByUserId: actorUserId, closingOperationId: id(11), inventoryOperationId: action === 'returned' ? id(12) : null, ...changes });
let request: ReturnType<typeof requested>; let events: ReturnType<typeof event>[]; let list: any;
function setTerminal(action = 'returned', changes = {}) {
  request = terminal(action, changes);
  events = [event({ id: id(11), type: action === 'returned' ? 'device.return.confirmed' : 'device.return.cancelled', before: { revision: '1', status: 'requested' }, after: { revision: '2', status: action }, inventoryOperationId: action === 'returned' ? id(12) : null, reason }), event()];
  list = { ...envelope, requests: [request], total: 1, page: 1, limit: 25 };
}
beforeEach(() => {
  jest.resetAllMocks(); request = requested(); events = [event()]; list = { ...envelope, requests: [request], total: 1, page: 1, limit: 25 };
  mockAccess.mockResolvedValue({ userId: actorUserId, subject: 'operator', permissions: [], demoMode: false });
  mockGet.mockImplementation(async (url: string) => {
    if (url === base + '/capabilities') return { status: 200, data: cap() };
    if (url === base) return { status: 200, data: list };
    if (url === base + '/' + requestId) return { status: 200, data: request, headers: { etag: deviceReturnEtag(request) } };
    if (url === base + '/' + requestId + '/history') return { status: 200, data: { ...envelope, requestId, events, total: events.length, page: 1, limit: 25 } };
    throw new Error('Unexpected endpoint ' + url);
  });
  mockPost.mockImplementation(async (_url: string, body: { action: string }) => {
    const value = terminal(body.action);
    return { status: 200, data: { ...envelope, deviceReturnsProtocol: 1, request: value, outcome: body.action, operationId: id(11) }, headers: { etag: deviceReturnEtag(value) } };
  });
});
async function openDetail() {
  const mounted = render(<DeviceReturnsView />);
  fireEvent.click(await screen.findByRole('button', { name: 'Rückgabe ASSET-1 öffnen' }));
  await screen.findByRole('region', { name: 'Rückgabeereignishistorie' }); return mounted;
}
function setReason(value = reason) { fireEvent.change(screen.getByLabelText('Begründung für Rückgabeentscheidung'), { target: { value } }); }
async function dialog(action: 'returned' | 'cancelled' = 'returned') {
  const mounted = await openDetail(); setReason();
  fireEvent.click(screen.getByRole('button', { name: action === 'returned' ? 'Physische Rückgabe bestätigen' : 'Rückgabeauftrag stornieren' }));
  return { mounted, confirmation: within(screen.getByRole('alertdialog')) };
}
function confirmCurrent() {
  const confirmation = within(screen.getByRole('alertdialog'));
  fireEvent.click(confirmation.getByRole('checkbox', { name: 'Ich bestätige genau diese Rückgabeentscheidung.' }));
  fireEvent.click(confirmation.getByRole('button', { name: 'Bestätigen' }));
}
test('explicit route entry loads only actual actor and capabilities/list without users.read', async () => {
  render(<DeviceReturnsView />); await screen.findByRole('region', { name: 'Rückgabeauftragsliste' });
  expect(mockAccess).toHaveBeenCalledTimes(1); expect(mockGet.mock.calls.map(([url]) => url)).toEqual([base + '/capabilities', base]); expect(mockPost).not.toHaveBeenCalled();
  expect(screen.getByText(/Ursprünglicher Mitarbeiter/)).toHaveTextContent(userId);
});
test.each([
  ['demo', { userId: actorUserId, demoMode: true }], ['no human', { userId: null, demoMode: false }], ['uppercase UUID', { userId: 'AAAAAAAA-0000-4000-8000-000000000001', demoMode: false }],
])('invalid identity %s cannot load inventory', async (_label, access) => {
  mockAccess.mockResolvedValue(access); render(<DeviceReturnsView />); await screen.findByRole('alert'); expect(mockGet).not.toHaveBeenCalled();
});
test('detail shows real original employee, serial, versions and actual request event', async () => {
  await openDetail(); const detail = within(screen.getByRole('region', { name: 'Rückgabeauftragdetails' }));
  expect(detail.getByText('ASSET-1 · SN-1')).toBeInTheDocument(); expect(detail.getByText(userId)).toBeInTheDocument();
  expect(detail.getByText(assignmentId)).toBeInTheDocument(); expect(detail.getByText(/Die ursprüngliche Gerätezuweisung besteht weiterhin/)).toBeInTheDocument();
  expect(within(screen.getByRole('region', { name: 'Rückgabeereignishistorie' })).getByText(/Rückgabe angefordert/)).toBeInTheDocument();
});
test('physical return requires explicit reason and checkbox; cancel dialog never sends', async () => {
  const { confirmation } = await dialog();
  expect(confirmation.getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); expect(confirmation.getByRole('button', { name: 'Abbrechen' })).toHaveFocus();
  expect(confirmation.getByText('"device-return-' + requestId + '-1-9007199254740993"')).toBeInTheDocument();
  fireEvent.click(confirmation.getByRole('button', { name: 'Abbrechen' })); expect(mockPost).not.toHaveBeenCalled();
});
test.each(['returned', 'cancelled'] as const)('explicit %s sends only exact decision body and strong combined ETag once', async action => {
  await dialog(action); const reads = mockGet.mock.calls.length; confirmCurrent();
  await screen.findByRole('region', { name: 'Ergebnis der Rückgabeentscheidung' });
  expect(mockPost).toHaveBeenCalledWith(base + '/' + requestId + '/decision', { action, reason, confirm: true }, { headers: { 'If-Match': '"device-return-' + requestId + '-1-9007199254740993"' }, signal: expect.any(AbortSignal) });
  expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(reads + 1); expect(mockGet.mock.calls[reads][0]).toBe(base + '/capabilities');
  expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeDisabled();
  expect(screen.getByText(/Keine Aussage über aktuelle Geräteverfügbarkeit/)).toBeInTheDocument();
});
test.each(['kurz', 'x'.repeat(501), 'physisch\nmit Steuerzeichen'])('invalid reason %s never opens confirmation', async value => {
  await openDetail(); setReason(value); fireEvent.click(screen.getByRole('button', { name: 'Physische Rückgabe bestätigen' }));
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('10 bis 500'); expect(mockPost).not.toHaveBeenCalled();
});
test('unknown physical ACK recovers original ETag/body even after a real new device assignment', async () => {
  await dialog(); mockPost.mockResolvedValueOnce({ status: 200, data: { ...envelope, deviceReturnsProtocol: 1, request: null, outcome: 'returned', operationId: id(11) } }); confirmCurrent();
  await screen.findByRole('alert'); expect(mockPost).toHaveBeenCalledTimes(1);
  const originalBody = mockPost.mock.calls[0][1]; const originalHeaders = mockPost.mock.calls[0][2].headers;
  expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeDisabled();
  setTerminal('returned', { currentDeviceRevision: '9007199254740999' });
  fireEvent.click(screen.getByRole('button', { name: 'Rückgaben und Historie neu laden' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeEnabled());
  expect(screen.getByText(/Historischer Rückgabenachweis/)).toHaveTextContent('keine aktuelle Verfügbarkeit');
  expect(screen.queryByRole('button', { name: 'Physische Rückgabe bestätigen' })).not.toBeInTheDocument();
  mockPost.mockResolvedValueOnce({ status: 200, data: { ...envelope, deviceReturnsProtocol: 1, request, outcome: 'already_returned', operationId: id(11) }, headers: { etag: deviceReturnEtag(request) } });
  fireEvent.click(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' }));
  expect(screen.getByRole('alertdialog', { name: 'Ursprüngliche Rückgabeentscheidung bestätigen' })).toBeInTheDocument(); confirmCurrent();
  await screen.findByText(/Ursprünglicher historischer Entscheidungsnachweis wiederhergestellt/);
  expect(mockPost.mock.calls[1][1]).toEqual(originalBody); expect(mockPost.mock.calls[1][2].headers).toEqual(originalHeaders);
  expect(mockGet.mock.calls.some(([url]) => url.endsWith('/assignment'))).toBe(false);
});
test('cancelled readback has no inventory effect and no decision buttons', async () => {
  setTerminal('cancelled'); await openDetail();
  expect(screen.getByText(/Nur der Auftrag wurde storniert/)).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Physische Rückgabe bestätigen' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Rückgabeauftrag stornieren' })).not.toBeInTheDocument(); expect(mockPost).not.toHaveBeenCalled();
});
test('ordinary release yields assignment_changed without fake returned event or actions', async () => {
  request = requested({ status: 'assignment_changed', currentDeviceRevision: '9007199254740995', closedAt: date, closedByUserId: id(15), inventoryOperationId: id(12) });
  list = { ...list, requests: [request] }; await openDetail();
  expect(screen.getByText(/Kein Rückgabeereignis und keine physische Rückgabe behauptet/)).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Physische Rückgabe bestätigen' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Rückgabeauftrag stornieren' })).not.toBeInTheDocument();
  const history = within(screen.getByRole('region', { name: 'Rückgabeereignishistorie' })); expect(history.queryByText('Physische Rückgabe manuell bestätigt')).not.toBeInTheDocument();
});
test.each([401, 403, 409, 412, 428, 503])('decision %s requires real readback with no silent version refresh or automatic retry', async code => {
  await dialog(); const reads = mockGet.mock.calls.length; mockPost.mockRejectedValueOnce({ response: { status: code } }); confirmCurrent();
  await screen.findByRole('alert'); expect(mockGet).toHaveBeenCalledTimes(reads + 1); expect(mockGet.mock.calls[reads][0]).toBe(base + '/capabilities'); expect(mockPost).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeDisabled();
});
test('session change while confirmation is open discards old intent and selected request', async () => {
  await dialog(); act(() => { window.dispatchEvent(new Event('od:session-error')); });
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Rückgaben und Historie neu laden' })); await screen.findByRole('region', { name: 'Rückgabeauftragsliste' });
  expect(screen.queryByRole('region', { name: 'Rückgabeauftragdetails' })).not.toBeInTheDocument(); expect(mockPost).not.toHaveBeenCalled();
});
test('unmount invalidates actual pending GET and ignores later response', async () => {
  let resolve: (value: unknown) => void;
  mockGet.mockImplementationOnce(() => new Promise(value => { resolve = value; }));
  const mounted = render(<DeviceReturnsView />); await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1));
  const signal = mockGet.mock.calls[0][1].signal as AbortSignal; mounted.unmount(); expect(signal.aborted).toBe(true);
  await act(async () => { resolve({ status: 200, data: cap() }); }); expect(mockGet).toHaveBeenCalledTimes(1); expect(mockPost).not.toHaveBeenCalled();
});
test('session change during a live decision aborts the request and ignores its late result', async () => {
  let resolve: (value: unknown) => void;
  await dialog(); mockPost.mockImplementationOnce(() => new Promise(value => { resolve = value; })); confirmCurrent();
  await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1)); const signal = mockPost.mock.calls[0][2].signal as AbortSignal;
  act(() => { window.dispatchEvent(new Event('od:session-error')); }); expect(signal.aborted).toBe(true);
  const value = terminal(); await act(async () => { resolve({ status: 200, data: { ...envelope, deviceReturnsProtocol: 1, request: value, outcome: 'returned', operationId: id(11) }, headers: { etag: deviceReturnEtag(value) } }); });
  expect(screen.queryByRole('region', { name: 'Ergebnis der Rückgabeentscheidung' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).not.toBeInTheDocument(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('status filter requests real exact server filter and never filters fabricated local data', async () => {
  render(<DeviceReturnsView />); await screen.findByRole('region', { name: 'Rückgabeauftragsliste' });
  setTerminal('cancelled'); fireEvent.change(screen.getByLabelText('Statusfilter'), { target: { value: 'cancelled' } });
  await waitFor(() => expect(screen.getByLabelText('Statusfilter')).toHaveValue('cancelled'));
  expect(mockGet).toHaveBeenCalledWith(base, { params: { page: 1, limit: 25, status: 'cancelled' }, signal: expect.any(AbortSignal) }); expect(mockPost).not.toHaveBeenCalled();
});
test('pagination requests later actual server page and preserves explicit read-only behavior', async () => {
  list = { ...envelope, requests: Array.from({ length: 25 }, (_, index) => requested({ id: id(100 + index), assetId: 'ASSET-' + index })), total: 26, page: 1, limit: 25 };
  render(<DeviceReturnsView />); await screen.findByRole('region', { name: 'Rückgabeauftragsliste' });
  list = { ...envelope, requests: [requested()], total: 26, page: 2, limit: 25 };
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Rückgabeauftragsseiten' })).getByRole('button', { name: 'Weiter' }));
  await screen.findByText('Seite 2 · 26 Einträge'); expect(mockGet).toHaveBeenCalledWith(base, { params: { page: 2, limit: 25 }, signal: expect.any(AbortSignal) }); expect(mockPost).not.toHaveBeenCalled();
});
