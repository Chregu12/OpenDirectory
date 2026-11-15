import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { api } from '@/lib/api';
import DeviceOrganizationalUnitPanel from '@/components/views/DeviceOrganizationalUnitPanel';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), put: jest.fn() } }));
const actor = '11111111-1111-4111-8111-111111111111', tenant = '22222222-2222-4222-8222-222222222222', id = '33333333-3333-4333-8333-333333333333', ouId = '44444444-4444-4444-8444-444444444444', eventId = '55555555-5555-4555-8555-555555555555';
const device: any = { id, tenantId: tenant, revision: '1', assetId: 'OU-001' }, timestamp = '2026-11-15T03:00:00.000Z';
const ou = { id: ouId, name: 'Engineering devices', parentId: null, generation: '2', revision: '3' };
let record: any, catalogDenied: boolean;
const base = '/api/devices/' + id + '/organizational-unit';
beforeEach(() => {
  jest.resetAllMocks(); catalogDenied = false;
  record = { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: actor, tenantId: tenant, deviceId: id, deviceRevision: '1', revision: '0', ou: null, updatedAt: null, updatedBy: null };
  (api.get as jest.Mock).mockImplementation(async url => {
    if (url === base) return { status: 200, headers: { etag: `"device-ou-${id}-1-${record.revision}"` }, data: record };
    if (url === '/api/devices/organizational-units') { if (catalogDenied) throw { response: { status: 403 } }; return { status: 200, data: { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: actor, tenantId: tenant, units: [ou], page: 1, limit: 25, total: 1 } }; }
    if (url === base + '/history') return { status: 200, data: { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: actor, tenantId: tenant, deviceId: id, page: 1, limit: 25, total: 0, events: [] } };
    if (url === base + '/status') throw { response: { status: 501 } };
    throw new Error('Unexpected device OU read');
  });
  (api.put as jest.Mock).mockImplementation(async (_url, body) => {
    record = { ...record, revision: String(Number(record.revision) + 1), ou: body.ou ? ou : null, updatedAt: timestamp, updatedBy: actor };
    return { status: 200, data: { ...record, operationId: eventId, deliveryStatus: 'pending' } };
  });
});
function show(canManage = true, props: any = {}) { return render(<DeviceOrganizationalUnitPanel device={device} actor={actor} canManage={canManage} disabled={false} onBusy={jest.fn()} onSecurityError={jest.fn()} {...props} />); }
async function select() {
  fireEvent.click(await screen.findByRole('button', { name: 'Zuordnung ändern' }));
  fireEvent.change(await screen.findByLabelText('Organisationseinheit auswählen'), { target: { value: ouId } });
  fireEvent.click(screen.getByRole('button', { name: 'OU-Zuordnung prüfen' }));
  const dialog = within(screen.getByRole('alertdialog'));
  fireEvent.change(dialog.getByLabelText('Begründung für OU-Zuordnung'), { target: { value: 'Assign this own device to the reviewed engineering unit' } }); return dialog;
}
test('inventory readers can inspect saved metadata and history without choosing or writing an OU', async () => {
  show(false); await screen.findByText('Keine Organisationseinheit zugeordnet.');
  expect(screen.queryByRole('button', { name: 'Zuordnung ändern' })).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'OU-Verlauf' })); await screen.findByText('Noch keine OU-Zuordnung geändert.');
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/devices/organizational-units')).toBe(false);
});
test('selection requires explicit confirmation and sends the original OU and device versions', async () => {
  show(); const dialog = await select(); expect(api.put).not.toHaveBeenCalled();
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); await screen.findByText('OU-Zuordnung gespeichert und protokolliert.');
  expect(api.put).toHaveBeenCalledWith(base, { ou: { id: ouId, generation: '2', revision: '3' }, reason: 'Assign this own device to the reviewed engineering unit', confirm: true }, expect.objectContaining({ headers: { 'If-Match': `"device-ou-${id}-1-0"` } }));
  expect(screen.getByText('Engineering devices')).toBeInTheDocument(); expect(api.put).toHaveBeenCalledTimes(1);
});
test('missing separate OU read permission leaves authorized inventory metadata usable', async () => {
  catalogDenied = true; const denied = jest.fn(); show(true, { onSecurityError: denied }); fireEvent.click(await screen.findByRole('button', { name: 'Zuordnung ändern' }));
  await screen.findByText(/zusätzlich die Berechtigung/); expect(screen.getByText('Keine Organisationseinheit zugeordnet.')).toBeInTheDocument(); expect(denied).not.toHaveBeenCalled(); expect(api.put).not.toHaveBeenCalled();
});
test('a stale write clears the old confirmation and never retries the command', async () => {
  (api.put as jest.Mock).mockRejectedValue({ response: { status: 412 } }); show(); const dialog = await select(); fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  await screen.findByText(/ausgewählte Organisationseinheit hat sich geändert/); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.put).toHaveBeenCalledTimes(1); expect(screen.queryByText('OU-Zuordnung gespeichert und protokolliert.')).not.toBeInTheDocument();
});
test('session loss ignores a late accepted write and releases the parent busy state', async () => {
  let complete: (value: any) => void = () => {}; (api.put as jest.Mock).mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  const busy = jest.fn(); show(true, { onBusy: busy }); const dialog = await select(); fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(api.put).toHaveBeenCalledTimes(1));
  act(() => window.dispatchEvent(new Event('od:session-error'))); await act(async () => { complete({ status: 200, data: { ...record, revision: '1', ou, updatedAt: timestamp, updatedBy: actor, operationId: eventId, deliveryStatus: 'pending' } }); });
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByText('OU-Zuordnung gespeichert und protokolliert.')).not.toBeInTheDocument(); expect(busy.mock.calls).toEqual([[true], [false]]);
});
test('an older receiver exposes no OU action until the protocol exists', async () => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status: 501 } }); const denied = jest.fn(); show(true, { onSecurityError: denied });
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Geräte-Organisationseinheit' })).not.toBeInTheDocument()); expect(denied).not.toHaveBeenCalled(); expect(api.put).not.toHaveBeenCalled();
});
test('a confirmed write cancels an older history read and ignores its late response', async () => {
  const originalGet = (api.get as jest.Mock).getMockImplementation()!;
  let complete: (value: any) => void = () => {}, signal: AbortSignal | undefined;
  (api.get as jest.Mock).mockImplementation((url, options) => url === base + '/history'
    ? new Promise(resolve => { complete = resolve; signal = options.signal; }) : originalGet(url, options));
  show(); fireEvent.click(await screen.findByRole('button', { name: 'OU-Verlauf' }));
  await waitFor(() => expect(signal).toBeDefined()); const dialog = await select();
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); await screen.findByText('OU-Zuordnung gespeichert und protokolliert.');
  expect(signal!.aborted).toBe(true);
  await act(async () => complete({ status: 200, data: { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: actor, tenantId: tenant, deviceId: id, page: 1, limit: 25, total: 0, events: [] } }));
  expect(screen.queryByText('Noch keine OU-Zuordnung geändert.')).not.toBeInTheDocument();
});
test('a substituted actor cannot populate a different current device panel', async () => {
  record.actorUserId = eventId; show(); await screen.findByRole('alert'); expect(screen.queryByRole('button', { name: 'Zuordnung ändern' })).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
});
