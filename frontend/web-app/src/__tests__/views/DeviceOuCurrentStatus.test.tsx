import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { api } from '@/lib/api';
import DeviceOuCurrentStatus from '@/components/views/DeviceOuCurrentStatus';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), put: jest.fn() } }));
const actor = '11111111-1111-4111-8111-111111111111', tenant = '22222222-2222-4222-8222-222222222222', id = '33333333-3333-4333-8333-333333333333', ouId = '44444444-4444-4444-8444-444444444444';
const device: any = { id, tenantId: tenant, revision: '1' };
const ou = { id: ouId, name: 'Original engineering', parentId: null, generation: '2', revision: '3' };
const assignment: any = { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: actor, tenantId: tenant, deviceId: id, deviceRevision: '1', revision: '1', ou, updatedAt: '2026-11-15T03:00:00.000Z', updatedBy: actor };
const base = '/api/devices/' + id + '/organizational-unit/status';
let data: any;
beforeEach(() => {
  jest.resetAllMocks();
  data = { schemaVersion: 1, deviceOuStatusProtocol: 1, actorUserId: actor, tenantId: tenant, deviceId: id, deviceRevision: '1', revision: '1', selection: { id: ouId, generation: '2' }, state: 'current', currentOu: { ...ou }, checkedAt: new Date().toISOString(), validUntil: Math.floor(Date.now() / 1000) + 60 };
  (api.get as jest.Mock).mockImplementation(async () => ({ status: 200, data }));
});
afterEach(() => jest.useRealTimers());
function show(callback = jest.fn()) { return render(<DeviceOuCurrentStatus device={device} actor={actor} assignment={assignment} disabled={false} onSecurityError={callback} />); }
test('current metadata is bound to the original device and association versions and performs no write', async () => {
  show(); await screen.findByText('OU aktuell bestätigt.');
  expect(api.get).toHaveBeenCalledWith(base, expect.objectContaining({ headers: { 'If-Match': `"device-ou-${id}-1-1"` } })); expect(api.put).not.toHaveBeenCalled();
});
test('a live rename stays distinct from the retained name and requires an explicit fresh read', async () => {
  show(); await screen.findByText('OU aktuell bestätigt.'); data = { ...data, state: 'changed', currentOu: { ...ou, name: 'Current platform unit', revision: '4' } };
  fireEvent.click(screen.getByRole('button', { name: 'OU-Stand prüfen' })); await screen.findByText('Die OU wurde seit der Zuordnung geändert.');
  expect(screen.getByText(/Aktuelle OU: Current platform unit/)).toBeInTheDocument(); expect(assignment.ou.name).toBe('Original engineering'); expect(api.put).not.toHaveBeenCalled();
});
test('retired or replaced-generation references reveal no current metadata', async () => {
  data = { ...data, state: 'not-current', currentOu: null }; show(); await screen.findByText('Die ursprüngliche OU ist nicht mehr als aktuelle eigene OU bestätigt.');
  expect(screen.queryByText(/Aktuelle OU:/)).not.toBeInTheDocument();
});
test.each(['actor', 'generation', 'state', 'version'])('a substituted %s cannot appear as confirmed current OU status', async variant => {
  if (variant === 'actor') data.actorUserId = ouId;
  if (variant === 'generation') data.currentOu.generation = '99';
  if (variant === 'state') data.state = 'unassigned';
  if (variant === 'version') data.revision = '2';
  show(); await screen.findByRole('alert'); expect(screen.queryByText('OU aktuell bestätigt.')).not.toBeInTheDocument(); expect(api.put).not.toHaveBeenCalled();
});
test('a separately denied OU read preserves allowed inventory and never signals a session failure', async () => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status: 403, data: { error: 'device_ou_status_directory_read_required' } } }); const failure = jest.fn(); show(failure);
  await screen.findByText(/zusätzlich „Organisationseinheiten lesen“/); expect(failure).not.toHaveBeenCalled();
});
test('an actual inventory denial remains a security failure', async () => {
  const denied = { response: { status: 403, data: { error: 'Inventory permission required' } } }; (api.get as jest.Mock).mockRejectedValue(denied); const failure = jest.fn(); show(failure);
  await waitFor(() => expect(failure).toHaveBeenCalledWith(denied)); expect(screen.queryByText('OU aktuell bestätigt.')).not.toBeInTheDocument();
});
test('an older receiver exposes no unsupported status control', async () => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status: 501 } }); show();
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Aktueller OU-Stand' })).not.toBeInTheDocument());
});
test('session loss ignores a late accepted status response', async () => {
  let complete: (value: any) => void = () => {}; (api.get as jest.Mock).mockImplementation(() => new Promise(resolve => { complete = resolve; })); show();
  await waitFor(() => expect(api.get).toHaveBeenCalledTimes(1)); act(() => window.dispatchEvent(new Event('od:session-error')));
  await act(async () => complete({ status: 200, data })); expect(screen.queryByText('OU aktuell bestätigt.')).not.toBeInTheDocument(); await screen.findByText(/erneut anmelden/);
});
test('the display expires with the captured authority deadline and does not silently renew it', async () => {
  jest.useFakeTimers(); data.validUntil = Math.floor(Date.now() / 1000) + 2; show(); await act(async () => {}); expect(screen.getByText('OU aktuell bestätigt.')).toBeInTheDocument();
  act(() => jest.advanceTimersByTime(2100)); expect(screen.queryByText('OU aktuell bestätigt.')).not.toBeInTheDocument(); expect(screen.getByText(/OU-Prüfung ist abgelaufen/)).toBeInTheDocument(); expect(api.get).toHaveBeenCalledTimes(1);
});
test('a stale association read never retries or changes the saved assignment', async () => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status: 412 } }); show(); await screen.findByText(/Bitte die Zuordnung neu laden/);
  expect(api.get).toHaveBeenCalledTimes(1); expect(api.put).not.toHaveBeenCalled(); expect(assignment.ou).toEqual(ou);
});
