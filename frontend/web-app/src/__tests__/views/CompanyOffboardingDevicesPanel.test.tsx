import React from 'react';
import { randomUUID } from 'crypto';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import CompanyOffboardingDevicesPanel from '@/components/views/CompanyOffboardingDevicesPanel';
import CompanyOffboardingPanel from '@/components/views/CompanyOffboardingPanel';
import { offboardingEtag } from '@/lib/companyOffboarding';
import { actorUserId, tenantId, userId, workflowId, context, reason, jobs, jobFixture, pendingFixture, queueFixture, historyFixture as parentHistory, capabilitiesFixture as parentCapabilities } from '../fixtures/companyOffboarding';

const mockGet = jest.fn(); const mockPost = jest.fn();
jest.mock('@/lib/api', () => ({ api: { get: (...args: unknown[]) => mockGet(...args), post: (...args: unknown[]) => mockPost(...args) } }));
const id = (number: number) => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const props = { actorUserId, tenantId, userId, workflowId, eligibilityRevision: '8' };
const target = { enabled: false, eligibilityRevision: '8' };
const base = `/api/devices/users/${userId}/offboarding-returns`;
const envelope = { schemaVersion: 1, actorUserId, tenantId, workflowId, userId };
const date = '2026-10-19T10:00:00.000Z';
const capability = () => ({ ...envelope, deviceOffboardingReturnsProtocol: 1, target, permissions: ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign'], managementMode: 'inventory-only' });
const device = (index = 1, changes = {}) => ({ deviceId: id(index), assignmentId: id(10 + index), assetId: 'ASSET-' + index, serialNumber: 'SN-' + index, deviceRevision: '9007199254740993', openRequestId: null, ...changes });
const previewFixture = (changes = {}) => ({ ...capability(), devices: [device(), device(2, { openRequestId: id(22) }), device(3)], total: 3, page: 1, limit: 25, ...changes });
const requestFixture = (requestId: string, changes = {}) => ({ id: requestId, tenantId, workflowId, userId, deviceId: id(1), assignmentId: id(11), assetId: 'ASSET-1', serialNumber: 'SN-1', revision: '1', deviceRevision: '9007199254740993', currentDeviceRevision: '9007199254740993', status: 'requested', reason, actorUserId, requestedAt: date, eligibilityRevision: '8', closedAt: null, closedByUserId: null, operationId: id(81), closingOperationId: null, inventoryOperationId: null, deliveryStatus: 'pending', ...changes });
let preview: ReturnType<typeof previewFixture>; let history: any;
beforeEach(() => {
  jest.resetAllMocks(); window.localStorage.clear();
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: randomUUID });
  preview = previewFixture(); history = { ...envelope, target, requests: [], total: 0, page: 1, limit: 25 };
  mockGet.mockImplementation(async (url: string) => {
    if (url === base + '/capabilities') return { status: 200, data: capability() };
    if (url === base) return { status: 200, data: preview };
    if (url === base + '/history') return { status: 200, data: history };
    throw new Error('Unexpected endpoint ' + url);
  });
  mockPost.mockImplementation(async (_url: string, body: { items: Array<{ deviceId: string; assignmentId: string; requestId: string }> }) => ({ status: 200, data: { ...envelope, correlationId: id(80), results: body.items.map((item, index) => ({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: 'requested', code: 200, operationId: id(81 + index) })) } }));
});
async function openPanel() {
  const mounted = render(<CompanyOffboardingDevicesPanel {...props} />);
  fireEvent.click(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' }));
  await screen.findByRole('region', { name: 'Gerätevorschau für Rückgaben' }); return mounted;
}
function select(index = 1) { fireEvent.click(screen.getByRole('checkbox', { name: `Rückgabe für ASSET-${index} auswählen` })); }
function setReason(value = reason) { fireEvent.change(screen.getByLabelText('Begründung für Rückgabeauftrag'), { target: { value } }); }
async function dialog() {
  const mounted = await openPanel(); select(); setReason('  ' + reason + '  ');
  fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Rückgaben anfordern' }));
  return { mounted, confirmation: within(screen.getByRole('alertdialog', { name: 'Rückgabeaufträge bestätigen' })) };
}
function confirmCurrent() {
  const confirmation = within(screen.getByRole('alertdialog'));
  fireEvent.click(confirmation.getByRole('checkbox', { name: 'Ich bestätige genau diese ursprünglichen Gerätezuweisungen.' }));
  fireEvent.click(confirmation.getByRole('button', { name: 'Bestätigen' }));
}
test('stays explicitly collapsed without any API calls', () => {
  render(<CompanyOffboardingDevicesPanel {...props} />);
  expect(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' })).toHaveAttribute('aria-expanded', 'false');
  expect(mockGet).not.toHaveBeenCalled(); expect(mockPost).not.toHaveBeenCalled();
});
test('opening reads real capabilities, preview and history; pending devices remain visible and disabled', async () => {
  await openPanel();
  expect(mockGet.mock.calls.map(([url]) => url)).toEqual([base + '/capabilities', base, base + '/history']);
  expect(screen.getByRole('checkbox', { name: 'Rückgabe für ASSET-2 auswählen' })).toBeDisabled();
  expect(screen.getByText(/Eine Anforderung ist keine physische Rückgabe/)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Geräterückgaben bearbeiten' })).toHaveAttribute('href', '/device-returns');
});
test('captures exact explicit subset once; two confirmation levels and cancel never write', async () => {
  const { confirmation } = await dialog();
  expect(confirmation.getByRole('button', { name: 'Bestätigen' })).toBeDisabled();
  expect(confirmation.getByText('ASSET-1 · Seriennummer SN-1')).toBeInTheDocument();
  expect(confirmation.queryByText('ASSET-3 · Seriennummer SN-3')).not.toBeInTheDocument();
  expect(confirmation.getByText('Begründung: ' + reason)).toBeInTheDocument(); expect(confirmation.getByText(id(11))).toBeInTheDocument();
  expect(confirmation.getByRole('button', { name: 'Abbrechen' })).toHaveFocus();
  fireEvent.click(confirmation.getByRole('button', { name: 'Abbrechen' })); expect(mockPost).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Rückgaben anfordern' })); confirmCurrent();
  await screen.findByRole('region', { name: 'Ergebnis der Rückgabeanforderung' });
  expect(mockPost).toHaveBeenCalledTimes(1);
  expect(mockPost.mock.calls[0][1]).toEqual({ workflowId, eligibilityRevision: '8', reason, confirm: true,
    items: [{ deviceId: id(1), deviceRevision: '9007199254740993', assignmentId: id(11), requestId: expect.stringMatching(/^[a-f0-9-]{36}$/) }] });
  expect(screen.getByText(/Keine physische Rückgabe bestätigt/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeDisabled();
});
test.each(['kurz', 'x'.repeat(501), 'Begründung\nmit Steuerzeichen'])('bad reason %s leaves API untouched', async value => {
  await openPanel(); select(); setReason(value); fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Rückgaben anfordern' }));
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('10 bis 500'); expect(mockPost).not.toHaveBeenCalled();
});
test('malformed committed ACK requires actual preview and history then explicit original UUID recovery; new assignment remains unselected', async () => {
  await dialog(); mockPost.mockResolvedValueOnce({ status: 200, data: { ...envelope, correlationId: id(80), results: [] } }); confirmCurrent();
  await screen.findByRole('alert'); expect(mockPost).toHaveBeenCalledTimes(1);
  const original = mockPost.mock.calls[0][1];
  expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeDisabled();
  preview = previewFixture({ devices: [device(1, { assignmentId: id(91), deviceRevision: '9007199254740995' })], total: 1 });
  history = { ...history, requests: [requestFixture(original.items[0].requestId, { status: 'assignment_changed', currentDeviceRevision: '9007199254740995', closedAt: date, closedByUserId: actorUserId, inventoryOperationId: id(92) })], total: 1 };
  fireEvent.click(screen.getByRole('button', { name: 'Gerätevorschau und Rückgabehistorie neu laden' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeEnabled());
  expect(screen.getByRole('checkbox', { name: 'Rückgabe für ASSET-1 auswählen' })).not.toBeChecked();
  expect(screen.getByRole('button', { name: 'Ausgewählte Rückgaben anfordern' })).toBeDisabled();
  expect(screen.getByText(/Ursprüngliche Zuweisung geändert/)).toBeInTheDocument();
  mockPost.mockImplementationOnce(async () => ({ status: 200, data: { ...envelope, correlationId: id(80), results: [{ deviceId: id(1), assignmentId: id(11), requestId: original.items[0].requestId, status: 'already_requested', code: 200, operationId: id(81) }] } }));
  fireEvent.click(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' }));
  expect(screen.getByRole('alertdialog', { name: 'Ursprüngliche Rückgabeaufträge bestätigen' })).toBeInTheDocument();
  confirmCurrent(); await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(2));
  expect(mockPost.mock.calls[1][1]).toEqual(original);
});
test('partial result keeps confirmed operations and marks not attempted entries without automatically retrying', async () => {
  preview = previewFixture({ devices: [device(), device(2), device(3)] });
  await openPanel(); select(); select(2); select(3); setReason();
  fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Rückgaben anfordern' }));
  mockPost.mockImplementationOnce(async (_url, body) => ({ status: 207, data: { ...envelope, correlationId: id(80), results: body.items.map((item, index) => ({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: ['requested', 'unconfirmed', 'not_attempted'][index], code: [200, 503, null][index], operationId: index === 0 ? id(81) : null })) } }));
  confirmCurrent(); const result = within(await screen.findByRole('region', { name: 'Ergebnis der Rückgabeanforderung' }));
  expect(result.getByText(/nicht vollständig bestätigt/)).toBeInTheDocument(); expect(result.getByText('Nicht versucht')).toBeInTheDocument(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test.each([403, 428, 409])('capability %s error has no fallback or selection', async code => {
  mockGet.mockRejectedValueOnce({ response: { status: code } });
  render(<CompanyOffboardingDevicesPanel {...props} />); fireEvent.click(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(mockPost).not.toHaveBeenCalled();
});
test('collapsing disposes a busy read and reopening cannot show the old late response', async () => {
  let resolve: (value: unknown) => void;
  mockGet.mockImplementationOnce(() => new Promise(value => { resolve = value; }));
  render(<CompanyOffboardingDevicesPanel {...props} />);
  const toggle = screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' }); fireEvent.click(toggle); fireEvent.click(toggle);
  await act(async () => { resolve({ status: 200, data: capability() }); });
  expect(screen.queryByRole('region', { name: 'Gerätevorschau für Rückgaben' })).not.toBeInTheDocument();
  fireEvent.click(toggle); await screen.findByRole('region', { name: 'Gerätevorschau für Rückgaben' }); expect(mockPost).not.toHaveBeenCalled();
});
test('collapse after an unknown write destroys recovery intent and closes modal; reopen is a new client', async () => {
  await dialog(); mockPost.mockRejectedValueOnce(new Error('Lost ACK')); confirmCurrent(); await screen.findByRole('alert');
  fireEvent.click(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' }));
  fireEvent.click(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' }));
  await screen.findByRole('region', { name: 'Gerätevorschau für Rückgaben' });
  expect(screen.queryByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).not.toBeInTheDocument(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('session change closes modal, clears selection/recovery and never accepts stale results', async () => {
  await dialog(); act(() => { window.dispatchEvent(new Event('od:session-error')); });
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' })).toHaveAttribute('aria-expanded', 'false');
  fireEvent.click(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' })); await screen.findByRole('region', { name: 'Gerätevorschau für Rückgaben' });
  expect(screen.getByRole('checkbox', { name: 'Rückgabe für ASSET-1 auswählen' })).not.toBeChecked(); expect(mockPost).not.toHaveBeenCalled();
});
test('binding change remounts collapsed and removes old confirmation', async () => {
  const { mounted } = await dialog(); mounted.rerender(<CompanyOffboardingDevicesPanel {...props} eligibilityRevision="9" />);
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' })).toHaveAttribute('aria-expanded', 'false');
});
test('collapse during a live POST aborts and rejects a late successful acknowledgement without stale recovery controls', async () => {
  let resolve: (value: unknown) => void;
  await dialog(); mockPost.mockImplementationOnce(() => new Promise(value => { resolve = value; })); confirmCurrent();
  await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
  const body = mockPost.mock.calls[0][1]; const signal = mockPost.mock.calls[0][2].signal as AbortSignal;
  fireEvent.click(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' })); expect(signal.aborted).toBe(true);
  await act(async () => { resolve({ status: 200, data: { ...envelope, correlationId: id(80), results: body.items.map(item => ({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: 'requested', code: 200, operationId: id(81) })) } }); });
  expect(screen.queryByRole('region', { name: 'Ergebnis der Rückgabeanforderung' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' })); await screen.findByRole('region', { name: 'Gerätevorschau für Rückgaben' });
  expect(screen.queryByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).not.toBeInTheDocument(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test.each(['licenses', 'paused', 'pending'] as const)('parent phase %s mounts only on a validated negative checkpoint, not on license completion', async phase => {
  const record = phase === 'pending' ? pendingFixture() : jobFixture({ phase, failure: phase === 'paused' ? { code: 503, step: 'licenses' } : null });
  mockGet.mockImplementation(async (url: string) => {
    if (url === jobs + '/capabilities') return { status: 200, data: parentCapabilities() };
    if (url === jobs) return { status: 200, data: queueFixture(record) };
    if (url === jobs + '/' + workflowId) return { status: 200, data: record, headers: { etag: offboardingEtag(record.workflow) } };
    if (url === jobs + '/' + workflowId + '/history') return { status: 200, data: parentHistory(record) };
    throw new Error('Unexpected endpoint ' + url);
  });
  render(<CompanyOffboardingPanel context={context} />);
  fireEvent.click(screen.getByRole('button', { name: 'Mitarbeiter-Offboarding' })); await screen.findByRole('heading', { name: 'Gespeicherte Vorgänge' });
  fireEvent.change(screen.getByLabelText('Bekannte Vorgangs-ID'), { target: { value: workflowId } }); fireEvent.click(screen.getByRole('button', { name: 'Arbeitsstand neu laden' }));
  await screen.findByRole('article', { name: 'Offboarding-Arbeitsstand' });
  if (phase === 'pending') expect(screen.queryByRole('button', { name: 'Geräterückgaben beim Austritt planen' })).not.toBeInTheDocument();
  else expect(screen.getByRole('button', { name: 'Geräterückgaben beim Austritt planen' })).toHaveAttribute('aria-expanded', 'false');
  expect(mockGet.mock.calls.some(([url]) => url.startsWith('/api/devices/'))).toBe(false); expect(mockPost).not.toHaveBeenCalled();
});
