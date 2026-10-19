import React from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import CompanyOffboardingAccessPanel from '@/components/views/CompanyOffboardingAccessPanel';
import CompanyOffboardingPanel from '@/components/views/CompanyOffboardingPanel';
import { offboardingEtag } from '@/lib/companyOffboarding';
import { context, userId, workflowId, actorUserId, tenantId, reason, jobs, capabilitiesFixture as parentCapabilities, jobFixture, pendingFixture, queueFixture, historyFixture as parentHistory } from '../fixtures/companyOffboarding';

const identifier = (index: number) => `55555555-5555-4555-8555-${String(index).padStart(12, '0')}`;
const version = 'a'.repeat(64);
const target = { enabled: false, eligibilityRevision: '8' };
const binding = { schemaVersion: 1, actorUserId, tenantId, workflowId, userId };
const props = { expectedActorUserId: actorUserId, tenantId, userId, workflowId, eligibilityRevision: '8' };
const base = '/api/users/' + userId + '/company-offboarding-access';
const item = (index = 1, changes = {}) => ({ id: identifier(index), role: 'directory-reader', version, createdAt: '2026-01-01T00:00:00.000Z', expiresAt: null, canRevoke: true, blockedReason: null, ...changes });
const capabilitiesFixture = (changes = {}): any => ({ ...binding, companyOffboardingAccessProtocol: 1, target, permissions: ['identities.roles.read', 'identities.roles.manage', 'pim.eligibilities.read', 'pim.eligibilities.manage'], supportedKinds: ['role', 'eligibility'], ...changes });
const previewFixture = (changes = {}): any => ({ ...binding, companyOffboardingAccessProtocol: 1, target, kind: 'role', canRevoke: true, items: [item()], total: 1, page: 1, limit: 25, ...changes });
const historyFixture = (changes = {}): any => ({ ...binding, target, kind: 'role', receipts: [], total: 0, page: 1, limit: 25, ...changes });
const outcomeFixture = (changes = {}): any => ({ ...binding, kind: 'role', correlationId: identifier(80), results: [{ id: identifier(1), status: 'revoked', code: 200, checkpointId: identifier(60) }], ...changes });
const mockGet = jest.fn(); const mockPost = jest.fn();
jest.mock('@/lib/api', () => ({ api: { get: (...args: unknown[]) => mockGet(...args), post: (...args: unknown[]) => mockPost(...args) } }));
let capabilities: any; let preview: any; let history: any;
beforeEach(() => {
  jest.resetAllMocks(); window.localStorage.clear(); window.history.replaceState({}, '', '/offboarding-access');
  capabilities = capabilitiesFixture(); preview = previewFixture(); history = historyFixture();
  mockGet.mockImplementation(async (url: string) => {
    if (url === base + '/capabilities') return { status: 200, data: capabilities };
    if (url === base) return { status: 200, data: preview };
    if (url === base + '/history') return { status: 200, data: history };
    throw new Error('Unexpected endpoint ' + url);
  });
  mockPost.mockResolvedValue({ status: 200, data: outcomeFixture() });
});
async function openPanel() {
  const mounted = render(<CompanyOffboardingAccessPanel {...props} />);
  fireEvent.click(screen.getByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' }));
  await screen.findByRole('region', { name: 'Rollen- und PIM-Vorschau' }); return mounted;
}
function select(index = 1, role = 'directory-reader') { fireEvent.click(screen.getByRole('checkbox', { name: `Zuweisung auswählen: ${role} · ${identifier(index)}` })); }
function setReason(value = reason) { fireEvent.change(screen.getByLabelText('Begründung für Berechtigungsentzug'), { target: { value } }); }
async function dialog() {
  const mounted = await openPanel(); select(); setReason('  ' + reason + '  '); fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Zuweisungen widerrufen' }));
  return { mounted, confirmation: within(screen.getByRole('alertdialog', { name: 'Berechtigungsentzug bestätigen' })) };
}
async function confirm() {
  const { mounted, confirmation } = await dialog();
  fireEvent.click(confirmation.getByRole('checkbox', { name: 'Ich bestätige genau diese ursprünglichen Zuweisungen.' }));
  fireEvent.click(confirmation.getByRole('button', { name: 'Bestätigen' })); return mounted;
}

test('starts explicitly collapsed without GET or POST', () => {
  render(<CompanyOffboardingAccessPanel {...props} />);
  expect(screen.getByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' })).toHaveAttribute('aria-expanded', 'false');
  expect(mockGet).not.toHaveBeenCalled(); expect(mockPost).not.toHaveBeenCalled();
});
test('only explicit open loads capabilities then bound preview and history and discloses limited scope', async () => {
  await openPanel(); expect(mockGet.mock.calls.map(([url]) => url)).toEqual([base + '/capabilities', base, base + '/history']);
  expect(screen.getByText(/Dies bestätigt keinen vollständigen Berechtigungsentzug/)).toBeInTheDocument();
  expect(screen.getByText(/Firmen-Ownership verleiht keine Adminrechte/)).toBeInTheDocument();
  expect(screen.getByText(/Auch abgelaufene Einträge sind enthalten/)).toBeInTheDocument();
  expect(screen.getByRole('tab', { name: 'Rollen' })).toHaveAttribute('aria-selected', 'true'); expect(mockPost).not.toHaveBeenCalled();
});
test('selection and reason are captured and confirmation checkbox is required before a single POST', async () => {
  const { confirmation } = await dialog(); expect(confirmation.getByText('Begründung: ' + reason)).toBeInTheDocument();
  expect(confirmation.getByText(version)).toBeInTheDocument(); expect(confirmation.getByText(workflowId)).toBeInTheDocument();
  expect(confirmation.getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); expect(mockPost).not.toHaveBeenCalled();
  fireEvent.click(confirmation.getByRole('checkbox', { name: 'Ich bestätige genau diese ursprünglichen Zuweisungen.' }));
  fireEvent.click(confirmation.getByRole('button', { name: 'Bestätigen' }));
  const outcome = within(await screen.findByRole('region', { name: 'Ergebnis des Berechtigungsentzugs' }));
  expect(outcome.getByRole('status')).toHaveTextContent('Nur die ausgewählten ursprünglichen Zuweisungen');
  expect(mockPost).toHaveBeenCalledWith(base, { workflowId, eligibilityRevision: '8', kind: 'role', reason, confirm: true, items: [{ id: identifier(1), version }] }, { signal: expect.any(AbortSignal) });
  expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(3); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
});
test('cancel never posts and invalid reasons cannot open confirmation', async () => {
  const { confirmation } = await dialog(); fireEvent.click(confirmation.getByRole('button', { name: 'Abbrechen' }));
  for (const value of ['kurz', 'x'.repeat(501), reason + '\u007f']) {
    setReason(value); fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Zuweisungen widerrufen' })); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  }
  expect(mockPost).not.toHaveBeenCalled();
});
test('protected rows stay visible disabled and only selected allowed subset is written', async () => {
  preview = previewFixture({ items: [item(1, { role: 'admin', canRevoke: false, blockedReason: 'protected_role' }), item(2), item(3)], total: 3 });
  await openPanel(); expect(screen.getByRole('checkbox', { name: `Zuweisung auswählen: admin · ${identifier(1)}` })).toBeDisabled();
  expect(screen.getByText(/Geschützte Rolle – tatsächliche Adminberechtigung/)).toBeInTheDocument(); select(3); setReason();
  fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Zuweisungen widerrufen' })); const confirmation = within(screen.getByRole('alertdialog'));
  expect(confirmation.queryByText('admin', { exact: true })).not.toBeInTheDocument(); expect(confirmation.getByText(identifier(3))).toBeInTheDocument();
  mockPost.mockResolvedValue({ status: 200, data: outcomeFixture({ results: [{ id: identifier(3), status: 'revoked', code: 200, checkpointId: identifier(60) }] }) });
  fireEvent.click(confirmation.getByRole('checkbox')); fireEvent.click(confirmation.getByRole('button', { name: 'Bestätigen' }));
  await screen.findByRole('region', { name: 'Ergebnis des Berechtigungsentzugs' }); expect(mockPost.mock.calls[0][1].items).toEqual([{ id: identifier(3), version }]);
});
test('read-only actor sees actual expired rows and no enabled mutation', async () => {
  capabilities = capabilitiesFixture({ permissions: ['identities.roles.read'], supportedKinds: ['role'] });
  preview = previewFixture({ canRevoke: false, items: [item(1, { canRevoke: false, blockedReason: 'permission_required', expiresAt: '2026-01-02T00:00:00.000Z' })] });
  await openPanel(); expect(screen.getByText(/Nur Lesezugriff/)).toBeInTheDocument(); expect(screen.getByText(/Abgelaufen:/)).toBeInTheDocument();
  expect(screen.getByRole('checkbox')).toBeDisabled(); expect(screen.getByRole('button', { name: 'Ausgewählte Zuweisungen widerrufen' })).toBeDisabled();
  expect(screen.queryByRole('tab', { name: 'PIM-Berechtigungen' })).not.toBeInTheDocument(); expect(mockPost).not.toHaveBeenCalled();
});
test('PIM-only actor can open directly without a role-tab or general directory calls', async () => {
  capabilities = capabilitiesFixture({ permissions: ['pim.eligibilities.read', 'pim.eligibilities.manage'], supportedKinds: ['eligibility'] });
  preview = previewFixture({ kind: 'eligibility' }); history = historyFixture({ kind: 'eligibility' }); await openPanel();
  expect(screen.queryByRole('tab', { name: 'Rollen' })).not.toBeInTheDocument(); expect(screen.getByRole('tab', { name: 'PIM-Berechtigungen' })).toHaveAttribute('aria-selected', 'true');
  select(); setReason(); fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Zuweisungen widerrufen' }));
  expect(within(screen.getByRole('alertdialog')).getByText(/bestehende PIM-Kaskade/)).toBeInTheDocument(); expect(mockGet).toHaveBeenCalledTimes(3);
});
test('switching supported tabs explicitly reads correct kind and clears selection', async () => {
  await openPanel(); select(); preview = previewFixture({ kind: 'eligibility' }); history = historyFixture({ kind: 'eligibility' });
  fireEvent.click(screen.getByRole('tab', { name: 'PIM-Berechtigungen' })); await screen.findByText('PIM-Berechtigungen – nicht widerrufene Zuweisungen');
  expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(mockGet).toHaveBeenCalledTimes(6);
  expect(mockGet).toHaveBeenNthCalledWith(5, base, { params: { workflowId, kind: 'eligibility', page: '1', limit: '25' }, signal: expect.any(AbortSignal) }); expect(mockPost).not.toHaveBeenCalled();
});
test('paging explicitly displays only 25 rows and selection never crosses pages', async () => {
  preview = previewFixture({ items: Array.from({ length: 25 }, (_, index) => item(index + 1)), total: 26 }); await openPanel(); select();
  preview = previewFixture({ items: [item(26)], total: 26, page: 2 });
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Berechtigungsvorschauseiten' })).getByRole('button', { name: 'Weiter' }));
  await screen.findByRole('checkbox', { name: `Zuweisung auswählen: directory-reader · ${identifier(26)}` });
  expect(screen.getAllByRole('checkbox')).toHaveLength(1); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(mockPost).not.toHaveBeenCalled();
});
test.each([401, 403, 404, 409, 412, 428, 503])('status %s fails closed without automatic retries', async status => {
  mockGet.mockRejectedValue({ response: { status } }); render(<CompanyOffboardingAccessPanel {...props} />);
  fireEvent.click(screen.getByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' })); await screen.findByRole('alert');
  expect(mockGet).toHaveBeenCalledTimes(1); expect(mockPost).not.toHaveBeenCalled(); expect(screen.queryByRole('region', { name: 'Rollen- und PIM-Vorschau' })).not.toBeInTheDocument();
  if (status === 403) expect(screen.getByRole('alert')).toHaveTextContent('Separate Rollen- oder PIM-Berechtigung erforderlich');
});
test('unconfirmed transport result has no automatic POST and only explicit original intent recovery excludes new grants', async () => {
  mockPost.mockRejectedValueOnce(new Error('Lost ACK')); await confirm(); await screen.findByRole('alert');
  expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(3);
  expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeDisabled();
  preview = previewFixture({ items: [item(2, { version: 'b'.repeat(64) })] });
  fireEvent.click(screen.getByRole('button', { name: 'Vorschau und Historie neu laden' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })); const confirmation = within(screen.getByRole('alertdialog', { name: 'Ursprünglichen Versuch bestätigen' }));
  expect(confirmation.getByText(identifier(1))).toBeInTheDocument(); expect(confirmation.queryByText(identifier(2))).not.toBeInTheDocument(); expect(confirmation.getByRole('button', { name: 'Bestätigen' })).toBeDisabled();
  mockPost.mockResolvedValue({ status: 200, data: outcomeFixture({ results: [{ id: identifier(1), status: 'already_revoked', code: 200, checkpointId: identifier(60) }] }) });
  fireEvent.click(confirmation.getByRole('checkbox')); fireEvent.click(confirmation.getByRole('button', { name: 'Bestätigen' }));
  await screen.findByRole('region', { name: 'Ergebnis des Berechtigungsentzugs' }); expect(mockPost.mock.calls[1][1].items).toEqual([{ id: identifier(1), version }]); expect(mockPost).toHaveBeenCalledTimes(2);
});
test('partial outcomes show individual checkpoint truth and stop without background writes', async () => {
  preview = previewFixture({ items: [item(1), item(2), item(3)], total: 3 }); await openPanel(); select(1); select(2); select(3); setReason();
  fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Zuweisungen widerrufen' })); const confirmation = within(screen.getByRole('alertdialog'));
  mockPost.mockResolvedValue({ status: 207, data: outcomeFixture({ results: [
    { id: identifier(1), status: 'revoked', code: 200, checkpointId: identifier(60) },
    { id: identifier(2), status: 'unconfirmed', code: 503, checkpointId: null },
    { id: identifier(3), status: 'not_attempted', code: null, checkpointId: null },
  ] }) });
  fireEvent.click(confirmation.getByRole('checkbox')); fireEvent.click(confirmation.getByRole('button', { name: 'Bestätigen' }));
  const outcome = within(await screen.findByRole('region', { name: 'Ergebnis des Berechtigungsentzugs' }));
  expect(outcome.getByRole('status')).toHaveTextContent('nicht vollständig bestätigt'); expect(outcome.getByText(/Nicht bestätigt · Status 503/)).toBeInTheDocument();
  expect(outcome.getByText(/Nicht versucht/)).toBeInTheDocument(); expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(3);
});
test('honest history shows persisted checkpoint, original hash and pending delivery', async () => {
  history = historyFixture({ receipts: [{ id: identifier(50), resourceId: identifier(1), role: 'directory-reader', version, kind: 'role', checkpointId: identifier(60), actorUserId, correlationId: identifier(80), reason, createdAt: '2026-01-01T00:00:00.000Z', deliveryStatus: 'pending' }], total: 1 });
  await openPanel(); const region = within(screen.getByRole('region', { name: 'Berechtigungsentzugs-Historie' }));
  expect(region.getByText(/Ereigniszustellung ausstehend/)).toBeInTheDocument(); expect(region.getByText(identifier(60))).toBeInTheDocument(); expect(region.getByText(version)).toBeInTheDocument();
});
test('session event clears displayed data, confirmation and recoverable intent without retry', async () => {
  const { confirmation } = await dialog(); fireEvent.click(confirmation.getByRole('checkbox'));
  act(() => window.dispatchEvent(new Event('od:session-error')));
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Rollen- und PIM-Vorschau' })).not.toBeInTheDocument(); expect(mockPost).not.toHaveBeenCalled();
  expect(screen.getByRole('alert')).toHaveTextContent('Sitzung ungültig'); expect(mockGet).toHaveBeenCalledTimes(3);
});
test('identity prop replacement remounts collapsed with no inherited selection, capability or write', async () => {
  const mounted = await openPanel(); select(); mounted.rerender(<CompanyOffboardingAccessPanel {...props} workflowId={identifier(90)} />);
  expect(screen.getByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' })).toHaveAttribute('aria-expanded', 'false');
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(mockGet).toHaveBeenCalledTimes(3); expect(mockPost).not.toHaveBeenCalled();
});
test('collapse disposes the attempted intent and reopening never offers recovery of that old intent', async () => {
  mockPost.mockRejectedValueOnce(new Error('Lost ACK')); await confirm(); await screen.findByRole('alert');
  expect(screen.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' }));
  expect(screen.queryByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' }));
  await screen.findByRole('region', { name: 'Rollen- und PIM-Vorschau' });
  expect(screen.queryByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen' })).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Ergebnis des Berechtigungsentzugs' })).not.toBeInTheDocument();
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(mockGet).toHaveBeenCalledTimes(6); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('late capability response after unmount is aborted and cannot restore an action', async () => {
  let resolve: (value: any) => void; mockGet.mockReturnValue(new Promise(complete => { resolve = complete; }));
  const mounted = render(<CompanyOffboardingAccessPanel {...props} />); fireEvent.click(screen.getByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' }));
  const signal = mockGet.mock.calls[0][1].signal; mounted.unmount(); expect(signal.aborted).toBe(true);
  await act(async () => { resolve({ status: 200, data: capabilitiesFixture() }); }); expect(mockGet).toHaveBeenCalledTimes(1); expect(mockPost).not.toHaveBeenCalled();
});
test.each(['licenses', 'paused'])('parent negative checkpoint mounts collapsed independently while %s is incomplete', async phase => {
  const job = jobFixture(phase === 'paused' ? { phase, failure: { code: 503, step: 'licenses' } } : {});
  mockGet.mockImplementation(async (url: string) => {
    if (url === jobs + '/capabilities') return { status: 200, data: parentCapabilities() };
    if (url === jobs) return { status: 200, data: queueFixture(job) };
    if (url === jobs + '/' + workflowId) return { status: 200, data: job, headers: { etag: offboardingEtag(job.workflow) } };
    if (url === jobs + '/' + workflowId + '/history') return { status: 200, data: parentHistory(job) };
    throw new Error('Unexpected endpoint ' + url);
  });
  render(<CompanyOffboardingPanel context={context} />);
  fireEvent.click(screen.getByRole('button', { name: 'Mitarbeiter-Offboarding' }));
  await screen.findByRole('heading', { name: 'Gespeicherte Vorgänge' });
  fireEvent.change(screen.getByLabelText('Bekannte Vorgangs-ID'), { target: { value: workflowId } }); fireEvent.click(screen.getByRole('button', { name: 'Arbeitsstand neu laden' }));
  const toggle = await screen.findByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' });
  expect(toggle).toHaveAttribute('aria-expanded', 'false'); expect(mockGet.mock.calls.some(([url]) => url.startsWith(base))).toBe(false); expect(mockPost).not.toHaveBeenCalled();
});
test('parent without a negative checkpoint cannot mount access cleanup', async () => {
  const job = pendingFixture();
  mockGet.mockImplementation(async (url: string) => {
    if (url === jobs + '/capabilities') return { status: 200, data: parentCapabilities() };
    if (url === jobs) return { status: 200, data: queueFixture(job) };
    if (url === jobs + '/' + workflowId) return { status: 200, data: job, headers: { etag: offboardingEtag(job.workflow) } };
    if (url === jobs + '/' + workflowId + '/history') return { status: 200, data: parentHistory(job) };
    throw new Error('Unexpected endpoint ' + url);
  });
  render(<CompanyOffboardingPanel context={context} />); fireEvent.click(screen.getByRole('button', { name: 'Mitarbeiter-Offboarding' }));
  await screen.findByRole('heading', { name: 'Gespeicherte Vorgänge' });
  fireEvent.change(screen.getByLabelText('Bekannte Vorgangs-ID'), { target: { value: workflowId } }); fireEvent.click(screen.getByRole('button', { name: 'Arbeitsstand neu laden' }));
  await screen.findByRole('article', { name: 'Offboarding-Arbeitsstand' }); expect(screen.queryByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' })).not.toBeInTheDocument();
});
