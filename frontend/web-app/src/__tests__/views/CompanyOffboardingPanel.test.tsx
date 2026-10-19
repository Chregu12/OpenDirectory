import React from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import CompanyOffboardingPanel from '@/components/views/CompanyOffboardingPanel';
import CompanyApplicationsView from '@/components/views/CompanyApplicationsView';
import UserDetailPanel from '@/components/views/UserDetailPanel';
import { api } from '@/lib/api';
import { offboardingEtag } from '@/lib/companyOffboarding';
import { actorUserId, tenantId, userId, workflowId, poolId, assignmentId, otherId, context, base, jobs, reason, requestedRevision, capabilitiesFixture, previewFixture, itemFixture, jobFixture, pendingFixture, completedFixture, queueFixture, historyFixture, createdAt } from '../fixtures/companyOffboarding';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
let access: any;
let record: any;
let preview: any;
let companyPermissions: string[];
async function getResponse(url: string) {
  if (url === jobs + '/capabilities') return { status: 200, data: access };
  if (url === jobs) return { status: 200, data: queueFixture(record) };
  if (url === base + '/users/' + userId + '/offboarding-preview') return { status: 200, data: preview };
  if (url === jobs + '/' + workflowId) return { status: 200, data: record, headers: { etag: offboardingEtag(record.workflow) } };
  if (url === jobs + '/' + workflowId + '/history') return { status: 200, data: historyFixture(record) };
  if (url === base + '/capabilities') return { status: 200, data: { schemaVersion: 1, ...context, companyLicenseProtocol: 1, permissions: companyPermissions, allocationMode: 'local-only', supportedTargets: ['user'] } };
  if (url === base + '/pools') return { status: 200, data: { schemaVersion: 1, ...context, pools: [], total: 0, page: 1, limit: 25 } };
  throw new Error('Unexpected endpoint ' + url);
}
beforeEach(() => {
  jest.resetAllMocks(); window.localStorage.clear(); window.history.replaceState({}, '', '/applications');
  Object.defineProperty(window.crypto, 'randomUUID', { configurable: true, value: jest.fn(() => workflowId) });
  access = capabilitiesFixture(); record = jobFixture(); preview = previewFixture(); companyPermissions = ['company.apps.read', 'company.apps.assign'];
  (api.get as jest.Mock).mockImplementation(getResponse);
  (api.post as jest.Mock).mockResolvedValue({ status: 201, data: record });
});
async function openPanel() {
  const result = render(<CompanyOffboardingPanel context={context} />);
  fireEvent.click(screen.getByRole('button', { name: 'Mitarbeiter-Offboarding' }));
  await screen.findByRole('heading', { name: 'Gespeicherte Vorgänge' }); return result;
}
function setReason() { fireEvent.change(screen.getByLabelText('Begründung für neuen Offboarding-Vorgang'), { target: { value: reason } }); }
async function createDialog(onRender?: (result: ReturnType<typeof render>) => void) {
  const result = await openPanel(); onRender?.(result); fireEvent.change(screen.getByLabelText('Mitarbeiter-ID'), { target: { value: userId } });
  fireEvent.click(screen.getByRole('button', { name: 'Mitarbeitervorschau laden' }));
  await screen.findByRole('button', { name: 'Kontosperre und Lizenzrückgabe starten' });
  setReason(); fireEvent.click(screen.getByRole('button', { name: 'Kontosperre und Lizenzrückgabe starten' }));
  return within(screen.getByRole('alertdialog', { name: 'Mitarbeiter-Offboarding bestätigen' }));
}
async function loadRecord() {
  await openPanel();
  fireEvent.change(screen.getByLabelText('Bekannte Vorgangs-ID'), { target: { value: workflowId } });
  fireEvent.click(screen.getByRole('button', { name: 'Arbeitsstand neu laden' }));
  await screen.findByRole('article', { name: 'Offboarding-Arbeitsstand' });
}

test('stays collapsed without fetching offboarding data until explicitly opened', () => {
  render(<CompanyOffboardingPanel context={context} />);
  expect(screen.getByRole('button', { name: 'Mitarbeiter-Offboarding' })).toHaveAttribute('aria-expanded', 'false');
  expect(api.get).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
});
test('optional URL prefill opens the panel but never previews or writes automatically', async () => {
  window.history.replaceState({}, '', '/applications?offboard=' + userId + '#company-offboarding');
  render(<CompanyOffboardingPanel context={context} />);
  expect(await screen.findByLabelText('Mitarbeiter-ID')).toHaveValue(userId);
  await screen.findByRole('heading', { name: 'Gespeicherte Vorgänge' });
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.endsWith('/offboarding-preview'))).toBe(false); expect(api.post).not.toHaveBeenCalled();
});
test('invalid prefill cannot open or authorize an offboarding target', () => {
  window.history.replaceState({}, '', '/applications?offboard=foreign-profile'); render(<CompanyOffboardingPanel context={context} />);
  expect(screen.getByRole('button', { name: 'Mitarbeiter-Offboarding' })).toHaveAttribute('aria-expanded', 'false'); expect(api.get).not.toHaveBeenCalled();
});
test('requires confirmation for creation and each further batch, shows partial counts and durable history', async () => {
  const dialog = await createDialog(); expect(api.post).not.toHaveBeenCalled();
  expect(dialog.getByText(/Anna Beispiel/)).toBeInTheDocument();
  expect(dialog.getByText(/Externe Zugangsdaten werden nicht gelöscht/)).toHaveTextContent('Bestehende Rollen und Gruppen, Geräte, Remote-Befehle und externe Lizenzanbieter werden nicht bearbeitet.');
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  const article = within(await screen.findByRole('article', { name: 'Offboarding-Arbeitsstand' }));
  expect(article.getByText('25 von 26 erfassten lokalen Lizenzzuweisungen zurückgegeben.')).toBeInTheDocument();
  expect(article.queryByRole('heading', { name: 'Kontosperre und lokale Lizenzen geprüft' })).not.toBeInTheDocument();
  expect(article.getByRole('button', { name: 'Nächsten Schritt fortsetzen' })).toBeDisabled(); expect(api.post).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Arbeitsstand neu laden' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Nächsten Schritt fortsetzen' })).toBeEnabled());
  expect(within(screen.getByRole('region', { name: 'Offboarding-Historie' })).getByText(/Ereigniszustellung ausstehend/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Nächsten Schritt fortsetzen' }));
  expect(api.post).toHaveBeenCalledTimes(1);
  record = completedFixture(); (api.post as jest.Mock).mockResolvedValue({ status: 200, data: record });
  fireEvent.click(within(screen.getByRole('alertdialog', { name: 'Fortsetzung bestätigen' })).getByRole('button', { name: 'Bestätigen' }));
  await screen.findByRole('heading', { name: 'Kontosperre und lokale Lizenzen geprüft' });
  expect(screen.getByText('26 von 26 erfassten lokalen Lizenzzuweisungen zurückgegeben.')).toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(2);
  expect(screen.getByText(/kein vollständiger Austrittsprozess/)).toBeInTheDocument();
});
test('cancel and invalid reason never write', async () => {
  const dialog = await createDialog(); fireEvent.click(dialog.getByRole('button', { name: 'Abbrechen' }));
  fireEvent.change(screen.getByLabelText('Begründung für neuen Offboarding-Vorgang'), { target: { value: 'kurz' } });
  fireEvent.click(screen.getByRole('button', { name: 'Kontosperre und Lizenzrückgabe starten' }));
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('10 bis 500'); expect(api.post).not.toHaveBeenCalled();
});
test('unknown create result is recovered by its durable ID using GET without replay', async () => {
  const dialog = await createDialog(); (api.post as jest.Mock).mockRejectedValue(new Error('Lost ACK'));
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  const recovery = within(await screen.findByRole('complementary', { name: 'Unbestätigter Offboarding-Vorgang' }));
  expect(screen.queryByLabelText('Mitarbeiter-ID')).not.toBeInTheDocument();
  expect(recovery.getByText(workflowId)).not.toBeVisible();
  fireEvent.click(recovery.getByRole('button', { name: 'Vorgang wiederherstellen' }));
  await screen.findByRole('article', { name: 'Offboarding-Arbeitsstand' });
  expect(api.get).toHaveBeenCalledWith(jobs + '/' + workflowId, { signal: expect.any(AbortSignal) }); expect(api.post).toHaveBeenCalledTimes(1);
});
test('paused review explicitly confirms latest GET pool versions and preserves captured IDs', async () => {
  record = jobFixture({ phase: 'paused', failure: { code: 412, step: 'licenses' }, reviewAssignments: [itemFixture({ poolRevision: '9007199254740999' })] });
  await loadRecord(); expect(screen.getByText(/Pausengrund: Lokale Lizenzrückgabe · Fehler 412/)).toBeInTheDocument();
  setReason(); fireEvent.click(screen.getByRole('button', { name: 'Geprüften Vorgang fortsetzen' }));
  const dialog = within(screen.getByRole('alertdialog', { name: 'Geprüfte Fortsetzung bestätigen' }));
  expect(dialog.getByText(/Poolversion 9007199254740999/)).toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: completedFixture() });
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); await screen.findByRole('heading', { name: 'Kontosperre und lokale Lizenzen geprüft' });
  expect((api.post as jest.Mock).mock.calls[0][1].assignments).toEqual([{ poolId, assignmentId, poolRevision: '9007199254740999' }]);
});
test('continuation always displays and sends the original readonly reason even when a new-plan reason is edited', async () => {
  await loadRecord();
  const original = screen.getByLabelText('Ursprüngliche Begründung für Fortsetzung'); expect(original).toHaveValue(reason); expect(original).toHaveAttribute('readonly');
  fireEvent.change(screen.getByLabelText('Begründung für neuen Offboarding-Vorgang'), { target: { value: 'Neue Begründung nur für neuen Vorgang' } });
  fireEvent.click(screen.getByRole('button', { name: 'Nächsten Schritt fortsetzen' }));
  const dialog = within(screen.getByRole('alertdialog', { name: 'Fortsetzung bestätigen' }));
  expect(dialog.getByText('Begründung: ' + reason)).toBeInTheDocument(); expect(dialog.queryByText(/Neue Begründung/)).not.toBeInTheDocument();
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: completedFixture() }); fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  await screen.findByRole('heading', { name: 'Kontosperre und lokale Lizenzen geprüft' }); expect((api.post as jest.Mock).mock.calls[0][1].reason).toBe(reason);
});
test('account receipt recovery keeps original revision without an automatic employee preview', async () => {
  record = pendingFixture({ phase: 'paused', failure: { code: 503, step: 'account' } }); record.currentTarget = { enabled: false, deleted: false, eligibilityRevision: '8' };
  await loadRecord(); setReason(); fireEvent.click(screen.getByRole('button', { name: 'Geprüften Vorgang fortsetzen' }));
  expect(screen.getByRole('alertdialog')).toHaveTextContent(requestedRevision);
  expect(screen.queryByRole('button', { name: 'Mitarbeitervorschau für Fortsetzung laden' })).not.toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.endsWith('/offboarding-preview'))).toBe(false);
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: jobFixture({ revision: '3' }) });
  fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1)); expect((api.post as jest.Mock).mock.calls[0][1].userRevision).toBe(requestedRevision);
  await screen.findByText('25 von 26 erfassten lokalen Lizenzzuweisungen zurückgegeben.');
});
test('412 account resume demands explicit employee reload and approval of changed record version', async () => {
  record = pendingFixture({ phase: 'paused', failure: { code: 412, step: 'account' } }); preview = previewFixture({ userRevision: '9007199254740999' });
  await loadRecord(); setReason(); expect(screen.getByRole('button', { name: 'Geprüften Vorgang fortsetzen' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Mitarbeitervorschau für Fortsetzung laden' }));
  await screen.findByText(/Datensatzversion 9007199254740993 → 9007199254740999/);
  fireEvent.click(screen.getByRole('button', { name: 'Geprüften Vorgang fortsetzen' }));
  expect(screen.getByRole('alertdialog')).toHaveTextContent('9007199254740993 → 9007199254740999'); expect(api.post).not.toHaveBeenCalled();
});
test('changed generation in a newly reviewed employee preview stops account retry', async () => {
  record = pendingFixture({ phase: 'paused', failure: { code: 412, step: 'account' } }); preview = previewFixture({ eligibilityRevision: '9' });
  await loadRecord(); fireEvent.click(screen.getByRole('button', { name: 'Mitarbeitervorschau für Fortsetzung laden' }));
  await screen.findByText(/Kontogeneration oder Status seit dem Abruf geändert/);
  expect(screen.getByRole('button', { name: 'Geprüften Vorgang fortsetzen' })).toBeDisabled(); expect(api.post).not.toHaveBeenCalled();
});
test('completed workflow with reactivated current target is explicitly historical and cannot continue', async () => {
  record = completedFixture(); record.currentTarget = { enabled: true, deleted: false, eligibilityRevision: '9' }; await loadRecord();
  const article = within(screen.getByRole('article', { name: 'Offboarding-Arbeitsstand' }));
  expect(article.getByText('Kontostatus beim letzten Abruf: Freigegeben.')).toBeInTheDocument();
  expect(article.getByText(/Historischer Abschluss/)).toBeInTheDocument(); expect(article.getByRole('alert')).toHaveTextContent(/Kontostatus oder Berechtigungsgeneration geändert/);
  expect(article.queryByRole('button', { name: /fortsetzen/i })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('checkpoint generation change hides all continuation actions', async () => {
  record = jobFixture({}, { eligibilityRevision: '9' }); await loadRecord();
  expect(screen.getByRole('alert')).toHaveTextContent(/Fortsetzen ist gesperrt/); expect(screen.queryByRole('button', { name: /fortsetzen/i })).not.toBeInTheDocument();
});
test('confirmed generation conflict without checkpoint requires a new workflow', async () => {
  record = pendingFixture({ phase: 'paused', failure: { code: 409, step: 'verify' } }); record.currentTarget.eligibilityRevision = '9';
  await loadRecord(); expect(screen.getByRole('alert')).toHaveTextContent(/neuer Vorgang erforderlich/);
  expect(screen.queryByRole('button', { name: /fortsetzen/i })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test.each([401, 403, 409, 412, 428, 503])('source %s clears profiles, jobs and history without automatic refresh or POST retry', async status => {
  await loadRecord(); setReason(); fireEvent.click(screen.getByRole('button', { name: 'Nächsten Schritt fortsetzen' }));
  (api.post as jest.Mock).mockRejectedValue({ response: { status, data: completedFixture() } });
  const reads = (api.get as jest.Mock).mock.calls.length;
  fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/neu laden/);
  expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByLabelText('Offboarding-Historie')).not.toBeInTheDocument();
  expect(screen.queryByText('Firmen Editor')).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1); expect((api.get as jest.Mock).mock.calls).toHaveLength(reads + 1);
});
test.each([{ actorUserId: otherId }, { tenantId: otherId }, { companyOffboardingProtocol: 0 }, { scope: 'complete-offboarding' }])('foreign source or protocol %j prevents previews and writes', async changes => {
  access = capabilitiesFixture(changes); render(<CompanyOffboardingPanel context={context} />); fireEvent.click(screen.getByRole('button', { name: 'Mitarbeiter-Offboarding' }));
  await screen.findByRole('alert'); expect(screen.queryByLabelText('Mitarbeiter-ID')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('stale ETag response cannot authorize a continuation', async () => {
  await openPanel(); (api.get as jest.Mock).mockImplementation(async url => url === jobs + '/' + workflowId ? { status: 200, data: record, headers: { etag: '"stale"' } } : getResponse(url));
  fireEvent.change(screen.getByLabelText('Bekannte Vorgangs-ID'), { target: { value: workflowId } }); fireEvent.click(screen.getByRole('button', { name: 'Arbeitsstand neu laden' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('session change aborts an in-flight write, hides late reply and preserves durable recovery ID', async () => {
  const dialog = await createDialog(); let finish: (value: any) => void;
  (api.post as jest.Mock).mockReturnValue(new Promise(resolve => { finish = resolve; }));
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1));
  const signal = (api.post as jest.Mock).mock.calls[0][2].signal;
  act(() => window.dispatchEvent(new CustomEvent('od:session-error'))); expect(signal.aborted).toBe(true);
  await act(async () => { finish({ status: 201, data: completedFixture() }); });
  expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.queryByRole('heading', { name: 'Kontosperre und lokale Lizenzen geprüft' })).not.toBeInTheDocument();
  expect(screen.getByRole('complementary', { name: 'Unbestätigter Offboarding-Vorgang' })).toHaveTextContent(workflowId); expect(api.post).toHaveBeenCalledTimes(1);
});
test('unmount aborts a request and a later client retains the workflow ID for GET recovery', async () => {
  let mounted: ReturnType<typeof render>;
  const dialog = await createDialog(result => { mounted = result; }); let finish: (value: any) => void;
  (api.post as jest.Mock).mockReturnValue(new Promise(resolve => { finish = resolve; }));
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1));
  const signal = (api.post as jest.Mock).mock.calls[0][2].signal;
  mounted.unmount();
  await act(async () => { finish({ status: 201, data: record }); });
  expect(signal.aborted).toBe(true); expect(window.localStorage.getItem(window.localStorage.key(0))).toBe(workflowId);
  await openPanel(); expect(screen.getByRole('complementary', { name: 'Unbestätigter Offboarding-Vorgang' })).toHaveTextContent(workflowId); expect(api.post).toHaveBeenCalledTimes(1);
});
test('UUIDs stay in closed native proof disclosures', async () => {
  await loadRecord(); const article = within(screen.getByRole('article', { name: 'Offboarding-Arbeitsstand' }));
  for (const identifier of [workflowId, userId, actorUserId, tenantId, poolId, assignmentId]) {
    for (const element of article.getAllByText(identifier, { exact: true })) { expect(element.closest('details')).not.toHaveAttribute('open'); expect(element).not.toBeVisible(); }
  }
});
test.each([[['company.apps.read']], [['company.apps.assign']], [[]]])('applications integration requires verified actual canAssign: %j', async permissions => {
  companyPermissions = permissions; render(<CompanyApplicationsView />);
  await waitFor(() => expect(screen.queryByText('Lizenzberechtigungen werden geprüft …')).not.toBeInTheDocument());
  expect(screen.queryByRole('button', { name: 'Mitarbeiter-Offboarding' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('applications integration exposes the collapsed panel only after actual assign/read capabilities', async () => {
  render(<CompanyApplicationsView />);
  fireEvent.click(await screen.findByRole('button', { name: 'Bisherige Direktverwaltung' }));
  expect(await screen.findByRole('button', { name: 'Mitarbeiter-Offboarding' })).toHaveAttribute('aria-expanded', 'false');
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.startsWith(jobs))).toBe(false);
});
test.each([[['users.update']], [['users.status.manage']], [[]]])('user detail link requires both actual permissions: %j', permissions => {
  render(<UserDetailPanel user={{ id: userId, username: 'anna', email: 'anna@example.test', enabled: true, revision: '1', createdAt }} permissions={permissions} actorUserId={actorUserId} onChanged={jest.fn()} onReload={jest.fn()} onDenied={jest.fn()} />);
  expect(screen.queryByRole('link', { name: 'Mitarbeiter-Offboarding' })).not.toBeInTheDocument();
});
test('user detail links the canonical target into applications and excludes self offboarding', () => {
  const props = { user: { id: userId, username: 'anna', email: 'anna@example.test', enabled: true, revision: '1', createdAt }, permissions: ['users.update', 'users.status.manage'], actorUserId, onChanged: jest.fn(), onReload: jest.fn(), onDenied: jest.fn() };
  const { rerender } = render(<UserDetailPanel {...props} />);
  expect(screen.getByRole('link', { name: 'Mitarbeiter-Offboarding' })).toHaveAttribute('href', '/applications?offboard=' + userId + '#company-offboarding');
  rerender(<UserDetailPanel {...props} actorUserId={userId} />); expect(screen.queryByRole('link', { name: 'Mitarbeiter-Offboarding' })).not.toBeInTheDocument();
});
