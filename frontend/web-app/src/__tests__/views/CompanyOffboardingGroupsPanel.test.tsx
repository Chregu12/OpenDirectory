import React from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import CompanyOffboardingGroupsPanel from '@/components/views/CompanyOffboardingGroupsPanel';
import CompanyOffboardingPanel from '@/components/views/CompanyOffboardingPanel';
import { offboardingEtag } from '@/lib/companyOffboarding';
import { context, userId, workflowId, otherId, reason, jobs, capabilitiesFixture, completedFixture, jobFixture, pendingFixture, queueFixture, historyFixture } from '../fixtures/companyOffboarding';
import { groupsBase, groupFixture, groupsPreviewFixture, groupsHistoryFixture, groupReceiptFixture, groupResultFixture, groupsOutcomeFixture, deferred } from '../fixtures/companyOffboardingGroups';

const mockGet = jest.fn();
const mockPost = jest.fn();
jest.mock('@/lib/api', () => ({ api: { get: (...args: unknown[]) => mockGet(...args), post: (...args: unknown[]) => mockPost(...args) } }));
const props = { context, workflowId, userId, eligibilityRevision: '8' };
let preview: unknown;
let history: unknown;
beforeEach(() => {
  jest.resetAllMocks(); window.localStorage.clear(); window.history.replaceState({}, '', '/applications');
  preview = groupsPreviewFixture(); history = groupsHistoryFixture();
  mockGet.mockImplementation(async (url: string) => {
    if (url === groupsBase) return { status: 200, data: preview };
    if (url === groupsBase + '/history') return { status: 200, data: history };
    throw new Error('Unexpected endpoint ' + url);
  });
  mockPost.mockResolvedValue({ status: 200, data: groupsOutcomeFixture() });
});
async function openPanel() {
  const mounted = render(<CompanyOffboardingGroupsPanel {...props} />);
  fireEvent.click(screen.getByRole('button', { name: 'Gruppen beim Austritt entfernen' }));
  await screen.findByRole('region', { name: 'Gruppenvorschau' }); return mounted;
}
function setReason(value = reason) { fireEvent.change(screen.getByLabelText('Begründung für Gruppenentfernung'), { target: { value } }); }
async function openDialog() {
  const mounted = await openPanel(); setReason('  ' + reason + '  ');
  fireEvent.click(screen.getByRole('button', { name: 'Angezeigte Gruppen entfernen' }));
  return { mounted, dialog: within(screen.getByRole('alertdialog', { name: 'Gruppenentfernung bestätigen' })) };
}

test('starts collapsed and never fetches or mutates before an explicit expand', () => {
  render(<CompanyOffboardingGroupsPanel {...props} />);
  expect(screen.getByRole('button', { name: 'Gruppen beim Austritt entfernen' })).toHaveAttribute('aria-expanded', 'false');
  expect(screen.queryByRole('region', { name: 'Gruppenvorschau' })).not.toBeInTheDocument(); expect(mockGet).not.toHaveBeenCalled(); expect(mockPost).not.toHaveBeenCalled();
});
test('opens exact preview and history and shows scope, linked proof and opaque group versions', async () => {
  await openPanel();
  expect(mockGet).toHaveBeenNthCalledWith(1, groupsBase, { params: { workflowId, page: 1, limit: 25 }, signal: expect.any(AbortSignal) });
  expect(mockGet).toHaveBeenNthCalledWith(2, groupsBase + '/history', { params: { workflowId, page: 1, limit: 25 }, signal: expect.any(AbortSignal) });
  expect(screen.getByText('Austrittsgruppe 1 · Gruppenversion 9007199254740993')).toBeInTheDocument();
  expect(screen.getByText(/Rollen, PIM, Organisationseinheiten/)).toHaveTextContent('werden nicht entfernt');
  expect(screen.getByText(/Rollen, PIM, Organisationseinheiten/)).toHaveTextContent('nur die aufgeführten kanonischen Gruppenmitgliedschaften');
  expect(screen.getByText(/Rollen, PIM, Organisationseinheiten/)).toHaveTextContent('keinen vollständigen Berechtigungsentzug');
  expect(screen.getByText(/keinen vollständigen Berechtigungsentzug oder Austritt/)).toBeInTheDocument(); expect(mockPost).not.toHaveBeenCalled();
  for (const element of screen.getAllByText(workflowId, { exact: true })) { expect(element.closest('details')).not.toHaveAttribute('open'); expect(element).not.toBeVisible(); }
});
test('confirmation displays only the exact page names, versions, trimmed reason and immutable parent', async () => {
  const { dialog } = await openDialog();
  expect(dialog.getByText('Austrittsgruppe 1 · Gruppenversion 9007199254740993')).toBeInTheDocument();
  expect(dialog.getByText('Begründung: ' + reason)).toBeInTheDocument(); expect(dialog.getByText(workflowId)).toBeInTheDocument();
  expect(dialog.getByText('8')).toBeInTheDocument(); expect(dialog.getByText(/Rollen, PIM, OU, Geräte/)).toBeInTheDocument();
  expect(mockPost).not.toHaveBeenCalled();
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  const result = within(await screen.findByRole('region', { name: 'Ergebnis der Gruppenentfernung' }));
  expect(result.getByRole('status')).toHaveTextContent('Angezeigte Gruppenentfernungen bestätigt. Vorschau und Historie ausdrücklich neu laden.');
  expect(mockPost).toHaveBeenCalledWith(groupsBase, {
    workflowId, eligibilityRevision: '8', reason, confirm: true,
    memberships: [{ groupId: groupFixture().groupId, groupRevision: '9007199254740993', membershipId: groupFixture().membershipId }],
  }, { signal: expect.any(AbortSignal) });
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Angezeigte Gruppen entfernen' })).not.toBeInTheDocument();
  expect(mockGet).toHaveBeenCalledTimes(2); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('cancel and invalid reason cannot send a mutation', async () => {
  const { dialog } = await openDialog(); fireEvent.click(dialog.getByRole('button', { name: 'Abbrechen' }));
  for (const value of ['kurz', reason + '\u007f', 'x'.repeat(501)]) {
    setReason(value); fireEvent.click(screen.getByRole('button', { name: 'Angezeigte Gruppen entfernen' }));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('10 bis 500 Zeichen ohne Steuerzeichen');
  }
  expect(mockPost).not.toHaveBeenCalled();
});
test('requires explicit readback after confirmation and shows retained receipt without all-access claims', async () => {
  const { dialog } = await openDialog(); fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  await screen.findByRole('region', { name: 'Ergebnis der Gruppenentfernung' });
  preview = groupsPreviewFixture({ groups: [], total: 0 }); history = groupsHistoryFixture({ receipts: [groupReceiptFixture()], total: 1 });
  expect(mockGet).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole('button', { name: 'Gruppenvorschau und Historie neu laden' }));
  expect(await screen.findByText('Auf dieser Seite sind derzeit keine Gruppenmitgliedschaften vorhanden. Daraus folgt kein vollständiger Zugriffsverlust.')).toBeInTheDocument();
  const receipts = within(screen.getByRole('region', { name: 'Gruppenentfernungs-Historie' }));
  expect(receipts.getByText('Austrittsgruppe 1 · Gruppenversion 9007199254740993 → 9007199254740994')).toBeInTheDocument();
  expect(receipts.getByText(/Ereigniszustellung ausstehend/)).toBeInTheDocument(); expect(receipts.getByText('Begründung: ' + reason)).toBeInTheDocument();
  expect(receipts.getByText(groupReceiptFixture().operationId)).not.toBeVisible();
  expect(screen.getByRole('button', { name: 'Angezeigte Gruppen entfernen' })).toBeDisabled(); expect(mockGet).toHaveBeenCalledTimes(4); expect(mockPost).toHaveBeenCalledTimes(1);
  expect(screen.queryByText(/alle Zugriffe entfernt|Austritt abgeschlossen/i)).not.toBeInTheDocument();
});
test('partial outcome preserves each ordered status and requires explicit readback without retries', async () => {
  preview = groupsPreviewFixture({ groups: [groupFixture(), groupFixture(1), groupFixture(2)], total: 3 });
  mockPost.mockResolvedValue({ status: 207, data: groupsOutcomeFixture({ results: [groupResultFixture(), groupResultFixture(1, { status: 'unconfirmed', code: 412, operationId: null }), groupResultFixture(2, { status: 'not_attempted', code: null, operationId: null })] }) });
  const { dialog } = await openDialog(); fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  const result = within(await screen.findByRole('region', { name: 'Ergebnis der Gruppenentfernung' }));
  expect(result.getByRole('status')).toHaveTextContent('Gruppenentfernung teilweise bestätigt. Bereits bestätigte Schritte bleiben wirksam. Vorschau und Historie ausdrücklich neu laden.');
  expect(result.getByText('Austrittsgruppe 1 · Entfernt · Status 200')).toBeInTheDocument();
  expect(result.getByText('Austrittsgruppe 2 · Nicht bestätigt · Status 412')).toBeInTheDocument();
  expect(result.getByText('Austrittsgruppe 3 · Nicht versucht')).toBeInTheDocument();
  expect(result.getAllByText('Kein bestätigter Nachweis')).toHaveLength(2); expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(2);
  expect(screen.queryByRole('button', { name: 'Angezeigte Gruppen entfernen' })).not.toBeInTheDocument();
});
test('unknown committed reply never claims success, retains historical receipts and requires explicit GET recovery', async () => {
  history = groupsHistoryFixture({ receipts: [groupReceiptFixture(1)], total: 1 });
  mockPost.mockResolvedValue({ status: 200, data: { ...groupsOutcomeFixture(), unexpected: true } });
  const { dialog } = await openDialog(); fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Ergebnis nicht bestätigt. Gruppenvorschau und Historie ausdrücklich neu laden; keine automatische Wiederholung.');
  expect(screen.queryByRole('region', { name: 'Ergebnis der Gruppenentfernung' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Angezeigte Gruppen entfernen' })).not.toBeInTheDocument();
  expect(screen.getByText(/Historie vom letzten Abruf/)).toBeInTheDocument(); expect(mockGet).toHaveBeenCalledTimes(2); expect(mockPost).toHaveBeenCalledTimes(1);
  preview = groupsPreviewFixture({ groups: [], total: 0 }); history = groupsHistoryFixture({ receipts: [groupReceiptFixture()], total: 1 });
  fireEvent.click(screen.getByRole('button', { name: 'Gruppenvorschau und Historie neu laden' }));
  await screen.findByText('Austrittsgruppe 1 · Gruppenversion 9007199254740993 → 9007199254740994'); expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(4);
});
test('first-child failure never implies that any displayed removal was confirmed', async () => {
  mockPost.mockResolvedValue({ status: 207, data: groupsOutcomeFixture({ results: [groupResultFixture(0, { status: 'unconfirmed', code: 503, operationId: null })] }) });
  const { dialog } = await openDialog(); fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  const result = within(await screen.findByRole('region', { name: 'Ergebnis der Gruppenentfernung' }));
  expect(result.getByRole('status')).toHaveTextContent('Keine Gruppenentfernung bestätigt. Vorschau und Historie ausdrücklich neu laden. Frühere bestätigte Schritte bleiben wirksam.');
  expect(result.queryByText(/teilweise bestätigt/)).not.toBeInTheDocument(); expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(2);
});
test.each([401, 403, 404, 409, 412, 428, 503])('source denial %s clears preview without replay or automatic reads', async status => {
  const { dialog } = await openDialog(); mockPost.mockRejectedValue({ response: { status } });
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/neu laden/); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Gruppenvorschau' })).not.toBeInTheDocument(); expect(mockGet).toHaveBeenCalledTimes(2); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('old or absent group protocol fails closed before history and confirmation', async () => {
  preview = groupsPreviewFixture({ companyOffboardingGroupsProtocol: undefined }); render(<CompanyOffboardingGroupsPanel {...props} />);
  fireEvent.click(screen.getByRole('button', { name: 'Gruppen beim Austritt entfernen' }));
  await screen.findByRole('alert'); expect(mockGet).toHaveBeenCalledTimes(1); expect(mockPost).not.toHaveBeenCalled(); expect(screen.queryByRole('region', { name: 'Gruppenvorschau' })).not.toBeInTheDocument();
});
test('history failure withholds preview and write authorization until both reads explicitly succeed', async () => {
  history = groupsHistoryFixture({ tenantId: otherId }); render(<CompanyOffboardingGroupsPanel {...props} />);
  fireEvent.click(screen.getByRole('button', { name: 'Gruppen beim Austritt entfernen' })); await screen.findByRole('alert');
  expect(screen.queryByLabelText('Begründung für Gruppenentfernung')).not.toBeInTheDocument(); expect(mockPost).not.toHaveBeenCalled();
  history = groupsHistoryFixture(); fireEvent.click(screen.getByRole('button', { name: 'Gruppenvorschau und Historie neu laden' }));
  await screen.findByLabelText('Begründung für Gruppenentfernung'); expect(mockGet).toHaveBeenCalledTimes(4);
});
test('empty out-of-range page with nonzero total makes only a page-scoped statement', async () => {
  preview = groupsPreviewFixture({ groups: Array.from({ length: 25 }, (_, index) => groupFixture(index)), total: 26 });
  await openPanel(); preview = groupsPreviewFixture({ groups: [], total: 25, page: 2 });
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Gruppenvorschauseiten' })).getByRole('button', { name: 'Weiter' }));
  await screen.findByText('Auf dieser Seite sind derzeit keine Gruppenmitgliedschaften vorhanden. Daraus folgt kein vollständiger Zugriffsverlust.');
  expect(screen.getByText('0 angezeigte von 25 derzeitigen Gruppenmitgliedschaften. Bestätigt wird nur diese Seite mit höchstens 25 Gruppen.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Angezeigte Gruppen entfernen' })).toBeDisabled(); expect(mockPost).not.toHaveBeenCalled();
});
test('preview pagination and confirmation send only the currently displayed page with at most 25 rows', async () => {
  preview = groupsPreviewFixture({ groups: Array.from({ length: 25 }, (_, index) => groupFixture(index)), total: 26 });
  await openPanel(); setReason(); fireEvent.click(screen.getByRole('button', { name: 'Angezeigte Gruppen entfernen' }));
  const first = within(screen.getByRole('alertdialog', { name: 'Gruppenentfernung bestätigen' }));
  expect(first.getAllByText(/· Gruppenversion 9007199254740993/)).toHaveLength(25); expect(first.queryByText(/Austrittsgruppe 26/)).not.toBeInTheDocument();
  fireEvent.click(first.getByRole('button', { name: 'Abbrechen' })); preview = groupsPreviewFixture({ groups: [groupFixture(25)], total: 26, page: 2 });
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Gruppenvorschauseiten' })).getByRole('button', { name: 'Weiter' }));
  await screen.findByText('Austrittsgruppe 26 · Gruppenversion 9007199254740993');
  expect(mockGet).toHaveBeenCalledWith(groupsBase, { params: { workflowId, page: 2, limit: 25 }, signal: expect.any(AbortSignal) });
  fireEvent.click(screen.getByRole('button', { name: 'Angezeigte Gruppen entfernen' })); const second = within(screen.getByRole('alertdialog'));
  expect(second.queryByText('Austrittsgruppe 1 · Gruppenversion 9007199254740993')).not.toBeInTheDocument(); expect(second.getAllByText(/· Gruppenversion/)).toHaveLength(1);
  mockPost.mockResolvedValue({ status: 200, data: groupsOutcomeFixture({ results: [groupResultFixture(25)] }) });
  fireEvent.click(second.getByRole('button', { name: 'Bestätigen' })); await screen.findByRole('region', { name: 'Ergebnis der Gruppenentfernung' });
  expect(mockPost.mock.calls[0][1].memberships).toEqual([{ groupId: groupFixture(25).groupId, membershipId: groupFixture(25).membershipId, groupRevision: '9007199254740993' }]);
});
test('history pages have independent accessible navigation and fixed exact query', async () => {
  history = groupsHistoryFixture({ receipts: Array.from({ length: 25 }, (_, index) => groupReceiptFixture(index)), total: 26 }); await openPanel();
  history = groupsHistoryFixture({ receipts: [groupReceiptFixture(25)], total: 26, page: 2 });
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Gruppenhistorienseiten' })).getByRole('button', { name: 'Weiter' }));
  await screen.findByText('Austrittsgruppe 26 · Gruppenversion 9007199254740993 → 9007199254740994');
  expect(mockGet).toHaveBeenLastCalledWith(groupsBase + '/history', { params: { workflowId, page: 2, limit: 25 }, signal: expect.any(AbortSignal) });
  expect(mockGet).toHaveBeenCalledTimes(3); expect(mockPost).not.toHaveBeenCalled();
});
test.each([
  { context: { ...context, actorUserId: otherId } }, { context: { ...context, tenantId: otherId } },
  { workflowId: otherId }, { userId: otherId }, { eligibilityRevision: '9' },
])('prop binding change removes stale confirmation and resets to collapsed without reads %#', async changes => {
  const { mounted } = await openDialog(); const reads = mockGet.mock.calls.length;
  mounted.rerender(<CompanyOffboardingGroupsPanel {...props} {...changes} />);
  expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Gruppenvorschau' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Gruppen beim Austritt entfernen' })).toHaveAttribute('aria-expanded', 'false'); expect(mockGet).toHaveBeenCalledTimes(reads); expect(mockPost).not.toHaveBeenCalled();
});
test('unmount aborts a late preview so its response cannot disclose data or authorize a write', async () => {
  const pending = deferred<{ status: number; data: unknown }>(); mockGet.mockReturnValue(pending.promise);
  const mounted = render(<CompanyOffboardingGroupsPanel {...props} />); fireEvent.click(screen.getByRole('button', { name: 'Gruppen beim Austritt entfernen' }));
  await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1)); const signal = mockGet.mock.calls[0][1].signal;
  mounted.unmount(); expect(signal.aborted).toBe(true);
  await act(async () => { pending.resolve({ status: 200, data: groupsPreviewFixture() }); });
  expect(mockGet).toHaveBeenCalledTimes(1); expect(mockPost).not.toHaveBeenCalled();
});
test('session change aborts writer, clears history and ignores late success without automatically fetching', async () => {
  const { dialog } = await openDialog(); const pending = deferred<{ status: number; data: unknown }>(); mockPost.mockReturnValue(pending.promise);
  fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
  const signal = mockPost.mock.calls[0][2].signal;
  act(() => window.dispatchEvent(new CustomEvent('od:session-error'))); expect(signal.aborted).toBe(true);
  await act(async () => { pending.resolve({ status: 200, data: groupsOutcomeFixture() }); });
  expect(screen.getByRole('alert')).toHaveTextContent('Sitzung ungültig'); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Ergebnis der Gruppenentfernung' })).not.toBeInTheDocument(); expect(mockGet).toHaveBeenCalledTimes(2); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('repeated confirm clicks cannot enqueue duplicate writers', async () => {
  const { dialog } = await openDialog(); const pending = deferred<{ status: number; data: unknown }>(); mockPost.mockReturnValue(pending.promise);
  const button = dialog.getByRole('button', { name: 'Bestätigen' }); fireEvent.click(button); fireEvent.click(button);
  expect(mockPost).toHaveBeenCalledTimes(1); expect(dialog.getByRole('button', { name: 'Wird ausgeführt …' })).toBeDisabled();
  await act(async () => { pending.resolve({ status: 200, data: groupsOutcomeFixture() }); }); expect(mockPost).toHaveBeenCalledTimes(1);
});

async function loadParent(record: ReturnType<typeof jobFixture>) {
  mockGet.mockImplementation(async (url: string) => {
    if (url === jobs + '/capabilities') return { status: 200, data: capabilitiesFixture() };
    if (url === jobs) return { status: 200, data: queueFixture(record) };
    if (url === jobs + '/' + workflowId) return { status: 200, data: record, headers: { etag: offboardingEtag(record.workflow) } };
    if (url === jobs + '/' + workflowId + '/history') return { status: 200, data: historyFixture(record) };
    if (url === groupsBase) return { status: 200, data: preview };
    if (url === groupsBase + '/history') return { status: 200, data: history };
    throw new Error('Unexpected endpoint ' + url);
  });
  render(<CompanyOffboardingPanel context={context} />); fireEvent.click(screen.getByRole('button', { name: 'Mitarbeiter-Offboarding' }));
  await screen.findByRole('heading', { name: 'Gespeicherte Vorgänge' });
  fireEvent.change(screen.getByLabelText('Bekannte Vorgangs-ID'), { target: { value: workflowId } }); fireEvent.click(screen.getByRole('button', { name: 'Arbeitsstand neu laden' }));
  await screen.findByRole('article', { name: 'Offboarding-Arbeitsstand' });
}
test('parent mounts only the explicitly collapsed linked child after completed_local, preserving historical scope', async () => {
  await loadParent(completedFixture()); const article = within(screen.getByRole('article', { name: 'Offboarding-Arbeitsstand' }));
  expect(article.getByRole('button', { name: 'Gruppen beim Austritt entfernen' })).toHaveAttribute('aria-expanded', 'false');
  expect(mockGet.mock.calls.some(([url]) => url.startsWith(groupsBase))).toBe(false);
  expect(screen.getByText(/Gruppenmitgliedschaften werden nur im separat verknüpften/)).toBeInTheDocument();
  preview = groupsPreviewFixture({ groups: [], total: 0 }); fireEvent.click(article.getByRole('button', { name: 'Gruppen beim Austritt entfernen' }));
  await screen.findByRole('region', { name: 'Gruppenvorschau' });
  expect(article.getByRole('heading', { name: 'Kontosperre und lokale Lizenzen geprüft' })).toBeInTheDocument(); expect(article.getByText(/Historischer Abschluss für Konto und erfasste lokale Lizenzen/)).toBeInTheDocument();
  expect(mockGet).toHaveBeenCalledWith(groupsBase, { params: { workflowId, page: 1, limit: 25 }, signal: expect.any(AbortSignal) }); expect(mockPost).not.toHaveBeenCalled();
});
test.each([pendingFixture(), completedFixture()])('parent hides child for absent or mismatched checkpoints %#', async record => {
  if (record.workflow.phase === 'completed_local' && record.workflow.checkpoint) record.currentTarget.eligibilityRevision = '9';
  await loadParent(record);
  expect(screen.queryByRole('button', { name: 'Gruppen beim Austritt entfernen' })).not.toBeInTheDocument(); expect(mockGet.mock.calls.some(([url]) => url.startsWith(groupsBase))).toBe(false);
});
test.each([
  jobFixture(),
  jobFixture({ phase: 'paused', failure: { code: 412, step: 'licenses' } }),
])('a valid negative account checkpoint permits group cleanup independently of unfinished licenses %#', async record => {
  await loadParent(record);
  const button = screen.getByRole('button', { name: 'Gruppen beim Austritt entfernen' });
  expect(button).toHaveAttribute('aria-expanded', 'false');
  expect(mockGet.mock.calls.some(([url]) => url.startsWith(groupsBase))).toBe(false);
  fireEvent.click(button);
  await screen.findByRole('region', { name: 'Gruppenvorschau' });
  expect(screen.getByText(/auch bei noch offener oder pausierter lokaler Lizenzrückgabe/)).toBeInTheDocument();
  expect(mockPost).not.toHaveBeenCalled();
});
test.each([{ enabled: true }, { deleted: true }, { eligibilityRevision: '9' }])('parent rejects the group mount for changed current target %j', async changes => {
  const record = completedFixture(); record.currentTarget = { ...record.currentTarget, ...changes }; await loadParent(record);
  expect(screen.queryByRole('button', { name: 'Gruppen beim Austritt entfernen' })).not.toBeInTheDocument(); expect(mockPost).not.toHaveBeenCalled();
});
