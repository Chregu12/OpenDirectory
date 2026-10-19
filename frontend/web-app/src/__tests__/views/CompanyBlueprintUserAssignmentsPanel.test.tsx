import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import CompanyBlueprintUserAssignmentsPanel from '@/components/views/CompanyBlueprintUserAssignmentsPanel';
import { api } from '@/lib/api';
import { companyBlueprintAssignmentEtag } from '@/lib/companyBlueprintAssignments';
import { CompanyBlueprintVersionDetail } from '@/lib/companyBlueprints';
import { assignmentId as id, assignmentContext, assignmentBlueprintAccess, assignmentPreview, assignmentBinding, assignmentConfiguration,
  assignmentEnvelope as envelope, assignmentOk as ok, assignmentNow, assignmentDeferred } from '../fixtures/companyAssignmentsV2';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const base = '/api/company-blueprint-assignments'; let hasBinding: boolean; let candidate: ReturnType<typeof assignmentPreview>; let sequence: number;
const version = (): CompanyBlueprintVersionDetail => ({ version: 1, sourceRevision: '1', publishedRevision: '2', actorUserId: id(90), operationId: id(92), createdAt: assignmentNow,
  draft: { name: 'Historischer Standard', description: '', platform: 'macos', configurations: [{ id: id(10), type: 'screen_lock', name: 'Sperre', payloadJson: '{"minutes":5,"requirePassword":true}' }], appPoolIds: [id(20)] },
  apps: [{ id: id(20), name: 'Büro-App', vendor: 'Firma', revision: '1' }] });
beforeEach(() => {
  jest.resetAllMocks(); hasBinding = false; candidate = assignmentPreview(); sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url.endsWith('/capabilities')) return ok(assignmentBlueprintAccess());
    if (url === '/api/identity/access') return ok({ subject: 'human', userId: id(90), permissions: ['users.read'], demoMode: false, directoryReadProtocol: 1 });
    if (url === '/api/users') return ok({ users: [{ id: id(5), username: 'anna', email: 'anna@example.test', displayName: 'Anna Mitarbeiter', enabled: true, revision: '99', createdAt: assignmentNow }], total: 1, page: 1, limit: 25 });
    if (url === base) return ok(envelope({ userId: id(5), assignments: hasBinding ? [assignmentBinding()] : [], total: hasBinding ? 1 : 0, page: 1, limit: 25 }));
    if (url.endsWith('/effective')) return ok(envelope({ userId: id(5), assignments: hasBinding ? [assignmentBinding()] : [], effectiveConfigurations: hasBinding ? [assignmentConfiguration()] : [], conflicts: [], hasConflicts: false, applications: [] }));
    if (url.endsWith('/removal-preview')) return ok(envelope({ assignment: assignmentBinding(), eligibilityRevision: '9007199254740993', pools: [{ poolId: id(20), poolRevision: '9007199254740993' }] }), { etag: companyBlueprintAssignmentEtag(assignmentBinding()) });
    throw new Error('Unexpected read ' + url);
  });
  (api.post as jest.Mock).mockImplementation(async (url: string, body: any, config: any) => {
    if (url.endsWith('/preview')) return ok(candidate);
    const removed = url.endsWith('/remove'); return ok(envelope({ operationId: config.headers['Idempotency-Key'], assignmentId: removed ? id(1) : body.id,
      action: removed ? 'removed' : 'assigned', outcome: 'applied', revision: removed ? '2' : '1', deliveryStatus: 'pending', pools: [{ poolId: id(20), eventId: id(60),
        beforeRevision: '9007199254740993', afterRevision: '9007199254740994', sourceAdded: !removed, sourceRemoved: removed, seatAllocated: false, seatReleased: false, effectiveAssignmentRetained: true }] }), {}, removed ? 200 : 201);
  });
});
async function mount() {
  const result = render(<CompanyBlueprintUserAssignmentsPanel context={assignmentContext} blueprintId={id(2)} version={version()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Mitarbeitenden zuweisen' }));
  const picker = await screen.findByRole('combobox', { name: 'Blueprint-Mitarbeiter auswählen' }); fireEvent.change(picker, { target: { value: id(5) } }); return result;
}
function reason() { fireEvent.change(screen.getByLabelText('Begründung der Blueprint-Zuweisung'), { target: { value: 'Geprüfte Mitarbeiterzuweisung' } }); }
function approve() { const dialog = screen.getByRole('alertdialog'); fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Ich bestätige diese lokale Zuweisung.' })); fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' })); }
test('collapsed immutable version does not borrow old blueprint or app authority or request profiles', () => {
  render(<CompanyBlueprintUserAssignmentsPanel context={assignmentContext} blueprintId={id(2)} version={version()} />);
  expect(api.get).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
});
test('real directory picker and explicit positive preview pin the immutable version, then allocate only after confirmation', async () => {
  await mount(); fireEvent.click(screen.getByRole('button', { name: 'Neue Zuweisung prüfen' })); await screen.findByRole('region', { name: 'Blueprint-Zuweisungsvorschau' });
  expect(api.post).toHaveBeenCalledTimes(1); expect(api.post).toHaveBeenCalledWith(base + '/preview', { userId: id(5), blueprintId: id(2), version: 1 }, expect.anything());
  reason(); fireEvent.click(screen.getByRole('button', { name: 'Blueprint-Zuweisung vorbereiten' })); const dialog = screen.getByRole('alertdialog');
  expect(within(dialog).getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); expect(api.post).toHaveBeenCalledTimes(1);
  approve(); await screen.findByRole('region', { name: 'Blueprint-Zuweisungsnachweis' }); expect(api.post).toHaveBeenCalledTimes(2);
  expect(screen.getByText(/Historischer Nachweis, nicht der aktuelle Stand/)).toBeInTheDocument(); expect(screen.getByText(/Lizenzplatz bleibt durch andere Quellen belegt/)).toBeInTheDocument();
});
test('normal removal loads bindings without causing a positive duplicate preview or using manual license revoke', async () => {
  hasBinding = true; await mount(); fireEvent.click(screen.getByRole('button', { name: 'Mitarbeiterzuweisungen laden' }));
  await screen.findByRole('region', { name: 'Gespeicherte Blueprint-Zuweisungen' }); expect(api.post).not.toHaveBeenCalled(); reason();
  fireEvent.click(screen.getByRole('button', { name: 'Zuweisung entfernen' })); await screen.findByRole('alertdialog', { name: 'Blueprint-Rücknahme bestätigen' });
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === base + '/' + id(1) + '/removal-preview')).toBe(true); expect(api.post).not.toHaveBeenCalled();
  approve(); await screen.findByText('Lokale Rücknahme bestätigt'); expect(api.post).toHaveBeenCalledTimes(1);
  expect((api.post as jest.Mock).mock.calls[0][0]).toBe(base + '/' + id(1) + '/remove');
});
test('intentionally requesting a duplicate assignment surfaces the real backend 409 without creating a source', async () => {
  await mount(); (api.post as jest.Mock).mockRejectedValueOnce({ response: { status: 409 } }); fireEvent.click(screen.getByRole('button', { name: 'Neue Zuweisung prüfen' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('region', { name: 'Blueprint-Zuweisungsvorschau' })).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('candidate license shortage prevents confirmation rather than adding a partial app assignment', async () => {
  candidate.pools[0].additionalSeats = 1; await mount(); fireEvent.click(screen.getByRole('button', { name: 'Neue Zuweisung prüfen' })); await screen.findByRole('region', { name: 'Blueprint-Zuweisungsvorschau' });
  expect(screen.getByRole('button', { name: 'Blueprint-Zuweisung vorbereiten' })).toBeDisabled(); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('unconfirmed response exposes only an explicit retry of the original frozen operation', async () => {
  await mount(); fireEvent.click(screen.getByRole('button', { name: 'Neue Zuweisung prüfen' })); await screen.findByRole('region', { name: 'Blueprint-Zuweisungsvorschau' }); reason();
  fireEvent.click(screen.getByRole('button', { name: 'Blueprint-Zuweisung vorbereiten' })); (api.post as jest.Mock).mockRejectedValueOnce(new Error('network')); approve();
  await screen.findByRole('complementary', { name: 'Unbestätigte Blueprint-Zuweisung' }); expect(api.post).toHaveBeenCalledTimes(2);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Ursprüngliche Zuweisung wiederaufnehmen' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Ursprüngliche Zuweisung wiederaufnehmen' })); approve(); await screen.findByText('Lokale Zuweisung bestätigt');
  const calls = (api.post as jest.Mock).mock.calls; expect(calls[2][1]).toBe(calls[1][1]); expect(calls[2][2].headers).toEqual(calls[1][2].headers);
});
test('late candidate response cannot restore a preview after collapse or session change', async () => {
  await mount(); const pending = assignmentDeferred<ReturnType<typeof ok>>(); (api.post as jest.Mock).mockReturnValueOnce(pending.promise);
  fireEvent.click(screen.getByRole('button', { name: 'Neue Zuweisung prüfen' })); await act(async () => { window.dispatchEvent(new Event('od:session-error')); pending.resolve(ok(candidate)); });
  await screen.findByRole('alert'); expect(screen.queryByRole('region', { name: 'Blueprint-Zuweisungsvorschau' })).not.toBeInTheDocument(); expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
});
test.each([401, 403, 428])('authority status %s exposes no picker, target data or mutation', async status => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status, data: { secret: 'not-displayed' } } }); render(<CompanyBlueprintUserAssignmentsPanel context={assignmentContext} blueprintId={id(2)} version={version()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Mitarbeitenden zuweisen' })); await screen.findByRole('alert'); expect(screen.queryByRole('combobox')).not.toBeInTheDocument(); expect(screen.queryByText('not-displayed')).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('cancel never writes an assignment after a read-only preview', async () => {
  await mount(); fireEvent.click(screen.getByRole('button', { name: 'Neue Zuweisung prüfen' })); await screen.findByRole('region', { name: 'Blueprint-Zuweisungsvorschau' }); reason();
  fireEvent.click(screen.getByRole('button', { name: 'Blueprint-Zuweisung vorbereiten' })); fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Abbrechen' })); expect(api.post).toHaveBeenCalledTimes(1);
});
