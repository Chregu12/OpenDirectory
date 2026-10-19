import React from 'react';
import { act, fireEvent, render, screen, within, waitFor } from '@testing-library/react';
import CompanyApplicationAssignmentsPanel from '@/components/views/CompanyApplicationAssignmentsPanel';
import CompanyApplicationsView from '@/components/views/CompanyApplicationsView';
import { CompanyPool } from '@/lib/companyApplications';
import { api } from '@/lib/api';
import { assignmentId as id, assignmentContext, assignmentAppAccess, assignmentManualPreview, assignmentRow, assignmentV2Envelope as envelope,
  assignmentOk as ok, assignmentNow, assignmentBlueprintSource, assignmentDeferred } from '../fixtures/companyAssignmentsV2';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const base = '/api/licenses/company/v2'; let preview: ReturnType<typeof assignmentManualPreview>; let sequence: number;
const pool = (): CompanyPool => ({ id: id(20), tenantId: id(91), revision: '9007199254740993', name: 'Büro-App', vendor: 'Firma', description: '', totalSeats: 1,
  usedSeats: 1, availableSeats: 0, licenseType: 'per_user', allocationMode: 'local-only', createdAt: assignmentNow, updatedAt: assignmentNow });
beforeEach(() => {
  jest.resetAllMocks(); window.sessionStorage.clear(); window.history.replaceState({}, '', '/'); preview = assignmentManualPreview(); sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url === base + '/capabilities') return ok(assignmentAppAccess());
    if (url === '/api/licenses/company/capabilities') return ok({ ...assignmentAppAccess(), schemaVersion: 1, companyLicenseProtocol: 1 });
    if (url === '/api/licenses/company/pools') return ok({ schemaVersion: 1, ...assignmentContext, pools: [pool()], total: 1, page: 1, limit: 25 });
    if (url === '/api/licenses/company/pools/' + id(20)) return ok(pool(), { etag: '"company-pool-' + id(20) + '-9007199254740993"' });
    if (url.endsWith('/assignments')) return ok(envelope({ poolId: id(20), poolRevision: '9007199254740993', assignments: [assignmentRow()], total: 1, page: 1, limit: 25 }));
    if (url === '/api/identity/access') return ok({ subject: 'human', userId: id(90), permissions: [], demoMode: false, directoryReadProtocol: 1 });
    throw new Error('Unexpected read ' + url);
  });
  (api.post as jest.Mock).mockImplementation(async (url: string, body: any, config: any) => {
    if (url.endsWith('/assignment-preview')) return ok(preview);
    const removed = url.endsWith('/revoke'); return ok(envelope({ operationId: config.headers['Idempotency-Key'], outcome: 'applied', action: removed ? 'manual_revoke' : 'manual_assign', poolId: id(20), userId: id(5),
      assignmentId: id(40), sourceAdded: !removed, sourceRemoved: removed, seatAllocated: false, seatReleased: false, effectiveAssignmentRetained: true, eventId: id(60), poolRevision: '9007199254740994', deliveryStatus: 'pending' }), {}, removed ? 200 : 201);
  });
});
async function mount() { const result = render(<CompanyApplicationAssignmentsPanel context={assignmentContext} pool={pool()} onReload={jest.fn()} />); await screen.findByRole('region', { name: 'Vollständige Lizenzquellen' }); return result; }
async function inspect() { await mount(); fireEvent.click(screen.getByRole('button', { name: 'Lizenzquellen dieses Mitarbeiters prüfen' })); await screen.findByRole('region', { name: 'Manuelle Lizenzquellen-Vorschau' }); fireEvent.change(screen.getByLabelText('Begründung der manuellen Lizenzquelle'), { target: { value: 'Manuelle Quelle zurücknehmen' } }); }
function approve() { const dialog = screen.getByRole('alertdialog'); fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Ich bestätige diese manuelle Lizenzänderung.' })); fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' })); }
test('shows all origins and one seat rather than a misleading single-grant license row', async () => {
  await mount(); const list = within(screen.getByRole('region', { name: 'Vollständige Lizenzquellen' })); expect(list.getByText('Manuell')).toBeInTheDocument(); expect(list.getByText('Blueprint-Version')).toBeInTheDocument();
  expect(list.getByText(/1 Lizenzplatz/)).toBeInTheDocument(); expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false); expect(api.post).not.toHaveBeenCalled();
});
test('manual removal explicitly confirms only the manual origin and reports retained blueprint seat truthfully', async () => {
  await inspect(); fireEvent.click(screen.getByRole('button', { name: 'Manuelle Quelle entfernen' })); expect(api.post).toHaveBeenCalledTimes(1);
  expect(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); approve();
  const receipt = await screen.findByRole('region', { name: 'Quellenbasierter Lizenznachweis' }); expect(within(receipt).getByText('Manuelle Quelle entfernt')).toBeInTheDocument();
  expect(within(receipt).getByText('Der Lizenzplatz bleibt durch andere Quellen belegt.')).toBeInTheDocument(); expect(within(receipt).queryByText(/freigegeben/)).not.toBeInTheDocument();
  expect((api.post as jest.Mock).mock.calls[1][0]).toBe(base + '/pools/' + id(20) + '/assignments/' + id(40) + '/revoke');
});
test('at full capacity a blueprint-first seat still allows adding a manual origin without a second allocation', async () => {
  preview.assignment.sources = [assignmentBlueprintSource()]; await inspect(); fireEvent.click(screen.getByRole('button', { name: 'Manuelle Quelle hinzufügen' })); approve();
  await screen.findByRole('region', { name: 'Quellenbasierter Lizenznachweis' }); expect((api.post as jest.Mock).mock.calls[1][1].assignmentId).toBe(id(40));
});
test('a read-only preview or cancel does not revoke any source', async () => {
  await inspect(); fireEvent.click(screen.getByRole('button', { name: 'Manuelle Quelle entfernen' })); fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Abbrechen' }));
  expect(api.post).toHaveBeenCalledTimes(1); expect(screen.getByRole('region', { name: 'Manuelle Lizenzquellen-Vorschau' })).toBeInTheDocument();
});
test('unknown manual result keeps an explicit original-intent retry rather than generating a new grant', async () => {
  await inspect(); fireEvent.click(screen.getByRole('button', { name: 'Manuelle Quelle entfernen' })); (api.post as jest.Mock).mockRejectedValueOnce(new Error('network')); approve();
  await screen.findByRole('complementary', { name: 'Unbestätigte manuelle Lizenzänderung' }); expect(api.post).toHaveBeenCalledTimes(2);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Ursprüngliche Lizenzänderung wiederaufnehmen' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Ursprüngliche Lizenzänderung wiederaufnehmen' })); approve(); await screen.findByRole('region', { name: 'Quellenbasierter Lizenznachweis' });
  const calls = (api.post as jest.Mock).mock.calls; expect(calls[2][1]).toBe(calls[1][1]); expect(calls[2][2].headers).toEqual(calls[1][2].headers);
});
test.each([409, 412, 428])('write status %s never paints a confirmed release', async status => {
  await inspect(); fireEvent.click(screen.getByRole('button', { name: 'Manuelle Quelle entfernen' })); (api.post as jest.Mock).mockRejectedValueOnce({ response: { status } }); approve();
  await screen.findByRole('alert'); expect(screen.queryByRole('region', { name: 'Quellenbasierter Lizenznachweis' })).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(2);
});
test('session invalidation ignores late preview and clears source data and captured actions', async () => {
  await mount(); const pending = assignmentDeferred<ReturnType<typeof ok>>(); (api.post as jest.Mock).mockReturnValueOnce(pending.promise); fireEvent.click(screen.getByRole('button', { name: 'Lizenzquellen dieses Mitarbeiters prüfen' }));
  await act(async () => { window.dispatchEvent(new Event('od:session-error')); pending.resolve(ok(preview)); }); await screen.findByRole('alert');
  expect(screen.queryByRole('region', { name: 'Vollständige Lizenzquellen' })).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Manuelle Lizenzquellen-Vorschau' })).not.toBeInTheDocument();
});
test('the actual applications view defaults to V2 and never silently falls back to V1 source-dependent reads', async () => {
  render(<CompanyApplicationsView />); fireEvent.click(await screen.findByRole('button', { name: 'Büro-App' })); await screen.findByRole('region', { name: 'Vollständige Lizenzquellen' });
  expect(screen.getByRole('button', { name: 'Aktuelle quellenbasierte Verwaltung' })).toHaveAttribute('aria-pressed', 'true');
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/licenses/company/pools/' + id(20) + '/assignments')).toBe(false);
  expect(screen.getByRole('button', { name: 'Offboarding mit Blueprint-Rückgabe' })).toBeInTheDocument();
});
test('explicit V1 preference survives remount only for the same actor and tenant, without automatic mutation', async () => {
  const rendered = render(<CompanyApplicationsView />); fireEvent.click(await screen.findByRole('button', { name: 'Bisherige Direktverwaltung' }));
  expect(window.sessionStorage.getItem(`od:company-license-view:${id(91)}:${id(90)}`)).toBe('v1'); rendered.unmount();
  render(<CompanyApplicationsView />); expect(await screen.findByRole('heading', { name: 'Bisherige Offboarding-Vorgänge' })).toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('the explicit blueprint-offboarding link selects current sources even after a stored V1 preference', async () => {
  window.sessionStorage.setItem(`od:company-license-view:${id(91)}:${id(90)}`, 'v1'); window.history.replaceState({}, '', '/applications?licenseView=source-aware');
  render(<CompanyApplicationsView />); expect(await screen.findByRole('button', { name: 'Offboarding mit Blueprint-Rückgabe' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Aktuelle quellenbasierte Verwaltung' })).toHaveAttribute('aria-pressed', 'true'); expect(api.post).not.toHaveBeenCalled();
});
test('explicit protocol change disposes the current source preview without borrowing it for V1 or replaying it', async () => {
  render(<CompanyApplicationsView />); fireEvent.click(await screen.findByRole('button', { name: 'Büro-App' })); await screen.findByRole('region', { name: 'Vollständige Lizenzquellen' });
  fireEvent.click(screen.getByRole('button', { name: 'Lizenzquellen dieses Mitarbeiters prüfen' })); await screen.findByRole('region', { name: 'Manuelle Lizenzquellen-Vorschau' });
  fireEvent.click(screen.getByRole('button', { name: 'Bisherige Direktverwaltung' })); await screen.findByRole('heading', { name: 'Bisherige Offboarding-Vorgänge' });
  expect(screen.queryByRole('region', { name: 'Manuelle Lizenzquellen-Vorschau' })).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Vollständige Lizenzquellen' })).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
});
