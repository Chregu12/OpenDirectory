import React from 'react';
import { act, fireEvent, render, screen, within, waitFor } from '@testing-library/react';
import CompanyOffboardingV2Panel from '@/components/views/CompanyOffboardingV2Panel';
import { api } from '@/lib/api';
import { companyOffboardingV2Etag } from '@/lib/companyOffboardingV2';
import { assignmentId as id, assignmentContext, assignmentOffboardAccess, assignmentOffboardPreview, assignmentOffboardJob,
  assignmentV2Envelope as envelope, assignmentOk as ok } from '../fixtures/companyAssignmentsV2';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const base = '/api/licenses/company/v2'; const jobs = base + '/offboarding-workflows'; let job: ReturnType<typeof assignmentOffboardJob>; let sequence: number;
const recoveryKey = `od:company-offboarding-v2:${id(91)}:${id(90)}`;
beforeEach(() => {
  jest.resetAllMocks(); window.localStorage.clear(); job = assignmentOffboardJob(); sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url.endsWith('/capabilities')) return ok(assignmentOffboardAccess());
    if (url === jobs) return ok(envelope({ workflows: [], total: 0, page: 1, limit: 25 }));
    if (url.endsWith('/offboarding-preview')) return ok(assignmentOffboardPreview());
    if (url.endsWith('/history')) return ok(envelope({ workflowId: job.workflow.id, events: [], total: 0, page: 1, limit: 25 }));
    if (url === jobs + '/' + job.workflow.id) return ok(job, { etag: companyOffboardingV2Etag(job.workflow) });
    throw new Error('Unexpected read ' + url);
  });
  (api.post as jest.Mock).mockImplementation(async (url: string, body: any) => {
    if (url === jobs) { job.workflow.id = body.workflowId; job.workflow.checkpoint.workflowId = body.workflowId; job.workflow.reason = body.reason; return ok(job, {}, 201); }
    const completed = JSON.parse(JSON.stringify(job)); completed.workflow.phase = 'completed_local'; completed.workflow.revision = '4'; completed.workflow.completedBindings = 1; completed.workflow.nextBindings = [];
    return ok(completed);
  });
});
async function mount() { const result = render(<CompanyOffboardingV2Panel context={assignmentContext} />); fireEvent.click(screen.getByRole('button', { name: 'Offboarding mit Blueprint-Rückgabe' })); await screen.findByRole('region', { name: 'Blueprint-Offboarding vorbereiten' }); return result; }
async function load() { await mount(); fireEvent.change(screen.getByLabelText('Blueprint-Offboarding Vorgangs-ID'), { target: { value: id(80) } }); fireEvent.click(screen.getByRole('button', { name: 'Blueprint-Offboarding-Arbeitsstand laden' })); await screen.findByRole('article', { name: 'Blueprint-Offboarding-Arbeitsstand' }); }
function approve() { const dialog = screen.getByRole('alertdialog'); fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Ich bestätige diesen Blueprint-Offboarding-Schritt.' })); fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' })); }
test('reads a true zero-license, one-binding preview and makes that zero-app cleanup accessible', async () => {
  await mount(); fireEvent.change(screen.getByLabelText('Blueprint-Offboarding Mitarbeiter-ID'), { target: { value: id(5) } }); fireEvent.click(screen.getByRole('button', { name: 'Blueprint-Offboarding-Vorschau laden' }));
  const preview = await screen.findByText(/0 lokale Lizenzplätze · 1 Blueprint-Bindungen/);
  expect(preview).toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Blueprint-Offboarding starten' })).toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('new workflow is sent only after explicit confirmation with one persisted recovery ID and original server revisions', async () => {
  await mount(); fireEvent.change(screen.getByLabelText('Blueprint-Offboarding Mitarbeiter-ID'), { target: { value: id(5) } }); fireEvent.click(screen.getByRole('button', { name: 'Blueprint-Offboarding-Vorschau laden' }));
  await screen.findByRole('button', { name: 'Blueprint-Offboarding starten' }); fireEvent.change(screen.getByLabelText('Begründung des Blueprint-Offboardings'), { target: { value: 'Bewusster Mitarbeiteraustritt' } });
  fireEvent.click(screen.getByRole('button', { name: 'Blueprint-Offboarding starten' })); expect(api.post).not.toHaveBeenCalled(); approve(); await screen.findByRole('article', { name: 'Blueprint-Offboarding-Arbeitsstand' });
  const call = (api.post as jest.Mock).mock.calls[0]; expect(call[1]).toMatchObject({ userRevision: '99', eligibilityRevision: '9007199254740993', workflowId: call[2].headers['Idempotency-Key'] });
  expect(screen.getByText(/Historischer Änderungsnachweis/)).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Erfasste Rückgabe gemeinsam fortsetzen' })).not.toBeInTheDocument();
});
test('zero-app binding participates in the actual all-source continuation and prevents false license-only completion', async () => {
  await load(); expect(screen.getByText(/0 Lizenzpools und 1 Bindungen/)).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Erfasste Rückgabe gemeinsam fortsetzen' }));
  expect(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); approve(); await screen.findByText('Lokaler Abschluss bestätigt');
  expect((api.post as jest.Mock).mock.calls[0][1]).toMatchObject({ assignments: [], bindings: [{ id: id(1), revision: '1' }], userRevision: '99' });
  expect(screen.getByText(/erfasste Lizenzquellen und Blueprint-Bindungen beendet/)).toBeInTheDocument();
});
test.each(['reactivated', 'changed generation'])('a %s target blocks old captured negative work', async state => {
  if (state === 'reactivated') job.currentTarget.enabled = true; else job.currentTarget.eligibilityRevision = '9007199254740995';
  await load(); expect(screen.getByRole('alert')).toHaveTextContent(/Kontogeneration/); expect(screen.queryByRole('button', { name: 'Erfasste Rückgabe gemeinsam fortsetzen' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('deleted-target workflow explains the missing canonical lifecycle history and cannot replace the original checkpoint', async () => {
  job.currentTarget.deleted = true; await load(); expect(screen.getByRole('alert')).toHaveTextContent(/kanonische Lifecycle-Historie/);
  expect(screen.queryByRole('button', { name: 'Erfasste Rückgabe gemeinsam fortsetzen' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
test('unknown result retains a known workflow ID across session changes but never automatically replays a write', async () => {
  await load(); fireEvent.click(screen.getByRole('button', { name: 'Erfasste Rückgabe gemeinsam fortsetzen' })); (api.post as jest.Mock).mockRejectedValueOnce(new Error('network')); approve();
  await screen.findByRole('complementary', { name: 'Unbestätigter Blueprint-Offboarding-Versuch' }); expect(window.localStorage.getItem(recoveryKey)).toBe(id(80)); expect(api.post).toHaveBeenCalledTimes(1);
  await act(async () => { window.dispatchEvent(new Event('od:session-error')); }); expect(screen.queryByRole('button', { name: 'Ursprünglichen Blueprint-Offboarding-Schritt prüfen' })).not.toBeInTheDocument();
  expect(window.localStorage.getItem(recoveryKey)).toBe(id(80)); expect(api.post).toHaveBeenCalledTimes(1);
});
test('known recovery restores by actual GET, including zero-app bindings, without any automatic POST', async () => {
  window.localStorage.setItem(recoveryKey, id(80)); render(<CompanyOffboardingV2Panel context={assignmentContext} />); fireEvent.click(screen.getByRole('button', { name: 'Offboarding mit Blueprint-Rückgabe' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Blueprint-Offboarding wiederherstellen' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Blueprint-Offboarding wiederherstellen' })); await screen.findByRole('article', { name: 'Blueprint-Offboarding-Arbeitsstand' });
  expect(api.post).not.toHaveBeenCalled(); expect(window.localStorage.getItem(recoveryKey)).toBeNull();
});
test.each([403, 428])('source status %s never presents a successful or actionable negative workflow', async status => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status } }); render(<CompanyOffboardingV2Panel context={assignmentContext} />); fireEvent.click(screen.getByRole('button', { name: 'Offboarding mit Blueprint-Rückgabe' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('region', { name: 'Blueprint-Offboarding vorbereiten' })).not.toBeInTheDocument(); expect(api.post).not.toHaveBeenCalled();
});
