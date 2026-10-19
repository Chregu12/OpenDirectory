import React from 'react';
import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import toast from 'react-hot-toast';
import PIMView from '../../components/views/PIMView';
import { api } from '../../lib/api';
import { ensureSession, startLogin } from '../../lib/auth';
import { ActivationRequest, Eligibility } from '../../lib/privilegedActivation';
jest.mock('../../lib/auth', () => ({ ensureSession: jest.fn(async () => {}), startLogin: jest.fn() }));
const owner = '11111111-1111-4111-8111-111111111111'; const other = '22222222-2222-4222-8222-222222222222';
const eligibleId = '33333333-3333-4333-8333-333333333333'; const requestId = '44444444-4444-4444-8444-444444444444'; const assignmentId = '55555555-5555-4555-8555-555555555555';
let permissions: string[]; let eligible: Eligibility[]; let own: ActivationRequest[]; let queue: ActivationRequest[];
function eligibility(): Eligibility { return { id: eligibleId, userId: owner, role: 'license-manager', reason: 'Reviewed eligible license operator', maxDurationSeconds: 3600, createdAt: '2026-10-18T10:00:00.000Z', expiresAt: '2026-10-25T10:00:00.000Z', revokedAt: null, status: 'eligible' }; }
function record(status: ActivationRequest['status'] = 'pending', userId = owner): ActivationRequest {
  const decided = ['approved', 'active'].includes(status);
  return { id: requestId, eligibilityId: eligibleId, userId, role: 'license-manager', reason: 'Temporary license administration', durationSeconds: 3600,
    createdAt: '2026-10-18T10:00:00.000Z', deadlineAt: '2026-10-19T10:00:00.000Z', status, decidedAt: decided ? '2026-10-18T10:01:00.000Z' : null,
    decidedBy: decided ? other : null, approvalExpiresAt: decided ? '2026-10-18T10:06:00.000Z' : null, assignmentId: status === 'active' ? assignmentId : null, expiresAt: status === 'active' ? '2026-10-18T11:01:00.000Z' : null };
}
beforeEach(() => {
  jest.clearAllMocks(); permissions = []; eligible = []; own = []; queue = [];
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: () => requestId });
  (api.get as jest.Mock).mockImplementation(async (url: string, options: any = {}) => {
    if (url === '/api/identity/access') return { data: { subject: 'verified', userId: owner, permissions, demoMode: false } };
    if (url.endsWith('/catalog')) return { data: { roles: [{ role: 'license-manager', protected: false, assignable: true, reviewable: true, activationRequired:false,maxDurationSeconds:28800 }, { role: 'admin', protected: true, assignable: false, reviewable: false,activationRequired:false,maxDurationSeconds:28800 }], minDurationSeconds: 60, maxDurationSeconds: 28800, maxEligibilitySeconds: 2592000, approvalWindowSeconds: 300 } };
    if (url.endsWith('/self')) return { data: { userId: owner, eligibilities: eligible, requests: own, truncated: false } };
    if (url.endsWith('/eligibilities')) return { data: { userId: options.params.userId, eligibilities: [], truncated: false } };
    if (url.endsWith('/requests')) return { data: { requests: queue, truncated: false } };
    throw new Error('Unexpected API');
  });
  (api.post as jest.Mock).mockImplementation(async (url: string) => {
    if (url.endsWith('/requests')) { own = [record()]; return { status: 200, data: own[0] }; }
    const status: ActivationRequest['status'] = url.endsWith('/activate') ? 'active' : url.endsWith('/approve') ? 'approved' : 'cancelled';
    return { status: 200, data: record(status) };
  });
});
async function request() {
  eligible = [eligibility()]; render(<PIMView />); const user = userEvent.setup();
  await user.selectOptions(await screen.findByLabelText('Eigene Berechtigung'), eligibleId); await user.type(screen.getByLabelText('Aktivierungsbegründung'), record().reason);
  await user.click(screen.getByRole('button', { name: 'Aktivierung beantragen' })); return user;
}
test('ordinary bound users see only their own eligibility and requests, without directory or administrative reads', async () => {
  render(<PIMView />); await screen.findByText('Keine PIM-Berechtigung vorhanden.');
  expect((api.get as jest.Mock).mock.calls.every(([url]) => ['/api/identity/access', '/api/identity/pim/self', '/api/identity/pim/catalog'].includes(url))).toBe(true);
  expect(screen.queryByText('Berechtigungen verwalten')).not.toBeInTheDocument(); expect(screen.queryByText('Genehmigungsübersicht')).not.toBeInTheDocument();
});
test('source outage is not an empty-success response or a sample active role', async () => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status: 503 } }); render(<PIMView />); await screen.findByRole('alert'); expect(screen.queryByText('Aktiv')).not.toBeInTheDocument();
});
test('request confirmation sends a stable UUID and no beneficiary, reviewer or activation flag', async () => {
  const user = await request(); expect(api.post).not.toHaveBeenCalled();
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(toast.success).toHaveBeenCalled());
  expect(api.post).toHaveBeenCalledWith('/api/identity/pim/requests', { id: requestId, eligibilityId: eligibleId, durationSeconds: 3600, reason: record().reason }); expect(ensureSession).not.toHaveBeenCalled();
});
test('cancelling a confirmation does not create a request', async () => {
  const user = await request(); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Abbrechen' })); expect(api.post).not.toHaveBeenCalled();
});
test('an uncertain request outcome is never automatically retried or displayed as an active role', async () => {
  (api.post as jest.Mock).mockRejectedValue({ response: { status: 503 } }); const user = await request();
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await within(screen.getByRole('alertdialog')).findByRole('alert');
  expect(toast.success).not.toHaveBeenCalled(); expect(api.post).toHaveBeenCalledTimes(1); expect(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })).toBeDisabled();
});
test('an approval is not active and a valid activation receipt rechecks the actual browser session', async () => {
  own = [record('approved')]; render(<PIMView />); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name: 'Jetzt aktivieren' }));
  expect(ensureSession).not.toHaveBeenCalled(); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(ensureSession).toHaveBeenCalledWith(true));
  expect(api.post).toHaveBeenCalledWith(`/api/identity/pim/requests/${requestId}/activate`, {});
});
test('an active status without an actual canonical assignment is not a confirmed activation', async () => {
  own = [record('approved')]; (api.post as jest.Mock).mockResolvedValue({ status: 200, data: { ...record('active'), assignmentId: null } }); render(<PIMView />); const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Jetzt aktivieren' })); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await screen.findByRole('alert');
  expect(ensureSession).not.toHaveBeenCalled(); expect(toast.success).not.toHaveBeenCalled();
});
test('stale authentication requires an interactive login rather than pretending refresh is fresh authentication', async () => {
  own = [record('approved')]; (api.post as jest.Mock).mockRejectedValue({ response: { status: 428 } }); render(<PIMView />); const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Jetzt aktivieren' })); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await user.click(await screen.findByRole('button', { name: 'Für Aktivierung neu anmelden' })); expect(startLogin).toHaveBeenCalled(); expect(ensureSession).not.toHaveBeenCalled();
});
test('canonical beneficiaries cannot approve themselves even when they hold reviewer capabilities', async () => {
  permissions = ['pim.requests.read', 'pim.requests.review']; queue = [record()]; render(<PIMView />); await screen.findByText('Keine eigene Genehmigung oder Ablehnung.');
  expect(screen.queryByRole('button', { name: 'Genehmigen' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Ablehnen' })).not.toBeInTheDocument();
});
test('review-only users cannot create eligibility or read profiles', async () => {
  permissions = ['pim.requests.read', 'pim.requests.review']; queue = [record('pending', other)]; (api.post as jest.Mock).mockResolvedValue({ status: 200, data: { ...record('approved', other), decidedBy: owner } });
  render(<PIMView />); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name: 'Genehmigen' }));
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(toast.success).toHaveBeenCalled());
  expect(screen.queryByText('Berechtigungen verwalten')).not.toBeInTheDocument(); expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false);
});
test('eligibility managers cannot create their own eligibility or approve pending requests', async () => {
  permissions = ['pim.eligibilities.read', 'pim.eligibilities.manage']; render(<PIMView />); const user = userEvent.setup();
  await user.type(await screen.findByLabelText('Verzeichnis-ID'), owner); await user.click(screen.getByRole('button', { name: 'Berechtigungen laden' })); await screen.findByText('Keine Selbstverwaltung eigener PIM-Berechtigungen.');
  expect(screen.queryByLabelText('Berechtigte Rolle')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Genehmigen' })).not.toBeInTheDocument();
});
test('malformed foreign self-service rows disable all actions rather than inventing ownership', async () => {
  own = [record('pending', other)]; render(<PIMView />); await screen.findByRole('alert'); expect(screen.queryByRole('button', { name: 'Antrag abbrechen' })).not.toBeInTheDocument();
});
test('a confirmed independent denial never presents approval or active access', async () => {
  permissions = ['pim.requests.read', 'pim.requests.review']; queue = [record('pending', other)];
  (api.post as jest.Mock).mockImplementation(async () => { queue = [{ ...record('denied', other), decidedBy: owner, decidedAt: '2026-10-18T10:01:00.000Z' }]; return { status: 200, data: queue[0] }; });
  render(<PIMView />); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name: 'Ablehnen' }));
  expect(api.post).not.toHaveBeenCalled(); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await screen.findByRole('heading', { name: 'license-manager · Abgelehnt' }); expect(api.post).toHaveBeenCalledWith(`/api/identity/pim/requests/${requestId}/deny`, {});
  expect(ensureSession).not.toHaveBeenCalled(); expect(screen.queryByRole('button', { name: 'Jetzt aktivieren' })).not.toBeInTheDocument();
});
