import React from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import PIMGroupsPanel from '@/components/views/PIMGroupsPanel';
import { privilegedGroups } from '@/lib/privilegedGroups';
import { privilegedActivation } from '@/lib/privilegedActivation';
import { startLogin } from '@/lib/auth';
jest.mock('@/lib/privilegedGroups', () => ({ privilegedGroups: { load: jest.fn(), assign: jest.fn(), create: jest.fn(), disable: jest.fn(), initialize: jest.fn(), members: jest.fn(), history: jest.fn() } }));
jest.mock('@/lib/privilegedActivation', () => ({ privilegedActivation: { request: jest.fn(), change: jest.fn(), revokeEligibility: jest.fn() }, pimError: () => 'PIM-Ergebnis nicht bestätigt.' }));
jest.mock('@/lib/directoryUsers', () => ({ directoryUsers: { list: jest.fn(async () => ({ users: [{ id: other, username: 'engineer', displayName: 'Engineering User' }] })) }, userName: (user: any) => user.displayName || user.username }));
jest.mock('@/lib/auth', () => ({ startLogin: jest.fn() }));
const owner = '11111111-1111-4111-8111-111111111111'; const other = '22222222-2222-4222-8222-222222222222';
const groupId = '33333333-3333-4333-8333-333333333333'; const eligibilityId = '44444444-4444-4444-8444-444444444444'; const requestId = '55555555-5555-4555-8555-555555555555';
const group = { id: groupId, name: 'Lizenzen', description: 'Nur Lizenzbestand und Zuweisungen verwalten', role: 'license-administrator', maxDurationSeconds: 36000, configuredMaxDurationSeconds: 36000,
  enabled: true, protected: false, createdAt: '2026-11-08T12:00:00Z', canManage: true };
function fixture(changes = {}): any {
  const now = new Date().toISOString();
  return { schemaVersion: 1, userId: owner, groups: [group, { ...group, id: other, name: 'Global Security', role: 'admin', protected: true }], bindings: [{ groupId, eligibilityId, userId: owner }],
    standingRoles: [], canCreate: true, canReview: false, truncated: false,
    self: { userId: owner, eligibilities: [{ id: eligibilityId, userId: owner, role: group.role, reason: 'Actual independent group eligibility', maxDurationSeconds: 36000, createdAt: now, expiresAt: new Date(Date.now() + 86400000).toISOString(), revokedAt: null, status: 'eligible' }], requests: [], truncated: false },
    roles: [{ role: group.role, protected: false, assignable: true, reviewable: true, activationRequired: false, maxDurationSeconds: 36000 }], queue: [], ...changes };
}
function approved(status = 'approved'): any { return { id: requestId, eligibilityId, userId: owner, role: group.role, reason: 'Actual reviewed task activation', durationSeconds: 3600, status, expiresAt: status === 'active' ? new Date(Date.now() + 3600000).toISOString() : null }; }
beforeEach(() => {
  jest.clearAllMocks(); (privilegedGroups.load as jest.Mock).mockResolvedValue(fixture());
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: () => requestId });
});
test('overview displays separated tasks and identifies standing global administration honestly', async () => {
  (privilegedGroups.load as jest.Mock).mockResolvedValue(fixture({ standingRoles: ['admin'] })); render(<PIMGroupsPanel />);
  expect(await screen.findByRole('article', { name: 'PIM-Gruppe Lizenzen' })).toHaveTextContent('Nur Lizenzbestand');
  expect(screen.getByRole('article', { name: 'PIM-Gruppe Global Security' })).toHaveTextContent('Dauerhaft aktiv');
  expect(screen.getByText(/Dauerhafte Adminrechte sind bereits aktiv/)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Gruppen & Zuweisungen' })).toHaveAttribute('href', '/pim');
  expect(privilegedActivation.change).not.toHaveBeenCalled();
});
test('requests only the chosen group for ten hours after reason and explicit review', async () => {
  (privilegedActivation.request as jest.Mock).mockResolvedValue({ ...approved('pending') }); render(<PIMGroupsPanel />);
  const card = await screen.findByRole('article', { name: 'PIM-Gruppe Lizenzen' }); fireEvent.click(within(card).getByRole('button', { name: 'Aktivierung anfordern' }));
  fireEvent.change(screen.getByLabelText('Gewünschte Dauer'), { target: { value: '36000' } }); fireEvent.change(screen.getByLabelText('Begründung'), { target: { value: 'Lizenzen für den Engineering-Arbeitstag verwalten' } });
  fireEvent.click(screen.getByRole('button', { name: 'Vorgang prüfen' })); const dialog = await screen.findByRole('alertdialog');
  expect(dialog).toHaveTextContent('Lizenzen für 10 Stunden'); expect(privilegedActivation.request).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(privilegedActivation.request).toHaveBeenCalledTimes(1));
  expect(privilegedActivation.request).toHaveBeenCalledWith({ id: requestId, eligibilityId, durationSeconds: 36000, reason: 'Lizenzen für den Engineering-Arbeitstag verwalten' });
  expect(privilegedActivation.change).not.toHaveBeenCalled();
});
test('a confirmed approved activation starts a real new login for the changed canonical role', async () => {
  const state = fixture(); state.self.requests = [approved()]; (privilegedGroups.load as jest.Mock).mockResolvedValue(state);
  (privilegedActivation.change as jest.Mock).mockResolvedValue(approved('active')); render(<PIMGroupsPanel />);
  fireEvent.click(await screen.findByRole('button', { name: 'Jetzt aktivieren' })); expect(startLogin).not.toHaveBeenCalled();
  fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(startLogin).toHaveBeenCalledTimes(1)); expect(privilegedActivation.change).toHaveBeenCalledWith(requestId, 'activate');
});
test('assigning a selected user creates eligibility and never activates their role', async () => {
  render(<PIMGroupsPanel management />); const card = await screen.findByRole('article', { name: 'PIM-Gruppe Lizenzen' });
  fireEvent.click(within(card).getByRole('button', { name: 'Benutzer zuweisen' }));
  fireEvent.change(await screen.findByLabelText('Benutzer auswählen'), { target: { value: other } });
  fireEvent.change(screen.getByLabelText('Begründung'), { target: { value: 'Benutzer unabhängig für die Lizenzaufgabe berechtigen' } });
  fireEvent.click(screen.getByRole('button', { name: 'Vorgang prüfen' })); fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(privilegedGroups.assign).toHaveBeenCalledTimes(1));
  expect(privilegedGroups.assign).toHaveBeenCalledWith(groupId, { userId: other, maxDurationSeconds: 3600, validForSeconds: 604800, reason: 'Benutzer unabhängig für die Lizenzaufgabe berechtigen', confirm: true });
  expect(privilegedActivation.change).not.toHaveBeenCalled();
});
test('an unconfirmed write clears the old group state and cannot repeat without explicit readback', async () => {
  (privilegedActivation.request as jest.Mock).mockRejectedValue(new Error('lost reply')); render(<PIMGroupsPanel />);
  const card = await screen.findByRole('article', { name: 'PIM-Gruppe Lizenzen' }); fireEvent.click(within(card).getByRole('button', { name: 'Aktivierung anfordern' }));
  fireEvent.change(screen.getByLabelText('Begründung'), { target: { value: 'Diese konkrete Aufgabe ist nachvollziehbar nötig' } }); fireEvent.click(screen.getByRole('button', { name: 'Vorgang prüfen' }));
  fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('aktuellen Stand neu laden'); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(privilegedActivation.request).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'PIM neu laden' })); await screen.findByRole('article', { name: 'PIM-Gruppe Lizenzen' }); expect(privilegedActivation.request).toHaveBeenCalledTimes(1);
});
test('the group protocol shows actor, reason and planned end from the server', async () => {
  (privilegedGroups.history as jest.Mock).mockResolvedValue({ schemaVersion: 1, groupId, page: 1, limit: 25, total: 1, events: [{ id: requestId, userId: owner, actorUserId: other, role: group.role, action: 'active', reason: 'Actual immutable activation reason', createdAt: new Date().toISOString(), durationSeconds: 3600, expiresAt: new Date(Date.now() + 3600000).toISOString() }] });
  render(<PIMGroupsPanel />); const card = await screen.findByRole('article', { name: 'PIM-Gruppe Lizenzen' }); fireEvent.click(within(card).getByRole('button', { name: 'Protokoll' }));
  const log = await screen.findByRole('region', { name: 'PIM-Protokoll' }); await waitFor(() => expect(log).toHaveTextContent('Actual immutable activation reason')); expect(log).toHaveTextContent(other); expect(log).toHaveTextContent('Geplantes Ende');
});
test('expiry removes the activation cards without silently granting or reactivating rights', async () => {
  jest.useFakeTimers();
  try {
    const state = fixture(); state.self.requests = [{ ...approved('active'), expiresAt: new Date(Date.now() + 2000).toISOString() }]; (privilegedGroups.load as jest.Mock).mockResolvedValue(state);
    render(<PIMGroupsPanel />); await act(async () => {}); await act(async () => { jest.advanceTimersByTime(3000); });
    expect(screen.getByRole('status')).toHaveTextContent('abgelaufen'); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(privilegedActivation.change).not.toHaveBeenCalled();
  } finally { jest.useRealTimers(); }
});
