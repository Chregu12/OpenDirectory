import React from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import OrganizationUnitMembers from '@/components/OrganizationUnitMembers';
import { directoryOuMemberships } from '@/lib/directoryOuMemberships';
import { directoryUsers } from '@/lib/directoryUsers';
jest.mock('@/lib/directoryOuMemberships', () => ({ ...jest.requireActual('@/lib/directoryOuMemberships'), directoryOuMemberships: { list: jest.fn(), add: jest.fn(), remove: jest.fn() } }));
jest.mock('@/lib/directoryUsers', () => ({ ...jest.requireActual('@/lib/directoryUsers'), directoryUsers: { ...jest.requireActual('@/lib/directoryUsers').directoryUsers, list: jest.fn() } }));
const actor = '11111111-1111-4111-8111-111111111111'; const userId = '22222222-2222-4222-8222-222222222222';
const unit = { id: '33333333-3333-4333-8333-333333333333', name: 'Engineering', revision: '2', memberCount: 0, createdAt: '2026-10-19T00:00:00Z' };
const member = { id: '44444444-4444-4444-8444-444444444444', ouId: unit.id, userId, createdAt: unit.createdAt, profile: { username: 'employee', email: 'employee@example.invalid', displayName: 'Actual Employee' } };
const page = { schemaVersion: 1 as const, actorUserId: actor, unit, members: [], total: 0, page: 1, limit: 25, profileAccess: true };
const access = { subject: 'actual', userId: actor, permissions: ['ous.read', 'ous.members.manage', 'users.read'], demoMode: false, directoryOuMembershipProtocol: 1 };
beforeEach(() => { jest.clearAllMocks(); (directoryOuMemberships.list as jest.Mock).mockResolvedValue(page); (directoryUsers.list as jest.Mock).mockResolvedValue({ users: [{ id: userId, username: 'employee', displayName: 'Actual Employee', email: 'employee@example.invalid', enabled: false }], total: 1, page: 1, limit: 25 }); });
test('a real own-user search selects a canonical employee rather than inventing a membership', async () => {
  (directoryOuMemberships.add as jest.Mock).mockResolvedValue({ unit: { ...unit, revision: '3', memberCount: 1 }, membership: member, action: 'member-add' }); (directoryOuMemberships.list as jest.Mock).mockResolvedValueOnce(page).mockResolvedValue({ ...page, unit: { ...unit, revision: '3', memberCount: 1 }, total: 1, members: [member] });
  render(<OrganizationUnitMembers ouId={unit.id} access={access} onClose={jest.fn()} />); await screen.findByText('Mitglieder von Engineering'); fireEvent.change(screen.getByLabelText('Mitarbeitende suchen'), { target: { value: 'Actual' } }); fireEvent.click(await screen.findByRole('button', { name: 'Mitarbeitenden Actual Employee auswählen' })); expect(directoryOuMemberships.add).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Zuordnung hinzufügen' })); expect(await screen.findByText('Actual Employee', { selector: 'strong' })).toBeInTheDocument(); expect(directoryOuMemberships.add).toHaveBeenCalledWith(unit, userId); expect(directoryUsers.list).toHaveBeenCalledWith(1, 'Actual', '', expect.any(AbortSignal));
});
test('an OU-only manager uses known IDs without fetching unauthorized user profiles', async () => {
  (directoryOuMemberships.list as jest.Mock).mockResolvedValue({ ...page, profileAccess: false });
  render(<OrganizationUnitMembers ouId={unit.id} access={{ ...access, permissions: ['ous.read', 'ous.members.manage'] }} onClose={jest.fn()} />); await screen.findByText('Mitglieder von Engineering'); expect(screen.getByLabelText('Kanonische Benutzer-ID')).toBeInTheDocument(); expect(screen.queryByLabelText('Mitarbeitende suchen')).not.toBeInTheDocument(); expect(directoryUsers.list).not.toHaveBeenCalled();
});
test('read-only access exposes no assignment or removal controls', async () => {
  (directoryOuMemberships.list as jest.Mock).mockResolvedValue({ ...page, unit: { ...unit, memberCount: 1 }, total: 1, members: [member] }); render(<OrganizationUnitMembers ouId={unit.id} access={{ ...access, permissions: ['ous.read', 'users.read'] }} onClose={jest.fn()} />); await screen.findByText('Actual Employee', { selector: 'strong' }); expect(screen.queryByRole('button', { name: 'Zuordnung hinzufügen' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: /OU-Zuordnung.*entfernen/ })).not.toBeInTheDocument(); expect(directoryUsers.list).not.toHaveBeenCalled();
});
test('removal requires explicit confirmation for the exact current incarnation', async () => {
  (directoryOuMemberships.list as jest.Mock).mockResolvedValueOnce({ ...page, unit: { ...unit, memberCount: 1 }, total: 1, members: [member] }).mockResolvedValue(page); (directoryOuMemberships.remove as jest.Mock).mockResolvedValue({ action: 'member-remove' }); render(<OrganizationUnitMembers ouId={unit.id} access={access} onClose={jest.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'OU-Zuordnung Actual Employee entfernen' })); expect(directoryOuMemberships.remove).not.toHaveBeenCalled(); fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); expect(await screen.findByRole('status')).toHaveTextContent('OU-Zuordnung entfernt'); expect(directoryOuMemberships.remove).toHaveBeenCalledWith({ ...unit, memberCount: 1 }, member);
});
test('old protocol metadata does not start membership reads', () => {
  render(<OrganizationUnitMembers ouId={unit.id} access={{ ...access, directoryOuMembershipProtocol: undefined }} onClose={jest.fn()} />); expect(screen.getByRole('alert')).toHaveTextContent('nicht verfügbar'); expect(directoryOuMemberships.list).not.toHaveBeenCalled();
});
test('a rejected stale assignment clears actionable data and never retries the old version', async () => {
  (directoryOuMemberships.list as jest.Mock).mockResolvedValue({ ...page, profileAccess: false });
  (directoryOuMemberships.add as jest.Mock).mockRejectedValue({ response: { status: 412 } }); render(<OrganizationUnitMembers ouId={unit.id} access={{ ...access, permissions: ['ous.read', 'ous.members.manage'] }} onClose={jest.fn()} />); await screen.findByLabelText('Kanonische Benutzer-ID'); fireEvent.change(screen.getByLabelText('Kanonische Benutzer-ID'), { target: { value: userId } }); fireEvent.click(screen.getByRole('button', { name: 'Zuordnung hinzufügen' })); expect(await screen.findByRole('alert')).toHaveTextContent('zwischenzeitlich geändert'); expect(screen.queryByLabelText('Kanonische Benutzer-ID')).not.toBeInTheDocument(); expect(directoryOuMemberships.add).toHaveBeenCalledTimes(1);
});
test('a late old-session page cannot restore membership data after session loss', async () => {
  let resolve: (value: any) => void; (directoryOuMemberships.list as jest.Mock).mockReturnValue(new Promise(result => { resolve = result; })); render(<OrganizationUnitMembers ouId={unit.id} access={access} onClose={jest.fn()} />);
  await act(async () => { window.dispatchEvent(new Event('od:session-error')); resolve!({ ...page, members: [member], total: 1 }); }); expect(screen.queryByText('Actual Employee')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Sitzung');
});
test('a late old-session write cannot reload or confirm data after session loss', async () => {
  let resolve: (value: any) => void; (directoryOuMemberships.list as jest.Mock).mockResolvedValue({ ...page, profileAccess: false }); (directoryOuMemberships.add as jest.Mock).mockReturnValue(new Promise(result => { resolve = result; }));
  render(<OrganizationUnitMembers ouId={unit.id} access={{ ...access, permissions: ['ous.read', 'ous.members.manage'] }} onClose={jest.fn()} />); await screen.findByLabelText('Kanonische Benutzer-ID'); fireEvent.change(screen.getByLabelText('Kanonische Benutzer-ID'), { target: { value: userId } }); fireEvent.click(screen.getByRole('button', { name: 'Zuordnung hinzufügen' }));
  await act(async () => { window.dispatchEvent(new Event('od:session-error')); resolve!({ unit, membership: member, action: 'member-add' }); }); expect(screen.getByRole('alert')).toHaveTextContent('Sitzung'); expect(directoryOuMemberships.list).toHaveBeenCalledTimes(1); expect(screen.queryByText(/OU-Zuordnung gespeichert/)).not.toBeInTheDocument();
});
