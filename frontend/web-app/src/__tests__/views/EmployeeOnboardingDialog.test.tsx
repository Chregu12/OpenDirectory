import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import EmployeeOnboardingDialog from '../../components/views/EmployeeOnboardingDialog';
import { api } from '../../lib/api';
import { DirectoryUser } from '../../lib/directoryUsers';
import { DirectoryGroup } from '../../lib/directoryGroups';
import { EmployeeInvitationRecord } from '../../lib/employeeInvitationManagement';

const actor = '11111111-1111-4111-8111-111111111111';
const personId = '22222222-2222-4222-8222-222222222222';
const groupId = '33333333-3333-4333-8333-333333333333';
const invitationId = '44444444-4444-4444-8444-444444444444';
const tenantId = '55555555-5555-4555-8555-555555555555';
const createdAt = '2026-01-01T00:00:00.000Z';
let group: DirectoryGroup; let person: DirectoryUser | null; let invitation: EmployeeInvitationRecord | null;
let createFailure: number | null; let loseInvitationResponse: boolean; let ownerMfaMissing: boolean;
const requests = (url: string) => (api.post as jest.Mock).mock.calls.filter(call => call[0] === url);

beforeEach(() => {
  jest.clearAllMocks(); person = null; invitation = null; createFailure = null; loseInvitationResponse = false; ownerMfaMissing = false;
  group = { id: groupId, name: 'Engineering', members: [], revision: '1', createdAt };
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: jest.fn(() => invitationId) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url === '/api/identity/access') return { data: { subject: 'actual-owner-fixture', userId: actor, demoMode: false, companyOwner: true,
      permissions: ['users.read', 'users.create', 'groups.read', 'groups.members.manage'], directoryReadProtocol: 1, directoryCreationProtocol: 1, directoryGroupMutationProtocol: 1 } };
    if (url === '/api/groups') return { data: { groups: [group], total: 1 } };
    if (url === '/api/groups/' + groupId) return { data: group };
    if (url === '/api/users/' + personId && person) return { data: person };
    throw new Error('Unexpected read ' + url);
  });
  (api.post as jest.Mock).mockImplementation(async (url: string, input: any) => {
    if (url === '/api/employee-invitations/manage/list') {
      if (ownerMfaMissing) throw { response: { status: 403 } };
      return { data: { schemaVersion: 1, employeeInvitationProtocol: 1, page: 1, hasMore: false, invitations: invitation ? [invitation] : [] } };
    }
    if (url === '/api/users') { person = { ...input, id: personId, enabled: false, revision: '1', createdAt }; return { data: person }; }
    if (url === '/api/identity/employee-invitations') return { data: { schemaVersion: 1, employeeInvitationProtocol: 1, actorUserId: actor, tenant: { id: tenantId }, target: { id: personId, revision: person!.revision, username: person!.username, email: person!.email, enabled: false, unlinked: true, ordinary: true, tenantGeneration: '1' } } };
    if (url === '/api/groups/' + groupId + '/members') { group = { ...group, revision: String(Number(group.revision) + 1), members: [personId] }; return { data: group }; }
    if (url === '/api/employee-invitations/manage/create') {
      if (createFailure) throw { response: { status: createFailure } };
      invitation = { id: input.id, tenantId, userId: input.userId, loginName: input.loginName, organizationName: 'Example Company', status: 'pending', revision: '1', createdAt, expiresAt: '2099-01-01T00:00:00.000Z', credentialCreated: false, identityConfirmed: false };
      if (loseInvitationResponse) throw { response: { status: 503 } };
      return { data: { schemaVersion: 1, employeeInvitationProtocol: 1, invitation, created: true, invitationToken: invitationId + '.' + 'a'.repeat(43), mailStatus: 'not_configured' } };
    }
    if (url === '/api/employee-invitations/manage/get') {
      if (!invitation) throw { response: { status: 404 } };
      return { data: { schemaVersion: 1, employeeInvitationProtocol: 1, invitation } };
    }
    throw new Error('Unexpected mutation ' + url);
  });
  (api.delete as jest.Mock).mockImplementation(async (_url, options) => {
    if (options.headers['If-Match'] !== '"group-' + groupId + '-' + group.revision + '"') throw { response: { status: 412 } };
    group = { ...group, revision: String(Number(group.revision) + 1), members: [] }; return { data: group };
  });
});

async function prepare() {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText('Name', { exact: true }), 'Ada Lovelace');
  await user.type(screen.getByLabelText('E-Mail', { exact: true }), 'ada@example.invalid');
  await user.click(await screen.findByRole('checkbox', { name: 'Engineering' }));
  await user.click(screen.getByRole('button', { name: 'Aufnahme prüfen' }));
  await user.click(screen.getByRole('checkbox', { name: 'Ich bestätige die Aufnahme und die ausgewählten Gruppenmitgliedschaften.' }));
  return user;
}

test('one reviewed action creates the disabled person, prepares named groups and returns only a real invitation receipt', async () => {
  const onCreated = jest.fn(); const onInvited = jest.fn();
  render(<EmployeeOnboardingDialog actorUserId={actor} onCreated={onCreated} onInvited={onInvited} onClose={jest.fn()} />);
  const user = await prepare();
  expect(api.post).not.toHaveBeenCalled();
  expect(screen.getByText('Mitarbeiteraufnahme für Ada Lovelace')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Aufnahme starten' }));
  await screen.findByRole('heading', { name: 'Einladung vorbereitet' });
  expect(requests('/api/users')).toEqual([['/api/users', { username: 'ada', email: 'ada@example.invalid', displayName: 'Ada Lovelace', department: '', title: '' }]]);
  expect(person?.enabled).toBe(false); expect(onCreated).toHaveBeenCalledTimes(1); expect(onInvited).toHaveBeenCalledTimes(1);
  expect(requests('/api/employee-invitations/manage/create')).toHaveLength(1);
  expect(requests('/api/employee-invitations/manage/create')[0][1]).toEqual({ id: invitationId, userId: personId, userRevision: '1', loginName: 'ada', durationHours: 72, reason: 'Mitarbeiteraufnahme für Ada Lovelace', confirm: true });
  expect(group.members).toEqual([personId]);
  expect(screen.getByLabelText('Einmaliger Einladungslink')).toHaveValue(window.location.origin + '/employees/accept#' + invitationId + '.' + 'a'.repeat(43));
  expect(screen.getByText(/E-Mail-Versand ist nicht eingerichtet/)).toBeInTheDocument();
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});

test('a missing fresh owner MFA is detected before a person or group is created', async () => {
  ownerMfaMissing = true;
  render(<EmployeeOnboardingDialog actorUserId={actor} onClose={jest.fn()} />); const user = await prepare();
  await user.click(screen.getByRole('button', { name: 'Aufnahme starten' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('frischer MFA');
  expect(requests('/api/users')).toHaveLength(0); expect(requests('/api/groups/' + groupId + '/members')).toHaveLength(0); expect(requests('/api/employee-invitations/manage/create')).toHaveLength(0);
});

test('an unknown invitation result keeps the person and reads the original status without another create or email', async () => {
  loseInvitationResponse = true;
  render(<EmployeeOnboardingDialog actorUserId={actor} onClose={jest.fn()} />); const user = await prepare();
  await user.click(screen.getByRole('button', { name: 'Aufnahme starten' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('unklar');
  expect(screen.queryByRole('button', { name: 'Aufnahme starten' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Einladungsstatus prüfen' }));
  await screen.findByRole('heading', { name: 'Einladung vorbereitet' });
  expect(screen.getByText(/ursprüngliche Einladung ist vorhanden/)).toBeInTheDocument();
  expect(screen.queryByLabelText('Einmaliger Einladungslink')).not.toBeInTheDocument();
  expect(requests('/api/users')).toHaveLength(1); expect(requests('/api/employee-invitations/manage/create')).toHaveLength(1);
  expect(api.delete).not.toHaveBeenCalled();
});

test('an explicit re-preparation after a definite failure uses the same person and refreshed group versions', async () => {
  createFailure = 403;
  render(<EmployeeOnboardingDialog actorUserId={actor} onClose={jest.fn()} />); const user = await prepare();
  await user.click(screen.getByRole('button', { name: 'Aufnahme starten' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('zurückgenommen'); expect(group.revision).toBe('3');
  createFailure = null; await user.click(screen.getByRole('button', { name: 'Angaben bearbeiten' }));
  expect(await screen.findByLabelText('Name', { exact: true })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Aufnahme prüfen' }));
  await user.click(screen.getByRole('checkbox', { name: 'Ich bestätige die Aufnahme und die ausgewählten Gruppenmitgliedschaften.' }));
  await user.click(screen.getByRole('button', { name: 'Aufnahme starten' })); await screen.findByRole('heading', { name: 'Einladung vorbereitet' });
  expect(requests('/api/users')).toHaveLength(1); expect(requests('/api/employee-invitations/manage/create')).toHaveLength(2);
  expect(requests('/api/employee-invitations/manage/create').map(call => call[1].id)).toEqual([invitationId, invitationId]);
});

test('a changed reviewed group stops before membership and invitation effects', async () => {
  render(<EmployeeOnboardingDialog actorUserId={actor} onClose={jest.fn()} />); const user = await prepare(); group = { ...group, revision: '2' };
  await user.click(screen.getByRole('button', { name: 'Aufnahme starten' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('geändert');
  expect(requests('/api/users')).toHaveLength(1); expect(requests('/api/groups/' + groupId + '/members')).toHaveLength(0); expect(requests('/api/employee-invitations/manage/create')).toHaveLength(0);
  expect(screen.getByText(/ist als Verzeichniseintrag vorhanden/)).toBeInTheDocument();
});

test('session invalidation during creation prevents all automatic follow-ups and clears the private form', async () => {
  const original = (api.post as jest.Mock).getMockImplementation()!; let finish!: (value: unknown) => void;
  (api.post as jest.Mock).mockImplementation((url, input, options) => url === '/api/users' ? new Promise(resolve => { finish = resolve; }) : original(url, input, options));
  const onCreated = jest.fn(); const onClose = jest.fn(); render(<EmployeeOnboardingDialog actorUserId={actor} onCreated={onCreated} onClose={onClose} />); const user = await prepare();
  await user.click(screen.getByRole('button', { name: 'Aufnahme starten' })); await waitFor(() => expect(finish).toBeDefined());
  await act(async () => { window.dispatchEvent(new Event('od:session-error')); finish({ data: { id: personId, username: 'ada', email: 'ada@example.invalid', displayName: 'Ada Lovelace', enabled: false, revision: '1', createdAt } }); });
  expect(screen.getByRole('alert')).toHaveTextContent('Sitzung oder Berechtigung'); expect(screen.queryByText('Ada Lovelace')).not.toBeInTheDocument();
  expect(onCreated).not.toHaveBeenCalled(); expect(requests('/api/identity/employee-invitations')).toHaveLength(0); expect(requests('/api/employee-invitations/manage/create')).toHaveLength(0);
  await user.click(screen.getByRole('button', { name: 'Schliessen' })); expect(onClose).toHaveBeenCalledTimes(1);
});

test('an explicitly entered username is not overwritten by later email changes', async () => {
  render(<EmployeeOnboardingDialog actorUserId={actor} onClose={jest.fn()} />); const user = userEvent.setup();
  await user.type(screen.getByLabelText('E-Mail', { exact: true }), 'ada@example.invalid');
  expect(screen.getByLabelText('Benutzername')).toHaveValue('ada');
  await user.clear(screen.getByLabelText('Benutzername')); await user.type(screen.getByLabelText('Benutzername'), 'ada.lovelace');
  await user.clear(screen.getByLabelText('E-Mail', { exact: true })); await user.type(screen.getByLabelText('E-Mail', { exact: true }), 'new@example.invalid');
  expect(screen.getByLabelText('Benutzername')).toHaveValue('ada.lovelace');
});

test('a different owner cannot inherit the previous owner form or invitation link', async () => {
  const { rerender } = render(<EmployeeOnboardingDialog actorUserId={actor} onClose={jest.fn()} />); const user = await prepare();
  await user.click(screen.getByRole('button', { name: 'Aufnahme starten' })); await screen.findByRole('heading', { name: 'Einladung vorbereitet' });
  rerender(<EmployeeOnboardingDialog actorUserId={tenantId} onClose={jest.fn()} />);
  expect(screen.getByRole('alert')).toHaveTextContent('Sitzung oder Berechtigung'); expect(screen.queryByLabelText('Einmaliger Einladungslink')).not.toBeInTheDocument();
  expect(screen.queryByText('Ada Lovelace')).not.toBeInTheDocument();
});
