import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import CompanyRolesView from '@/components/views/CompanyRolesView';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { companyRoles } from '@/lib/companyRoles';
import { companyPim } from '@/lib/companyPim';
import { directoryUsers } from '@/lib/directoryUsers';

jest.mock('@/hooks/useIdentityAccess', () => ({ useIdentityAccess: jest.fn() }));
jest.mock('@/lib/companyRoles', () => ({ companyRoles: { list: jest.fn(), detail: jest.fn(), history: jest.fn(), definition: jest.fn(), assign: jest.fn() }, permissionLabels: { 'users.read': 'Benutzer lesen' } }));
jest.mock('@/lib/companyPim', () => ({ companyPim: { eligibilities: jest.fn(), assign: jest.fn() } }));
jest.mock('@/lib/directoryUsers', () => ({ directoryUsers: { get: jest.fn(), list: jest.fn() }, userName: (user: any) => user.displayName || user.username, directoryError: (error: any) => error.message }));
const actor = '11111111-1111-4111-8111-111111111111', target = '22222222-2222-4222-8222-222222222222', tenant = '33333333-3333-4333-8333-333333333333';
const role = { id: '44444444-4444-4444-8444-444444444444', tenantId: tenant, revision: '1', name: 'Engineering lesen', description: 'Verzeichnis lesen', permissions: ['users.read'], enabled: true, maxDurationSeconds: 36000 };
const person = { id: target, revision: '1', username: 'employee', displayName: 'Employee Example', email: 'employee@example.invalid', enabled: true };
let access: any;
beforeEach(() => {
  jest.clearAllMocks(); access = { subject: 'original-actor', userId: actor, permissions: ['users.read', 'company.roles.read', 'company.roles.manage'], companyRolesProtocol: 1, companyPimProtocol: 1 };
  (useIdentityAccess as jest.Mock).mockImplementation(() => ({ access, can: (permission: string) => access.permissions.includes(permission), unavailable: false }));
  (companyRoles.list as jest.Mock).mockImplementation(async () => ({ actorUserId: access.userId, tenantId: tenant, canManage: true, roles: [role], groups: [], ouPermissions: ['users.read'], page: 1, total: 1 }));
  (companyRoles.detail as jest.Mock).mockResolvedValue({ role, grants: [], page: 1, total: 0 }); (companyRoles.history as jest.Mock).mockResolvedValue({ events: [], page: 1, total: 0 });
  (companyPim.eligibilities as jest.Mock).mockResolvedValue({ eligibilities: [], page: 1, total: 0 }); (companyPim.assign as jest.Mock).mockResolvedValue({});
  (directoryUsers.get as jest.Mock).mockResolvedValue(person); (directoryUsers.list as jest.Mock).mockResolvedValue({ users: [person], page: 1, total: 1 });
});
async function openAssignment() {
  await screen.findByText('Aufgabe für Employee Example zuweisen'); fireEvent.click(screen.getByRole('button', { name: role.name, exact: true }));
  fireEvent.click(await screen.findByRole('button', { name: 'Rolle vergeben', exact: true })); return screen.getByRole('alertdialog');
}
test('carries the independently loaded person into one explicit eligible assignment without a second recipient search', async () => {
  render(<CompanyRolesView selectedUserId={target} />); const dialog = await openAssignment();
  expect(within(dialog).getByRole('region', { name: 'Bestätigte Person' })).toHaveTextContent(person.email);
  expect(within(dialog).queryByLabelText('Person auswählen')).not.toBeInTheDocument(); expect(directoryUsers.list).not.toHaveBeenCalled();
  expect(within(dialog).getByLabelText('Vergabeart')).toHaveValue('eligible'); expect(within(dialog).getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); expect(companyPim.assign).not.toHaveBeenCalled();
  fireEvent.change(within(dialog).getByLabelText('Begründung'), { target: { value: 'Engineering darf die Leseaufgabe selbst aktivieren' } }); fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(companyPim.assign).toHaveBeenCalledTimes(1));
  expect(companyPim.assign).toHaveBeenCalledWith(actor, tenant, role, { targetType: 'user', targetId: target, scopeType: 'tenant', ouId: null, reason: 'Engineering darf die Leseaufgabe selbst aktivieren', confirm: true, validForSeconds: 2592000 }, expect.any(AbortSignal));
  expect(companyRoles.assign).not.toHaveBeenCalled();
});
for (const kind of ['malformed', 'self', 'no-profile-access']) test('does not resolve or grant an unconfirmed contextual recipient: ' + kind, async () => {
  if (kind === 'no-profile-access') access.permissions = ['company.roles.read', 'company.roles.manage'];
  render(<CompanyRolesView selectedUserId={kind === 'malformed' ? 'not-a-person' : kind === 'self' ? actor : target} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('nicht als Empfänger bestätigt'); expect(directoryUsers.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: role.name })); expect(await screen.findByRole('button', { name: 'Rolle vergeben' })).toBeDisabled(); expect(companyPim.assign).not.toHaveBeenCalled();
});
for (const invalid of [{ ...person, enabled: false }, { ...person, id: actor }]) test('refuses a disabled or mismatched person response: ' + invalid.id + invalid.enabled, async () => {
  (directoryUsers.get as jest.Mock).mockResolvedValue(invalid); render(<CompanyRolesView selectedUserId={target} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('nicht als aktiver Empfänger bestätigt'); expect(screen.queryByText('Aufgabe für Employee Example zuweisen')).not.toBeInTheDocument(); expect(companyPim.assign).not.toHaveBeenCalled();
});
test('clears an old actor lookup before a later response can disclose its person', async () => {
  let finish!: (value: typeof person) => void; (directoryUsers.get as jest.Mock).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const view = render(<CompanyRolesView selectedUserId={target} />); await waitFor(() => expect(directoryUsers.get).toHaveBeenCalledTimes(1));
  (directoryUsers.get as jest.Mock).mockRejectedValue(new Error('Recipient unavailable for the new actor')); access = { ...access, subject: 'other-actor', userId: '55555555-5555-4555-8555-555555555555' }; view.rerender(<CompanyRolesView selectedUserId={target} />);
  await act(async () => finish(person)); expect(await screen.findByRole('alert')).toHaveTextContent('Recipient unavailable'); expect(screen.queryByText(/Employee Example/)).not.toBeInTheDocument(); expect(companyPim.assign).not.toHaveBeenCalled();
});
test('a lost assignment response is not repeated and clears the person and confirmation', async () => {
  (companyPim.assign as jest.Mock).mockRejectedValue(new Error('Original assignment outcome unknown')); render(<CompanyRolesView selectedUserId={target} />); const dialog = await openAssignment();
  fireEvent.change(within(dialog).getByLabelText('Begründung'), { target: { value: 'Diese konkrete Engineering-Aufgabe wurde geprüft' } }); fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Original assignment outcome unknown'); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(screen.queryByText(/Employee Example/)).not.toBeInTheDocument(); expect(companyPim.assign).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('link', { name: 'Erneut anmelden' })).toHaveAttribute('href', '/api/auth/oidc/login?returnTo='+encodeURIComponent('/company-roles?userId='+target));
});

test('fresh MFA is required before assignment and returns to the same selected person',async()=>{
 (companyRoles.list as jest.Mock).mockResolvedValue({actorUserId:actor,tenantId:tenant,canManage:false,roles:[role],groups:[],ouPermissions:[],page:1,total:1});render(<CompanyRolesView selectedUserId={target}/>);
 await screen.findByText('Aufgabe für Employee Example zuweisen');expect(screen.getByRole('link',{name:'Anmeldung bestätigen'})).toHaveAttribute('href','/api/auth/oidc/login?returnTo='+encodeURIComponent('/company-roles?userId='+target));expect(screen.queryByRole('button',{name:'Rolle vergeben'})).not.toBeInTheDocument();expect(companyPim.assign).not.toHaveBeenCalled();
});
