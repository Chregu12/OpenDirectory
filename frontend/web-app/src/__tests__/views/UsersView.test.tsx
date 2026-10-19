import React from 'react';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import toast from 'react-hot-toast';
import UsersView from '../../components/views/UsersView';
import { api } from '../../lib/api';
import { DirectoryUser, userEtag } from '../../lib/directoryUsers';

const targetId = '22222222-2222-4222-8222-222222222222';
const actorId = '11111111-1111-4111-8111-111111111111';
let permissions: string[]; let records: DirectoryUser[];

function record(overrides: Partial<DirectoryUser> = {}): DirectoryUser {
  return { id: targetId, username: 'employee', email: 'employee@test.invalid', displayName: 'Employee', enabled: true,
    department: 'Engineering', title: 'Engineer', revision: '1', createdAt: '2026-01-01T00:00:00.000Z', ...overrides };
}

beforeEach(() => {
  jest.clearAllMocks(); permissions = ['users.read']; records = [record()];
  (api.get as jest.Mock).mockImplementation(async (url: string, options: any = {}) => {
    if (url === '/api/identity/access') return { data: { subject: 'verified-subject', userId: actorId, permissions, demoMode: false, directoryReadProtocol: 1, directoryCreationProtocol: 1, directoryUserMutationProtocol: 1 } };
    if (url === '/api/users') {
      const { page = 1, search = '', enabled = '' } = options.params || {};
      const matching = records.filter(user => (!search || [user.username, user.displayName, user.email].join(' ').toLowerCase().includes(search.toLowerCase())) && (!enabled || user.enabled === (enabled === 'true')));
      return { data: { users: matching.slice((page - 1) * 25, page * 25), total: matching.length, page, limit: 25 } };
    }
    const user = records.find(user => url === '/api/users/' + user.id);
    if (!user) throw { response: { status: 404 } };
    return { data: user };
  });
  (api.put as jest.Mock).mockImplementation(async (url: string, patch: any) => {
    const current = records.find(user => url.endsWith(user.id));
    const updated = { ...current, ...patch, revision: String(Number(current!.revision) + 1) };
    records = records.map(user => user.id === updated.id ? updated : user); return { data: updated };
  });
  (api.post as jest.Mock).mockImplementation(async (url: string, profile: any) => {
    if (url.endsWith('/authorization/invalidate')) return { data: { userId: url.split('/')[3], revision: '99' } };
    const created = record({ ...profile, id: '33333333-3333-4333-8333-333333333333', enabled: false }); records.unshift(created); return { data: created };
  });
  (api.delete as jest.Mock).mockResolvedValue({ status: 204 });
});

async function select() {
  await userEvent.click(await screen.findByRole('button', { name: 'Benutzer employee' }));
  await screen.findByRole('heading', { name: 'Employee' });
}

test('ordinary users do not fetch the directory or see fake sample users', async () => {
  permissions = []; render(<UsersView />);
  expect(await screen.findByText('Keine Berechtigung zum Lesen der Benutzerliste.')).toBeInTheDocument();
  expect(api.get).toHaveBeenCalledTimes(1); expect(api.get).toHaveBeenCalledWith('/api/identity/access');
  expect(screen.queryByText('Alice Mueller')).not.toBeInTheDocument(); expect(screen.queryByText('Grace Hoffmann')).not.toBeInTheDocument();
});
test('a reader sees canonical enabled=false and no invented roles, MFA or administrative actions', async () => {
  records = [record({ enabled: false })]; render(<UsersView />); await select();
  expect(within(screen.getByRole('article', { name: 'Benutzerdetails' })).getByText('Gesperrt')).toBeInTheDocument();
  for (const name of ['Profil bearbeiten', 'Konto freigeben', 'Konto sperren', 'Sicherheitsreset', 'Eintrag löschen', 'Verzeichniseintrag erstellen', 'Reset Password', 'Manage MFA']) expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
  expect(api.get).not.toHaveBeenCalledWith('/api/lldap/users');
});
test('a confirmed empty directory is empty, never replaced by sample administrators', async () => {
  records = []; render(<UsersView />); expect(await screen.findByText('Keine Benutzer gefunden.')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /^Benutzer / })).not.toBeInTheDocument();
});
test.each([403, 503])('directory HTTP %i is an error, not a fallback or fabricated successful list', async status => {
  const original = (api.get as jest.Mock).getMockImplementation()!;
  (api.get as jest.Mock).mockImplementation((url, options) => url === '/api/users' ? Promise.reject({ response: { status } }) : original(url, options));
  render(<UsersView />); expect(await screen.findByRole('alert')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /^Benutzer / })).not.toBeInTheDocument(); expect(api.get).not.toHaveBeenCalledWith('/api/lldap/users');
});
test.each([{}, { subject: 'actor', permissions: 'admin', userId: null, demoMode: false }])('invalid capabilities fail closed: %j', access => {
  (api.get as jest.Mock).mockResolvedValue({ data: access }); render(<UsersView />);
  return screen.findByRole('alert').then(() => { expect(api.get).toHaveBeenCalledTimes(1); expect(screen.queryByRole('button', { name: 'Verzeichniseintrag erstellen' })).not.toBeInTheDocument(); });
});
test('an unavailable capability source does not authorize any directory read or action', async () => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status: 503 } }); render(<UsersView />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Verzeichnisberechtigungen nicht verfügbar'); expect(api.get).toHaveBeenCalledTimes(1);
});
test('a profile editor cannot toggle account status, and submits only profile fields with its selected record version', async () => {
  permissions = ['users.read', 'users.update']; const user = userEvent.setup(); render(<UsersView />); await select();
  expect(screen.queryByRole('button', { name: 'Konto sperren' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Profil bearbeiten' }));
  await user.clear(screen.getByLabelText('Position')); await user.type(screen.getByLabelText('Position'), 'Senior Engineer');
  await user.click(screen.getByRole('button', { name: 'Speichern' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledTimes(1));
  expect(api.put).toHaveBeenCalledWith('/api/users/' + targetId, { username: 'employee', email: 'employee@test.invalid', displayName: 'Employee', department: 'Engineering', title: 'Senior Engineer' }, { headers: { 'If-Match': userEtag(record()) } });
});
test('status requires both update and status grants and a confirmation; cancellation has no side effect', async () => {
  permissions = ['users.read', 'users.update', 'users.status.manage']; const user = userEvent.setup(); render(<UsersView />); await select();
  await user.click(screen.getByRole('button', { name: 'Konto sperren' })); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Abbrechen' })); expect(api.put).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Konto sperren' })); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledTimes(1));
  expect(api.put).toHaveBeenCalledWith('/api/users/' + targetId, { enabled: false }, { headers: { 'If-Match': userEtag(record()) } });
  await screen.findByRole('button', { name: 'Konto freigeben' }); expect(toast.success).toHaveBeenCalled();
});
test('a status-only grant does not silently grant profile editing', async () => {
  permissions = ['users.read', 'users.status.manage']; render(<UsersView />); await select(); expect(screen.queryByRole('button', { name: 'Konto sperren' })).not.toBeInTheDocument();
});
test('an unconfirmed status outcome never flips the displayed status, shows success, or automatically retries', async () => {
  permissions = ['users.read', 'users.update', 'users.status.manage']; (api.put as jest.Mock).mockRejectedValue({ response: { status: 503 } });
  const user = userEvent.setup(); render(<UsersView />); await select(); await user.click(screen.getByRole('button', { name: 'Konto sperren' }));
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('nicht bestätigt'); expect(toast.success).not.toHaveBeenCalled();
  expect(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); expect(api.put).toHaveBeenCalledTimes(1);
});
test('a delayed mutation response cannot replace the details of a different selected user', async () => {
  permissions = ['users.read', 'users.update', 'users.status.manage'];
  const other = record({ id: '44444444-4444-4444-8444-444444444444', username: 'other', displayName: 'Other Employee' }); records.push(other);
  let finish: (value: unknown) => void;
  (api.put as jest.Mock).mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const user = userEvent.setup(); render(<UsersView />); await select(); await user.click(screen.getByRole('button', { name: 'Konto sperren' }));
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await user.click(screen.getByRole('button', { name: 'Benutzer other' })); await screen.findByRole('heading', { name: 'Other Employee' });
  await act(async () => { finish!({ data: record({ enabled: false, revision: '2' }) }); });
  await waitFor(() => expect(toast.success).toHaveBeenCalled());
  await screen.findByRole('heading', { name: 'Other Employee' });
  expect(screen.queryByRole('heading', { name: 'Employee' })).not.toBeInTheDocument();
});
test('stale profile edits are reported rather than overwriting the new record or forcing an automatic retry', async () => {
  permissions = ['users.read', 'users.update']; (api.put as jest.Mock).mockRejectedValue({ response: { status: 412 } });
  const user = userEvent.setup(); render(<UsersView />); await select(); await user.click(screen.getByRole('button', { name: 'Profil bearbeiten' }));
  await user.click(screen.getByRole('button', { name: 'Speichern' })); expect(await screen.findByRole('alert')).toHaveTextContent('zwischenzeitlich geändert');
  expect(screen.getByRole('button', { name: 'Speichern' })).toBeDisabled(); expect(api.put).toHaveBeenCalledTimes(1); expect(toast.success).not.toHaveBeenCalled();
});
test('creation sends no password, role or activation flag and starts with a confirmed disabled record', async () => {
  permissions = ['users.read', 'users.create']; const user = userEvent.setup(); render(<UsersView />);
  await user.click(await screen.findByRole('button', { name: 'Verzeichniseintrag erstellen' }));
  expect(screen.getByText(/Zugangsdaten, Rollen, MFA/)).toBeInTheDocument();
  await user.type(screen.getByLabelText('Benutzername'), 'new-person'); await user.type(screen.getByLabelText('E-Mail'), 'new@test.invalid');
  await user.click(screen.getByRole('button', { name: 'Speichern' })); await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1));
  expect(api.post).toHaveBeenCalledWith('/api/users', { username: 'new-person', email: 'new@test.invalid', displayName: '', department: '', title: '' });
  await screen.findByRole('heading', { name: 'new-person' });
});
test('create-only operators receive the new canonical ID without reading unrelated profiles', async () => {
  permissions = ['users.create']; const user = userEvent.setup(); render(<UsersView />);
  await user.click(await screen.findByRole('button', { name: 'Verzeichniseintrag erstellen' })); await user.type(screen.getByLabelText('Benutzername'), 'new-person'); await user.type(screen.getByLabelText('E-Mail'), 'new@test.invalid');
  await user.click(screen.getByRole('button', { name: 'Speichern' }));
  expect(await screen.findByRole('region', { name: 'Erstellter Verzeichniseintrag' })).toHaveTextContent('33333333-3333-4333-8333-333333333333');
  expect(api.get).toHaveBeenCalledTimes(2);expect((api.get as jest.Mock).mock.calls.every(call=>call[0]==='/api/identity/access')).toBe(true);
});
test('a malformed or unexpectedly enabled creation result is not presented as successful and cannot be blindly retried', async () => {
  permissions = ['users.create']; (api.post as jest.Mock).mockResolvedValue({ data: record({ enabled: true }) });
  const user = userEvent.setup(); render(<UsersView />); await user.click(await screen.findByRole('button', { name: 'Verzeichniseintrag erstellen' }));
  await user.type(screen.getByLabelText('Benutzername'), 'new-person'); await user.type(screen.getByLabelText('E-Mail'), 'new@test.invalid'); await user.click(screen.getByRole('button', { name: 'Speichern' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('nicht bestätigt'); expect(screen.getByRole('button', { name: 'Speichern' })).toBeDisabled(); expect(toast.success).not.toHaveBeenCalled();
  expect(screen.queryByRole('region', { name: 'Erstellter Verzeichniseintrag' })).not.toBeInTheDocument(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('an unexpected successful delete status is an unconfirmed outcome, not a fake deletion', async () => {
  permissions = ['users.read', 'users.delete']; (api.delete as jest.Mock).mockResolvedValue({ status: 200, data: {} });
  const user = userEvent.setup(); render(<UsersView />); await select(); await user.click(screen.getByRole('button', { name: 'Eintrag löschen' }));
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('nicht bestätigt'); expect(toast.success).not.toHaveBeenCalled(); expect(api.delete).toHaveBeenCalledTimes(1);
});
test('a reset-only operator submits only a known canonical UUID, with no profile read or status privileges', async () => {
  permissions = ['users.sessions.invalidate']; const user = userEvent.setup(); render(<UsersView />);
  await user.type(await screen.findByLabelText('Kanonische Benutzer-ID'), targetId); await user.click(screen.getByRole('button', { name: 'Sicherheitsreset vorbereiten' }));
  expect(api.post).not.toHaveBeenCalled(); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/users/' + targetId + '/authorization/invalidate', {})); expect(api.get).toHaveBeenCalledTimes(2); expect((api.get as jest.Mock).mock.calls.every(([url])=>url==='/api/identity/access')).toBe(true);
});
test('deletion is a separate grant, confirmation and exact-version request', async () => {
  permissions = ['users.read', 'users.delete']; const user = userEvent.setup(); render(<UsersView />); await select();
  await user.click(screen.getByRole('button', { name: 'Eintrag löschen' })); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(api.delete).toHaveBeenCalledWith('/api/users/' + targetId, { headers: { 'If-Match': userEtag(record()) } }));
});
test('server-side pagination and status filters replace the visible page instead of retaining sample or stale users', async () => {
  records = Array.from({ length: 26 }, (_, position) => record({ id: '90000000-0000-4000-8000-' + String(position + 1).padStart(12, '0'), username: 'person-' + (position + 1), displayName: 'Person ' + (position + 1), enabled: position !== 25 }));
  const user = userEvent.setup(); render(<UsersView />); await screen.findByRole('button', { name: 'Benutzer person-1' });
  await user.click(screen.getByRole('button', { name: 'Weiter' })); await screen.findByRole('button', { name: 'Benutzer person-26' }); expect(screen.queryByRole('button', { name: 'Benutzer person-1' })).not.toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText('Kontostatus'), 'false'); await screen.findByRole('button', { name: 'Benutzer person-26' });
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/users', expect.objectContaining({ params: { page: 1, limit: 25, enabled: 'false' } })));
});
