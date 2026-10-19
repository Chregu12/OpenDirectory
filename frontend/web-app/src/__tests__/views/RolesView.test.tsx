import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import toast from 'react-hot-toast';
import RolesView from '../../components/views/RolesView';
import { api } from '../../lib/api';

const target = '22222222-2222-4222-8222-222222222222'; const actor = '11111111-1111-4111-8111-111111111111';
const identifier = '33333333-3333-4333-8333-333333333333';
let permissions: string[]; let rows: any[];
const row = () => ({ id: identifier, userId: target, role: 'license-manager', reason: 'Reviewed license delegation', createdAt: '2026-10-18T10:00:00.000Z', expiresAt: '2026-10-18T11:00:00.000Z', revokedAt: null, status: 'active' });
beforeEach(() => {
  jest.clearAllMocks(); permissions = ['identities.roles.read']; rows = [];
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url === '/api/identity/access') return { data: { subject: 'verified', userId: actor, permissions, demoMode: false, directoryReadProtocol: 1 } };
    if (url === '/api/identity/roles/catalog') return { data: { roles: [{ role: 'admin', protected: true, assignable: false }, { role: 'license-manager', protected: false, assignable: true }], minDurationSeconds: 60, maxDurationSeconds: 28800 } };
    return { data: { userId: url.split('/')[3], assignments: rows, truncated: false } };
  });
  (api.post as jest.Mock).mockImplementation(async () => { rows = [row()]; return { status: 201, data: row() }; });
  (api.delete as jest.Mock).mockImplementation(async () => { rows = [{ ...row(), revokedAt: '2026-10-18T10:05:00.000Z', status: 'revoked' }]; return { status: 200, data: { id: identifier, userId: target, revoked: true } }; });
});
async function load(userId = target) {
  const user = userEvent.setup(); await user.type(await screen.findByLabelText('Verzeichnis-ID'), userId);
  await user.click(screen.getByRole('button', { name: 'Zuweisungen laden' })); await screen.findByRole('heading', { name: 'Rollenzuweisungen für ' + userId }); return user;
}
async function grant() {
  permissions.push('identities.roles.manage'); render(<RolesView />); const user = await load();
  await user.selectOptions(await screen.findByLabelText('Rolle'), 'license-manager'); await user.type(screen.getByLabelText('Begründung'), row().reason);
  await user.click(screen.getByRole('button', { name: 'Rollenzuweisung prüfen' })); return user;
}
test('ordinary users do not query either role or directory stores', async () => {
  permissions = []; render(<RolesView />); await screen.findByText('Keine Berechtigung zum Lesen der Rollenzuweisungen.');
  expect(api.get).toHaveBeenCalledTimes(1); expect(screen.queryByLabelText('Verzeichnis-ID')).not.toBeInTheDocument();
});
test('source outage never displays sample global administrators', async () => {
  (api.get as jest.Mock).mockRejectedValue({ response: { status: 503 } }); render(<RolesView />); await screen.findByRole('alert');
  expect(screen.queryByText('Global Administrator')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Rollenzuweisung prüfen' })).not.toBeInTheDocument();
});
test('role readers can load a known canonical UUID without directory-profile reads or mutation controls', async () => {
  rows = [{ ...row(), status: 'expired' }]; render(<RolesView />); await load(); await screen.findByText('license-manager');
  expect(screen.getByText(/Abgelaufen/)).toBeInTheDocument(); expect(screen.queryByLabelText('Begründung')).not.toBeInTheDocument();
  expect((api.get as jest.Mock).mock.calls.every(([url]) => url === '/api/identity/access' || url === '/api/identity/roles/catalog' || url === `/api/users/${target}/roles`)).toBe(true);
});
test('granting requires confirmation and sends no actor, permission, permanent or external-provider fields', async () => {
  const user = await grant(); expect(api.post).not.toHaveBeenCalled(); expect(screen.getByRole('option', { name: 'admin · geschützt' })).toBeDisabled();
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(toast.success).toHaveBeenCalled());
  expect(api.post).toHaveBeenCalledWith(`/api/users/${target}/roles`, { role: 'license-manager', durationSeconds: 3600, reason: row().reason });
  await screen.findByText('license-manager', { selector: 'strong' });
});
test('cancel never dispatches a role mutation', async () => {
  const user = await grant(); await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Abbrechen' })); expect(api.post).not.toHaveBeenCalled();
});
test('an uncertain mutation cannot invent success or automatically retry', async () => {
  (api.post as jest.Mock).mockRejectedValue({ response: { status: 503 } }); const user = await grant();
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' }));
  await within(screen.getByRole('alertdialog')).findByRole('alert'); expect(toast.success).not.toHaveBeenCalled(); expect(api.post).toHaveBeenCalledTimes(1);
  expect(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })).toBeDisabled();
});
test.each([200, 202])('HTTP %i is not confirmed role creation', async status => {
  (api.post as jest.Mock).mockResolvedValue({ status, data: row() }); const user = await grant();
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await screen.findByRole('alert'); expect(toast.success).not.toHaveBeenCalled();
});
test('a different target or unbounded lifetime is an unconfirmed outcome', async () => {
  (api.post as jest.Mock).mockResolvedValue({ status: 201, data: { ...row(), expiresAt: null } }); const user = await grant();
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await screen.findByRole('alert'); expect(toast.success).not.toHaveBeenCalled();
});
test('canonical self-administration is not offered even to a role manager', async () => {
  permissions.push('identities.roles.manage'); render(<RolesView />); await load(actor); await screen.findByText('Eigene Rollen können hier nicht selbst administriert werden.');
  expect(screen.queryByLabelText('Begründung')).not.toBeInTheDocument();
});
test('revocation uses the canonical assignment ID and requires a confirmed server result', async () => {
  permissions.push('identities.roles.manage'); rows = [row()]; render(<RolesView />); const user = await load();
  await user.click(await screen.findByRole('button', { name: 'Widerrufen: license-manager' })); expect(api.delete).not.toHaveBeenCalled();
  await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Bestätigen' })); await waitFor(() => expect(toast.success).toHaveBeenCalled());
  expect(api.delete).toHaveBeenCalledWith(`/api/users/${target}/roles/${identifier}`); await screen.findByText(/· Widerrufen$/);
});
test('a malformed role list never creates empty-success or writable state', async () => {
  permissions.push('identities.roles.manage'); rows = [{ ...row(), userId: actor }]; render(<RolesView />); const user = userEvent.setup();
  await user.type(await screen.findByLabelText('Verzeichnis-ID'), target); await user.click(screen.getByRole('button', { name: 'Zuweisungen laden' }));
  await screen.findByRole('alert'); expect(screen.queryByLabelText('Begründung')).not.toBeInTheDocument(); expect(screen.queryByText('Keine Rollenzuweisungen vorhanden.')).not.toBeInTheDocument();
});
