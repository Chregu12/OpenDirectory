import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import OrganizationUnits from '@/components/OrganizationUnits';
import { directoryOus } from '@/lib/directoryOus';
jest.mock('@/lib/directoryOus', () => ({ ...jest.requireActual('@/lib/directoryOus'), directoryOus: { list: jest.fn(), create: jest.fn(), update: jest.fn(), remove: jest.fn() } }));
const root = { id: '11111111-1111-4111-8111-111111111111', name: 'Engineering', createdAt: '2026-10-19T00:00:00Z' };
const access = { subject: 'actual-owner', userId: root.id, permissions: ['ous.read', 'ous.create'], demoMode: false, directoryReadProtocol: 1, directoryCreationProtocol: 1 };
beforeEach(() => { jest.clearAllMocks(); (directoryOus.list as jest.Mock).mockResolvedValue([root]); });
test('creates a real child unit only after an actual receipt', async () => {
  (directoryOus.create as jest.Mock).mockResolvedValue({ ...root, id: '22222222-2222-4222-8222-222222222222', name: 'Platform', parentId: root.id }); render(<OrganizationUnits access={access} />);
  await screen.findByText('Engineering', { selector: 'strong' }); fireEvent.change(screen.getByLabelText('Name der Organisationseinheit'), { target: { value: 'Platform' } }); fireEvent.change(screen.getByLabelText('Übergeordnete Einheit'), { target: { value: root.id } });
  fireEvent.click(screen.getByRole('button', { name: 'Organisationseinheit erstellen' })); expect(await screen.findByRole('status')).toHaveTextContent('„Platform“ bestätigt'); expect(directoryOus.create).toHaveBeenCalledWith({ name: 'Platform', description: null, parentId: root.id });
});
test('read-only access renders the actual hierarchy without a create form', async () => {
  render(<OrganizationUnits access={{ ...access, permissions: ['ous.read'] }} />); await screen.findByText('Engineering', { selector: 'strong' }); expect(screen.queryByLabelText('Name der Organisationseinheit')).not.toBeInTheDocument();
});
test('unsupported metadata does not load directory data', () => {
  render(<OrganizationUnits access={{ ...access, directoryReadProtocol: undefined }} />); expect(screen.getByRole('alert')).toHaveTextContent('nicht verfügbar'); expect(directoryOus.list).not.toHaveBeenCalled();
});
test('an uncertain write removes stale data and requires an explicit reload, never automatic retry', async () => {
  (directoryOus.create as jest.Mock).mockRejectedValue(new Error('lost receipt')); render(<OrganizationUnits access={access} />); await screen.findByText('Engineering', { selector: 'strong' });
  fireEvent.change(screen.getByLabelText('Name der Organisationseinheit'), { target: { value: 'Uncertain' } }); fireEvent.click(screen.getByRole('button', { name: 'Organisationseinheit erstellen' })); await screen.findByRole('alert');
  expect(screen.queryByText('Engineering', { selector: 'strong' })).not.toBeInTheDocument(); expect(screen.queryByLabelText('Name der Organisationseinheit')).not.toBeInTheDocument(); expect(directoryOus.create).toHaveBeenCalledTimes(1);
});
test('a late former-session response cannot restore the hierarchy after session loss', async () => {
  let resolve: (value: any) => void; (directoryOus.list as jest.Mock).mockReturnValue(new Promise(result => { resolve = result; })); render(<OrganizationUnits access={access} />);
  await act(async () => { window.dispatchEvent(new Event('od:session-error')); resolve!([root]); }); expect(screen.queryByText('Engineering')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Sitzung');
});
const versioned = { ...root, revision: '2' }; const mutable = { ...access, directoryOuMutationProtocol: 1, permissions: [...access.permissions, 'ous.update', 'ous.delete'] };
test('an exact-version edit can move a real unit to another own parent', async () => {
  const other = { ...versioned, id: '22222222-2222-4222-8222-222222222222', name: 'Other root' }; (directoryOus.list as jest.Mock).mockResolvedValue([versioned, other]); (directoryOus.update as jest.Mock).mockResolvedValue({ ...versioned, parentId: other.id, revision: '3' });
  render(<OrganizationUnits access={mutable} />); fireEvent.click(await screen.findByRole('button', { name: 'Organisationseinheit Engineering bearbeiten' })); fireEvent.change(screen.getByLabelText('Übergeordnete Einheit'), { target: { value: other.id } }); fireEvent.click(screen.getByRole('button', { name: 'Organisationseinheit speichern' }));
  expect(await screen.findByRole('status')).toHaveTextContent('„Engineering“ bestätigt'); expect(directoryOus.update).toHaveBeenCalledWith(versioned, { name: root.name, description: null, parentId: other.id });
});
test('a parent cannot be deleted and neither self nor a descendant is offered as its new parent', async () => {
  const child = { ...versioned, id: '22222222-2222-4222-8222-222222222222', name: 'Child', parentId: root.id }; (directoryOus.list as jest.Mock).mockResolvedValue([versioned, child]); render(<OrganizationUnits access={mutable} />);
  expect(await screen.findByRole('button', { name: 'Organisationseinheit Engineering löschen' })).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Organisationseinheit Engineering bearbeiten' })); expect(screen.queryByRole('option', { name: 'Engineering' })).not.toBeInTheDocument(); expect(screen.queryByRole('option', { name: 'Child' })).not.toBeInTheDocument();
});
test('leaf deletion requires confirmation and a real receipt before removing the row', async () => {
  (directoryOus.list as jest.Mock).mockResolvedValue([versioned]); (directoryOus.remove as jest.Mock).mockResolvedValue(undefined); render(<OrganizationUnits access={mutable} />); fireEvent.click(await screen.findByRole('button', { name: 'Organisationseinheit Engineering löschen' })); expect(directoryOus.remove).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Bestätigen' })); expect(await screen.findByRole('status')).toHaveTextContent('„Engineering“ gelöscht'); expect(directoryOus.remove).toHaveBeenCalledWith(versioned); expect(screen.queryByText('Engineering', { selector: 'strong' })).not.toBeInTheDocument();
});
test('an old protocol or unconfirmed version disables mutation controls', async () => {
  (directoryOus.list as jest.Mock).mockResolvedValue([versioned]); render(<OrganizationUnits access={{ ...mutable, directoryOuMutationProtocol: undefined }} />); expect(await screen.findByRole('button', { name: 'Organisationseinheit Engineering bearbeiten' })).toBeDisabled(); expect(screen.getByRole('button', { name: 'Organisationseinheit Engineering löschen' })).toBeDisabled(); expect(directoryOus.update).not.toHaveBeenCalled();
});
test('a stale mutation clears actionable data instead of silently retrying an old version', async () => {
  (directoryOus.list as jest.Mock).mockResolvedValue([versioned]); (directoryOus.update as jest.Mock).mockRejectedValue({ response: { status: 412 } }); render(<OrganizationUnits access={mutable} />); fireEvent.click(await screen.findByRole('button', { name: 'Organisationseinheit Engineering bearbeiten' })); fireEvent.click(screen.getByRole('button', { name: 'Organisationseinheit speichern' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('zwischenzeitlich geändert'); expect(screen.queryByText('Engineering', { selector: 'strong' })).not.toBeInTheDocument(); expect(directoryOus.update).toHaveBeenCalledTimes(1);
});
