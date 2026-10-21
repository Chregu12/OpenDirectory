import React from 'react';
import '@testing-library/jest-dom';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CompanyLicenseGroupsPanel from '@/components/views/CompanyLicenseGroupsPanel';
import { companyLicenseGroups } from '@/lib/companyLicenseGroups';
const id = (n: number) => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');
const mockContext = { actorUserId: id(1), tenantId: id(2) };
const mockPool = { id: id(5), name: 'Office', availableSeats: 2, totalSeats: 2 };
jest.mock('@/lib/companyApplications', () => ({ CompanyApplicationsClient: jest.fn(() => ({ reload: jest.fn(async () => mockContext), list: jest.fn(async () => ({ pools: [mockPool], total: 1 })), dispose: jest.fn() })) }));
jest.mock('@/lib/companyLicenseGroups', () => ({ companyLicenseGroups: { list: jest.fn(), link: jest.fn(), sync: jest.fn(), unlink: jest.fn() } }));
const group = { id: id(4), name: 'Engineering', members: [], createdAt: '2026-10-22T10:00:00.000Z', revision: '1' };
const rule: any = { id: id(3), groupId: group.id, poolId: mockPool.id, status: 'active', revision: '1' };
let rules: any[];
beforeEach(() => {
  jest.clearAllMocks(); rules = [];
  (companyLicenseGroups.list as jest.Mock).mockImplementation(async () => ({ ...mockContext, rules, truncated: false }));
  (companyLicenseGroups.link as jest.Mock).mockImplementation(async () => { rules = [rule]; return rule; });
  (companyLicenseGroups.sync as jest.Mock).mockResolvedValue([{ userId: id(7), status: 'assigned', code: null }]);
  (companyLicenseGroups.unlink as jest.Mock).mockResolvedValue({ ...rule, status: 'unlinked', revision: '2' });
});
async function ready() { await waitFor(() => expect(screen.getByLabelText('Lizenzpool')).toBeEnabled()); }
function reason() { fireEvent.change(screen.getByLabelText('Begründung der Lizenzgruppenänderung'), { target: { value: 'Geprüfte Lizenzgruppenänderung' } }); }
test('an ordinary group needs an explicit pool link; showing it never allocates', async () => {
  render(<CompanyLicenseGroupsPanel group={group} actorUserId={id(1)}/>); await ready();
  expect(screen.getByText('Normale Gruppe: kein Lizenzpool verknüpft.')).toBeInTheDocument(); expect(companyLicenseGroups.sync).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Lizenzpool'), { target: { value: id(5) } }); reason();
  fireEvent.click(screen.getByRole('button', { name: 'Pool verknüpfen und Mitglieder zuweisen' })); await screen.findByText(/1 zugewiesen, 0 entfernt/);
  expect(companyLicenseGroups.link).toHaveBeenCalledWith(group.id, id(5), 'Geprüfte Lizenzgruppenänderung', expect.objectContaining(mockContext));
});
test('a confirmed membership revision triggers reconciliation of existing links', async () => {
  rules = [rule]; const view = render(<CompanyLicenseGroupsPanel group={group} actorUserId={id(1)}/>); await ready();
  view.rerender(<CompanyLicenseGroupsPanel group={{ ...group, revision: '2', members: [id(7)] }} actorUserId={id(1)}/>);
  await screen.findByText(/1 zugewiesen, 0 entfernt/); expect(companyLicenseGroups.sync).toHaveBeenCalledTimes(1);
});
test('keeps a confirmed link visible if the later allocation fails', async () => {
  (companyLicenseGroups.sync as jest.Mock).mockRejectedValue(new Error('Abgleich unbestätigt'));
  render(<CompanyLicenseGroupsPanel group={group} actorUserId={id(1)}/>); await ready(); reason();
  fireEvent.change(screen.getByLabelText('Lizenzpool'), { target: { value: id(5) } }); fireEvent.click(screen.getByRole('button', { name: 'Pool verknüpfen und Mitglieder zuweisen' }));
  await screen.findByRole('alert'); expect(screen.getByRole('button', { name: 'Mitglieder abgleichen' })).toBeInTheDocument(); expect(companyLicenseGroups.link).toHaveBeenCalledTimes(1);
});
test('unlink requires a concrete confirmation and then cleans up that source', async () => {
  rules = [rule]; render(<CompanyLicenseGroupsPanel group={group} actorUserId={id(1)}/>); await ready(); reason();
  fireEvent.click(screen.getByRole('button', { name: 'Pool-Verknüpfung entfernen' })); expect(companyLicenseGroups.unlink).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Verknüpfung verbindlich entfernen' })); await waitFor(() => expect(companyLicenseGroups.sync).toHaveBeenCalled());
  expect((companyLicenseGroups.sync as jest.Mock).mock.calls[0][0].status).toBe('unlinked');
});
