import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import CompanyPimPanel from '@/components/views/CompanyPimPanel';
import { companyPim } from '@/lib/companyPim';
import { companyPimApprovals } from '@/lib/companyPimApprovals';
jest.mock('@/hooks/useIdentityAccess', () => ({ useIdentityAccess: () => ({ access: { userId: 'actor', companyPimProtocol: 1, companyPimApprovalProtocol: 1 }, can: () => false }) }));
jest.mock('@/lib/companyPim', () => ({ companyPim: { self: jest.fn(), activate: jest.fn() } }));
jest.mock('@/lib/companyPimApprovals', () => ({ companyPimApprovals: { options: jest.fn(), create: jest.fn() } }));
jest.mock('@/components/views/CompanyPimRequestPanel', () => () => <p>Aktueller Antrag</p>);
const eligibility = { id: 'eligible', scopeType: 'tenant' };
beforeEach(() => {
  jest.clearAllMocks(); (companyPim.self as jest.Mock).mockResolvedValue({ tenantId: 'tenant', canActivate: true, total: 1, items: [{ role: { name: 'Engineering' }, eligibility, maximumDurationSeconds: 36000 }] });
  (companyPimApprovals.options as jest.Mock).mockResolvedValue({ canRequest: true, approvalRequired: true, maximumDurationSeconds: 61 });
  (companyPimApprovals.create as jest.Mock).mockResolvedValue({}); (companyPim.activate as jest.Mock).mockResolvedValue({});
});
async function open() {
  render(<CompanyPimPanel />); fireEvent.click(await screen.findByRole('button', { name: 'Aktivieren', exact: true })); const dialog = await screen.findByRole('alertdialog');
  fireEvent.change(within(dialog).getByLabelText('Begründung'), { target: { value: 'Diese konkrete Engineering-Aufgabe ist erforderlich' } }); return dialog;
}
test('keeps a short authoritative approval limit exact and requests without activating', async () => {
  const dialog = await open(); expect(within(dialog).getByLabelText('Gewünschte Dauer')).toHaveValue('61'); fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(companyPimApprovals.create).toHaveBeenCalledTimes(1));
  expect(companyPimApprovals.create).toHaveBeenCalledWith('actor', 'tenant', eligibility, expect.objectContaining({ maximumDurationSeconds: 61 }), 61, 'Diese konkrete Engineering-Aufgabe ist erforderlich', expect.any(AbortSignal)); expect(companyPim.activate).not.toHaveBeenCalled();
});
test('custom minutes produce one exact direct activation in seconds', async () => {
  (companyPimApprovals.options as jest.Mock).mockResolvedValue({ canRequest: true, approvalRequired: false, maximumDurationSeconds: 5400 }); const dialog = await open();
  fireEvent.change(within(dialog).getByLabelText('Gewünschte Dauer'), { target: { value: 'custom' } }); fireEvent.change(within(dialog).getByLabelText('Dauer (Minuten)'), { target: { value: '1.5' } }); fireEvent.click(within(dialog).getByRole('button', { name: 'Bestätigen' }));
  await waitFor(() => expect(companyPim.activate).toHaveBeenCalledTimes(1)); expect(companyPim.activate).toHaveBeenCalledWith('actor', 'tenant', eligibility, 90, 'Diese konkrete Engineering-Aufgabe ist erforderlich', expect.any(AbortSignal)); expect(companyPimApprovals.create).not.toHaveBeenCalled();
});
test('custom duration cannot exceed the independently loaded approval limit', async () => {
  const dialog = await open(); fireEvent.change(within(dialog).getByLabelText('Gewünschte Dauer'), { target: { value: 'custom' } }); fireEvent.change(within(dialog).getByLabelText('Dauer (Minuten)'), { target: { value: '2' } });
  expect(within(dialog).getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); expect(companyPimApprovals.create).not.toHaveBeenCalled(); expect(companyPim.activate).not.toHaveBeenCalled();
});
