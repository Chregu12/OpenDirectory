import React from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import CompanyOffboardingAccessView from '@/components/views/CompanyOffboardingAccessView';

const actorUserId = '11111111-1111-4111-8111-111111111111';
const userId = '33333333-3333-4333-8333-333333333333';
const workflowId = '44444444-4444-4444-8444-444444444444';
const mockAccess = jest.fn(); const mockGet = jest.fn(); const mockPost = jest.fn();
jest.mock('@/lib/directoryUsers', () => ({ directoryUsers: { access: (...args: unknown[]) => mockAccess(...args) } }));
jest.mock('@/lib/api', () => ({ api: { get: (...args: unknown[]) => mockGet(...args), post: (...args: unknown[]) => mockPost(...args) } }));
beforeEach(() => { jest.resetAllMocks(); mockAccess.mockResolvedValue({ subject: 'actual-person', userId: actorUserId, permissions: ['pim.eligibilities.read'], demoMode: false }); });
function enter(target = userId, workflow = workflowId) {
  fireEvent.change(screen.getByLabelText('Benutzer-ID'), { target: { value: target } }); fireEvent.change(screen.getByLabelText('Vorgangs-ID der Kontosperre'), { target: { value: workflow } });
  fireEvent.click(screen.getByRole('button', { name: 'Arbeitsbereich öffnen' }));
}
test('does not read identity or resources before explicit known-ID submit', () => {
  render(<CompanyOffboardingAccessView />); expect(mockAccess).not.toHaveBeenCalled(); expect(mockGet).not.toHaveBeenCalled(); expect(mockPost).not.toHaveBeenCalled();
});
test('opens standalone collapsed for PIM-only canonical actor with no users.read, company.apps or role read duty', async () => {
  render(<CompanyOffboardingAccessView />); enter();
  const toggle = await screen.findByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' }); expect(toggle).toHaveAttribute('aria-expanded', 'false');
  expect(mockAccess).toHaveBeenCalledTimes(1); expect(mockGet).not.toHaveBeenCalled(); expect(mockPost).not.toHaveBeenCalled();
});
test.each([['', workflowId], ['not-an-id', workflowId], [userId, 'not-a-workflow'], ['ABCDEF12-3333-4333-8333-333333333333', workflowId]])('rejects invalid identifiers %s/%s before identity GET', async (target, workflow) => {
  render(<CompanyOffboardingAccessView />); enter(target, workflow); expect(await screen.findByRole('alert')).toHaveTextContent('Kanonische Benutzer-ID'); expect(mockAccess).not.toHaveBeenCalled(); expect(mockGet).not.toHaveBeenCalled();
});
test.each([{ userId: null, demoMode: false }, { userId: actorUserId, demoMode: true }, { userId: 'not-uuid', demoMode: false }])('rejects unconfirmed actor %# without resources', async access => {
  mockAccess.mockResolvedValue(access); render(<CompanyOffboardingAccessView />); enter(); await screen.findByRole('alert');
  expect(screen.queryByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' })).not.toBeInTheDocument(); expect(mockGet).not.toHaveBeenCalled(); expect(mockPost).not.toHaveBeenCalled();
});
test('denies self target without capabilities request', async () => {
  render(<CompanyOffboardingAccessView />); enter(actorUserId); expect(await screen.findByRole('alert')).toHaveTextContent('Eigene Berechtigungen'); expect(mockGet).not.toHaveBeenCalled();
});
test('input replacement removes old actor and parent-bound panel', async () => {
  render(<CompanyOffboardingAccessView />); enter(); await screen.findByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' });
  fireEvent.change(screen.getByLabelText('Vorgangs-ID der Kontosperre'), { target: { value: userId } });
  expect(screen.queryByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' })).not.toBeInTheDocument(); expect(mockAccess).toHaveBeenCalledTimes(1); expect(mockGet).not.toHaveBeenCalled();
});
test('session change discards pending access response and never opens a stale actor-bound panel', async () => {
  let resolve: (value: any) => void; mockAccess.mockReturnValue(new Promise(complete => { resolve = complete; })); render(<CompanyOffboardingAccessView />); enter();
  act(() => window.dispatchEvent(new Event('od:session-error'))); await act(async () => { resolve({ userId: actorUserId, demoMode: false }); });
  expect(screen.queryByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' })).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Sitzung geändert'); expect(mockGet).not.toHaveBeenCalled();
});
test('failed access is not retried or aliased and explicit retry is available', async () => {
  mockAccess.mockRejectedValueOnce({ response: { status: 403 } }); render(<CompanyOffboardingAccessView />); enter();
  expect(await screen.findByRole('alert')).toHaveTextContent('Separate Rollen- oder PIM-Berechtigung'); expect(mockAccess).toHaveBeenCalledTimes(1); expect(mockGet).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Arbeitsbereich öffnen' })); await waitFor(() => expect(mockAccess).toHaveBeenCalledTimes(2)); await screen.findByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen' });
});
