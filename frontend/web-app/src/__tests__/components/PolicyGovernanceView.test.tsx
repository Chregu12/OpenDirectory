import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import PolicyGovernanceView from '@/components/views/PolicyGovernanceView';
import { policyGovernance } from '@/lib/policyGovernance';
jest.mock('@/lib/policyGovernance', () => ({ policyGovernance: { access: jest.fn(), list: jest.fn(), create: jest.fn(), transition: jest.fn() } }));
jest.mock('@/components/views/PolicyPublicationPanel', () => ({ __esModule: true, default: ({ onSelect, access }: { onSelect: (id: string) => void; access: { permissions: string[] } }) => access.permissions.includes('policies.deploy') ? require('react').createElement('button', { onClick: () => onSelect('33333333-3333-4333-8333-333333333333') }, 'Test gespeicherte Freigabe auswählen') : null }));
const mock = policyGovernance as jest.Mocked<typeof policyGovernance>;
const userId = '11111111-1111-4111-8111-111111111111';
const row = { id: '22222222-2222-4222-8222-222222222222', name: 'Owned policy', type: 'security', platform: 'all', status: 'draft', version: 1, settings: {}, created_by: userId };
const access = { schemaVersion: 4 as const, subject: 'operator', userId, permissions: ['policies.read', 'policies.manage', 'policies.deploy'], freshMfa: true, writeAuthenticationMaxAgeSeconds: 300 as const };
beforeEach(() => { jest.resetAllMocks(); mock.access.mockResolvedValue(access); mock.list.mockResolvedValue({ policies: [row], total: 1 }); });
test('read-only operators receive real data without configuration or deployment controls', async () => {
  mock.access.mockResolvedValue({ ...access, permissions: ['policies.read'] }); render(<PolicyGovernanceView />);
  expect(await screen.findByText('Owned policy')).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Aktivierung prüfen' })).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Name der Richtlinie')).not.toBeInTheDocument(); expect(mock.create).not.toHaveBeenCalled();
});
test('unavailable authority shows no sample policies or success-only local controls', async () => {
  mock.access.mockRejectedValue(new Error('Owned authority unavailable')); render(<PolicyGovernanceView />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Keine Beispieldaten'); expect(mock.list).not.toHaveBeenCalled(); expect(screen.queryByText('Owned policy')).not.toBeInTheDocument();
});
test('stale MFA disables writes even with a held configuration role', async () => {
  mock.access.mockResolvedValue({ ...access, freshMfa: false }); render(<PolicyGovernanceView />); await screen.findByText('Owned policy');
  expect(screen.getByRole('button', { name: 'Richtlinienentwurf prüfen' })).toBeDisabled(); expect(screen.getByRole('button', { name: 'Aktivierung prüfen' })).toBeDisabled();
});
test('stages exact draft content, requires acknowledgement and confirms a real server receipt', async () => {
  mock.create.mockResolvedValue({ ...row, id: '33333333-3333-4333-8333-333333333333', name: 'Confirmed policy' }); render(<PolicyGovernanceView />); await screen.findByText('Owned policy');
  fireEvent.change(screen.getByLabelText('Name der Richtlinie'), { target: { value: 'Confirmed policy' } });
  fireEvent.click(screen.getByRole('button', { name: 'Richtlinienentwurf prüfen' }));
  expect(screen.getByRole('button', { name: 'Richtlinienänderung verbindlich bestätigen' })).toBeDisabled(); expect(mock.create).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Begründung der Richtlinienänderung'), { target: { value: 'Owned exact policy change confirmation' } }); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Richtlinienänderung verbindlich bestätigen' }));
  await screen.findByText('Richtlinienentwurf im kanonischen Dienst bestätigt.'); expect(mock.create).toHaveBeenCalledWith({ name: 'Confirmed policy', type: 'security', platform: 'all', settings: {} }, userId, 'Owned exact policy change confirmation'); expect(mock.create).toHaveBeenCalledTimes(1);
});
test('a changed original actor or session discards the captured mutation and late responses', async () => {
  render(<PolicyGovernanceView />); await screen.findByText('Owned policy'); fireEvent.click(screen.getByRole('button', { name: 'Test gespeicherte Freigabe auswählen' })); fireEvent.click(screen.getByRole('button', { name: 'Aktivierung prüfen' }));
  mock.access.mockResolvedValue({ ...access, subject: 'someone-else', userId: row.id }); fireEvent.change(screen.getByLabelText('Begründung der Richtlinienänderung'), { target: { value: 'Owned exact policy change confirmation' } }); fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Richtlinienänderung verbindlich bestätigen' })); await screen.findByRole('alert'); expect(mock.transition).not.toHaveBeenCalled();
  expect(screen.queryByText('Owned policy')).not.toBeInTheDocument();
  await act(async () => window.dispatchEvent(new Event('od:session-error'))); expect(screen.queryByRole('group', { name: 'Richtlinienänderung bestätigen' })).not.toBeInTheDocument();
});
test('an unconfirmed write is never retried or optimistically shown as applied', async () => {
  mock.transition.mockRejectedValue(new Error('Owned lost receipt')); render(<PolicyGovernanceView />); await screen.findByText('Owned policy');
  fireEvent.click(screen.getByRole('button', { name: 'Test gespeicherte Freigabe auswählen' })); fireEvent.click(screen.getByRole('button', { name: 'Aktivierung prüfen' })); fireEvent.change(screen.getByLabelText('Begründung der Richtlinienänderung'), { target: { value: 'Owned exact policy change confirmation' } }); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Richtlinienänderung verbindlich bestätigen' }));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('nicht blind wiederholen')); expect(mock.transition).toHaveBeenCalledTimes(1); expect(screen.queryByText('Owned policy')).not.toBeInTheDocument();
});
