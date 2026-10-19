import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import PolicyCommandPanel from '@/components/views/PolicyCommandPanel';
import { policyCommands, OwnedPolicyCommand, PolicyCancellationReceipt } from '@/lib/policyCommands';
import { policyGovernance } from '@/lib/policyGovernance';
jest.mock('@/lib/policyCommands', () => ({ policyCommands: { list: jest.fn(), cancel: jest.fn() } }));
jest.mock('@/lib/policyGovernance', () => ({ policyGovernance: { access: jest.fn() } }));
const model = policyCommands as jest.Mocked<typeof policyCommands>; const authority = policyGovernance as jest.Mocked<typeof policyGovernance>;
const userId = '11111111-1111-4111-8111-111111111111'; const resourceId = '22222222-2222-4222-8222-222222222222'; const commandId = '33333333-3333-4333-8333-333333333333';
const access = { schemaVersion: 4 as const, subject: 'owned-operator', userId, permissions: ['policies.deploy'], freshMfa: true, writeAuthenticationMaxAgeSeconds: 300 as const };
const command: OwnedPolicyCommand = { id: commandId, status: 'pending', previouslyOffered: false, cancellationReceipt: null, enforcementConfirmed: false,
  policyReceipt: { schemaVersion: 1, commandId, operationId: resourceId, deviceId: 'owned-device', deviceGeneration: '1', operatorUserId: userId, reference: { resourceKind: 'blueprint', resourceId, resourceVersion: 3, publicationId: commandId, configurationId: commandId }, configurationVersion: 2, configurationHash: 'a'.repeat(64), publicationVersion: 2, payloadHash: 'b'.repeat(64), expiresAt: '2025-01-01T00:00:00.000Z', persistence: 'committed' } };
const reason = 'Stop this exact known device command';
beforeEach(() => {
  jest.resetAllMocks(); Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: () => '44444444-4444-4444-8444-444444444444' });
  model.list.mockResolvedValue({ commands: [command], truncated: false }); authority.access.mockResolvedValue(access);
  model.cancel.mockImplementation(async (original, actor, operationId, justification): Promise<PolicyCancellationReceipt> => ({ schemaVersion: 1, commandId: original.commandId, deviceId: original.deviceId, operationId, cancelledByUserId: actor,
    cancelledAt: '2026-01-01T00:00:00.000Z', reason: justification, previouslyOffered: false, policyReceipt: original, persistence: 'committed', furtherOffersStopped: true, enforcementConfirmed: false }));
});
const stage = async () => { fireEvent.click(await screen.findByRole('button', { name: 'Eigenen Geräteauftrag stoppen prüfen' })); fireEvent.change(screen.getByLabelText('Begründung der Auftragsstornierung'), { target: { value: reason } }); fireEvent.click(screen.getByRole('checkbox')); };
test('fresh deployers recover their own SQL history and must explicitly confirm one exact command before a stop', async () => {
  render(<PolicyCommandPanel resourceId={resourceId} access={access} refresh={0} />); await screen.findByText(`Geräteauftrag ${commandId} · Abholfrist ${command.policyReceipt.expiresAt}`);
  fireEvent.click(screen.getByRole('button', { name: 'Eigenen Geräteauftrag stoppen prüfen' })); expect(screen.getByRole('button', { name: 'Geräteauftrag verbindlich stoppen' })).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Begründung der Auftragsstornierung'), { target: { value: reason } }); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Geräteauftrag verbindlich stoppen' }));
  await screen.findByText(/Weitere Angebote dieses Auftrags gestoppt/); expect(model.cancel).toHaveBeenCalledWith(command.policyReceipt, userId, '44444444-4444-4444-8444-444444444444', reason);
  expect(screen.queryByRole('button', { name: 'Eigenen Geräteauftrag stoppen prüfen' })).not.toBeInTheDocument(); expect(screen.getByText(/Status cancelled/)).toBeInTheDocument();
});
test.each([{ ...access, permissions: ['policies.read'] }, { ...access, freshMfa: false }])('read-only or stale-factor viewers have no owned mutation purpose', async viewer => {
  render(<PolicyCommandPanel resourceId={resourceId} access={viewer} refresh={0} />); expect(screen.getByText(/benötigen Zustellberechtigung/)).toBeInTheDocument(); expect(model.list).not.toHaveBeenCalled(); expect(model.cancel).not.toHaveBeenCalled();
});
test('changed canonical actor or lost fresh MFA stops a captured cancellation before any command write', async () => {
  authority.access.mockResolvedValue({ ...access, userId: resourceId }); render(<PolicyCommandPanel resourceId={resourceId} access={access} refresh={0} />); await stage(); fireEvent.click(screen.getByRole('button', { name: 'Geräteauftrag verbindlich stoppen' }));
  await screen.findByRole('alert'); expect(model.cancel).not.toHaveBeenCalled(); expect(screen.queryByRole('group', { name: 'Geräteauftrag stoppen bestätigen' })).not.toBeInTheDocument();
});
test('an unconfirmed write is not replayed and a later explicit read recovers its actual retained result', async () => {
  model.cancel.mockRejectedValue(new Error('Acknowledgement lost')); render(<PolicyCommandPanel resourceId={resourceId} access={access} refresh={0} />); await stage(); fireEvent.click(screen.getByRole('button', { name: 'Geräteauftrag verbindlich stoppen' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('nicht blind wiederholen'); expect(model.cancel).toHaveBeenCalledTimes(1);
  model.list.mockResolvedValue({ commands: [{ ...command, status: 'cancelled', cancellationReceipt: { reason } as PolicyCancellationReceipt }], truncated: false }); fireEvent.click(screen.getByRole('button', { name: 'Gespeicherten Auftragsstatus neu laden' }));
  await screen.findByText(/Status cancelled/); expect(model.cancel).toHaveBeenCalledTimes(1);
});
test('a failed read cannot look like an empty fleet; pagination is explicit rather than silently omitting older commands', async () => {
  model.list.mockResolvedValue({ commands: [command], truncated: true }); render(<PolicyCommandPanel resourceId={resourceId} access={access} refresh={0} />); await screen.findByText(/Weitere eigene Aufträge vorhanden/);
  model.list.mockRejectedValue(new Error('Owned SQL unavailable')); fireEvent.click(screen.getByRole('button', { name: 'Ältere Aufträge' })); await screen.findByRole('alert');
  expect(model.list).toHaveBeenLastCalledWith(resourceId, userId, 200); expect(screen.queryByText('Keine eigenen Aufträge in diesem Ausschnitt.')).not.toBeInTheDocument();
});
test('a late history response after a resource switch cannot revive another blueprint command or pending confirmation', async () => {
  let complete!: (value: { commands: OwnedPolicyCommand[]; truncated: boolean }) => void; model.list.mockReturnValueOnce(new Promise(resolve => { complete = resolve; }));
  const view = render(<PolicyCommandPanel resourceId={resourceId} access={access} refresh={0} />); model.list.mockResolvedValue({ commands: [], truncated: false }); view.rerender(<PolicyCommandPanel resourceId={commandId} access={access} refresh={0} />);
  await screen.findByText('Keine eigenen Aufträge in diesem Ausschnitt.'); complete({ commands: [command], truncated: false }); await waitFor(() => expect(screen.queryByText(/Geräteauftrag 33333333/)).not.toBeInTheDocument());
});
