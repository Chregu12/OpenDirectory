import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import DeviceAgentPanel from '@/components/views/DeviceAgentPanel';
import { readAgent, manageAgent } from '@/lib/deviceAgents';
jest.mock('@/lib/deviceAgents', () => ({ readAgent: jest.fn(), manageAgent: jest.fn() }));
const id = '11111111-1111-4111-8111-111111111111';
const actor = '22222222-2222-4222-8222-222222222222';
const device: any = { id, tenantId: actor, assetId: 'DEVICE-01', serialNumber: 'SERIAL-01', platform: 'linux', lifecycle: 'available', revision: '1' };
const base: any = { revision: '0', status: 'not-enrolled', enrolledAt: null, lastSeen: null, credentialExpiresAt: null, enrollmentExpiresAt: null, report: null, history: { total: 0, page: 1, limit: 25, events: [] } };
const secret = 'odae_' + 'a'.repeat(43);
const onSecurityError = jest.fn(), onBusy = jest.fn();
function mount(extra = {}) { return render(<DeviceAgentPanel device={device} actor={actor} canManage disabled={false} onBusy={onBusy} onSecurityError={onSecurityError} {...extra} />); }
beforeEach(() => { jest.clearAllMocks(); (readAgent as jest.Mock).mockResolvedValue(base); (manageAgent as jest.Mock).mockResolvedValue({ connection: { ...base, revision: '1', status: 'pending', enrollmentExpiresAt: '2026-12-01T12:10:00.000Z' }, enrollmentToken: secret }); });
async function issue() {
 fireEvent.click(await screen.findByRole('button', { name: 'Registrierungscode erstellen' }));
 const dialog = within(screen.getByRole('alertdialog'));
 expect(dialog.getByRole('button', { name: 'Bestätigen' })).toBeDisabled();
 fireEvent.change(dialog.getByLabelText('Begründung'), { target: { value: 'Explizite Registrierung des Firmenlaptops' } });
 fireEvent.click(dialog.getByRole('button', { name: 'Bestätigen' }));
}
test('confirms an audited device-specific enrollment and displays its code once', async () => {
 mount(); await issue(); expect(await screen.findByLabelText('Registrierungscode')).toHaveValue(secret);
 expect(manageAgent).toHaveBeenCalledWith(device, actor, base, 'issue', 'Explizite Registrierung des Firmenlaptops', expect.any(AbortSignal));
 fireEvent.click(screen.getByRole('button', { name: 'Code ausblenden' })); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
 expect(onBusy.mock.calls).toEqual([[true], [false]]);
});
test('readers can see real reports without issuing or revoking credentials', async () => {
 (readAgent as jest.Mock).mockResolvedValue({ ...base, status: 'connected', lastSeen: '2026-11-14T12:00:00.000Z', report: { hostname: 'actual-laptop', architecture: 'aarch64', agentVersion: '1.1.0' } });
 mount({ canManage: false }); await screen.findByText('Online'); expect(screen.getByText('actual-laptop')).toBeInTheDocument();
 expect(screen.queryByRole('button', { name: 'Registrierungscode erstellen' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Gerätezugang widerrufen' })).not.toBeInTheDocument();
});
test.each([401, 403, 428])('original authority errors clear device details through the parent (%s)', async status => {
 (readAgent as jest.Mock).mockRejectedValue({ response: { status } }); mount(); await waitFor(() => expect(onSecurityError).toHaveBeenCalledWith({ response: { status } }));
});
test('session invalidation clears an already displayed secret immediately', async () => {
 mount(); await issue(); await screen.findByLabelText('Registrierungscode'); act(() => window.dispatchEvent(new Event('od:session-error')));
 expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
});
test('a response from an old selected device cannot expose a new credential', async () => {
 let resolve: (value: any) => void = () => {}; (manageAgent as jest.Mock).mockImplementation(() => new Promise(done => { resolve = done; }));
 const result = mount(); await issue(); result.rerender(<DeviceAgentPanel device={{ ...device, id: actor }} actor={actor} canManage disabled={false} onBusy={onBusy} onSecurityError={onSecurityError} />);
 await act(async () => { resolve({ connection: { ...base, status: 'pending' }, enrollmentToken: secret }); }); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
});
test('stale command errors never retry or retain the enrollment dialog', async () => {
 (manageAgent as jest.Mock).mockRejectedValue({ response: { status: 412 } }); mount(); await issue(); await screen.findByRole('alert'); expect(manageAgent).toHaveBeenCalledTimes(1); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
});
