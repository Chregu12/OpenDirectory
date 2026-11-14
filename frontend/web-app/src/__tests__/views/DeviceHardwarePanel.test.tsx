import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import DeviceHardwarePanel from '@/components/views/DeviceHardwarePanel';
import { api } from '@/lib/api';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn() } }));
const id = '11111111-1111-4111-8111-111111111111', actor = '22222222-2222-4222-8222-222222222222';
const device: any = { id, tenantId: actor, platform: 'linux', revision: '1' };
const envelope = () => ({ schemaVersion: 1, inventoryProtocol: 1, actorUserId: actor, tenantId: actor, deviceId: id, checkedAt: '2026-11-14T12:01:00.000Z', connectionStatus: 'connected', status: 'current', inventory: { schemaVersion: 1, receivedAt: '2026-11-14T12:00:00.000Z', enrolledAt: '2026-11-14T11:00:00.000Z', revision: '3', platform: 'linux', agentVersion: '1.2.0', facts: { schemaVersion: 1, cpu: { model: 'Actual fixture CPU', logicalProcessors: 8 }, memory: { totalBytes: '34359738368', availableBytes: '17179869184' }, systemDisk: null, uptimeSeconds: '86461' } } });
beforeEach(() => jest.resetAllMocks());
test('renders actual measured capacity, unknown disk, source time and independent compliance meaning', async () => {
 (api.get as jest.Mock).mockResolvedValue({ status: 200, data: envelope() });
 render(<DeviceHardwarePanel device={device} actor={actor} connection={{} as any} onSecurityError={jest.fn()} />);
 await screen.findByText('Actual fixture CPU'); expect(screen.getByText('8 logische Prozessoren')).toBeInTheDocument(); expect(screen.getByText('32 GiB gesamt')).toBeInTheDocument();
 expect(screen.getByRole('progressbar', { name: 'Arbeitsspeicher belegt' })).toHaveAttribute('value', '50'); expect(screen.getByText('Unbekannt')).toBeInTheDocument(); expect(screen.getByText(/keine Compliance-Bestätigung/)).toBeInTheDocument();
});
test('fresh MFA rejection is propagated and does not display measurements', async () => {
 const failed = jest.fn(); (api.get as jest.Mock).mockRejectedValue({ response: { status: 428 } });
 render(<DeviceHardwarePanel device={device} actor={actor} connection={{} as any} onSecurityError={failed} />);
 await waitFor(() => expect(failed).toHaveBeenCalled()); expect(screen.queryByText('Actual fixture CPU')).not.toBeInTheDocument();
});
test('a late response after resource change cannot repopulate the former device', async () => {
 let resolve: (value: any) => void; (api.get as jest.Mock).mockReturnValueOnce(new Promise(done => { resolve = done; })).mockResolvedValueOnce({ status: 200, data: { ...envelope(), deviceId: actor, status: 'missing', inventory: null } });
 const connection: any = {}; const view = render(<DeviceHardwarePanel device={device} actor={actor} connection={connection} onSecurityError={jest.fn()} />);
 view.rerender(<DeviceHardwarePanel device={{ ...device, id: actor }} actor={actor} connection={connection} onSecurityError={jest.fn()} />); await screen.findByText(/Noch keine Systemdaten/);
 resolve!({ status: 200, data: envelope() }); await waitFor(() => expect(screen.queryByText('Actual fixture CPU')).not.toBeInTheDocument());
});
