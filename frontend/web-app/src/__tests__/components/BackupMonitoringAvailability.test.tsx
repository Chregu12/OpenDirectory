import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import toast from 'react-hot-toast';
import BackupRecoveryWizard from '@/components/setup/BackupRecoveryWizard';
import MonitoringAlertingWizard from '@/components/setup/MonitoringAlertingWizard';
import { api } from '@/lib/api';

const mockGet = jest.fn();
let storageWrite: jest.SpyInstance;

beforeEach(() => {
  jest.clearAllMocks();
  localStorage.clear();
  storageWrite = jest.spyOn(Storage.prototype, 'setItem');
  mockGet.mockReset().mockResolvedValue({ data: {} });
  api.get = mockGet;
});

afterEach(() => {
  expect(api.post).not.toHaveBeenCalled();
  expect(api.put).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  expect(storageWrite).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
  storageWrite.mockRestore();
});

describe.each([
  {
    name: 'Backup',
    Component: BackupRecoveryWizard,
    routes: ['/api/backup/status'],
    href: '/backup',
    linkName: 'Zur Backup-Übersicht',
  },
  {
    name: 'Monitoring',
    Component: MonitoringAlertingWizard,
    routes: ['/api/prometheus/status', '/api/grafana/status', '/api/monitoring/status'],
    href: '/monitoring',
    linkName: 'Zur Monitoring-Übersicht',
  },
])('$name setup availability', ({ Component, routes, href, linkName }) => {
  test('explains unsupported setup accessibly, keeps status reads and the real view link', async () => {
    const onClose = jest.fn();
    render(<Component onClose={onClose} />);

    expect(screen.getByRole('status', { name: /Einrichtung nicht verfügbar \(Unsupported\)/ })).toHaveTextContent('nicht implementiert');
    expect(screen.getByRole('link', { name: linkName })).toHaveAttribute('href', href);
    expect(screen.queryByRole('button', { name: /aktivieren|Test-Backup|Dashboard erstellen|Weiter/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText(/wird geladen/)).not.toBeInTheDocument());
    expect(mockGet.mock.calls).toEqual(routes.map(route => [route]));
    expect(onClose).not.toHaveBeenCalled();
  });

  test('Schliessen only closes and never applies setup', async () => {
    const onClose = jest.fn();
    render(<Component onClose={onClose} />);
    await waitFor(() => expect(screen.queryByText(/wird geladen/)).not.toBeInTheDocument());
    await userEvent.setup().click(screen.getByRole('button', { name: 'Schliessen' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('Abbrechen preserves the caller close behavior', async () => {
    const onClose = jest.fn();
    render(<Component onClose={onClose} />);
    await waitFor(() => expect(screen.queryByText(/wird geladen/)).not.toBeInTheDocument());
    await userEvent.setup().click(screen.getByRole('button', { name: 'Abbrechen' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test.each([
    ['unauthenticated', { response: { status: 401, data: { error: 'Anmeldung erforderlich' } } }, 'Anmeldung erforderlich'],
    ['forbidden', { response: { status: 403, data: { error: 'Zugriff verweigert' } } }, 'Zugriff verweigert'],
    ['missing handler', { response: { status: 404, data: { error: 'Endpoint nicht gefunden' } } }, 'Endpoint nicht gefunden'],
    ['network failure', new Error('Backend nicht erreichbar'), 'Backend nicht erreichbar'],
  ])('shows %s read failures without success or writes', async (_name, error, message) => {
    mockGet.mockRejectedValue(error);
    const onClose = jest.fn();
    render(<Component onClose={onClose} />);

    const alerts = await screen.findAllByRole('alert');
    expect(alerts).toHaveLength(routes.length);
    alerts.forEach(alert => expect(alert).toHaveTextContent(String(message)));
    expect(screen.getByRole('status')).toHaveTextContent('Unsupported');
    expect(screen.queryByText(/Noch keins|Verbunden|erfolgreich|abgeschlossen/)).not.toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Schliessen' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

test('backup displays returned status values without claiming setup is available', async () => {
  mockGet.mockResolvedValue({ data: { lastBackup: null, totalBackups: 7, storageUsed: '1.5 GB' } });
  render(<BackupRecoveryWizard onClose={jest.fn()} />);

  const overview = screen.getByRole('region', { name: 'Backup-Status' });
  expect(await within(overview).findByText('7')).toBeInTheDocument();
  expect(within(overview).getByText('1.5 GB')).toBeInTheDocument();
  expect(within(overview).getByText('Unbekannt')).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Unsupported');
});

test('an incomplete backup read does not invent an empty or successful backup history', async () => {
  render(<BackupRecoveryWizard onClose={jest.fn()} />);
  expect(await screen.findAllByText('Unbekannt')).toHaveLength(3);
  expect(screen.queryByText('Noch keins')).not.toBeInTheDocument();
  expect(screen.queryByText('0')).not.toBeInTheDocument();
});

test('monitoring displays actual service states instead of assuming healthy from HTTP success', async () => {
  mockGet.mockImplementation((url: string) => Promise.resolve({
    data: { status: url === '/api/prometheus/status' ? 'unhealthy' : url === '/api/grafana/status' ? 'unknown' : 'degraded' },
  }));
  render(<MonitoringAlertingWizard onClose={jest.fn()} />);

  const overview = screen.getByRole('region', { name: 'Service-Status' });
  expect(await within(overview).findByText('unhealthy')).toBeInTheDocument();
  expect(within(overview).getByText('unknown')).toBeInTheDocument();
  expect(within(overview).getByText('degraded')).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Unsupported');
});

test('a missing system handler preserves independent Prometheus and Grafana reads', async () => {
  mockGet.mockImplementation((url: string) => url === '/api/monitoring/status'
    ? Promise.reject(new Error('System-Handler nicht implementiert'))
    : Promise.resolve({ data: { status: 'healthy' } }));
  render(<MonitoringAlertingWizard onClose={jest.fn()} />);

  expect(await screen.findByRole('alert')).toHaveTextContent('System-Handler nicht implementiert');
  expect(screen.getAllByText('healthy')).toHaveLength(2);
  expect(mockGet).toHaveBeenCalledTimes(3);
});

test.each([null, [], { lastBackup: 'not-a-date' }, { totalBackups: -1 }, { totalBackups: 1.5 }, { totalBackups: {} }, { storageUsed: {} }])('malformed backup observations remain unavailable instead of rendering misleading counters (%#)', async data => {
  mockGet.mockResolvedValue({ data }); render(<BackupRecoveryWizard onClose={jest.fn()} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Unbestätigter Backup-Status');
  expect(screen.getByRole('status')).toHaveTextContent('Unsupported');
});

test('an absent successful monitoring response is unknown, not a healthy service or a setup completion', async () => {
  mockGet.mockResolvedValue(undefined); render(<MonitoringAlertingWizard onClose={jest.fn()} />);
  await waitFor(() => expect(screen.getAllByText('Unbekannt')).toHaveLength(3));
  expect(screen.getByRole('status')).toHaveTextContent('Unsupported');
});
