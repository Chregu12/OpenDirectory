import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import toast from 'react-hot-toast';
import DeviceEnrollmentWizard from '@/components/setup/DeviceEnrollmentWizard';
import { api, deviceApi } from '@/lib/api';

jest.mock('@/lib/api', () => ({
  api: { post: jest.fn() },
  deviceApi: { getEnrollmentToken: jest.fn() },
}));

const devices = [
  { deviceName: 'workstation-01', platform: 'windows', serialNumber: 'SN12345' },
  { deviceName: 'server-02', platform: 'linux', serialNumber: '' },
];
const csv = 'deviceName,platform,serialNumber\nworkstation-01,windows,SN12345\nserver-02,linux,';
const onClose = jest.fn();
const post = api.post as jest.Mock;

function bulkResponse() {
  return {
    total: 2,
    succeeded: 2,
    failed: 0,
    results: devices.map((device, index) => ({
      index,
      deviceName: device.deviceName,
      success: true,
      result: {
        success: true,
        deviceId: `device-${index}`,
        computerDn: `CN=${device.deviceName},CN=Computers,DC=opendirectory,DC=local`,
        platform: device.platform,
        enrollmentUrl: null,
        platformConfig: {},
        nextSteps: ['Verify the endpoint configuration'],
        completedSteps: [
          'create-device-record',
          'create-ad-computer',
          ...(device.platform === 'windows'
            ? ['configure-winrm', 'push-windows-gpo']
            : ['generate-sssd-config', 'create-kerberos-keytab', 'push-linux-hardening-policy']),
        ].map(name => ({ name, ok: true })),
      },
      error: null,
    })),
  };
}

function submitBulk() {
  const view = render(<DeviceEnrollmentWizard onClose={onClose} />);
  fireEvent.click(screen.getByRole('button', { name: 'Bulk Enroll' }));
  fireEvent.change(screen.getByLabelText('CSV Input'), { target: { value: csv } });
  fireEvent.click(screen.getByRole('button', { name: 'Enroll 2 Devices' }));
  return view;
}

beforeEach(() => {
  jest.clearAllMocks();
  post.mockReset();
});

test('keeps the original four platform choices', () => {
  render(<DeviceEnrollmentWizard onClose={onClose} />);
  for (const name of ['Windows', 'macOS', 'Linux', 'Drucker / Scanner']) {
    expect(screen.getByText(name)).toBeInTheDocument();
  }
  expect(screen.queryByText('iOS')).not.toBeInTheDocument();
  expect(screen.queryByText('Android')).not.toBeInTheDocument();
  expect(post).not.toHaveBeenCalled();
});

test.each(['windows', 'macos', 'linux'] as const)('%s single enrollment is unavailable without token requests, random tokens or executable instructions', platform => {
  const random = jest.spyOn(Math, 'random').mockReturnValue(0.123456789);
  try {
    const { container } = render(<DeviceEnrollmentWizard onClose={onClose} initialPlatform={platform} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Token-basiertes Einzel-Enrollment ist derzeit nicht verfügbar.');
    expect(screen.getByRole('link', { name: 'Gerätebestand ansehen' })).toHaveAttribute('href', '/devices');
    expect(container.querySelector('pre, code')).toBeNull();
    expect(container.textContent).not.toMatch(/od-enroll-|Gültig bis|bereits hinzugefügt|TOKEN/);
    expect(deviceApi.getEnrollmentToken).not.toHaveBeenCalled();
    expect(post).not.toHaveBeenCalled();
    expect(random).not.toHaveBeenCalled();
    expect(toast.success).not.toHaveBeenCalled();
  } finally {
    random.mockRestore();
  }
});

test('changing platforms and finishing never counts a device as enrolled', () => {
  render(<DeviceEnrollmentWizard onClose={onClose} initialPlatform="windows" />);
  fireEvent.click(screen.getByRole('button', { name: 'Andere Plattform auswählen' }));
  fireEvent.click(screen.getByText('Linux'));
  expect(screen.getByRole('alert')).toHaveTextContent('Einzel-Enrollment ist derzeit nicht verfügbar');
  expect(screen.queryByText(/bereits hinzugefügt/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Fertig' }));
  expect(onClose).toHaveBeenCalledTimes(1);
  expect(post).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
});

test('preserves printer discovery instructions and navigation without submitting inert printer fields', () => {
  const { container } = render(<DeviceEnrollmentWizard onClose={onClose} initialPlatform="printer" />);
  expect(container.querySelector('pre')).toHaveTextContent(`${window.location.origin}/api/printers/discover`);
  expect(container.querySelector('pre')).toHaveTextContent('192.168.1.0/24');
  expect(screen.getByText(/Drucker-Name, IP-Adresse und Protokoll/)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Druckerverwaltung öffnen' })).toHaveAttribute('href', '/printers');
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(deviceApi.getEnrollmentToken).not.toHaveBeenCalled();
  expect(post).not.toHaveBeenCalled();
});

test('printer discovery commands are copied only on request', async () => {
  const user = userEvent.setup();
  const clipboard = jest.spyOn(navigator.clipboard, 'writeText');
  render(<DeviceEnrollmentWizard onClose={onClose} initialPlatform="printer" />);
  expect(clipboard).not.toHaveBeenCalled();
  await act(async () => { await user.click(screen.getByTitle('Kopieren')); });
  expect(clipboard).toHaveBeenCalledWith(expect.stringContaining('/api/printers/discover'));
  expect(toast.success).toHaveBeenCalledWith('Printer Discovery kopiert');
  expect(post).not.toHaveBeenCalled();
  clipboard.mockRestore();
});

test('reports clipboard failure without claiming the command was copied', async () => {
  const user = userEvent.setup();
  const clipboard = jest.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('Clipboard denied'));
  render(<DeviceEnrollmentWizard onClose={onClose} initialPlatform="printer" />);
  await act(async () => { await user.click(screen.getByTitle('Kopieren')); });
  expect(toast.error).toHaveBeenCalledWith('Kopieren fehlgeschlagen');
  expect(toast.success).not.toHaveBeenCalled();
  clipboard.mockRestore();
});

test('submits the existing bulk contract and renders confirmed per-device steps', async () => {
  post.mockResolvedValue({ data: bulkResponse() });
  submitBulk();
  await screen.findByText('Enrollment Results');
  expect(post).toHaveBeenCalledTimes(1);
  expect(post).toHaveBeenCalledWith('/api/quick/devices/bulk-enroll', { devices });
  expect(screen.getAllByText('success')).toHaveLength(2);
  const rows = screen.getAllByRole('row').slice(1);
  expect(within(rows[0]).getByText(/configure-winrm: ok/)).toBeInTheDocument();
  expect(within(rows[1]).getByText(/create-kerberos-keytab: ok/)).toBeInTheDocument();
  expect(toast.success).toHaveBeenCalledWith('Backend confirmed all 2 enrollment workflows. Check device inventory for device status.');
  expect(screen.getByRole('link', { name: 'Gerätebestand ansehen' })).toHaveAttribute('href', '/devices');
});

test('renders a real partial orchestration failure from result.error and completedSteps', async () => {
  const data = bulkResponse();
  post.mockResolvedValue({ data: {
    ...data,
    succeeded: 1,
    failed: 1,
    results: [data.results[0], {
      ...data.results[1],
      success: false,
      result: {
        ...data.results[1].result,
        success: false,
        error: 'Kerberos unavailable',
        completedSteps: [{ name: 'create-kerberos-keytab', ok: false, error: 'Kerberos unavailable' }],
      },
    }],
  } });
  submitBulk();
  await screen.findByText('Enrollment Results');
  expect(screen.getAllByText('success')).toHaveLength(1);
  expect(screen.getAllByText('failed')).toHaveLength(1);
  expect(screen.getByText('Kerberos unavailable')).toBeInTheDocument();
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledWith('Backend confirmed 1/2 enrollment workflows. Check results for errors.');
});

test('renders the real rejected-item contract with a null result', async () => {
  const data = bulkResponse();
  post.mockResolvedValue({ data: {
    ...data,
    succeeded: 1,
    failed: 1,
    results: [data.results[0], { index: 1, deviceName: devices[1].deviceName, success: false, result: null, error: 'Event publishing failed' }],
  } });
  submitBulk();
  await screen.findByText('Enrollment Results');
  expect(screen.getByText('Event publishing failed')).toBeInTheDocument();
  expect(screen.getAllByText('success')).toHaveLength(1);
  expect(screen.getAllByText('failed')).toHaveLength(1);
  expect(toast.success).not.toHaveBeenCalled();
});

const invalidResponses: [string, (data: ReturnType<typeof bulkResponse>) => unknown][] = [
  ['missing results', () => ({})],
  ['null response', () => null],
  ['empty results', data => ({ ...data, results: [] })],
  ['non-array results', data => ({ ...data, results: {} })],
  ['incomplete results', data => ({ ...data, results: data.results.slice(0, 1) })],
  ['incorrect total', data => ({ ...data, total: 3 })],
  ['inconsistent summary counts', data => ({ ...data, succeeded: 0, failed: 2 })],
  ['unexpected envelope', data => ({ data })],
  ['old status-only results', data => ({ ...data, results: devices.map(device => ({ deviceName: device.deviceName, status: 'success' })) })],
  ['unmatched device name', data => ({ ...data, results: [{ ...data.results[0], deviceName: 'another-device' }, data.results[1]] })],
  ['duplicate index', data => ({ ...data, results: [data.results[0], { ...data.results[1], index: 0 }] })],
  ['non-boolean success', data => ({ ...data, results: [{ ...data.results[0], success: 'true' }, data.results[1]] })],
  ['missing nested evidence', data => ({ ...data, results: [{ ...data.results[0], result: {} }, data.results[1]] })],
  ['contradictory nested success', data => ({ ...data, results: [{ ...data.results[0], result: { ...data.results[0].result, success: false } }, data.results[1]] })],
  ['wrong platform', data => ({ ...data, results: [{ ...data.results[0], result: { ...data.results[0].result, platform: 'macos' } }, data.results[1]] })],
  ['missing device ID', data => ({ ...data, results: [{ ...data.results[0], result: { ...data.results[0].result, deviceId: '' } }, data.results[1]] })],
  ['missing steps', data => ({ ...data, results: [{ ...data.results[0], result: { ...data.results[0].result, completedSteps: [] } }, data.results[1]] })],
  ['invalid step status', data => ({ ...data, results: [{ ...data.results[0], result: { ...data.results[0].result, completedSteps: [{ name: 'create-device-record', ok: 'yes' }] } }, data.results[1]] })],
  ['failed step inside reported success', data => ({ ...data, results: [{ ...data.results[0], result: { ...data.results[0].result, completedSteps: [{ name: 'create-device-record', ok: false }] } }, data.results[1]] })],
  ['success with null result', data => ({ ...data, results: [{ ...data.results[0], result: null }, data.results[1]] })],
];

test.each(invalidResponses)('%s cannot become fabricated bulk success', async (_name, invalidResponse) => {
  post.mockResolvedValue({ data: invalidResponse(bulkResponse()) });
  submitBulk();
  await screen.findByText('Enrollment Results');
  expect(screen.getAllByText('unconfirmed')).toHaveLength(2);
  expect(screen.queryByText('success')).not.toBeInTheDocument();
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledWith(expect.stringContaining('Check device inventory before retrying.'));
  expect(post).toHaveBeenCalledTimes(1);
});

test.each([[401, 'unauthorized'], [403, 'forbidden'], [500, 'downstream unavailable']])('HTTP %s errors remain unconfirmed and surface the handler error', async (status, error) => {
  post.mockRejectedValue({ response: { status, data: { error } } });
  submitBulk();
  await screen.findByText('Enrollment Results');
  expect(screen.getAllByText('unconfirmed')).toHaveLength(2);
  expect(toast.error).toHaveBeenCalledWith(expect.stringContaining(String(error)));
  expect(toast.success).not.toHaveBeenCalled();
  expect(post).toHaveBeenCalledTimes(1);
});

test('a lost response does not imply either successful enrollment or a safe automatic retry', async () => {
  post.mockRejectedValue(new Error('Network disconnected'));
  submitBulk();
  await screen.findByText('Enrollment Results');
  expect(screen.getAllByText('unconfirmed')).toHaveLength(2);
  expect(toast.error).toHaveBeenCalledWith(expect.stringContaining('Network disconnected'));
  expect(toast.success).not.toHaveBeenCalled();
  expect(post).toHaveBeenCalledTimes(1);
});

test('invalid CSV blocks submission of an otherwise valid subset', () => {
  render(<DeviceEnrollmentWizard onClose={onClose} />);
  fireEvent.click(screen.getByRole('button', { name: 'Bulk Enroll' }));
  fireEvent.change(screen.getByLabelText('CSV Input'), { target: { value: 'valid,windows,SN1\ninvalid' } });
  const enroll = screen.getByRole('button', { name: 'Enroll 1 Device' });
  expect(enroll).toBeDisabled();
  fireEvent.click(enroll);
  expect(post).not.toHaveBeenCalled();
});

test('unknown platforms cannot produce an enrollment with skipped platform steps', () => {
  render(<DeviceEnrollmentWizard onClose={onClose} />);
  fireEvent.click(screen.getByRole('button', { name: 'Bulk Enroll' }));
  fireEvent.change(screen.getByLabelText('CSV Input'), { target: { value: 'printer-01,printer,SN1' } });
  expect(screen.getByText(/unsupported platform/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Enroll Devices' })).toBeDisabled();
  expect(post).not.toHaveBeenCalled();
});

test('an in-flight bulk submission locks the submitted CSV and prevents duplicate enrollment', async () => {
  let resolveRequest: (response: { data: unknown }) => void;
  post.mockReturnValue(new Promise(resolve => { resolveRequest = resolve; }));
  submitBulk();
  expect(screen.getByLabelText('CSV Input')).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Single Device' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Bulk Enroll' })).toBeDisabled();
  const submit = screen.getByRole('button', { name: 'Enrolling…' });
  expect(submit).toBeDisabled();
  fireEvent.click(submit);
  expect(post).toHaveBeenCalledTimes(1);
  await act(async () => resolveRequest({ data: bulkResponse() }));
  await screen.findByText('Enrollment Results');
});

test.each(['resolve', 'reject'])('a late bulk %s after unmount cannot report results or toast success in a new wizard', async outcome => {
  let resolveRequest: (response: { data: unknown }) => void;
  let rejectRequest: (error: Error) => void;
  post.mockReturnValue(new Promise((resolve, reject) => { resolveRequest = resolve; rejectRequest = reject; }));
  const view = submitBulk();
  view.unmount();
  render(<DeviceEnrollmentWizard onClose={onClose} />);
  await act(async () => {
    if (outcome === 'resolve') resolveRequest({ data: bulkResponse() });
    else rejectRequest(new Error('Late response failure'));
  });
  await waitFor(() => expect(screen.getByText('Gerät hinzufügen')).toBeInTheDocument());
  expect(screen.queryByText('Enrollment Results')).not.toBeInTheDocument();
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).not.toHaveBeenCalled();
  expect(post).toHaveBeenCalledTimes(1);
});
