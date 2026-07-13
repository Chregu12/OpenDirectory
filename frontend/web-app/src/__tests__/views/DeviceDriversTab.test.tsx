import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DeviceDriversTab from '../../components/views/tabs/DeviceDriversTab';
import { api } from '../../lib/api';
import toast from 'react-hot-toast';

const mockedApi = api as jest.Mocked<typeof api>;
const mockedToast = toast as unknown as { success: jest.Mock; error: jest.Mock };

// ─── Sample data ────────────────────────────────────────────────────────────────

const driverArrayOs = {
  id: 'drv-1',
  name: 'Intel Wi-Fi 6 AX200',
  version: '22.190.0',
  vendor: 'Intel',
  deviceType: 'network',
  format: 'inf',
  os: ['windows', 'linux'],
  architecture: 'x64',
  source: 'catalog',
};

const driverStringOs = {
  id: 'drv-2',
  name: 'Legacy Sound Card',
  version: '1.0',
  vendor: 'Creative',
  deviceType: 'audio',
  os: 'windows', // legacy record: os stored as a plain string, not an array
};

const recWithApt = {
  id: 'rec-1',
  name: 'Realtek Ethernet Driver',
  version: '2.5',
  deviceType: 'network',
  os: ['linux'],
  aptPackage: 'firmware-realtek',
};

const recWithDownload = {
  id: 'rec-2',
  name: 'NVIDIA Display Driver',
  version: '535.1',
  deviceType: 'display',
  os: ['windows'],
  downloadUrl: 'https://example.com/nvidia-driver.exe',
  vendor: 'NVIDIA',
  format: 'exe',
  description: 'GPU driver',
};

const recWithoutDownload = {
  id: 'rec-3',
  name: 'Unknown USB Controller',
  deviceType: 'usb',
  os: ['windows'],
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mockDriversList(drivers: object[]) {
  mockedApi.get.mockImplementation((url: string) => {
    if (url === '/api/devices/drivers') {
      return Promise.resolve({ data: { success: true, data: drivers } });
    }
    return Promise.resolve({ data: { success: true, data: [] } });
  });
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('DeviceDriversTab', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedApi.get = jest.fn().mockResolvedValue({ data: { success: true, data: [] } });
    mockedApi.post = jest.fn().mockResolvedValue({ data: { success: true } });
    mockedApi.delete = jest.fn().mockResolvedValue({ data: { success: true } });
  });

  // ── Installed drivers list ───────────────────────────────────────────────

  test('renders installed drivers with name, version and badges', async () => {
    mockDriversList([driverArrayOs]);
    render(<DeviceDriversTab />);

    await screen.findByText('Intel Wi-Fi 6 AX200');
    expect(screen.getByText('v22.190.0')).toBeInTheDocument();
    expect(screen.getByText('Intel')).toBeInTheDocument();
    expect(screen.getByText('network')).toBeInTheDocument();
    expect(screen.getByText('inf')).toBeInTheDocument();
    expect(screen.getByText('windows')).toBeInTheDocument();
    expect(screen.getByText('linux')).toBeInTheDocument();
    expect(screen.getByText('x64')).toBeInTheDocument();
    expect(screen.getByText('· catalog')).toBeInTheDocument();
  });

  test('shows empty state with catalog button when no drivers are installed', async () => {
    mockDriversList([]);
    render(<DeviceDriversTab />);

    await screen.findByText('Keine Geräte-Treiber installiert');
    expect(
      screen.getByRole('button', { name: /Treiber-Katalog öffnen/i })
    ).toBeInTheDocument();
  });

  test('renders a driver whose "os" field is a plain string without crashing', async () => {
    mockDriversList([driverStringOs]);
    render(<DeviceDriversTab />);

    await screen.findByText('Legacy Sound Card');
    // toOsList() should wrap the string into a single-item array
    expect(screen.getByText('windows')).toBeInTheDocument();
  });

  test('renders a driver whose "os" field is an array without crashing', async () => {
    mockDriversList([driverArrayOs]);
    render(<DeviceDriversTab />);

    await screen.findByText('Intel Wi-Fi 6 AX200');
    expect(screen.getByText('windows')).toBeInTheDocument();
    expect(screen.getByText('linux')).toBeInTheDocument();
  });

  test('a failing initial load does not crash and shows a retry option', async () => {
    mockedApi.get = jest.fn().mockRejectedValue(new Error('network down'));
    render(<DeviceDriversTab />);

    await screen.findByText('Treiber konnten nicht geladen werden');
    expect(screen.getByRole('button', { name: /Erneut versuchen/i })).toBeInTheDocument();
  });

  // ── Upload ────────────────────────────────────────────────────────────────

  test('uploading a file posts FormData with a "driver" field, toasts success and reloads the list', async () => {
    const user = userEvent.setup();
    mockDriversList([]);
    render(<DeviceDriversTab />);
    await screen.findByText('Keine Geräte-Treiber installiert');

    const file = new File(['binarydata'], 'wifi-driver.inf', { type: 'text/plain' });
    const input = screen.getByLabelText(/Treiber hochladen/i) as HTMLInputElement;

    await user.upload(input, file);

    await waitFor(() => expect(mockedApi.post).toHaveBeenCalledTimes(1));
    const [url, body] = mockedApi.post.mock.calls[0];
    expect(url).toBe('/api/devices/drivers/upload');
    expect(body).toBeInstanceOf(FormData);
    expect((body as FormData).get('driver')).toBeInstanceOf(File);
    expect(((body as FormData).get('driver') as File).name).toBe('wifi-driver.inf');

    await waitFor(() => expect(mockedToast.success).toHaveBeenCalled());
    // Initial load + reload after upload = 2 GET calls for the drivers list
    await waitFor(() =>
      expect(
        mockedApi.get.mock.calls.filter(c => c[0] === '/api/devices/drivers').length
      ).toBe(2)
    );
  });

  // ── Recommendations panel ────────────────────────────────────────────────

  test('fetching recommendations for a hostname calls the driver-recommendations endpoint', async () => {
    const user = userEvent.setup();
    mockedApi.get = jest.fn().mockImplementation((url: string) => {
      if (url === '/api/devices/drivers') return Promise.resolve({ data: { success: true, data: [] } });
      if (url === '/api/devices/DESKTOP-AB1234/driver-recommendations') {
        return Promise.resolve({ data: { recommendations: [recWithApt, recWithDownload] } });
      }
      return Promise.resolve({ data: {} });
    });
    render(<DeviceDriversTab />);
    await screen.findByText('Keine Geräte-Treiber installiert');

    const hostInput = screen.getByPlaceholderText(/Hostname eingeben/i);
    await user.type(hostInput, 'DESKTOP-AB1234');
    await user.click(screen.getByRole('button', { name: /Empfehlungen laden/i }));

    await waitFor(() =>
      expect(mockedApi.get).toHaveBeenCalledWith(
        '/api/devices/DESKTOP-AB1234/driver-recommendations'
      )
    );
  });

  test('recommendation with an aptPackage renders an apt-install snippet', async () => {
    const user = userEvent.setup();
    mockedApi.get = jest.fn().mockImplementation((url: string) => {
      if (url === '/api/devices/drivers') return Promise.resolve({ data: { success: true, data: [] } });
      if (url.includes('driver-recommendations')) {
        return Promise.resolve({ data: { recommendations: [recWithApt] } });
      }
      return Promise.resolve({ data: {} });
    });
    render(<DeviceDriversTab />);
    await screen.findByText('Keine Geräte-Treiber installiert');

    const hostInput = screen.getByPlaceholderText(/Hostname eingeben/i);
    await user.type(hostInput, 'host1{Enter}');

    await screen.findByText('Realtek Ethernet Driver');
    expect(screen.getByText(/apt install firmware-realtek/i)).toBeInTheDocument();
  });

  test('recommendation with a downloadUrl renders an enabled Importieren button', async () => {
    const user = userEvent.setup();
    mockedApi.get = jest.fn().mockImplementation((url: string) => {
      if (url === '/api/devices/drivers') return Promise.resolve({ data: { success: true, data: [] } });
      if (url.includes('driver-recommendations')) {
        return Promise.resolve({ data: { recommendations: [recWithDownload] } });
      }
      return Promise.resolve({ data: {} });
    });
    render(<DeviceDriversTab />);
    await screen.findByText('Keine Geräte-Treiber installiert');

    const hostInput = screen.getByPlaceholderText(/Hostname eingeben/i);
    await user.type(hostInput, 'host1{Enter}');

    await screen.findByText('NVIDIA Display Driver');
    const importBtn = screen.getByRole('button', { name: /Importieren/i });
    expect(importBtn).toBeEnabled();
  });

  // ── Import a recommendation ──────────────────────────────────────────────

  test('importing a recommendation posts to import-url and flips the button to "Importiert"', async () => {
    const user = userEvent.setup();
    mockedApi.get = jest.fn().mockImplementation((url: string) => {
      if (url === '/api/devices/drivers') return Promise.resolve({ data: { success: true, data: [] } });
      if (url.includes('driver-recommendations')) {
        return Promise.resolve({ data: { recommendations: [recWithDownload] } });
      }
      return Promise.resolve({ data: {} });
    });
    render(<DeviceDriversTab />);
    await screen.findByText('Keine Geräte-Treiber installiert');

    const hostInput = screen.getByPlaceholderText(/Hostname eingeben/i);
    await user.type(hostInput, 'host1{Enter}');
    await screen.findByText('NVIDIA Display Driver');

    await user.click(screen.getByRole('button', { name: /Importieren/i }));

    await waitFor(() =>
      expect(mockedApi.post).toHaveBeenCalledWith(
        '/api/devices/drivers/import-url',
        expect.objectContaining({
          url: recWithDownload.downloadUrl,
          name: recWithDownload.name,
        })
      )
    );

    expect(await screen.findByRole('button', { name: /Importiert/i })).toBeDisabled();
  });

  // ── Error paths ───────────────────────────────────────────────────────────

  test('a recommendation without downloadUrl or aptPackage renders a disabled import button', async () => {
    const user = userEvent.setup();
    mockedApi.get = jest.fn().mockImplementation((url: string) => {
      if (url === '/api/devices/drivers') return Promise.resolve({ data: { success: true, data: [] } });
      if (url.includes('driver-recommendations')) {
        return Promise.resolve({ data: { recommendations: [recWithoutDownload] } });
      }
      return Promise.resolve({ data: {} });
    });
    render(<DeviceDriversTab />);
    await screen.findByText('Keine Geräte-Treiber installiert');

    const hostInput = screen.getByPlaceholderText(/Hostname eingeben/i);
    await user.type(hostInput, 'host1{Enter}');
    await screen.findByText('Unknown USB Controller');

    const importBtn = screen.getByRole('button', { name: /Importieren/i });
    expect(importBtn).toBeDisabled();
  });

  test('a failing recommendations lookup does not crash and shows the no-results message', async () => {
    const user = userEvent.setup();
    mockedApi.get = jest.fn().mockImplementation((url: string) => {
      if (url === '/api/devices/drivers') return Promise.resolve({ data: { success: true, data: [] } });
      if (url.includes('driver-recommendations')) {
        return Promise.reject(new Error('lookup failed'));
      }
      return Promise.resolve({ data: {} });
    });
    render(<DeviceDriversTab />);
    await screen.findByText('Keine Geräte-Treiber installiert');

    const hostInput = screen.getByPlaceholderText(/Hostname eingeben/i);
    await user.type(hostInput, 'host1{Enter}');

    await screen.findByText(/Keine Empfehlungen gefunden/i);
    expect(mockedToast.error).toHaveBeenCalled();
  });

  // ── Delete ────────────────────────────────────────────────────────────────

  test('deleting a driver calls api.delete and removes the row after confirmation', async () => {
    const user = userEvent.setup();
    (window as any).confirm = jest.fn().mockReturnValue(true);
    mockDriversList([driverArrayOs]);
    render(<DeviceDriversTab />);

    await screen.findByText('Intel Wi-Fi 6 AX200');
    await user.click(screen.getByTitle('Treiber löschen'));

    await waitFor(() =>
      expect(mockedApi.delete).toHaveBeenCalledWith('/api/devices/drivers/drv-1')
    );
    await waitFor(() =>
      expect(screen.queryByText('Intel Wi-Fi 6 AX200')).not.toBeInTheDocument()
    );
  });

  test('declining the confirmation dialog does not call api.delete', async () => {
    const user = userEvent.setup();
    (window as any).confirm = jest.fn().mockReturnValue(false);
    mockDriversList([driverArrayOs]);
    render(<DeviceDriversTab />);

    await screen.findByText('Intel Wi-Fi 6 AX200');
    await user.click(screen.getByTitle('Treiber löschen'));

    expect(mockedApi.delete).not.toHaveBeenCalled();
    expect(screen.getByText('Intel Wi-Fi 6 AX200')).toBeInTheDocument();
  });
});
