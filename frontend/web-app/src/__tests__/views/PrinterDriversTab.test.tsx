import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PrinterDriversTab from '../../components/views/tabs/PrinterDriversTab';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

// ── Sample drivers ────────────────────────────────────────────────────────────

const driverWithStringOs = {
  id: 'drv-1',
  name: 'HP LaserJet Pro',
  version: '2.1',
  vendor: 'HP',
  format: 'PPD',
  os: 'linux',
  source: 'openprinting',
};

const driverWithArrayOs = {
  id: 'drv-2',
  name: 'Dell Universal Printer',
  version: '5.0',
  vendor: 'Dell',
  format: 'EXE',
  os: ['Windows', 'macOS'],
};

function mockDrivers(drivers: object[]) {
  mockedApi.get = jest.fn().mockResolvedValue({ data: { drivers } });
}

describe('PrinterDriversTab', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockDrivers([]);
    mockedApi.post = jest.fn().mockResolvedValue({ data: {} });
    mockedApi.delete = jest.fn().mockResolvedValue({ data: {} });
  });

  // ── List rendering ────────────────────────────────────────────────────────

  test('renders drivers fetched from GET /api/printer/drivers', async () => {
    mockDrivers([driverWithStringOs]);
    render(<PrinterDriversTab />);
    await waitFor(() => expect(mockedApi.get).toHaveBeenCalledWith('/api/printer/drivers'));
    expect(await screen.findByText('HP LaserJet Pro')).toBeInTheDocument();
    expect(screen.getByText('HP')).toBeInTheDocument();
    expect(screen.getByText('PPD')).toBeInTheDocument();
  });

  test('shows empty state when no drivers are installed', async () => {
    render(<PrinterDriversTab />);
    await waitFor(() => expect(screen.getByText('Keine Treiber installiert')).toBeInTheDocument());
  });

  // ── toOsList: string vs array ────────────────────────────────────────────

  test('renders a single OS badge when os is a plain string', async () => {
    mockDrivers([driverWithStringOs]);
    render(<PrinterDriversTab />);
    await screen.findByText('HP LaserJet Pro');
    expect(screen.getByText('linux')).toBeInTheDocument();
  });

  test('renders multiple OS badges when os is an array', async () => {
    mockDrivers([driverWithArrayOs]);
    render(<PrinterDriversTab />);
    await screen.findByText('Dell Universal Printer');
    expect(screen.getByText('Windows')).toBeInTheDocument();
    expect(screen.getByText('macOS')).toBeInTheDocument();
  });

  // ── Upload ────────────────────────────────────────────────────────────────

  test('uploading a file posts FormData with field "driver" to the upload endpoint', async () => {
    const user = userEvent.setup();
    render(<PrinterDriversTab />);
    await waitFor(() => expect(screen.getByText('Keine Treiber installiert')).toBeInTheDocument());

    const file = new File(['dummy'], 'driver.ppd', { type: 'application/octet-stream' });
    const input = screen.getByLabelText(/Treiber hochladen/i) as HTMLInputElement;
    await user.upload(input, file);

    await waitFor(() => expect(mockedApi.post).toHaveBeenCalledWith(
      '/api/printer/drivers/upload',
      expect.any(FormData),
      expect.objectContaining({ headers: { 'Content-Type': 'multipart/form-data' } }),
    ));
    const formData = (mockedApi.post as jest.Mock).mock.calls[0][1] as FormData;
    expect(formData.get('driver')).toBe(file);
  });

  // ── Delete ────────────────────────────────────────────────────────────────

  test('deleting a driver calls DELETE after confirm() and removes it from the list', async () => {
    mockDrivers([driverWithStringOs]);
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    const user = userEvent.setup();
    render(<PrinterDriversTab />);
    await screen.findByText('HP LaserJet Pro');

    const deleteBtn = screen.getByTitle('Treiber löschen');
    await user.click(deleteBtn);

    await waitFor(() => expect(mockedApi.delete).toHaveBeenCalledWith('/api/printer/drivers/drv-1'));
    await waitFor(() => expect(screen.queryByText('HP LaserJet Pro')).not.toBeInTheDocument());
    confirmSpy.mockRestore();
  });

  test('declining the confirm() dialog does not call DELETE', async () => {
    mockDrivers([driverWithStringOs]);
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    const user = userEvent.setup();
    render(<PrinterDriversTab />);
    await screen.findByText('HP LaserJet Pro');

    await user.click(screen.getByTitle('Treiber löschen'));

    expect(mockedApi.delete).not.toHaveBeenCalled();
    expect(screen.getByText('HP LaserJet Pro')).toBeInTheDocument();
    confirmSpy.mockRestore();
  });

  // ── Error path ────────────────────────────────────────────────────────────

  test('does not crash and shows a retry option when GET /api/printer/drivers rejects', async () => {
    mockedApi.get = jest.fn().mockRejectedValue(new Error('network down'));
    render(<PrinterDriversTab />);
    await waitFor(() => expect(screen.getByText('Treiber konnten nicht geladen werden')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: /Erneut versuchen/i })).toBeInTheDocument();
  });

  // ── Catalog modal ─────────────────────────────────────────────────────────

  test('clicking "Aus Katalog" opens the driver catalog browser', async () => {
    const user = userEvent.setup();
    render(<PrinterDriversTab />);
    await waitFor(() => expect(screen.getByText('Keine Treiber installiert')).toBeInTheDocument());

    await user.click(screen.getByText('Aus Katalog'));
    expect(await screen.findByText('Treiber-Katalog')).toBeInTheDocument();
  });
});
