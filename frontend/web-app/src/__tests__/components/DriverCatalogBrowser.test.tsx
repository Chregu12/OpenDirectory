import React from 'react';
import { render, screen, waitFor, within, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DriverCatalogBrowser from '../../components/drivers/DriverCatalogBrowser';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

// ── Sample data ────────────────────────────────────────────────────────────────

const hpEntry = {
  id: 'entry-1',
  source: 'hp',
  name: 'HP LaserJet Pro M404',
  version: '3.2',
  vendor: 'HP',
  os: ['Linux', 'Windows'],
  deviceType: 'printer',
  format: 'PPD',
  architecture: 'x86_64',
  description: 'HP LaserJet driver package',
  downloadUrl: 'https://example.com/hp-driver.ppd',
  models: ['M404dn', 'M404n'],
  fileSize: 1048576,
  tags: [],
  licenseType: 'open-source',
};

const vendorList = [
  { vendor: 'HP', count: 5 },
  { vendor: 'Dell', count: 2 },
];

function mockApi({ vendors = vendorList, results = [hpEntry] as object[] } = {}) {
  mockedApi.get = jest.fn((url: string) => {
    if (url === '/api/printer/catalog/vendors') {
      return Promise.resolve({ data: { vendors } });
    }
    if (url === '/api/printer/catalog/search') {
      return Promise.resolve({ data: { entries: results, total: results.length } });
    }
    return Promise.resolve({ data: {} });
  }) as any;
  mockedApi.post = jest.fn().mockResolvedValue({ data: {} });
}

// The card wrapping a result entry is the element with the "hover:shadow-sm"
// class — scope queries to it so the (identically-labelled) URL-import panel
// button isn't picked up by accident.
function getCard(name: string): HTMLElement {
  return screen.getByText(name).closest('div[class*="hover:shadow-sm"]') as HTMLElement;
}

function getUrlImportPanel(): HTMLElement {
  return screen.getByText('URL-Import').closest('div') as HTMLElement;
}

describe('DriverCatalogBrowser', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockApi();
  });

  // ── Initial load ──────────────────────────────────────────────────────────

  test('loads the vendor list and initial search results on open', async () => {
    render(<DriverCatalogBrowser onClose={jest.fn()} />);

    await waitFor(() => expect(mockedApi.get).toHaveBeenCalledWith('/api/printer/catalog/vendors'));
    await waitFor(() => expect(mockedApi.get).toHaveBeenCalledWith(
      '/api/printer/catalog/search',
      { params: { q: '' } },
    ));

    expect(await screen.findByText('HP LaserJet Pro M404')).toBeInTheDocument();
    // OS badges (scoped to the result card — "Linux"/"Windows" also appear
    // as <option> values in the OS filter select)
    const card = getCard('HP LaserJet Pro M404');
    expect(within(card).getByText('Linux')).toBeInTheDocument();
    expect(within(card).getByText('Windows')).toBeInTheDocument();
    // Device-type badge
    expect(within(card).getByText('printer')).toBeInTheDocument();
    // Vendor sidebar entry
    expect(screen.getByRole('button', { name: /^HP/ })).toBeInTheDocument();
  });

  // ── Search ────────────────────────────────────────────────────────────────

  test('typing a query and clicking Suchen sends the query as the q param', async () => {
    const user = userEvent.setup();
    render(<DriverCatalogBrowser onClose={jest.fn()} />);
    await screen.findByText('HP LaserJet Pro M404');

    const searchInput = screen.getByPlaceholderText(/HP LaserJet/i);
    await user.type(searchInput, 'LaserJet');
    await user.click(screen.getByRole('button', { name: /Suchen/i }));

    await waitFor(() => expect(mockedApi.get).toHaveBeenCalledWith(
      '/api/printer/catalog/search',
      { params: { q: 'LaserJet' } },
    ));
  });

  // ── Vendor filter ─────────────────────────────────────────────────────────

  test('selecting a vendor in the sidebar re-runs the search with a vendor param', async () => {
    const user = userEvent.setup();
    render(<DriverCatalogBrowser onClose={jest.fn()} />);
    await screen.findByText('HP LaserJet Pro M404');

    await user.click(screen.getByRole('button', { name: /^HP/ }));

    await waitFor(() => expect(mockedApi.get).toHaveBeenCalledWith(
      '/api/printer/catalog/search',
      { params: { q: '', vendor: 'hp' } },
    ));
  });

  // ── Import (printer target, default) ────────────────────────────────────

  test('importing a result with the default (printer) target posts to the printer catalog import endpoint', async () => {
    const onImported = jest.fn();
    const user = userEvent.setup();
    render(<DriverCatalogBrowser onClose={jest.fn()} onImported={onImported} />);
    await screen.findByText('HP LaserJet Pro M404');

    const card = getCard('HP LaserJet Pro M404');
    await user.click(within(card).getByRole('button', { name: /Importieren/i }));

    await waitFor(() => expect(mockedApi.post).toHaveBeenCalledWith(
      '/api/printer/catalog/import',
      { entry: hpEntry },
    ));
    expect(await within(card).findByText('Importiert')).toBeInTheDocument();
    expect(onImported).toHaveBeenCalledWith('HP LaserJet Pro M404');
  });

  // ── Import (device target) ──────────────────────────────────────────────

  test('importing a result with importTarget="device" posts to the device driver import endpoint, not the printer one', async () => {
    const onImported = jest.fn();
    const user = userEvent.setup();
    render(<DriverCatalogBrowser onClose={jest.fn()} onImported={onImported} importTarget="device" />);
    await screen.findByText('HP LaserJet Pro M404');

    const card = getCard('HP LaserJet Pro M404');
    await user.click(within(card).getByRole('button', { name: /Importieren/i }));

    await waitFor(() => expect(mockedApi.post).toHaveBeenCalledWith(
      '/api/devices/drivers/import-url',
      expect.objectContaining({
        url: hpEntry.downloadUrl,
        name: hpEntry.name,
        deviceType: hpEntry.deviceType,
      }),
    ));
    expect(mockedApi.post).not.toHaveBeenCalledWith('/api/printer/catalog/import', expect.anything());
    expect(await within(card).findByText('Importiert')).toBeInTheDocument();
    expect(onImported).toHaveBeenCalledWith('HP LaserJet Pro M404');
  });

  // ── URL import panel ──────────────────────────────────────────────────────

  test('URL-import panel sends the English deviceType API value (not the German label) to the printer import-url endpoint by default', async () => {
    const user = userEvent.setup();
    render(<DriverCatalogBrowser onClose={jest.fn()} />);
    await screen.findByText('HP LaserJet Pro M404');

    const panel = getUrlImportPanel();
    await user.type(within(panel).getByPlaceholderText(/download.example.com/i), 'https://vendor.example.com/driver.exe');
    const selects = within(panel).getAllByRole('combobox');
    // Betriebssystem, Gerätetyp, Format — in that DOM order
    await user.selectOptions(selects[1], 'Drucker');

    await act(async () => {
      await user.click(within(panel).getByRole('button', { name: /Importieren/i }));
    });

    await waitFor(() => expect(mockedApi.post).toHaveBeenCalledWith(
      '/api/printer/catalog/import-url',
      expect.objectContaining({ deviceType: 'printer' }),
    ));
  });

  test('URL-import panel posts to the device import endpoint when importTarget="device"', async () => {
    const user = userEvent.setup();
    render(<DriverCatalogBrowser onClose={jest.fn()} importTarget="device" />);
    await screen.findByText('HP LaserJet Pro M404');

    const panel = getUrlImportPanel();
    await user.type(within(panel).getByPlaceholderText(/download.example.com/i), 'https://vendor.example.com/driver.exe');

    await act(async () => {
      await user.click(within(panel).getByRole('button', { name: /Importieren/i }));
    });

    await waitFor(() => expect(mockedApi.post).toHaveBeenCalledWith(
      '/api/devices/drivers/import-url',
      expect.any(Object),
    ));
    expect(mockedApi.post).not.toHaveBeenCalledWith('/api/printer/catalog/import-url', expect.anything());
  });

  // ── Error path ────────────────────────────────────────────────────────────

  test('a failed import shows an error message on the card and does not mark it as imported', async () => {
    mockedApi.post = jest.fn().mockRejectedValue({ response: { data: { error: 'Server nicht erreichbar' } } });
    const user = userEvent.setup();
    render(<DriverCatalogBrowser onClose={jest.fn()} />);
    await screen.findByText('HP LaserJet Pro M404');

    const card = getCard('HP LaserJet Pro M404');
    await act(async () => {
      await user.click(within(card).getByRole('button', { name: /Importieren/i }));
    });

    expect(await within(card).findByText('Server nicht erreichbar')).toBeInTheDocument();
    expect(within(card).queryByText('Importiert')).not.toBeInTheDocument();
  });

  // ── Close ─────────────────────────────────────────────────────────────────

  test('clicking the close button calls onClose', async () => {
    const onClose = jest.fn();
    const user = userEvent.setup();
    render(<DriverCatalogBrowser onClose={onClose} />);
    await screen.findByText('Treiber-Katalog');

    // The header close button is the only icon-only button rendered before
    // any data-dependent buttons exist, so it is always the first button.
    const buttons = screen.getAllByRole('button');
    await user.click(buttons[0]);

    expect(onClose).toHaveBeenCalled();
  });
});
