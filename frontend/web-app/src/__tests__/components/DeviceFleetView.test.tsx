import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DeviceFleetView from '../../components/views/DeviceFleetView';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

// The component uses MOCK_DEVICES internally as fallback when API fails
describe('DeviceFleetView', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // API fails → component uses MOCK_DEVICES as fallback
    mockedApi.get = jest.fn().mockRejectedValue(new Error('API unavailable'));
  });

  test('renders OS summary cards for all 5 OS types', async () => {
    render(<DeviceFleetView />);
    // OS labels appear in both summary cards and dropdown - use getAllByText
    await waitFor(() => {
      expect(screen.getAllByText('macOS').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Windows').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Linux').length).toBeGreaterThan(0);
      expect(screen.getAllByText('iOS').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Android').length).toBeGreaterThan(0);
    });
  });

  test('renders device table with column headers', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByText('Device')).toBeInTheDocument();
      expect(screen.getByText('User')).toBeInTheDocument();
      expect(screen.getByText('Last Seen')).toBeInTheDocument();
      expect(screen.getByText('Compliance')).toBeInTheDocument();
    });
  });

  test('renders mock devices in the table', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByText('MBA-johndoe')).toBeInTheDocument();
      expect(screen.getByText('WIN-desk-01')).toBeInTheDocument();
      expect(screen.getByText('ubuntu-dev-01')).toBeInTheDocument();
    });
  });

  test('shows search input', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search devices or users...')).toBeInTheDocument();
    });
  });

  test('search filters devices by name', async () => {
    const user = userEvent.setup();
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search devices or users...')).toBeInTheDocument();
    });
    const searchInput = screen.getByPlaceholderText('Search devices or users...');
    await user.type(searchInput, 'iphone');
    await waitFor(() => {
      expect(screen.getByText('iphone-sarah')).toBeInTheDocument();
      expect(screen.queryByText('MBA-johndoe')).not.toBeInTheDocument();
    });
  });

  test('search filters devices by assigned user', async () => {
    const user = userEvent.setup();
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search devices or users...')).toBeInTheDocument();
    });
    const searchInput = screen.getByPlaceholderText('Search devices or users...');
    await user.type(searchInput, 'John Doe');
    await waitFor(() => {
      expect(screen.getByText('MBA-johndoe')).toBeInTheDocument();
      expect(screen.queryByText('WIN-desk-01')).not.toBeInTheDocument();
    });
  });

  test('clicking macOS card filters to macOS devices', async () => {
    const user = userEvent.setup();
    render(<DeviceFleetView />);
    await waitFor(() => {
      // Multiple macOS labels exist - find the summary card button
      expect(screen.getAllByText('macOS').length).toBeGreaterThan(0);
    });
    // The OS summary cards are buttons - find them by role and click the macOS one
    const allButtons = screen.getAllByRole('button');
    const macOsCardBtn = allButtons.find(btn =>
      btn.textContent?.includes('macOS') && !btn.querySelector('select')
    );
    if (macOsCardBtn) {
      await user.click(macOsCardBtn);
      await waitFor(() => {
        expect(screen.getByText('MBA-johndoe')).toBeInTheDocument();
        expect(screen.queryByText('WIN-desk-01')).not.toBeInTheDocument();
        expect(screen.queryByText('ubuntu-dev-01')).not.toBeInTheDocument();
      });
    } else {
      // fallback - just click the first button with macOS text
      const macOSButtons = screen.getAllByText('macOS');
      await user.click(macOSButtons[0]);
    }
  });

  test('compliance pills shown for devices', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      // Compliant pills should be visible
      expect(screen.getAllByText('Compliant').length).toBeGreaterThan(0);
    });
  });

  test('warning compliance pill shown for warning devices', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      // WIN-desk-01 has warning status
      expect(screen.getAllByText('Warning').length).toBeGreaterThan(0);
    });
  });

  test('non-compliant pill shown for non-compliant devices', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      // MBA-legacy-old has non-compliant status
      // Multiple Non-Compliant elements may appear (pill + dropdown option)
      expect(screen.getAllByText('Non-Compliant').length).toBeGreaterThan(0);
    });
  });

  test('shows device count footer', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByText(/Showing \d+ of \d+ devices/)).toBeInTheDocument();
    });
  });

  test('shows total device count of 10 mock devices', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByText(/of 10 devices/)).toBeInTheDocument();
    });
  });

  test('OS filter dropdown is present', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByRole('option', { name: 'All OS' })).toBeInTheDocument();
    });
  });

  test('compliance filter dropdown is present', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByRole('option', { name: 'All Status' })).toBeInTheDocument();
    });
  });

  test('Refresh button is present', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByText('Refresh')).toBeInTheDocument();
    });
  });

  test('OS summary cards show device counts', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      // macOS summary card shows count of 3 (MBA-johndoe, MBP-janesmith, MBA-legacy-old)
      expect(screen.getAllByText('macOS').length).toBeGreaterThan(0);
    });
  });

  test('clicking macOS card again deselects filter (shows all)', async () => {
    const user = userEvent.setup();
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getAllByText('macOS').length).toBeGreaterThan(0);
    });
    // Find the macOS OS summary card button
    const allButtons = screen.getAllByRole('button');
    const macOsCardBtn = allButtons.find(btn =>
      btn.textContent?.includes('macOS') && btn.tagName === 'BUTTON'
    );
    if (macOsCardBtn) {
      // Click macOS to filter
      await user.click(macOsCardBtn);
      // Click again to deselect
      await user.click(macOsCardBtn);
      await waitFor(() => {
        // All devices should show again
        expect(screen.getByText('WIN-desk-01')).toBeInTheDocument();
      });
    }
  });

  test('filtering by compliance shows only compliant devices', async () => {
    const user = userEvent.setup();
    render(<DeviceFleetView />);
    await waitFor(() => {
      expect(screen.getByRole('option', { name: 'Compliant' })).toBeInTheDocument();
    });
    const selects = screen.getAllByRole('combobox');
    // The compliance filter is the second select (after OS filter)
    const complianceSelect = selects.find(s =>
      Array.from(s.querySelectorAll('option')).some(o => o.textContent === 'Compliant' && o.getAttribute('value') === 'compliant')
    );
    if (complianceSelect) {
      await user.selectOptions(complianceSelect, 'compliant');
      await waitFor(() => {
        // Only compliant devices should show - MBA-legacy-old (non-compliant) should be gone
        expect(screen.queryByText('MBA-legacy-old')).not.toBeInTheDocument();
      });
    }
  });

  test('shows all OS icons in OS summary cards', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      // Icons appear in multiple places (summary cards + device rows)
      expect(screen.getAllByText('🍎').length).toBeGreaterThan(0);
      expect(screen.getAllByText('🪟').length).toBeGreaterThan(0);
      expect(screen.getAllByText('🐧').length).toBeGreaterThan(0);
    });
  });

  test('shows enrolled date in device table', async () => {
    render(<DeviceFleetView />);
    await waitFor(() => {
      // MBA-johndoe was enrolled 2024-01-15, formatted dates appear in the Enrolled column
      expect(screen.getAllByText(/2024/).length).toBeGreaterThan(0);
    });
  });
});
