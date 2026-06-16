import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ComplianceSnapshot from '../../components/views/ComplianceSnapshot';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

describe('ComplianceSnapshot', () => {
  const onClose = jest.fn();
  const onViewChange = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    // Default: API returns mock data
    mockedApi.get = jest.fn().mockResolvedValue({
      data: {
        compliant: 412,
        warning: 87,
        nonCompliant: 36,
        lastScan: new Date().toISOString(),
        topViolations: [
          { policy: 'Disk Encryption Required', count: 23, severity: 'high' },
          { policy: 'OS Updates Pending', count: 41, severity: 'medium' },
        ],
        devicesNeedingAttention: [
          { id: '1', name: 'MBA-legacy-old', issue: 'No disk encryption', os: '🍎' },
        ],
      },
    });
    mockedApi.post = jest.fn().mockResolvedValue({ data: {} });
  });

  test('renders Compliance Snapshot header', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    expect(screen.getByText('Compliance Snapshot')).toBeInTheDocument();
  });

  test('renders Device Compliance Overview section', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('Device Compliance Overview')).toBeInTheDocument();
    });
  });

  test('renders SVG donut chart', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    // SVG is rendered
    const svgElement = document.querySelector('svg');
    expect(svgElement).toBeTruthy();
  });

  test('shows compliance numbers from mock data', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      // Total = 412 + 87 + 36 = 535 shown in SVG
      expect(screen.getByText('535')).toBeInTheDocument();
    });
  });

  test('shows Compliant label', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('Compliant')).toBeInTheDocument();
    });
  });

  test('shows Warning label', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('Warning')).toBeInTheDocument();
    });
  });

  test('shows Non-Compliant label', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('Non-Compliant')).toBeInTheDocument();
    });
  });

  test('shows Top 5 Policy Violations section', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    expect(screen.getByText('Top 5 Policy Violations')).toBeInTheDocument();
  });

  test('shows top violation from mock data', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    // MOCK_DATA in the component has "Disk Encryption Required" violation
    await waitFor(() => {
      expect(screen.getByText('Disk Encryption Required')).toBeInTheDocument();
    });
  });

  test('shows Devices Needing Attention section', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    expect(screen.getByText('Devices Needing Attention')).toBeInTheDocument();
  });

  test('shows Run Scan Now button', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    expect(screen.getByText('Run Scan Now')).toBeInTheDocument();
  });

  test('Run Scan Now calls API', async () => {
    const user = userEvent.setup();
    render(<ComplianceSnapshot onClose={onClose} />);
    await user.click(screen.getByText('Run Scan Now'));
    await waitFor(() => {
      expect(mockedApi.post).toHaveBeenCalledWith('/api/scanner/scan', {});
    });
  });

  test('shows Full Report button', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    expect(screen.getByText('Full Report →')).toBeInTheDocument();
  });

  test('Full Report button calls onViewChange with compliance', async () => {
    const user = userEvent.setup();
    render(<ComplianceSnapshot onClose={onClose} onViewChange={onViewChange} />);
    await user.click(screen.getByText('Full Report →'));
    expect(onViewChange).toHaveBeenCalledWith('compliance');
    expect(onClose).toHaveBeenCalled();
  });

  test('shows devices needing attention from MOCK_DATA', async () => {
    // Default mock data in component has MBA-legacy-old
    mockedApi.get = jest.fn().mockRejectedValue(new Error('API fail'));
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('MBA-legacy-old')).toBeInTheDocument();
    });
  });

  test('device issue text is shown', async () => {
    mockedApi.get = jest.fn().mockRejectedValue(new Error('API fail'));
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('No disk encryption')).toBeInTheDocument();
    });
  });

  test('shows Last scan time', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    expect(screen.getByText(/Last scan:/i)).toBeInTheDocument();
  });

  test('severity badges shown for violations', async () => {
    mockedApi.get = jest.fn().mockRejectedValue(new Error('API fail'));
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      // MOCK_DATA has 'high' severity violations
      expect(screen.getAllByText('high').length).toBeGreaterThan(0);
    });
  });

  test('close button calls onClose', async () => {
    const user = userEvent.setup();
    render(<ComplianceSnapshot onClose={onClose} />);
    // X button in header
    const closeButtons = screen.getAllByRole('button');
    const xButton = closeButtons.find(btn => btn.querySelector('svg'));
    if (xButton) {
      await user.click(xButton);
    }
    // Or click via the header close button
    const buttons = screen.getAllByRole('button');
    await user.click(buttons[0]);
    expect(onClose).toHaveBeenCalled();
  });
});
