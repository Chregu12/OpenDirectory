import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ComplianceSnapshot from '../../components/views/ComplianceSnapshot';

// ComplianceSnapshot talks to the quick-actions service directly via raw
// `fetch` (GET /api/quick/compliance/snapshot, POST /api/quick/policies/deploy),
// not the axios-based `api` client. Mock global.fetch accordingly.

const SNAPSHOT_DATA = {
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
};

function mockFetch(snapshotData: object | null = SNAPSHOT_DATA) {
  global.fetch = jest.fn((url: any) => {
    const u = String(url);
    if (u.includes('/api/quick/compliance/snapshot')) {
      if (snapshotData === null) {
        return Promise.resolve({ ok: false, status: 500, json: async () => ({}) } as any);
      }
      return Promise.resolve({ ok: true, json: async () => snapshotData } as any);
    }
    // /api/quick/policies/deploy (Run Scan Now) and anything else
    return Promise.resolve({ ok: true, json: async () => ({}) } as any);
  }) as any;
}

describe('ComplianceSnapshot', () => {
  const onClose = jest.fn();
  const onViewChange = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch();
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

  test('renders SVG donut chart once data has loaded', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      // Total = 412 + 87 + 36 = 535, rendered in the donut's center label
      expect(screen.getByText('535')).toBeInTheDocument();
    });
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

  test('shows Top Policy Violations section', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('Top Policy Violations')).toBeInTheDocument();
    });
  });

  test('shows top violation from mock data', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('Disk Encryption Required')).toBeInTheDocument();
    });
  });

  test('shows Devices Needing Attention section', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('Devices Needing Attention')).toBeInTheDocument();
    });
  });

  test('shows Run Scan Now button', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    expect(screen.getByText('Run Scan Now')).toBeInTheDocument();
  });

  test('Run Scan Now calls the quick-actions deploy endpoint', async () => {
    const user = userEvent.setup();
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => expect(screen.getByText('535')).toBeInTheDocument());
    await user.click(screen.getByText('Run Scan Now'));
    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        '/api/quick/policies/deploy',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ targetType: 'all', dryRun: false }),
        })
      );
    });
  });

  test('shows Full Report button', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    expect(screen.getByText('Full Report')).toBeInTheDocument();
  });

  test('Full Report button calls onViewChange with compliance', async () => {
    const user = userEvent.setup();
    render(<ComplianceSnapshot onClose={onClose} onViewChange={onViewChange} />);
    await user.click(screen.getByText('Full Report'));
    expect(onViewChange).toHaveBeenCalledWith('compliance');
    expect(onClose).toHaveBeenCalled();
  });

  test('shows devices needing attention from snapshot data', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('MBA-legacy-old')).toBeInTheDocument();
    });
  });

  test('device issue text is shown', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText('No disk encryption')).toBeInTheDocument();
    });
  });

  test('shows Last scan time once loaded', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText(/Last scan:/i)).toBeInTheDocument();
    });
  });

  test('severity badges shown for violations', async () => {
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      // Mock data has a 'high' severity violation
      expect(screen.getAllByText('high').length).toBeGreaterThan(0);
    });
  });

  test('shows an error banner when the snapshot request fails', async () => {
    mockFetch(null);
    render(<ComplianceSnapshot onClose={onClose} />);
    await waitFor(() => {
      expect(screen.getByText(/Data unavailable/i)).toBeInTheDocument();
      expect(screen.getByText(/showing cached data/i)).toBeInTheDocument();
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
