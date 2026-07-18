import React from 'react';
import { render, screen, act, waitFor } from '@testing-library/react';
import ThreatDashboardView from '../../components/views/ThreatDashboardView';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

// ThreatDashboardView fetches threats/anomalies/recommendations independently
// via the axios-based `api` client (api.get('/api/analytics/...')), not a
// single raw `fetch('/api/threats')` call. Mock `api.get` accordingly.

function mockEmptyResponses() {
  mockedApi.get = jest.fn().mockResolvedValue({ data: [] });
}

function mockThreatResponses() {
  mockedApi.get = jest.fn((url: string) => {
    if (url.includes('/api/analytics/threats')) {
      return Promise.resolve({
        data: [
          {
            id: 'threat-1',
            type: 'Brute Force Attack',
            severity: 'high',
            device: 'server-02',
            detectedAt: new Date().toISOString(),
            status: 'active',
          },
        ],
      });
    }
    return Promise.resolve({ data: [] });
  }) as any;
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('ThreatDashboardView', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedApi.post = jest.fn().mockResolvedValue({ data: {} });
  });

  test('renders without crashing (empty data)', async () => {
    mockEmptyResponses();
    await act(async () => {
      render(<ThreatDashboardView />);
    });
    // component mounted without throwing
    expect(document.body).toBeTruthy();
  });

  test('shows "Threat Detection" heading', async () => {
    mockEmptyResponses();
    await act(async () => {
      render(<ThreatDashboardView />);
    });
    const heading = screen.getByRole('heading', { name: /Threat Detection/ });
    expect(heading).toBeInTheDocument();
  });

  test('severity filter buttons render with correct options', async () => {
    mockEmptyResponses();
    await act(async () => {
      render(<ThreatDashboardView />);
    });

    // Severity filtering is a row of toggle buttons, not a <select>.
    expect(screen.getByText('Severity:')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'All' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'critical' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'high' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'medium' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'low' })).toBeInTheDocument();
  });

  test('"Resolve" button present when an active threat is in mock data', async () => {
    mockThreatResponses();
    await act(async () => {
      render(<ThreatDashboardView />);
    });

    await waitFor(() => {
      expect(screen.getByText('Resolve')).toBeInTheDocument();
    });
  });

  test('threat title is rendered from mock data', async () => {
    mockThreatResponses();
    await act(async () => {
      render(<ThreatDashboardView />);
    });

    await waitFor(() => {
      expect(screen.getByText('Brute Force Attack')).toBeInTheDocument();
    });
  });

  test('auto-refresh interval is set via setInterval at 30 000 ms', async () => {
    const setIntervalSpy = jest.spyOn(global, 'setInterval');
    mockEmptyResponses();

    await act(async () => {
      render(<ThreatDashboardView />);
    });

    expect(setIntervalSpy).toHaveBeenCalledWith(
      expect.any(Function),
      30_000,
    );

    setIntervalSpy.mockRestore();
  });

  test('interval is cleared on unmount', async () => {
    const clearIntervalSpy = jest.spyOn(global, 'clearInterval');
    mockEmptyResponses();

    let unmount: () => void;
    await act(async () => {
      const result = render(<ThreatDashboardView />);
      unmount = result.unmount;
    });

    act(() => {
      unmount();
    });

    expect(clearIntervalSpy).toHaveBeenCalled();
    clearIntervalSpy.mockRestore();
  });

  test('api.get is called for threats, anomalies, and recommendations on mount', async () => {
    mockEmptyResponses();

    await act(async () => {
      render(<ThreatDashboardView />);
    });

    expect(mockedApi.get).toHaveBeenCalledWith('/api/analytics/threats');
    expect(mockedApi.get).toHaveBeenCalledWith('/api/analytics/anomalies');
    expect(mockedApi.get).toHaveBeenCalledWith('/api/analytics/recommendations');
  });
});
