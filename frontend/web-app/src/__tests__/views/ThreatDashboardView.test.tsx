import React from 'react';
import { render, screen, act, waitFor } from '@testing-library/react';
import ThreatDashboardView from '../../components/views/ThreatDashboardView';

// ── Helpers ────────────────────────────────────────────────────────────────────

const emptyData = { threats: [], anomalies: [], recommendations: [] };

const threatData = {
  threats: [
    {
      id: 'threat-1',
      title: 'Brute Force Attack',
      severity: 'high' as const,
      description: 'Multiple failed login attempts detected.',
      detectedAt: new Date().toISOString(),
      status: 'active' as const,
      source: 'auth-service',
    },
  ],
  anomalies: [],
  recommendations: [],
};

function makeFetch(data: object) {
  return jest.fn().mockResolvedValue({
    ok: true,
    json: async () => data,
  } as unknown as Response);
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('ThreatDashboardView', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    jest.useFakeTimers();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.useRealTimers();
    jest.clearAllMocks();
  });

  test('renders without crashing (empty data)', async () => {
    global.fetch = makeFetch(emptyData);
    await act(async () => {
      render(<ThreatDashboardView />);
    });
    // component mounted without throwing
    expect(document.body).toBeTruthy();
  });

  test('shows "Active Threats" heading', async () => {
    global.fetch = makeFetch(emptyData);
    await act(async () => {
      render(<ThreatDashboardView />);
    });
    // The h1 contains "Active Threats" (the summary card also shows the text,
    // so we target the heading role specifically).
    const heading = screen.getByRole('heading', { name: /Active Threats/ });
    expect(heading).toBeInTheDocument();
  });

  test('severity filter dropdown renders with correct options', async () => {
    global.fetch = makeFetch(emptyData);
    await act(async () => {
      render(<ThreatDashboardView />);
    });

    const select = screen.getByLabelText('Filter by severity');
    expect(select).toBeInTheDocument();

    const options = Array.from(select.querySelectorAll('option')).map(o => o.value);
    expect(options).toContain('all');
    expect(options).toContain('critical');
    expect(options).toContain('high');
    expect(options).toContain('medium');
    expect(options).toContain('low');
  });

  test('"Resolve" button present when an active threat is in mock data', async () => {
    global.fetch = makeFetch(threatData);
    await act(async () => {
      render(<ThreatDashboardView />);
    });

    await waitFor(() => {
      expect(screen.getByText('Resolve')).toBeInTheDocument();
    });
  });

  test('threat title is rendered from mock data', async () => {
    global.fetch = makeFetch(threatData);
    await act(async () => {
      render(<ThreatDashboardView />);
    });

    await waitFor(() => {
      expect(screen.getByText('Brute Force Attack')).toBeInTheDocument();
    });
  });

  test('auto-refresh interval is set via setInterval at 60 000 ms', async () => {
    const setIntervalSpy = jest.spyOn(global, 'setInterval');
    global.fetch = makeFetch(emptyData);

    await act(async () => {
      render(<ThreatDashboardView />);
    });

    expect(setIntervalSpy).toHaveBeenCalledWith(
      expect.any(Function),
      60_000,
    );

    setIntervalSpy.mockRestore();
  });

  test('interval is cleared on unmount', async () => {
    const clearIntervalSpy = jest.spyOn(global, 'clearInterval');
    global.fetch = makeFetch(emptyData);

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

  test('fetch is called with /api/threats on mount', async () => {
    const fetchMock = makeFetch(emptyData);
    global.fetch = fetchMock;

    await act(async () => {
      render(<ThreatDashboardView />);
    });

    expect(fetchMock).toHaveBeenCalledWith('/api/threats');
  });
});
