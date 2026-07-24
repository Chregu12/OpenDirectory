import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import ComplianceView from '../../components/views/ComplianceView';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

// ComplianceView renders in Simple mode by default (useUiMode's context has
// no Provider here, and its default value is isSimple: true).

// ── Fixtures: the REAL compliance-engine response shapes ────────────────────
// (compliance-engine wraps everything as { success, data, count? } — these
// are NOT the { fleetScore, devices, violations, trend } shape the component
// used to assume.)

const DASHBOARD_RESPONSE = {
  data: {
    success: true,
    data: {
      fleet: {
        deviceCount: 12,
        averageScore: 76.5,
        minScore: 40,
        maxScore: 100,
        medianScore: 80,
        totalCriticalFailures: 3,
        totalHighFailures: 5,
        totalFailures: 20,
        distribution: { compliant: 8, partially_compliant: 2, at_risk: 1, non_compliant: 1 },
      },
      domain: {},
      waivers: { active: 1, expired: 0, revoked: 0, total: 1, expiringSoon: 0 },
      trends: {
        period: { days: 30 },
        fleetTrend: [
          { date: '2026-06-24T00:00:00.000Z', averageScore: 70.1, minScore: 50, maxScore: 90, deviceCount: 10 },
          { date: '2026-06-25T00:00:00.000Z', averageScore: 72.3, minScore: 52, maxScore: 92, deviceCount: 11 },
        ],
        regressions: [],
        improvements: [],
        topFailures: [],
        predictions: {},
      },
      generatedAt: '2026-07-24T00:00:00.000Z',
    },
  },
};

const BASELINES_RESPONSE = {
  data: {
    success: true,
    count: 1,
    data: [
      { id: 'b1', name: 'CIS Windows 11 L1', framework: 'cis', platform: 'windows', enabled: true },
    ],
  },
};

const WAIVERS_RESPONSE = {
  data: {
    success: true,
    count: 1,
    data: [
      {
        id: 'w1',
        check_id: 'c1',
        baseline_name: 'CIS Windows 11 L1',
        device_id: 'd1',
        reason: 'Compensating control in place',
        approved_by: 'admin',
        expires_at: '2026-12-31T00:00:00.000Z',
        status: 'active',
      },
    ],
  },
};

function mockRealBackend() {
  mockedApi.get = jest.fn((url: string) => {
    if (url.startsWith('/api/compliance/dashboard')) return Promise.resolve(DASHBOARD_RESPONSE);
    if (url.startsWith('/api/compliance/baselines')) return Promise.resolve(BASELINES_RESPONSE);
    if (url.startsWith('/api/compliance/waivers')) return Promise.resolve(WAIVERS_RESPONSE);
    return Promise.resolve({ data: {} });
  }) as any;
}

describe('ComplianceView (real compliance-engine contract)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('renders without crashing against the real compliance-engine response shape', async () => {
    mockRealBackend();
    render(<ComplianceView />);
    await waitFor(() => {
      expect(screen.getByText(/Attention Required|Fleet Compliant/)).toBeInTheDocument();
    });
  });

  test('maps fleet.averageScore (not a nonexistent fleetScore field) into the score display', async () => {
    mockRealBackend();
    render(<ComplianceView />);
    await waitFor(() => {
      // fleet.averageScore = 76.5 -> displayed rounded to whole percent
      expect(screen.getByText('77%')).toBeInTheDocument();
    });
  });

  test('baselines count reflects the unwrapped data array, not the {success,data,count} envelope', async () => {
    mockRealBackend();
    render(<ComplianceView />);
    await waitFor(() => {
      // 1 baseline from BASELINES_RESPONSE.data.data
      const label = screen.getByText('Baselines');
      const card = label.closest('div')?.parentElement as HTMLElement;
      expect(card).not.toBeNull();
      expect(card.textContent).toContain('1');
    });
  });

  test('falls back to demo data when the dashboard call fails entirely', async () => {
    mockedApi.get = jest.fn().mockRejectedValue(new Error('network error'));
    render(<ComplianceView />);
    await waitFor(() => {
      // demo fleet score is 87.3 -> rounds to 87%
      expect(screen.getByText('87%')).toBeInTheDocument();
    });
  });

  test('does not crash when compliance-engine returns an empty dashboard (no per-device roster available)', async () => {
    mockedApi.get = jest.fn((url: string) => {
      if (url.startsWith('/api/compliance/dashboard')) return Promise.resolve(DASHBOARD_RESPONSE);
      return Promise.resolve({ data: { success: true, data: [] } });
    }) as any;
    render(<ComplianceView />);
    await waitFor(() => {
      expect(screen.getByText(/0 of 0 devices compliant/)).toBeInTheDocument();
    });
  });
});
