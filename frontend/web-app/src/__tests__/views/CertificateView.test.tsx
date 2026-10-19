import React from 'react';
import { render, screen, act, waitFor } from '@testing-library/react';
import CertificateView from '../../components/views/CertificateView';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

// ── Helpers ────────────────────────────────────────────────────────────────────

/** A valid cert expiring in 60 days — not near-expiry. */
const farCert = {
  id: '1',
  cn: 'test.example.com',
  issuer: 'Test CA',
  notAfter: new Date(Date.now() + 60 * 24 * 3600 * 1000).toISOString(),
  status: 'valid' as const,
  serialNumber: 'DEADBEEF01',
};

/** A valid cert expiring in 20 days — triggers near-expiry danger styling (< 30 days). */
const nearExpiryCert = {
  id: '2',
  cn: 'expiring.example.com',
  issuer: 'Test CA',
  notAfter: new Date(Date.now() + 20 * 24 * 3600 * 1000).toISOString(),
  status: 'valid' as const,
  serialNumber: 'DEADBEEF02',
};

function mockCerts(certs: object[]) {
  mockedApi.get = jest.fn().mockResolvedValue({
    data: { certificates: certs },
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('CertificateView', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockCerts([]);
  });

  test('renders without crashing', async () => {
    await act(async () => {
      render(<CertificateView />);
    });
    expect(document.body).toBeTruthy();
  });

  test('renders "Certificate Lifecycle" heading', async () => {
    await act(async () => {
      render(<CertificateView />);
    });
    expect(screen.getByText('Certificate Lifecycle')).toBeInTheDocument();
  });

  test('"Issue Certificate" button is present', async () => {
    await act(async () => {
      render(<CertificateView />);
    });
    expect(screen.getByText('Issue Certificate')).toBeInTheDocument();
  });

  test('renders certificate table with Common Name column', async () => {
    mockCerts([farCert]);
    await act(async () => {
      render(<CertificateView />);
    });

    await waitFor(() => {
      expect(screen.getByText('test.example.com')).toBeInTheDocument();
    });
  });

  test('certificate serial number is shown in the table', async () => {
    mockCerts([farCert]);
    await act(async () => {
      render(<CertificateView />);
    });

    await waitFor(() => {
      expect(screen.getByText(/DEADBEEF01/)).toBeInTheDocument();
    });
  });

  test('near-expiry cert (< 30 days) shows danger "d left" badge', async () => {
    mockCerts([nearExpiryCert]);
    await act(async () => {
      render(<CertificateView />);
    });

    await waitFor(() => {
      // StatusBadge renders "<N>d left" for certs expiring in < 30 days
      expect(screen.getByText(/d left/)).toBeInTheDocument();
    });
  });

  test('near-expiry badge uses red danger colour (background #fee2e2)', async () => {
    mockCerts([nearExpiryCert]);
    await act(async () => {
      render(<CertificateView />);
    });

    await waitFor(() => {
      const badge = screen.getByText(/d left/);
      expect(badge).toHaveStyle({ background: '#fee2e2' });
    });
  });

  test('"Revoke" button is present for a valid cert', async () => {
    mockCerts([farCert]);
    await act(async () => {
      render(<CertificateView />);
    });

    await waitFor(() => {
      expect(screen.getByText('Revoke')).toBeInTheDocument();
    });
  });

  test('"Renew" button is present for a valid cert', async () => {
    mockCerts([farCert]);
    await act(async () => {
      render(<CertificateView />);
    });

    await waitFor(() => {
      expect(screen.getByText('Renew')).toBeInTheDocument();
    });
  });

  test('api.get is called with /api/certificates on mount', async () => {
    await act(async () => {
      render(<CertificateView />);
    });

    expect(mockedApi.get).toHaveBeenCalledWith('/api/certificates');
  });

  test('empty state message shown when no certificates', async () => {
    mockCerts([]);
    await act(async () => {
      render(<CertificateView />);
    });

    await waitFor(() => {
      expect(screen.getByText(/No certificates found/)).toBeInTheDocument();
    });
  });
});
