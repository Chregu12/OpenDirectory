import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ScanDestinationsTab } from '../../components/views/PrintersView';

// ─── fetch mock ───────────────────────────────────────────────────────────────

function mockFetch(destinations: object[] = []) {
  global.fetch = jest.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ destinations }),
  } as any);
}

// ─── Sample destinations ──────────────────────────────────────────────────────

const destWithVariable = {
  id: 'dest-1',
  entityType: 'group',
  entityId: 'all-users',
  type: 'smb',
  smbServer: '192.168.1.10',
  smbShare: 'scans',
  smbPath: 'scanner/@{username}',
  smbUsername: 'scanuser',
  label: 'All Users',
};

const destWithPercentU = {
  id: 'dest-2',
  entityType: 'group',
  entityId: 'staff',
  type: 'smb',
  smbServer: '10.0.0.5',
  smbShare: 'home',
  smbPath: 'samba/%U',
  smbUsername: 'scanuser',
  label: 'Staff',
};

const destWithoutVariable = {
  id: 'dest-3',
  entityType: 'user',
  entityId: 'jdoe@corp.com',
  type: 'smb',
  smbServer: '192.168.1.10',
  smbShare: 'scans',
  smbPath: 'Marketing/Incoming',
  label: 'Marketing',
};

const destLocalWithVariable = {
  id: 'dest-4',
  entityType: 'group',
  entityId: 'engineers',
  type: 'local',
  smbServer: null,
  smbShare: null,
  smbPath: null,
  localPath: '/mnt/scans/@{username}',
  label: 'Engineers',
};

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('ScanDestinationsTab', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch([]);
  });

  // ── Rendering ──────────────────────────────────────────────────────────────

  test('renders the Add Destination button', async () => {
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText(/Add Destination/i)).toBeInTheDocument());
  });

  test('shows empty state when no destinations exist', async () => {
    render(<ScanDestinationsTab />);
    await waitFor(() =>
      expect(screen.getByText(/No scan destinations configured/i)).toBeInTheDocument()
    );
  });

  test('shows fetched destinations in the table', async () => {
    mockFetch([destWithVariable]);
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText('all-users')).toBeInTheDocument());
  });

  // ── Variable badge in table ────────────────────────────────────────────────

  test('@{username} path is rendered in the table', async () => {
    mockFetch([destWithVariable]);
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText('scanner/@{username}')).toBeInTheDocument());
  });

  test('%U path is rendered in the table', async () => {
    mockFetch([destWithPercentU]);
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText('samba/%U')).toBeInTheDocument());
  });

  test('path without variable shows plain text (no blue highlight)', async () => {
    mockFetch([destWithoutVariable]);
    render(<ScanDestinationsTab />);
    await waitFor(() => {
      const cell = screen.getByText('Marketing/Incoming');
      // Plain paths use a span without the blue colour class
      expect(cell.tagName).toBe('SPAN');
      expect(cell.className).not.toMatch(/text-blue/);
    });
  });

  test('@{username} path cell has blue colour class', async () => {
    mockFetch([destWithVariable]);
    render(<ScanDestinationsTab />);
    await waitFor(() => {
      const cell = screen.getByText('scanner/@{username}');
      expect(cell.className).toMatch(/text-blue/);
    });
  });

  test('%U path cell has blue colour class', async () => {
    mockFetch([destWithPercentU]);
    render(<ScanDestinationsTab />);
    await waitFor(() => {
      const cell = screen.getByText('samba/%U');
      expect(cell.className).toMatch(/text-blue/);
    });
  });

  test('shows — for destination with no smbPath', async () => {
    mockFetch([destLocalWithVariable]);
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText('engineers')).toBeInTheDocument());
    // smbPath is null → should show dash placeholder
    const dashes = screen.getAllByText('—');
    expect(dashes.length).toBeGreaterThan(0);
  });

  // ── Add Destination form ───────────────────────────────────────────────────

  test('clicking Add Destination opens the dialog', async () => {
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText(/Add Destination/i)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Add Destination/i));
    expect(screen.getByText(/Add Scan Destination/i)).toBeInTheDocument();
  });

  test('Sub-path field placeholder mentions @{username}', async () => {
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText(/Add Destination/i)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Add Destination/i));
    const subPathInput = screen.getByPlaceholderText(/scanner\/@\{username\}/i);
    expect(subPathInput).toBeInTheDocument();
  });

  test('hint text about @{username} variable is shown below the Sub-path field', async () => {
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText(/Add Destination/i)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Add Destination/i));
    expect(screen.getByText(/Login-Name/i)).toBeInTheDocument();
  });

  test('hint text mentions @{email} variable', async () => {
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText(/Add Destination/i)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Add Destination/i));
    expect(screen.getByText(/E-Mail/i)).toBeInTheDocument();
  });

  test('hint text mentions %U Samba alias', async () => {
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText(/Add Destination/i)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Add Destination/i));
    expect(screen.getByText(/Samba/i)).toBeInTheDocument();
  });

  test('switching to Local type shows local path placeholder with @{username}', async () => {
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText(/Add Destination/i)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Add Destination/i));
    // Change Destination Type to Local
    const typeSelect = screen.getByDisplayValue('SMB');
    fireEvent.change(typeSelect, { target: { value: 'local' } });
    const localInput = screen.getByPlaceholderText(/\/mnt\/storage\/scans\/@\{username\}/i);
    expect(localInput).toBeInTheDocument();
  });

  // ── Cancel dialog ──────────────────────────────────────────────────────────

  test('Cancel button closes the dialog', async () => {
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText(/Add Destination/i)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Add Destination/i));
    expect(screen.getByText(/Add Scan Destination/i)).toBeInTheDocument();
    fireEvent.click(screen.getByText('Cancel'));
    expect(screen.queryByText(/Add Scan Destination/i)).not.toBeInTheDocument();
  });

  // ── Edit existing destination ──────────────────────────────────────────────

  test('clicking Edit opens dialog prefilled with existing path', async () => {
    mockFetch([destWithVariable]);
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText(/Edit/i)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Edit/i));
    // Dialog title changes to "Edit Scan Destination"
    expect(screen.getByText(/Edit Scan Destination/i)).toBeInTheDocument();
    // The Sub-path field should be prefilled
    const subPathInput = screen.getByDisplayValue('scanner/@{username}');
    expect(subPathInput).toBeInTheDocument();
  });

  // ── Table columns ──────────────────────────────────────────────────────────

  test('table renders all expected column headers', async () => {
    mockFetch([destWithVariable]);
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText('all-users')).toBeInTheDocument());
    for (const header of ['Type', 'Entity ID', 'Destination', 'Server / Share', 'Path', 'Label', 'Actions']) {
      expect(screen.getByText(header)).toBeInTheDocument();
    }
  });

  test('user entity type shows blue badge', async () => {
    mockFetch([destWithoutVariable]);
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText('user')).toBeInTheDocument());
    const badge = screen.getByText('user');
    expect(badge.className).toMatch(/blue/);
  });

  test('group entity type shows purple badge', async () => {
    mockFetch([destWithVariable]);
    render(<ScanDestinationsTab />);
    await waitFor(() => expect(screen.getByText('group')).toBeInTheDocument());
    const badge = screen.getByText('group');
    expect(badge.className).toMatch(/purple/);
  });
});
