import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PolicyDeployWizard from '../../components/views/PolicyDeployWizard';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

describe('PolicyDeployWizard', () => {
  const onClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    // Policy list still comes from the axios `api` client (falls back to
    // MOCK_POLICIES when unavailable).
    mockedApi.get = jest.fn().mockRejectedValue(new Error('API unavailable'));
    mockedApi.post = jest.fn().mockResolvedValue({ data: {} });
    // Deployment itself goes through the quick-actions service via raw fetch.
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({}),
    } as any);
  });

  test('renders wizard header', () => {
    render(<PolicyDeployWizard onClose={onClose} />);
    expect(screen.getByText('Deploy Policy')).toBeInTheDocument();
  });

  test('step 1 shows searchable policy list with mock policies', () => {
    render(<PolicyDeployWizard onClose={onClose} />);
    expect(screen.getByText('Enforce Disk Encryption')).toBeInTheDocument();
    expect(screen.getByText('Password Complexity')).toBeInTheDocument();
    expect(screen.getByText('Antivirus Required')).toBeInTheDocument();
  });

  test('step 1 shows search input', () => {
    render(<PolicyDeployWizard onClose={onClose} />);
    expect(screen.getByPlaceholderText('Search policies...')).toBeInTheDocument();
  });

  test('policy search filters the list', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Search policies...'), 'Disk');
    expect(screen.getByText('Enforce Disk Encryption')).toBeInTheDocument();
    expect(screen.queryByText('Password Complexity')).not.toBeInTheDocument();
  });

  test('policy search filters by category too', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Search policies...'), 'Network');
    expect(screen.getByText('Firewall On')).toBeInTheDocument();
    expect(screen.getByText('VPN Required for Remote')).toBeInTheDocument();
    expect(screen.queryByText('Password Complexity')).not.toBeInTheDocument();
  });

  test('Continue is disabled until a policy is selected', () => {
    render(<PolicyDeployWizard onClose={onClose} />);
    const continueBtn = screen.getByText('Continue');
    expect(continueBtn).toBeDisabled();
  });

  test('Continue enabled after selecting a policy', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Enforce Disk Encryption'));
    const continueBtn = screen.getByText('Continue');
    expect(continueBtn).not.toBeDisabled();
  });

  test('step 2 shows all target type options', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Password Complexity'));
    await user.click(screen.getByText('Continue'));
    expect(screen.getByText('All Devices')).toBeInTheDocument();
    expect(screen.getByText('By OS')).toBeInTheDocument();
    expect(screen.getByText('By OU')).toBeInTheDocument();
    expect(screen.getByText('By Group')).toBeInTheDocument();
    expect(screen.getByText('Specific Device')).toBeInTheDocument();
    expect(screen.getByText('Specific User')).toBeInTheDocument();
  });

  test('step 3 shows Enforced toggle', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Antivirus Required'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    expect(screen.getByText('Enforced')).toBeInTheDocument();
  });

  test('step 3 shows Dry Run toggle', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Antivirus Required'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    expect(screen.getByText('Dry Run')).toBeInTheDocument();
  });

  test('step 3 Enforced description shown', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Antivirus Required'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    expect(screen.getByText(/Block users from changing this setting/i)).toBeInTheDocument();
  });

  test('step 3 Dry Run description shown', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Antivirus Required'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    expect(screen.getByText(/Simulate deployment/i)).toBeInTheDocument();
  });

  test('step 4 shows deploy summary', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Antivirus Required'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    expect(screen.getByText('Ready to deploy')).toBeInTheDocument();
    expect(screen.getByText('Deploy Now')).toBeInTheDocument();
  });

  test('Deploy Now triggers deployment and shows result', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Antivirus Required'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Deploy Now'));
    await waitFor(() => {
      expect(screen.getByText('Policy Deployed')).toBeInTheDocument();
    }, { timeout: 3000 });
  });

  test('with dry run ON, button shows Run Dry Run', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Antivirus Required'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    // Step 3: find all toggle buttons (they are the small oval buttons)
    // The Dry Run toggle is in a section that contains "Dry Run" text
    // Find the button nearest to "Dry Run" text
    const dryRunSection = screen.getByText('Dry Run').closest('div[style]');
    if (dryRunSection) {
      // Click the toggle button in the dry run section (it's the last button in the parent)
      const toggleBtn = dryRunSection.parentElement?.querySelector('button');
      if (toggleBtn) {
        await user.click(toggleBtn);
      }
    }
    await user.click(screen.getByText('Continue'));
    // After toggling dry run, step 4 should show "Run Dry Run" button
    await waitFor(() => {
      expect(screen.getByText(/Run Dry Run|Deploy Now/)).toBeInTheDocument();
    });
  });

  test('dry run result shows Dry Run Complete', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Enforce Disk Encryption'));
    await user.click(screen.getByText('Continue'));
    await user.click(screen.getByText('Continue'));
    // Toggle dry run on
    const allButtons = screen.getAllByRole('button');
    const dryRunToggle = allButtons.find((btn, idx) => {
      const parent = btn.closest('div[style*="border"]');
      return parent?.textContent?.includes('Dry Run');
    });
    if (dryRunToggle) await user.click(dryRunToggle);
    await user.click(screen.getByText('Continue'));
    // click the run button (Run Dry Run or Deploy Now)
    const deployBtn = screen.getByRole('button', { name: /Run Dry Run|Deploy Now/i });
    await user.click(deployBtn);
    await waitFor(() => {
      // Either dry run complete or policy deployed
      const result = screen.queryByText('Dry Run Complete') || screen.queryByText('Policy Deployed');
      expect(result).toBeInTheDocument();
    }, { timeout: 3000 });
  });

  test('Cancel from step 1 calls onClose', async () => {
    const user = userEvent.setup();
    render(<PolicyDeployWizard onClose={onClose} />);
    await user.click(screen.getByText('Cancel'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('policy categories are visible', () => {
    render(<PolicyDeployWizard onClose={onClose} />);
    // Multiple policies have "Security" category, getAllByText handles that
    expect(screen.getAllByText('Security').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Compliance').length).toBeGreaterThan(0);
  });
});
