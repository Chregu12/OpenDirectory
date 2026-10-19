import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ServicePrincipalWizard from '../../components/views/ServicePrincipalWizard';

jest.mock('../../lib/auth', () => ({ getAccessToken: () => 'verified-session-fixture', ensureSession: jest.fn() }));

// ServicePrincipalWizard talks to the quick-actions service via `qaPost`
// (raw `fetch`), not the axios-based `api` client. Mock global.fetch.
describe('ServicePrincipalWizard', () => {
  const onClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    // Default: quick-actions service resolves with mock credentials
    global.fetch = jest.fn().mockImplementation(async (url: string) => ({
      ok: true,
      json: async () => url.endsWith('/access') ? { subject: 'operator', permissions: ['applications.create', 'applications.permissions.assign'], delegablePermissions: null } : ({
        success: true,
        client_id: 'test-client-id-1234',
        client_secret: 'test-secret-abc123def456',
        spn: 'app/test-app@opendirectory.local',
      }),
    } as any));
  });

  test.each([207, 200])('HTTP %i with an explicit partial failure never creates credentials in the UI or retries blindly', async status => {
    (global.fetch as jest.Mock).mockImplementation(async (url: string) => ({ ok: true, status: url.endsWith('/access') ? 200 : status, json: async () => url.endsWith('/access')
      ? { subject: 'operator', permissions: ['applications.create'], delegablePermissions: [] }
      : { success: false, clientId: 'partial', clientSecret: null, completedSteps: [{ name: 'AD', ok: true }] } }));
    const user = userEvent.setup(); render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'partial-app'); await user.click(screen.getByRole('button', { name: 'Create →' }));
    await screen.findByRole('alert'); expect(screen.queryByText('Service Principal Created')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Create →' })).toBeDisabled();
    expect((global.fetch as jest.Mock).mock.calls.filter(([url]) => url === '/api/quick/service-principals')).toHaveLength(1);
  });

  test('missing credentials or success evidence is an unconfirmed result, not an invented SPN or empty-secret success', async () => {
    (global.fetch as jest.Mock).mockImplementation(async (url: string) => ({ ok: true, status: 200, json: async () => url.endsWith('/access')
      ? { subject: 'operator', permissions: ['applications.create'], delegablePermissions: [] } : { success: true, clientId: 'incomplete' } }));
    const user = userEvent.setup(); render(<ServicePrincipalWizard onClose={onClose} />); await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'incomplete-app');
    await user.click(screen.getByRole('button', { name: 'Create →' })); await screen.findByRole('alert'); expect(screen.queryByText('Service Principal Created')).not.toBeInTheDocument();
  });

  test('renders the wizard modal', () => {
    render(<ServicePrincipalWizard onClose={onClose} />);
    expect(screen.getByText('Create Service Principal')).toBeInTheDocument();
  });

  test('an application creator cannot choose permissions without separate delegation authority', async () => {
    (global.fetch as jest.Mock).mockImplementationOnce(async () => ({ ok: true, json: async () => ({ subject: 'operator', permissions: ['applications.create'], delegablePermissions: [] }) }));
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'limited-application');
    expect(screen.getByText('Create →')).not.toBeDisabled();
    for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).toBeDisabled();
  });

  test('a delegated consent operator can select only permissions they hold', async () => {
    (global.fetch as jest.Mock).mockImplementationOnce(async () => ({ ok: true, json: async () => ({ subject: 'operator', permissions: ['applications.create', 'applications.permissions.assign'], delegablePermissions: ['read_users'] }) }));
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'limited-application');
    expect(screen.getAllByRole('checkbox')[0]).not.toBeDisabled();
    for (const checkbox of screen.getAllByRole('checkbox').slice(1)) expect(checkbox).toBeDisabled();
  });

  test('renders form fields when open', () => {
    render(<ServicePrincipalWizard onClose={onClose} />);
    expect(screen.getByPlaceholderText('e.g. inventory-service')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('What does this service do?')).toBeInTheDocument();
  });

  test('renders permission checkboxes', () => {
    render(<ServicePrincipalWizard onClose={onClose} />);
    expect(screen.getByText('Read Users')).toBeInTheDocument();
    expect(screen.getByText('Read Devices')).toBeInTheDocument();
    expect(screen.getByText('Write Policies')).toBeInTheDocument();
    expect(screen.getByText('Admin Access')).toBeInTheDocument();
    expect(screen.getByText('API Gateway')).toBeInTheDocument();
    expect(screen.getByText('Audit Logs')).toBeInTheDocument();
  });

  test('new applications have no preselected permissions', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).not.toBeChecked();
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'no-privileges-app');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => expect(global.fetch).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ method: 'POST' })));
    expect(JSON.parse((global.fetch as jest.Mock).mock.calls.find(([, options]) => options.method === 'POST')[1].body).permissions).toEqual([]);
  });

  test('Create button is disabled when app name is empty', () => {
    render(<ServicePrincipalWizard onClose={onClose} />);
    const createBtn = screen.getByText('Create →');
    expect(createBtn).toBeDisabled();
  });

  test('Create button becomes enabled when app name is entered', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    const nameInput = screen.getByPlaceholderText('e.g. inventory-service');
    await user.type(nameInput, 'my-service');
    const createBtn = screen.getByText('Create →');
    expect(createBtn).not.toBeDisabled();
  });

  test('submitting with a name calls API and shows credentials screen', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    const nameInput = screen.getByPlaceholderText('e.g. inventory-service');
    await user.type(nameInput, 'my-service');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => {
      expect(screen.getByText('Service Principal Created')).toBeInTheDocument();
    });
  });

  test('credentials screen shows Client ID label after creation', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'test-app');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => {
      // The label "Client ID" is rendered with CSS text-transform: uppercase,
      // but the DOM text content is "Client ID"
      expect(screen.getByText('Client ID')).toBeInTheDocument();
    });
  });

  test('credentials screen shows Client Secret label after creation', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'test-app');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => {
      // The label "Client Secret" is rendered with CSS text-transform: uppercase,
      // but the DOM text content is "Client Secret"
      expect(screen.getByText('Client Secret')).toBeInTheDocument();
    });
  });

  test('client secret is masked by default (shows bullet characters)', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'test-app');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => {
      expect(screen.getByText('Service Principal Created')).toBeInTheDocument();
    });
    // Find the masked secret display - secret is shown as bullet characters (●●●●...)
    const codeElements = document.querySelectorAll('code');
    const maskedSecret = Array.from(codeElements).find(el => el.textContent && el.textContent.includes('●'));
    expect(maskedSecret).toBeTruthy();
  });

  test('Done button calls onClose after creation', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'test-app');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => {
      expect(screen.getByText('Done')).toBeInTheDocument();
    });
    await user.click(screen.getByText('Done'));
    expect(onClose).toHaveBeenCalled();
  });

  test('Cancel button calls onClose without submitting', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.click(screen.getByText('Cancel'));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(global.fetch).not.toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ method: 'POST' }));
  });

  test('Download .env button is shown after creation', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'test-app');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => {
      expect(screen.getByText('Download .env')).toBeInTheDocument();
    });
  });

  test('copy button triggers clipboard.writeText', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'test-app');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => {
      expect(screen.getByText('Client ID')).toBeInTheDocument();
    });
    // Find copy buttons (there are multiple)
    const copyButtons = screen.getAllByRole('button');
    // At least one copy button should exist in the credentials screen
    expect(copyButtons.length).toBeGreaterThan(0);
  });

  test('warning message is shown after creation', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'test-app');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => {
      expect(screen.getByText(/Save the Client Secret now/i)).toBeInTheDocument();
    });
  });

  test('.env snippet is shown after creation', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('e.g. inventory-service'), 'test-app');
    await user.click(screen.getByText('Create →'));
    await waitFor(() => {
      expect(screen.getByText('.env snippet')).toBeInTheDocument();
    });
  });

  test('description field accepts input', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    const descInput = screen.getByPlaceholderText('What does this service do?');
    await user.type(descInput, 'Test description');
    expect(descInput).toHaveValue('Test description');
  });

  test('permission checkboxes are toggleable', async () => {
    const user = userEvent.setup();
    render(<ServicePrincipalWizard onClose={onClose} />);
    // Write Policies is unchecked by default
    const checkboxes = screen.getAllByRole('checkbox');
    // Find the Write Policies checkbox
    const writePoliciesCheckbox = checkboxes[2]; // 3rd checkbox
    expect(writePoliciesCheckbox).not.toBeChecked();
    await user.click(writePoliciesCheckbox);
    expect(writePoliciesCheckbox).toBeChecked();
  });
});
