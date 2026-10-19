import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import QuickActionsBar from '../../components/views/QuickActionsBar';
import { qaGet } from '../../lib/quickActionsApi';
import { useIdentityAccess } from '../../hooks/useIdentityAccess';

jest.mock('../../lib/quickActionsApi', () => ({ qaGet: jest.fn() }));
jest.mock('../../hooks/useIdentityAccess', () => ({ useIdentityAccess: jest.fn() }));

function identityPermissions(permissions: string[]) { (useIdentityAccess as jest.Mock).mockReturnValue({ access: {}, unavailable: false, can: (permission: string) => permissions.includes(permission) }); }

const capabilities = ['devices.enroll', 'users.onboard', 'applications.create', 'policies.deploy', 'compliance.read'];

async function renderReady() {
  render(<QuickActionsBar {...defaultProps} />);
  await screen.findByText('Enroll Device');
}

const defaultProps = {
  onEnrollDevice: jest.fn(),
  onNewUser: jest.fn(),
  onServicePrincipal: jest.fn(),
  onDeployPolicy: jest.fn(),
  onComplianceSnapshot: jest.fn(),
};

describe('QuickActionsBar', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    identityPermissions(['users.read']);
    (qaGet as jest.Mock).mockResolvedValue({ subject: 'operator', permissions: capabilities });
  });

  test('renders all 5 action buttons for authorized operators', async () => {
    await renderReady();
    expect(screen.getByText('Enroll Device')).toBeInTheDocument();
    expect(screen.getByText('Benutzerverwaltung')).toBeInTheDocument();
    expect(screen.getByText('Service Principal')).toBeInTheDocument();
    expect(screen.getByText('Deploy Policy')).toBeInTheDocument();
    expect(screen.getByText('Compliance Snapshot')).toBeInTheDocument();
  });

  test('clicking Enroll Device calls onEnrollDevice', async () => {
    const user = userEvent.setup();
    await renderReady();
    await user.click(screen.getByText('Enroll Device'));
    expect(defaultProps.onEnrollDevice).toHaveBeenCalledTimes(1);
  });

  test('clicking New User calls onNewUser', async () => {
    const user = userEvent.setup();
    await renderReady();
    await user.click(screen.getByText('Benutzerverwaltung'));
    expect(defaultProps.onNewUser).toHaveBeenCalledTimes(1);
  });

  test('clicking Service Principal calls onServicePrincipal', async () => {
    const user = userEvent.setup();
    await renderReady();
    await user.click(screen.getByText('Service Principal'));
    expect(defaultProps.onServicePrincipal).toHaveBeenCalledTimes(1);
  });

  test('clicking Deploy Policy calls onDeployPolicy', async () => {
    const user = userEvent.setup();
    await renderReady();
    await user.click(screen.getByText('Deploy Policy'));
    expect(defaultProps.onDeployPolicy).toHaveBeenCalledTimes(1);
  });

  test('clicking Compliance Snapshot calls onComplianceSnapshot', async () => {
    const user = userEvent.setup();
    await renderReady();
    await user.click(screen.getByText('Compliance Snapshot'));
    expect(defaultProps.onComplianceSnapshot).toHaveBeenCalledTimes(1);
  });

  test('authorized buttons are enabled', async () => {
    await renderReady();
    const buttons = screen.getAllByRole('button');
    buttons.forEach(btn => {
      expect(btn).not.toBeDisabled();
    });
  });

  test('renders exactly 5 buttons with all capabilities', async () => {
    await renderReady();
    const buttons = screen.getAllByRole('button');
    expect(buttons).toHaveLength(5);
  });

  test('Enroll Device button has accent styling (it is the primary action)', async () => {
    await renderReady();
    // Enroll Device is the accent button - it's first and has different styling
    const enrollBtn = screen.getByText('Enroll Device');
    expect(enrollBtn).toBeInTheDocument();
  });

  test('each button calls its own handler and not others', async () => {
    const user = userEvent.setup();
    await renderReady();

    await user.click(screen.getByText('Benutzerverwaltung'));
    expect(defaultProps.onNewUser).toHaveBeenCalledTimes(1);
    expect(defaultProps.onEnrollDevice).not.toHaveBeenCalled();
    expect(defaultProps.onServicePrincipal).not.toHaveBeenCalled();
    expect(defaultProps.onDeployPolicy).not.toHaveBeenCalled();
    expect(defaultProps.onComplianceSnapshot).not.toHaveBeenCalled();
  });

  test('does not render privileged actions while the capability request is pending', () => {
    identityPermissions([]);
    (qaGet as jest.Mock).mockReturnValue(new Promise(() => {}));
    render(<QuickActionsBar {...defaultProps} />);
    expect(screen.getByRole('status')).toHaveTextContent('Checking action permissions');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  test('shows only the operation granted by the server', async () => {
    identityPermissions([]);
    (qaGet as jest.Mock).mockResolvedValue({ subject: 'reader', permissions: ['compliance.read'] });
    render(<QuickActionsBar {...defaultProps} />);
    expect(await screen.findByRole('button', { name: 'Compliance Snapshot' })).toBeInTheDocument();
    expect(screen.getAllByRole('button')).toHaveLength(1);
    expect(qaGet).toHaveBeenCalledWith('/api/quick/access');
  });
  test('canonical user management does not depend on a legacy onboarding grant or quick-actions availability', async () => {
    identityPermissions(['users.read']);
    (qaGet as jest.Mock).mockRejectedValue(new Error('Legacy service offline'));
    render(<QuickActionsBar {...defaultProps} />);
    expect(await screen.findByRole('button', { name: 'Benutzerverwaltung' })).toBeInTheDocument();
    expect(screen.queryByText('New User')).not.toBeInTheDocument();
  });

  test('ordinary authenticated users receive no administrative buttons', async () => {
    identityPermissions([]);
    (qaGet as jest.Mock).mockResolvedValue({ subject: 'user', permissions: [] });
    render(<QuickActionsBar {...defaultProps} />);
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument());
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  test('a capability outage fails closed instead of displaying administrative controls', async () => {
    identityPermissions([]);
    (qaGet as jest.Mock).mockRejectedValue(new Error('Unavailable'));
    render(<QuickActionsBar {...defaultProps} />);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  test.each([{}, { subject: '', permissions: capabilities }, { subject: 'operator', permissions: 'admin' }])('rejects malformed capabilities: %j', access => {
    identityPermissions([]);
    (qaGet as jest.Mock).mockResolvedValue(access);
    render(<QuickActionsBar {...defaultProps} />);
    return screen.findByRole('alert').then(() => expect(screen.queryByRole('button')).not.toBeInTheDocument());
  });
});
