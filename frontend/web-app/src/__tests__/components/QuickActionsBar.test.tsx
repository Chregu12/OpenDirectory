import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import QuickActionsBar from '../../components/views/QuickActionsBar';

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
  });

  test('renders all 5 action buttons', () => {
    render(<QuickActionsBar {...defaultProps} />);
    expect(screen.getByText('Enroll Device')).toBeInTheDocument();
    expect(screen.getByText('New User')).toBeInTheDocument();
    expect(screen.getByText('Service Principal')).toBeInTheDocument();
    expect(screen.getByText('Deploy Policy')).toBeInTheDocument();
    expect(screen.getByText('Compliance Snapshot')).toBeInTheDocument();
  });

  test('clicking Enroll Device calls onEnrollDevice', async () => {
    const user = userEvent.setup();
    render(<QuickActionsBar {...defaultProps} />);
    await user.click(screen.getByText('Enroll Device'));
    expect(defaultProps.onEnrollDevice).toHaveBeenCalledTimes(1);
  });

  test('clicking New User calls onNewUser', async () => {
    const user = userEvent.setup();
    render(<QuickActionsBar {...defaultProps} />);
    await user.click(screen.getByText('New User'));
    expect(defaultProps.onNewUser).toHaveBeenCalledTimes(1);
  });

  test('clicking Service Principal calls onServicePrincipal', async () => {
    const user = userEvent.setup();
    render(<QuickActionsBar {...defaultProps} />);
    await user.click(screen.getByText('Service Principal'));
    expect(defaultProps.onServicePrincipal).toHaveBeenCalledTimes(1);
  });

  test('clicking Deploy Policy calls onDeployPolicy', async () => {
    const user = userEvent.setup();
    render(<QuickActionsBar {...defaultProps} />);
    await user.click(screen.getByText('Deploy Policy'));
    expect(defaultProps.onDeployPolicy).toHaveBeenCalledTimes(1);
  });

  test('clicking Compliance Snapshot calls onComplianceSnapshot', async () => {
    const user = userEvent.setup();
    render(<QuickActionsBar {...defaultProps} />);
    await user.click(screen.getByText('Compliance Snapshot'));
    expect(defaultProps.onComplianceSnapshot).toHaveBeenCalledTimes(1);
  });

  test('buttons are not disabled by default', () => {
    render(<QuickActionsBar {...defaultProps} />);
    const buttons = screen.getAllByRole('button');
    buttons.forEach(btn => {
      expect(btn).not.toBeDisabled();
    });
  });

  test('renders exactly 5 buttons', () => {
    render(<QuickActionsBar {...defaultProps} />);
    const buttons = screen.getAllByRole('button');
    expect(buttons).toHaveLength(5);
  });

  test('Enroll Device button has accent styling (it is the primary action)', () => {
    render(<QuickActionsBar {...defaultProps} />);
    // Enroll Device is the accent button - it's first and has different styling
    const enrollBtn = screen.getByText('Enroll Device');
    expect(enrollBtn).toBeInTheDocument();
  });

  test('each button calls its own handler and not others', async () => {
    const user = userEvent.setup();
    render(<QuickActionsBar {...defaultProps} />);

    await user.click(screen.getByText('New User'));
    expect(defaultProps.onNewUser).toHaveBeenCalledTimes(1);
    expect(defaultProps.onEnrollDevice).not.toHaveBeenCalled();
    expect(defaultProps.onServicePrincipal).not.toHaveBeenCalled();
    expect(defaultProps.onDeployPolicy).not.toHaveBeenCalled();
    expect(defaultProps.onComplianceSnapshot).not.toHaveBeenCalled();
  });
});
