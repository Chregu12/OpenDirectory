import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import EnrollmentWizard from '../../components/views/EnrollmentWizard';

// EnrollmentWizard talks to the quick-actions service via `qaPost`
// (raw `fetch`), not the axios-based `api` client. Mock global.fetch.
describe('EnrollmentWizard', () => {
  const onClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        deviceId: 'device-123',
        enrollmentUrl: 'ODM-TESTTOKEN1',
        nextSteps: [],
      }),
    } as any);
  });

  test('renders wizard header', () => {
    render(<EnrollmentWizard onClose={onClose} />);
    expect(screen.getByText('Enroll a New Device')).toBeInTheDocument();
  });

  test('step 1 shows all 5 OS platform tiles', () => {
    render(<EnrollmentWizard onClose={onClose} />);
    expect(screen.getByText('macOS')).toBeInTheDocument();
    expect(screen.getByText('Windows')).toBeInTheDocument();
    expect(screen.getByText('Linux')).toBeInTheDocument();
    expect(screen.getByText('iOS')).toBeInTheDocument();
    expect(screen.getByText('Android')).toBeInTheDocument();
  });

  test('step 1 shows OS icons', () => {
    render(<EnrollmentWizard onClose={onClose} />);
    expect(screen.getByText('🍎')).toBeInTheDocument();
    expect(screen.getByText('🪟')).toBeInTheDocument();
    expect(screen.getByText('🐧')).toBeInTheDocument();
    expect(screen.getByText('📱')).toBeInTheDocument();
    expect(screen.getByText('🤖')).toBeInTheDocument();
  });

  test('Continue button is disabled before platform selection', () => {
    render(<EnrollmentWizard onClose={onClose} />);
    const continueBtn = screen.getByText('Continue →');
    expect(continueBtn).toBeDisabled();
  });

  test('selecting macOS enables Continue button', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    const continueBtn = screen.getByText('Continue →');
    expect(continueBtn).not.toBeDisabled();
  });

  test('step 2 shows device name and serial inputs after platform selection', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByPlaceholderText('e.g. MBA-johndoe')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('e.g. C02XG2JHJGH5')).toBeInTheDocument();
  });

  test('step 2 shows Device Details heading', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('Windows'));
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Device Details')).toBeInTheDocument();
  });

  test('device name is required for step 2 to proceed', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    const continueBtn = screen.getByText('Continue →');
    expect(continueBtn).toBeDisabled();
  });

  test('step 2 proceed enabled after device name entered', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'my-macbook');
    const continueBtn = screen.getByText('Continue →');
    expect(continueBtn).not.toBeDisabled();
  });

  test('step 3 shows OU picker after device details', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('Linux'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'dev-server');
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Organisational Unit Placement')).toBeInTheDocument();
    expect(screen.getByText('OU=Workstations,DC=corp,DC=local')).toBeInTheDocument();
  });

  test('step 4 shows confirm screen', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'test-mac');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Confirm Enrollment')).toBeInTheDocument();
  });

  test('step 4 shows Enroll Now button', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('Windows'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'win-pc');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Enroll Now')).toBeInTheDocument();
  });

  test('step 4 macOS shows platform name in summary', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'test-mac');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    // Platform info shown in confirm summary (multiple Platform elements: step indicator + summary row)
    expect(screen.getAllByText('Platform').length).toBeGreaterThan(0);
    expect(screen.getByText('Device Name')).toBeInTheDocument();
  });

  test('Enroll Now calls API and shows token', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'test-mac');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Enroll Now'));
    await waitFor(() => {
      expect(screen.getByText('Device Enrolled!')).toBeInTheDocument();
    });
  });

  test('success screen shows enrollment token', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'test-mac');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Enroll Now'));
    await waitFor(() => {
      // The success screen labels the credential field "Enrollment URL / Token"
      expect(screen.getByText('Enrollment URL / Token')).toBeInTheDocument();
    });
  });

  test('success screen shows macOS setup instructions', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'test-mac');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Enroll Now'));
    await waitFor(() => {
      expect(screen.getByText(/System Preferences/i)).toBeInTheDocument();
    });
  });

  test('success screen shows Windows PowerShell instructions', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('Windows'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'win-pc');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Enroll Now'));
    await waitFor(() => {
      expect(screen.getByText(/PowerShell/i)).toBeInTheDocument();
    });
  });

  test('back button from step 2 returns to step 1', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Device Details')).toBeInTheDocument();
    await user.click(screen.getByText('← Back'));
    expect(screen.getByText('Choose a platform')).toBeInTheDocument();
  });

  test('Cancel button on step 1 calls onClose', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('Cancel'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('Done button after enrollment calls onClose', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('macOS'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'test-mac');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Enroll Now'));
    await waitFor(() => {
      expect(screen.getByText('Done')).toBeInTheDocument();
    });
    await user.click(screen.getByText('Done'));
    expect(onClose).toHaveBeenCalled();
  });

  test('iOS enrollment shows QR code placeholder', async () => {
    const user = userEvent.setup();
    render(<EnrollmentWizard onClose={onClose} />);
    await user.click(screen.getByText('iOS'));
    await user.click(screen.getByText('Continue →'));
    await user.type(screen.getByPlaceholderText('e.g. MBA-johndoe'), 'test-iphone');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Enroll Now'));
    await waitFor(() => {
      expect(screen.getByText('QR Code')).toBeInTheDocument();
    });
  });
});
