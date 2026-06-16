import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import UserOnboardingWizard from '../../components/views/UserOnboardingWizard';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

describe('UserOnboardingWizard', () => {
  const onClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockedApi.post = jest.fn().mockResolvedValue({
      data: {
        temp_password: 'Temp@Test1234',
        username: 'jane.smith',
      },
    });
  });

  test('renders wizard header', () => {
    render(<UserOnboardingWizard onClose={onClose} />);
    expect(screen.getByText('Onboard New User')).toBeInTheDocument();
  });

  test('step 1 shows First Name and Last Name fields', () => {
    render(<UserOnboardingWizard onClose={onClose} />);
    expect(screen.getByPlaceholderText('Jane')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Smith')).toBeInTheDocument();
  });

  test('step 1 shows Work Email field', () => {
    render(<UserOnboardingWizard onClose={onClose} />);
    expect(screen.getByPlaceholderText('jane.smith@company.com')).toBeInTheDocument();
  });

  test('step 1 shows Job Title field', () => {
    render(<UserOnboardingWizard onClose={onClose} />);
    expect(screen.getByPlaceholderText('e.g. Software Engineer')).toBeInTheDocument();
  });

  test('step 1 shows Department dropdown', () => {
    render(<UserOnboardingWizard onClose={onClose} />);
    expect(screen.getByText('Select department...')).toBeInTheDocument();
  });

  test('Continue is disabled when required step 1 fields are empty', () => {
    render(<UserOnboardingWizard onClose={onClose} />);
    const continueBtn = screen.getByText('Continue →');
    expect(continueBtn).toBeDisabled();
  });

  test('Continue becomes enabled when name and email are filled', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    const continueBtn = screen.getByText('Continue →');
    expect(continueBtn).not.toBeDisabled();
  });

  test('step 2 shows Role dropdown', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Standard User')).toBeInTheDocument();
    expect(screen.getByText('IT Admin')).toBeInTheDocument();
    expect(screen.getByText('Developer')).toBeInTheDocument();
  });

  test('step 2 shows Manager field', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByPlaceholderText('Type manager name or email...')).toBeInTheDocument();
  });

  test('step 3 shows Will enroll later option', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Will enroll later')).toBeInTheDocument();
  });

  test('step 3 shows Assign existing device option', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Assign existing device')).toBeInTheDocument();
  });

  test('step 4 shows review summary with entered data', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Review & Create Account')).toBeInTheDocument();
    expect(screen.getByText('Jane Smith')).toBeInTheDocument();
    expect(screen.getByText('jane@test.com')).toBeInTheDocument();
  });

  test('step 4 shows Role in review', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Role')).toBeInTheDocument();
  });

  test('creating account shows success header', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Create Employee Account'));
    await waitFor(() => {
      expect(screen.getByText('Employee Account Created')).toBeInTheDocument();
    });
  });

  test('success screen shows temporary password', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Create Employee Account'));
    await waitFor(() => {
      // "Temporary Password" is styled with CSS text-transform: uppercase,
      // but the DOM text is "Temporary Password"
      expect(screen.getByText('Temporary Password')).toBeInTheDocument();
    });
  });

  test('success screen shows user display name', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Alice');
    await user.type(screen.getByPlaceholderText('Smith'), 'Brown');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'alice@test.com');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Create Employee Account'));
    await waitFor(() => {
      expect(screen.getByText('Alice Brown')).toBeInTheDocument();
    });
  });

  test('Done button after creation calls onClose', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Create Employee Account'));
    await waitFor(() => {
      expect(screen.getByText('Done')).toBeInTheDocument();
    });
    await user.click(screen.getByText('Done'));
    expect(onClose).toHaveBeenCalled();
  });

  test('Cancel button calls onClose', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.click(screen.getByText('Cancel'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('Back button from step 2 goes to step 1', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    expect(screen.getByText('Role')).toBeInTheDocument();
    await user.click(screen.getByText('← Back'));
    expect(screen.getByPlaceholderText('Jane')).toBeInTheDocument();
  });

  test('warning shown on success screen about password', async () => {
    const user = userEvent.setup();
    render(<UserOnboardingWizard onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Jane'), 'Jane');
    await user.type(screen.getByPlaceholderText('Smith'), 'Smith');
    await user.type(screen.getByPlaceholderText('jane.smith@company.com'), 'jane@test.com');
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Continue →'));
    await user.click(screen.getByText('Create Employee Account'));
    await waitFor(() => {
      expect(screen.getByText(/Share this password securely/i)).toBeInTheDocument();
    });
  });
});
