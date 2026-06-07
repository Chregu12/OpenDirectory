import '@testing-library/jest-dom';

// Mock axios globally - the api module uses axios.create()
jest.mock('axios', () => {
  const mockAxios: any = {
    get: jest.fn().mockResolvedValue({ data: {} }),
    post: jest.fn().mockResolvedValue({ data: {} }),
    put: jest.fn().mockResolvedValue({ data: {} }),
    delete: jest.fn().mockResolvedValue({ data: {} }),
    interceptors: {
      request: { use: jest.fn(), eject: jest.fn() },
      response: { use: jest.fn(), eject: jest.fn() },
    },
    defaults: { headers: { common: {} } },
  };
  mockAxios.create = jest.fn(() => mockAxios);
  return { default: mockAxios, ...mockAxios };
});

// Mock react-hot-toast
jest.mock('react-hot-toast', () => ({
  default: {
    success: jest.fn(),
    error: jest.fn(),
  },
  success: jest.fn(),
  error: jest.fn(),
  Toaster: () => null,
}));

// Mock URL.createObjectURL / revokeObjectURL
global.URL.createObjectURL = jest.fn().mockReturnValue('blob:mock-url');
global.URL.revokeObjectURL = jest.fn();

// Note: Do NOT mock navigator.clipboard here — userEvent.setup() manages it.
// If a test needs clipboard assertions, use userEvent's built-in clipboard support.
