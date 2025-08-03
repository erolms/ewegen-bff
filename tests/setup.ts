// Jest setup file for global test configuration

// Set test timeout
jest.setTimeout(10000);

// Global test utilities
global.console = {
  ...console,
  // Suppress console.log during tests unless explicitly needed
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Mock environment variables for testing
process.env.NODE_ENV = 'test';
process.env.PORT = '8080';

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
  jest.clearAllTimers();
});

// Export test utilities for use in test files
export const testUtils = {
  // Helper to create mock Express request
  createMockRequest: (overrides = {}) => ({
    body: {},
    query: {},
    params: {},
    headers: {},
    method: 'GET',
    url: '/',
    ...overrides,
  }),

  // Helper to create mock Express response
  createMockResponse: () => {
    const res: Record<string, unknown> = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    res.send = jest.fn().mockReturnValue(res);
    res.end = jest.fn().mockReturnValue(res);
    res.setHeader = jest.fn().mockReturnValue(res);
    res.getHeader = jest.fn();
    return res;
  },

  // Helper to create mock Express next function
  createMockNext: () => jest.fn(),
}; 
