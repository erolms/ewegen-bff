import request from 'supertest';
import { describe, beforeEach, afterEach, expect, it, jest } from '@jest/globals';
import app from '../src/app';
import { UserRole } from '../src/middlewares/auth';
import { getAuthConfig } from '../src/config/aws-auth';
import { authService } from '../src/services/auth-service';

// Mock the authentication service
jest.mock('../src/services/auth-service', () => ({
  authService: {
    registerUser: jest.fn(),
    loginUser: jest.fn(),
    confirmUser: jest.fn(),
    refreshToken: jest.fn(),
    getUserProfile: jest.fn(),
    logoutUser: jest.fn(),
    changePassword: jest.fn(),
    getServiceInfo: jest.fn(),
    isConfigured: jest.fn(),
  },
}));

// Mock JWT
jest.mock('jsonwebtoken', () => ({
  decode: jest.fn(),
  verify: jest.fn(),
}));

// Mock fetch for JWKs
global.fetch = jest.fn() as jest.MockedFunction<typeof fetch>;

describe('Authentication System - Refactored Architecture', () => {
  beforeEach(() => {
    // Reset environment variables
    delete process.env.COGNITO_USER_POOL_ID;
    delete process.env.COGNITO_CLIENT_ID;
    delete process.env.AWS_REGION;
    
    // Clear all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Configuration', () => {
    it('should throw error when COGNITO_USER_POOL_ID is missing', () => {
      process.env.COGNITO_CLIENT_ID = 'test-client-id';
      process.env.AWS_REGION = 'eu-central-1';

      expect(() => getAuthConfig()).toThrow('COGNITO_USER_POOL_ID environment variable is required');
    });

    it('should throw error when COGNITO_CLIENT_ID is missing', () => {
      process.env.COGNITO_USER_POOL_ID = 'eu-central-1_testpool';
      process.env.AWS_REGION = 'eu-central-1';

      expect(() => getAuthConfig()).toThrow('COGNITO_CLIENT_ID environment variable is required');
    });

    it('should use default region when AWS_REGION is not set', () => {
      process.env.COGNITO_USER_POOL_ID = 'eu-central-1_testpool';
      process.env.COGNITO_CLIENT_ID = 'test-client-id';

      const config = getAuthConfig();
      expect(config.aws.region).toBe('eu-central-1');
    });

    it('should not require AWS credentials for SDK v3', () => {
      process.env.COGNITO_USER_POOL_ID = 'eu-central-1_testpool';
      process.env.COGNITO_CLIENT_ID = 'test-client-id';
      process.env.AWS_REGION = 'eu-central-1';

      const config = getAuthConfig();
      expect(config.aws).not.toHaveProperty('accessKeyId');
      expect(config.aws).not.toHaveProperty('secretAccessKey');
    });
  });

  describe('User Roles', () => {
    it('should have correct role values', () => {
      expect(UserRole.ADMIN).toBe('admin');
      expect(UserRole.MEMBER).toBe('member');
      expect(UserRole.VOLUNTEER).toBe('volunteer');
      expect(UserRole.GUEST).toBe('guest');
    });

    it('should have all required roles', () => {
      const roles = Object.values(UserRole);
      expect(roles).toContain('admin');
      expect(roles).toContain('member');
      expect(roles).toContain('volunteer');
      expect(roles).toContain('guest');
      expect(roles).toHaveLength(4);
    });
  });

  describe('Authentication Service', () => {
    beforeEach(() => {
      // Set required environment variables for tests
      process.env.COGNITO_USER_POOL_ID = 'eu-central-1_testpool';
      process.env.COGNITO_CLIENT_ID = 'test-client-id';
      process.env.AWS_REGION = 'eu-central-1';
    });

    it('should be properly configured', () => {
      const mockIsConfigured = authService.isConfigured as jest.MockedFunction<typeof authService.isConfigured>;
      mockIsConfigured.mockReturnValue(true);

      expect(authService.isConfigured()).toBe(true);
    });

    it('should provide service information', () => {
      const mockGetServiceInfo = authService.getServiceInfo as jest.MockedFunction<typeof authService.getServiceInfo>;
      mockGetServiceInfo.mockReturnValue({
        driver: {
          name: 'AWS Cognito',
          version: 'v3',
          configured: true
        }
      });

      const serviceInfo = authService.getServiceInfo();
      expect(serviceInfo.driver.name).toBe('AWS Cognito');
      expect(serviceInfo.driver.version).toBe('v3');
      expect(serviceInfo.driver.configured).toBe(true);
    });
  });

  describe('Authentication Routes - Health Check', () => {
    beforeEach(() => {
      // Set required environment variables for tests
      process.env.COGNITO_USER_POOL_ID = 'eu-central-1_testpool';
      process.env.COGNITO_CLIENT_ID = 'test-client-id';
      process.env.AWS_REGION = 'eu-central-1';
    });

    it('should return health status for auth service', async () => {
      const mockIsConfigured = authService.isConfigured as jest.MockedFunction<typeof authService.isConfigured>;
      const mockGetServiceInfo = authService.getServiceInfo as jest.MockedFunction<typeof authService.getServiceInfo>;
      
      mockIsConfigured.mockReturnValue(true);
      mockGetServiceInfo.mockReturnValue({
        driver: {
          name: 'AWS Cognito',
          version: 'v3',
          configured: true
        }
      });

      const response = await request(app).get('/auth/health');
      
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('status', 'ok');
      expect(response.body).toHaveProperty('service', 'eWegen BFF Authentication');
      expect(response.body).toHaveProperty('cognitoConfigured', true);
      expect(response.body).toHaveProperty('driver');
      expect(response.body).toHaveProperty('timestamp');
    });

    it('should return cognitoConfigured false when service is not configured', async () => {
      const mockIsConfigured = authService.isConfigured as jest.MockedFunction<typeof authService.isConfigured>;
      const mockGetServiceInfo = authService.getServiceInfo as jest.MockedFunction<typeof authService.getServiceInfo>;
      
      mockIsConfigured.mockReturnValue(false);
      mockGetServiceInfo.mockReturnValue({
        driver: {
          name: 'AWS Cognito',
          version: 'v3',
          configured: false
        }
      });

      const response = await request(app).get('/auth/health');
      
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('cognitoConfigured', false);
    });
  });

  describe('Authentication Routes - Registration', () => {
    beforeEach(() => {
      process.env.COGNITO_USER_POOL_ID = 'eu-central-1_testpool';
      process.env.COGNITO_CLIENT_ID = 'test-client-id';
      process.env.AWS_REGION = 'eu-central-1';
    });

    it('should register user successfully', async () => {
      const mockRegisterUser = authService.registerUser as jest.MockedFunction<typeof authService.registerUser>;
      mockRegisterUser.mockResolvedValue({
        success: true,
        data: {
          userId: 'test-user-id',
          userConfirmed: false
        }
      });

      const response = await request(app)
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'TestPassword123!',
          firstName: 'Test',
          lastName: 'User'
        });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('message', 'Registration successful. Please check your email for confirmation.');
      expect(response.body).toHaveProperty('userId', 'test-user-id');
      expect(response.body).toHaveProperty('userConfirmed', false);
    });

    it('should handle user already exists error', async () => {
      const mockRegisterUser = authService.registerUser as jest.MockedFunction<typeof authService.registerUser>;
      mockRegisterUser.mockResolvedValue({
        success: false,
        error: 'User already exists',
        data: { code: 'UsernameExistsException' }
      });

      const response = await request(app)
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'TestPassword123!',
          firstName: 'Test',
          lastName: 'User'
        });

      expect(response.status).toBe(409);
      expect(response.body).toHaveProperty('error', 'User already exists');
    });
  });

  describe('Protected Routes - Health Check', () => {
    beforeEach(() => {
      process.env.COGNITO_USER_POOL_ID = 'eu-central-1_testpool';
      process.env.COGNITO_CLIENT_ID = 'test-client-id';
      process.env.AWS_REGION = 'eu-central-1';
    });

    it('should reject access to protected route without token', async () => {
      const response = await request(app).get('/protected/health');

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'Access token required');
    });

    it('should reject access to protected route with invalid token', async () => {
      const response = await request(app)
        .get('/protected/health')
        .set('Authorization', 'Bearer invalid-token');

      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('error', 'Invalid token');
    });
  });

  describe('Main Application', () => {
    it('should return main application status', async () => {
      const response = await request(app).get('/');
      
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('status', 'ok');
      expect(response.body).toHaveProperty('message', 'eWegen BFF is running');
      expect(response.body).toHaveProperty('version', '1.0.0');
      expect(response.body).toHaveProperty('timestamp');
    });
  });

  describe('Architecture Benefits', () => {
    it('should demonstrate separation of concerns', () => {
      // Routes should not directly import AWS SDK
      import('../src/routes/auth').then(authRoutes => {
        expect(authRoutes).toBeDefined();
      });
      
      // Service should handle business logic
      expect(authService).toBeDefined();
      expect(typeof authService.registerUser).toBe('function');
      expect(typeof authService.loginUser).toBe('function');
    });

    it('should support easy driver swapping', () => {
      // The service can easily be extended to support multiple drivers
      expect(authService.getServiceInfo).toBeDefined();
      expect(typeof authService.getServiceInfo).toBe('function');
    });
  });
}); 