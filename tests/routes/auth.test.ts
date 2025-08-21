// Ensure required env vars are present before modules import
process.env.COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'eu-central-1_testpool123';
process.env.COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || 'test-client-id';
process.env.AWS_REGION = process.env.AWS_REGION || 'eu-central-1';

import { Request, Response } from 'express';
import { authService } from '../../src/services/auth-service';
import { AuthenticatedRequest, UserRole, getAuthStatus } from '../../src/middlewares/auth';
import { _test } from '../../src/routes/auth';
import { beforeEach, describe, expect, it, jest, afterEach } from '@jest/globals';

// Mock dependencies
jest.mock('../../src/services/auth-service');
jest.mock('../../src/middlewares/auth');
jest.mock('../../src/middlewares/logger', () => ({
  __esModule: true,
  default: {
    getInstance: jest.fn(() => ({
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn()
    }))
  }
}));

const mockAuthService = authService as jest.Mocked<typeof authService>;
const mockAuthStatus = getAuthStatus as jest.Mocked<typeof getAuthStatus>;

describe('Auth Routes', () => {
  let mockRequest: Partial<Request> | Partial<AuthenticatedRequest>;
  let mockResponse: Partial<Response>;

  beforeEach(() => {
    jest.clearAllMocks();

    mockRequest = {
      body: {},
      headers: {},
      method: 'POST',
      url: '/auth/register'
    };

    mockResponse = {
      status: jest.fn().mockReturnThis() as jest.MockedFunction<Response['status']>,
      json: jest.fn().mockReturnThis() as jest.MockedFunction<Response['json']>
    };

    // Setup default auth service mocks
    mockAuthService.registerUser = jest.fn();
    mockAuthService.loginUser = jest.fn();
    mockAuthService.confirmUser = jest.fn();
    mockAuthService.refreshToken = jest.fn();
    mockAuthService.getUserProfile = jest.fn();
    mockAuthService.logoutUser = jest.fn();
    mockAuthService.changePassword = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /auth/register', () => {
    const validRegistrationData = {
      email: 'test@example.com',
      password: 'TestPassword123!',
      firstName: 'John',
      lastName: 'Doe'
    };

    it('should register user successfully', async () => {
      mockRequest.body = validRegistrationData;
      mockAuthService.registerUser.mockResolvedValue({
        success: true,
        data: { userId: 'user123', userConfirmed: false }
      });

      await _test.handleRegister(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.registerUser).toHaveBeenCalledWith(validRegistrationData);
      expect(mockResponse.status).toHaveBeenCalledWith(201);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Registration successful. Please check your email for confirmation.',
        userId: 'user123',
        userConfirmed: false
      });
    });

    it('should return 400 when missing required fields', async () => {
      mockRequest.body = { email: 'test@example.com' }; // Missing password, firstName, lastName

      await _test.handleRegister(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Missing required fields: email, password, firstName, lastName'
      });
      expect(mockAuthService.registerUser).not.toHaveBeenCalled();
    });

    it('should return 409 when user already exists', async () => {
      mockRequest.body = validRegistrationData;
      mockAuthService.registerUser.mockResolvedValue({
        success: false,
        error: 'User already exists',
        data: { code: 'UsernameExistsException' }
      });

      await _test.handleRegister(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(409);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'User already exists' });
    });

    it('should return 400 when password is invalid', async () => {
      mockRequest.body = validRegistrationData;
      mockAuthService.registerUser.mockResolvedValue({
        success: false,
        error: 'Invalid password',
        data: { code: 'InvalidPasswordException' }
      });

      await _test.handleRegister(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Password does not meet requirements' });
    });

    it('should return 500 for other registration failures', async () => {
      mockRequest.body = validRegistrationData;
      mockAuthService.registerUser.mockResolvedValue({
        success: false,
        error: 'Unknown error'
      });

      await _test.handleRegister(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Unknown error' });
    });

    it('should handle registration service exceptions', async () => {
      mockRequest.body = validRegistrationData;
      mockAuthService.registerUser.mockRejectedValue(new Error('Service error'));

      await _test.handleRegister(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Registration failed' });
    });
  });

  describe('POST /auth/login', () => {
    const validLoginData = {
      email: 'test@example.com',
      password: 'TestPassword123!'
    };

    it('should login user successfully', async () => {
      mockRequest.body = validLoginData;
      mockAuthService.loginUser.mockResolvedValue({
        success: true,
        data: { tokens: { accessToken: 'access123', refreshToken: 'refresh123' } }
      });

      await _test.handleLogin(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.loginUser).toHaveBeenCalledWith(validLoginData);
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Login successful',
        tokens: { accessToken: 'access123', refreshToken: 'refresh123' }
      });
    });

    it('should handle new password required challenge', async () => {
      mockRequest.body = validLoginData;
      mockAuthService.loginUser.mockResolvedValue({
        success: true,
        challenge: 'NEW_PASSWORD_REQUIRED',
        session: 'session123'
      });

      await _test.handleLogin(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        challenge: 'NEW_PASSWORD_REQUIRED',
        session: 'session123',
        message: 'New password required'
      });
    });

    it('should return 400 when missing required fields', async () => {
      mockRequest.body = { email: 'test@example.com' }; // Missing password

      await _test.handleLogin(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Missing required fields: email, password'
      });
      expect(mockAuthService.loginUser).not.toHaveBeenCalled();
    });

    it('should return 401 for invalid credentials', async () => {
      mockRequest.body = validLoginData;
      mockAuthService.loginUser.mockResolvedValue({
        success: false,
        error: 'Invalid credentials',
        data: { code: 'NotAuthorizedException' }
      });

      await _test.handleLogin(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid credentials' });
    });

    it('should return 400 when user not confirmed', async () => {
      mockRequest.body = validLoginData;
      mockAuthService.loginUser.mockResolvedValue({
        success: false,
        error: 'User not confirmed',
        data: { code: 'UserNotConfirmedException' }
      });

      await _test.handleLogin(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'User not confirmed. Please check your email.' });
    });

    it('should return 500 for other login failures', async () => {
      mockRequest.body = validLoginData;
      mockAuthService.loginUser.mockResolvedValue({
        success: false,
        error: 'Unknown error'
      });

      await _test.handleLogin(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Unknown error' });
    });

    it('should handle login service exceptions', async () => {
      mockRequest.body = validLoginData;
      mockAuthService.loginUser.mockRejectedValue(new Error('Service error'));

      await _test.handleLogin(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Login failed' });
    });
  });

  describe('POST /auth/confirm', () => {
    const validConfirmData = {
      email: 'test@example.com',
      confirmationCode: '123456'
    };

    it('should confirm user successfully', async () => {
      mockRequest.body = validConfirmData;
      mockAuthService.confirmUser.mockResolvedValue({
        success: true
      });

      await _test.handleConfirm(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.confirmUser).toHaveBeenCalledWith('test@example.com', '123456');
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'User confirmed successfully'
      });
    });

    it('should return 400 when missing required fields', async () => {
      mockRequest.body = { email: 'test@example.com' }; // Missing confirmationCode

      await _test.handleConfirm(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Missing required fields: email, confirmationCode'
      });
      expect(mockAuthService.confirmUser).not.toHaveBeenCalled();
    });

    it('should return 400 for invalid confirmation code', async () => {
      mockRequest.body = validConfirmData;
      mockAuthService.confirmUser.mockResolvedValue({
        success: false,
        error: 'Invalid code',
        data: { code: 'CodeMismatchException' }
      });

      await _test.handleConfirm(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid confirmation code' });
    });

    it('should return 400 for expired confirmation code', async () => {
      mockRequest.body = validConfirmData;
      mockAuthService.confirmUser.mockResolvedValue({
        success: false,
        error: 'Code expired',
        data: { code: 'ExpiredCodeException' }
      });

      await _test.handleConfirm(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Confirmation code expired' });
    });

    it('should return 500 for other confirmation failures', async () => {
      mockRequest.body = validConfirmData;
      mockAuthService.confirmUser.mockResolvedValue({
        success: false,
        error: 'Unknown error'
      });

      await _test.handleConfirm(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Unknown error' });
    });

    it('should handle confirmation service exceptions', async () => {
      mockRequest.body = validConfirmData;
      mockAuthService.confirmUser.mockRejectedValue(new Error('Service error'));

      await _test.handleConfirm(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Confirmation failed' });
    });
  });

  describe('POST /auth/refresh', () => {
    const validRefreshData = {
      refreshToken: 'refresh123'
    };

    it('should refresh token successfully', async () => {
      mockRequest.body = validRefreshData;
      mockAuthService.refreshToken.mockResolvedValue({
        success: true,
        data: { tokens: { accessToken: 'newAccess123', refreshToken: 'newRefresh123' } }
      });

      await _test.handleRefresh(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.refreshToken).toHaveBeenCalledWith('refresh123');
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Token refreshed successfully',
        tokens: { accessToken: 'newAccess123', refreshToken: 'newRefresh123' }
      });
    });

    it('should return 400 when missing refresh token', async () => {
      mockRequest.body = {};

      await _test.handleRefresh(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Missing required field: refreshToken'
      });
      expect(mockAuthService.refreshToken).not.toHaveBeenCalled();
    });

    it('should return 401 for invalid refresh token', async () => {
      mockRequest.body = validRefreshData;
      mockAuthService.refreshToken.mockResolvedValue({
        success: false,
        error: 'Invalid token',
        data: { code: 'NotAuthorizedException' }
      });

      await _test.handleRefresh(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid refresh token' });
    });

    it('should return 500 for other refresh failures', async () => {
      mockRequest.body = validRefreshData;
      mockAuthService.refreshToken.mockResolvedValue({
        success: false,
        error: 'Unknown error'
      });

      await _test.handleRefresh(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Unknown error' });
    });

    it('should handle refresh service exceptions', async () => {
      mockRequest.body = validRefreshData;
      mockAuthService.refreshToken.mockRejectedValue(new Error('Service error'));

      await _test.handleRefresh(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Token refresh failed' });
    });
  });

  describe('GET /auth/profile', () => {
    const mockUser = {
      sub: 'user123',
      email: 'test@example.com',
      roles: [UserRole.ADMIN],
      cognitoUsername: 'testuser'
    };

    it('should get user profile successfully', async () => {
      (mockRequest as Partial<AuthenticatedRequest>).headers = { authorization: 'Bearer access123' };
      (mockRequest as Partial<AuthenticatedRequest>).user = mockUser;
      mockAuthService.getUserProfile.mockResolvedValue({
        success: true,
        data: { profile: { firstName: 'John', lastName: 'Doe' } }
      });

      await _test.handleGetProfile(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockAuthService.getUserProfile).toHaveBeenCalledWith('access123');
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        user: {
          id: 'user123',
          email: 'test@example.com',
          roles: ['admin'],
          username: 'testuser',
          profile: { firstName: 'John', lastName: 'Doe' }
        }
      });
    });

    it('should return 401 when user not authenticated', async () => {
      (mockRequest as Partial<AuthenticatedRequest>).user = undefined;

      await _test.handleGetProfile(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'User not authenticated' });
      expect(mockAuthService.getUserProfile).not.toHaveBeenCalled();
    });

    it('should return 401 when access token missing', async () => {
      (mockRequest as Partial<AuthenticatedRequest>).user = mockUser;
      (mockRequest as Partial<AuthenticatedRequest>).headers = {};

      await _test.handleGetProfile(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Access token required' });
      expect(mockAuthService.getUserProfile).not.toHaveBeenCalled();
    });

    it('should return 500 when profile fetch fails', async () => {
      (mockRequest as Partial<AuthenticatedRequest>).headers = { authorization: 'Bearer access123' };
      (mockRequest as Partial<AuthenticatedRequest>).user = mockUser;
      mockAuthService.getUserProfile.mockResolvedValue({
        success: false,
        error: 'Profile fetch failed'
      });

      await _test.handleGetProfile(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Profile fetch failed' });
    });

    it('should handle profile service exceptions', async () => {
      (mockRequest as Partial<AuthenticatedRequest>).headers = { authorization: 'Bearer access123' };
      (mockRequest as Partial<AuthenticatedRequest>).user = mockUser;
      mockAuthService.getUserProfile.mockRejectedValue(new Error('Service error'));

      await _test.handleGetProfile(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Failed to get profile' });
    });
  });

  describe('POST /auth/logout', () => {
    const validLogoutData = {
      refreshToken: 'refresh123'
    };

    it('should logout user successfully', async () => {
      mockRequest.body = validLogoutData;
      mockAuthService.logoutUser.mockResolvedValue({
        success: true
      });

      await _test.handleLogout(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockAuthService.logoutUser).toHaveBeenCalledWith('refresh123');
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Logout successful'
      });
    });

    it('should return 400 when missing refresh token', async () => {
      mockRequest.body = {};

      await _test.handleLogout(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Missing required field: refreshToken'
      });
      expect(mockAuthService.logoutUser).not.toHaveBeenCalled();
    });

    it('should return 500 when logout fails', async () => {
      mockRequest.body = validLogoutData;
      mockAuthService.logoutUser.mockResolvedValue({
        success: false,
        error: 'Logout failed'
      });

      await _test.handleLogout(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Logout failed' });
    });

    it('should handle logout service exceptions', async () => {
      mockRequest.body = validLogoutData;
      mockAuthService.logoutUser.mockRejectedValue(new Error('Service error'));

      await _test.handleLogout(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Logout failed' });
    });
  });

  describe('POST /auth/change-password', () => {
    const validChangePasswordData = {
      oldPassword: 'OldPassword123!',
      newPassword: 'NewPassword123!'
    };

    const mockUser = {
      sub: 'user123',
      email: 'test@example.com',
      roles: [UserRole.ADMIN],
      cognitoUsername: 'testuser'
    };

    it('should change password successfully', async () => {
      mockRequest.body = validChangePasswordData;
      (mockRequest as Partial<AuthenticatedRequest>).headers = { authorization: 'Bearer access123' };
      (mockRequest as Partial<AuthenticatedRequest>).user = mockUser;
      mockAuthService.changePassword.mockResolvedValue({
        success: true
      });

      await _test.handleChangePassword(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockAuthService.changePassword).toHaveBeenCalledWith('access123', 'OldPassword123!', 'NewPassword123!');
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Password changed successfully'
      });
    });

    it('should return 400 when missing required fields', async () => {
      mockRequest.body = { oldPassword: 'OldPassword123!' }; // Missing newPassword

      await _test.handleChangePassword(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Missing required fields: oldPassword, newPassword'
      });
      expect(mockAuthService.changePassword).not.toHaveBeenCalled();
    });

    it('should return 401 when access token missing', async () => {
      mockRequest.body = validChangePasswordData;
      (mockRequest as Partial<AuthenticatedRequest>).headers = {};

      await _test.handleChangePassword(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Access token required' });
      expect(mockAuthService.changePassword).not.toHaveBeenCalled();
    });

    it('should return 401 for invalid old password', async () => {
      mockRequest.body = validChangePasswordData;
      (mockRequest as Partial<AuthenticatedRequest>).headers = { authorization: 'Bearer access123' };
      (mockRequest as Partial<AuthenticatedRequest>).user = mockUser;
      mockAuthService.changePassword.mockResolvedValue({
        success: false,
        error: 'Invalid old password',
        data: { code: 'NotAuthorizedException' }
      });

      await _test.handleChangePassword(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid old password' });
    });

    it('should return 400 for invalid new password', async () => {
      mockRequest.body = validChangePasswordData;
      (mockRequest as Partial<AuthenticatedRequest>).headers = { authorization: 'Bearer access123' };
      (mockRequest as Partial<AuthenticatedRequest>).user = mockUser;
      mockAuthService.changePassword.mockResolvedValue({
        success: false,
        error: 'Invalid new password',
        data: { code: 'InvalidPasswordException' }
      });

      await _test.handleChangePassword(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'New password does not meet requirements' });
    });

    it('should return 500 for other password change failures', async () => {
      mockRequest.body = validChangePasswordData;
      (mockRequest as Partial<AuthenticatedRequest>).headers = { authorization: 'Bearer access123' };
      (mockRequest as Partial<AuthenticatedRequest>).user = mockUser;
      mockAuthService.changePassword.mockResolvedValue({
        success: false,
        error: 'Unknown error'
      });

      await _test.handleChangePassword(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Unknown error' });
    });

    it('should handle password change service exceptions', async () => {
      mockRequest.body = validChangePasswordData;
      (mockRequest as Partial<AuthenticatedRequest>).headers = { authorization: 'Bearer access123' };
      (mockRequest as Partial<AuthenticatedRequest>).user = mockUser;
      mockAuthService.changePassword.mockRejectedValue(new Error('Service error'));

      await _test.handleChangePassword(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Password change failed' });
    });
  });

  describe('GET /auth/health', () => {
    it('should return health status successfully', async () => {
      // Mock the authService methods that getAuthStatus depends on
      mockAuthService.isConfigured.mockReturnValue(true);
      mockAuthService.getServiceInfo.mockReturnValue({
        driver: { name: 'AWS cognito mock', version: 'v3', configured: mockAuthService.isConfigured() }
      });
      mockAuthStatus.mockReturnValue({
        configured: mockAuthService.isConfigured(),
        driver: mockAuthService.getServiceInfo().driver
      });

      await _test.handleHealth(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'ok',
        service: 'eWegen BFF Authentication',
        timestamp: expect.anything(),
        cognitoConfigured: true,
        driver: { name: 'AWS cognito mock', version: 'v3', configured: true }
      });
    });
  });
});
