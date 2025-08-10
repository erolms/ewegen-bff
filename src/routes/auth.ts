import { Router, Request, Response } from 'express';
import winston from 'winston';
import { authenticateToken, AuthenticatedRequest, getAuthStatus } from '../middlewares/auth';
import { authService } from '../services/auth-service';

const router = Router();

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'ewegen-bff-auth-routes' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

/**
 * User registration
 * POST /auth/register
 */
router.post('/register', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, firstName, lastName } = req.body;

    // Validate required fields
    if (!email || !password || !firstName || !lastName) {
      res.status(400).json({
        error: 'Missing required fields: email, password, firstName, lastName'
      });
      return;
    }

    // Use authentication service
    const result = await authService.registerUser({
      email,
      password,
      firstName,
      lastName
    });

    if (result.success) {
      res.status(201).json({
        message: 'Registration successful. Please check your email for confirmation.',
        userId: result.data?.userId,
        userConfirmed: result.data?.userConfirmed
      });
    } else {
      // Handle specific error codes
      const errorCode = result.data?.code;
      if (errorCode === 'UsernameExistsException') {
        res.status(409).json({ error: 'User already exists' });
        return;
      }
      if (errorCode === 'InvalidPasswordException') {
        res.status(400).json({ error: 'Password does not meet requirements' });
        return;
      }
      
      res.status(500).json({ error: result.error || 'Registration failed' });
    }

  } catch (error) {
    logger.error('User registration failed', { 
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    res.status(500).json({ error: 'Registration failed' });
  }
});

/**
 * User login
 * POST /auth/login
 */
router.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({
        error: 'Missing required fields: email, password'
      });
      return;
    }

    // Use authentication service
    const result = await authService.loginUser({ email, password });

    if (result.success) {
      if (result.challenge === 'NEW_PASSWORD_REQUIRED') {
        res.status(200).json({
          challenge: 'NEW_PASSWORD_REQUIRED',
          session: result.session,
          message: 'New password required'
        });
        return;
      }

      res.status(200).json({
        message: 'Login successful',
        tokens: result.data?.tokens
      });
    } else {
      // Handle specific error codes
      const errorCode = result.data?.code;
      if (errorCode === 'NotAuthorizedException') {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }
      if (errorCode === 'UserNotConfirmedException') {
        res.status(400).json({ error: 'User not confirmed. Please check your email.' });
        return;
      }
      
      res.status(500).json({ error: result.error || 'Login failed' });
    }

  } catch (error) {
    logger.error('User login failed', { 
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    res.status(500).json({ error: 'Login failed' });
  }
});

/**
 * Confirm user registration
 * POST /auth/confirm
 */
router.post('/confirm', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, confirmationCode } = req.body;

    if (!email || !confirmationCode) {
      res.status(400).json({
        error: 'Missing required fields: email, confirmationCode'
      });
      return;
    }

    // Use authentication service
    const result = await authService.confirmUser(email, confirmationCode);

    if (result.success) {
      res.status(200).json({
        message: 'User confirmed successfully'
      });
    } else {
      // Handle specific error codes
      const errorCode = result.data?.code;
      if (errorCode === 'CodeMismatchException') {
        res.status(400).json({ error: 'Invalid confirmation code' });
        return;
      }
      if (errorCode === 'ExpiredCodeException') {
        res.status(400).json({ error: 'Confirmation code expired' });
        return;
      }
      
      res.status(500).json({ error: result.error || 'Confirmation failed' });
    }

  } catch (error) {
    logger.error('User confirmation failed', { 
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    res.status(500).json({ error: 'Confirmation failed' });
  }
});

/**
 * Refresh access token
 * POST /auth/refresh
 */
router.post('/refresh', async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({
        error: 'Missing required field: refreshToken'
      });
      return;
    }

    // Use authentication service
    const result = await authService.refreshToken(refreshToken);

    if (result.success) {
      res.status(200).json({
        message: 'Token refreshed successfully',
        tokens: result.data?.tokens
      });
    } else {
      // Handle specific error codes
      const errorCode = result.data?.code;
      if (errorCode === 'NotAuthorizedException') {
        res.status(401).json({ error: 'Invalid refresh token' });
        return;
      }
      
      res.status(500).json({ error: result.error || 'Token refresh failed' });
    }

  } catch (error) {
    logger.error('Token refresh failed', { 
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

/**
 * Get current user profile
 * GET /auth/profile
 */
router.get('/profile', authenticateToken, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'User not authenticated' });
      return;
    }

    // Get access token from authorization header
    const accessToken = req.headers.authorization?.split(' ')[1];
    if (!accessToken) {
      res.status(401).json({ error: 'Access token required' });
      return;
    }

    // Use authentication service to get user profile
    const result = await authService.getUserProfile(accessToken);

    if (result.success) {
      res.status(200).json({
        user: {
          id: req.user.sub,
          email: req.user.email,
          roles: req.user.roles,
          username: req.user.cognitoUsername,
          profile: result.data?.profile
        }
      });
    } else {
      res.status(500).json({ error: result.error || 'Failed to get profile' });
    }

  } catch (error) {
    logger.error('Get profile failed', { error: error instanceof Error ? error.message : 'Unknown error' });
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

/**
 * Logout user
 * POST /auth/logout
 */
router.post('/logout', authenticateToken, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({
        error: 'Missing required field: refreshToken'
      });
      return;
    }

    // Use authentication service
    const result = await authService.logoutUser(refreshToken);

    if (result.success) {
      res.status(200).json({
        message: 'Logout successful'
      });
    } else {
      res.status(500).json({ error: result.error || 'Logout failed' });
    }

  } catch (error) {
    logger.error('User logout failed', { 
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    res.status(500).json({ error: 'Logout failed' });
  }
});

/**
 * Change password
 * POST /auth/change-password
 */
router.post('/change-password', authenticateToken, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      res.status(400).json({
        error: 'Missing required fields: oldPassword, newPassword'
      });
      return;
    }

    // Get access token from authorization header
    const accessToken = req.headers.authorization?.split(' ')[1];
    if (!accessToken) {
      res.status(401).json({ error: 'Access token required' });
      return;
    }

    // Use authentication service
    const result = await authService.changePassword(accessToken, oldPassword, newPassword);

    if (result.success) {
      res.status(200).json({
        message: 'Password changed successfully'
      });
    } else {
      // Handle specific error codes
      const errorCode = result.data?.code;
      if (errorCode === 'NotAuthorizedException') {
        res.status(401).json({ error: 'Invalid old password' });
        return;
      }
      if (errorCode === 'InvalidPasswordException') {
        res.status(400).json({ error: 'New password does not meet requirements' });
        return;
      }
      
      res.status(500).json({ error: result.error || 'Password change failed' });
    }

  } catch (error) {
    logger.error('Password change failed', { 
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    res.status(500).json({ error: 'Password change failed' });
  }
});

/**
 * Health check endpoint for authentication service
 * GET /auth/health
 */
router.get('/health', (_req: Request, res: Response): void => {
  const authStatus = getAuthStatus();
  
  res.status(200).json({
    status: 'ok',
    service: 'eWegen BFF Authentication',
    timestamp: new Date().toISOString(),
    cognitoConfigured: authStatus.configured,
    driver: authStatus.driver
  });
});

export default router; 