import { CognitoAuthDriver, AuthResult, UserRegistrationData, UserLoginData } from './auth-drivers/cognito-driver';
import Logger from '../middlewares/logger';

/**
 * Authentication Service
 * Provides a unified interface for authentication operations
 * Can be easily extended to support multiple authentication providers
 */
export class AuthService {
  private driver: CognitoAuthDriver;
  private logger;

  constructor() {
    this.driver = new CognitoAuthDriver();
    this.logger = Logger.getInstance();
  }

  /**
   * Register a new user
   */
  async registerUser(data: UserRegistrationData): Promise<AuthResult> {
    this.logger.info('Registering new user', { email: data.email });
    return await this.driver.registerUser(data);
  }

  /**
   * Authenticate user login
   */
  async loginUser(data: UserLoginData): Promise<AuthResult> {
    this.logger.info('User login attempt', { email: data.email });
    return await this.driver.loginUser(data);
  }

  /**
   * Confirm user registration
   */
  async confirmUser(email: string, confirmationCode: string): Promise<AuthResult> {
    this.logger.info('Confirming user registration', { email });
    return await this.driver.confirmUser(email, confirmationCode);
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string): Promise<AuthResult> {
    this.logger.info('Refreshing access token');
    return await this.driver.refreshToken(refreshToken);
  }

  /**
   * Get user profile
   */
  async getUserProfile(accessToken: string): Promise<AuthResult> {
    this.logger.info('Getting user profile');
    return await this.driver.getUserProfile(accessToken);
  }

  /**
   * Logout user
   */
  async logoutUser(refreshToken: string): Promise<AuthResult> {
    this.logger.info('User logout');
    return await this.driver.logoutUser(refreshToken);
  }

  /**
   * Change user password
   */
  async changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<AuthResult> {
    this.logger.info('Changing user password');
    return await this.driver.changePassword(accessToken, oldPassword, newPassword);
  }

  /**
   * Get authentication service information
   */
  getServiceInfo(): { driver: { name: string; version: string; configured: boolean } } {
    return {
      driver: this.driver.getDriverInfo()
    };
  }

  /**
   * Check if authentication service is properly configured
   */
  isConfigured(): boolean {
    return this.driver.getDriverInfo().configured;
  }
}

// Export a singleton instance
export const authService = new AuthService();
