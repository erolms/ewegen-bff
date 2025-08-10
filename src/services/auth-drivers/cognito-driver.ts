import { 
  CognitoIdentityProviderClient,
  SignUpCommand,
  InitiateAuthCommand,
  ConfirmSignUpCommand,
  RevokeTokenCommand,
  ChangePasswordCommand,
  GetUserCommand
} from '@aws-sdk/client-cognito-identity-provider';
import winston from 'winston';

// Authentication result interfaces
export interface AuthResult {
  success: boolean;
  data?: any;
  error?: string;
  challenge?: string;
  session?: string;
}

export interface UserRegistrationData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

export interface UserLoginData {
  email: string;
  password: string;
}

export interface TokenData {
  accessToken: string;
  refreshToken: string;
  idToken: string;
  expiresIn: number;
}

export interface UserProfile {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  groups: string[];
  username: string;
}

/**
 * Cognito Authentication Driver
 * Handles all AWS Cognito interactions
 */
export class CognitoAuthDriver {
  private client: CognitoIdentityProviderClient;
  private logger: winston.Logger;
  private userPoolId: string;
  private clientId: string;

  constructor() {
    this.userPoolId = process.env.COGNITO_USER_POOL_ID || '';
    this.clientId = process.env.COGNITO_CLIENT_ID || '';
    
    if (!this.userPoolId || !this.clientId) {
      throw new Error('COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID environment variables are required');
    }

    this.client = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION || 'eu-central-1',
    });

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: { service: 'cognito-auth-driver' },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });
  }

  /**
   * Register a new user
   */
  async registerUser(data: UserRegistrationData): Promise<AuthResult> {
    try {
      const command = new SignUpCommand({
        ClientId: this.clientId,
        Username: data.email,
        Password: data.password,
        UserAttributes: [
          {
            Name: 'email',
            Value: data.email
          },
          {
            Name: 'given_name',
            Value: data.firstName
          },
          {
            Name: 'family_name',
            Value: data.lastName
          }
        ]
      });

      const result = await this.client.send(command);

      this.logger.info('User registration initiated', { 
        email: data.email, 
        userId: result.UserSub 
      });

      return {
        success: true,
        data: {
          userId: result.UserSub,
          userConfirmed: result.UserConfirmed
        }
      };

    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const errorName = error instanceof Error ? (error as any).name : 'UnknownError';
      
      this.logger.error('User registration failed', { 
        error: errorMessage, 
        code: errorName 
      });

      return {
        success: false,
        error: errorMessage,
        data: { code: errorName }
      };
    }
  }

  /**
   * Authenticate user login
   */
  async loginUser(data: UserLoginData): Promise<AuthResult> {
    try {
      const command = new InitiateAuthCommand({
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: this.clientId,
        AuthParameters: {
          USERNAME: data.email,
          PASSWORD: data.password
        }
      });

      const result = await this.client.send(command);

      if (result.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
        return {
          success: true,
          challenge: 'NEW_PASSWORD_REQUIRED',
          session: result.Session,
          data: { message: 'New password required' }
        };
      }

      if (result.AuthenticationResult) {
        this.logger.info('User login successful', { email: data.email });

        const tokens: TokenData = {
          accessToken: result.AuthenticationResult.AccessToken || '',
          refreshToken: result.AuthenticationResult.RefreshToken || '',
          idToken: result.AuthenticationResult.IdToken || '',
          expiresIn: result.AuthenticationResult.ExpiresIn || 3600
        };

        return {
          success: true,
          data: { tokens }
        };
      }

      return {
        success: false,
        error: 'Authentication failed'
      };

    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const errorName = error instanceof Error ? (error as any).name : 'UnknownError';
      
      this.logger.error('User login failed', { 
        error: errorMessage, 
        code: errorName 
      });

      return {
        success: false,
        error: errorMessage,
        data: { code: errorName }
      };
    }
  }

  /**
   * Confirm user registration
   */
  async confirmUser(email: string, confirmationCode: string): Promise<AuthResult> {
    try {
      const command = new ConfirmSignUpCommand({
        ClientId: this.clientId,
        Username: email,
        ConfirmationCode: confirmationCode
      });

      await this.client.send(command);

      this.logger.info('User confirmation successful', { email });

      return {
        success: true,
        data: { message: 'User confirmed successfully' }
      };

    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const errorName = error instanceof Error ? (error as any).name : 'UnknownError';
      
      this.logger.error('User confirmation failed', { 
        error: errorMessage, 
        code: errorName 
      });

      return {
        success: false,
        error: errorMessage,
        data: { code: errorName }
      };
    }
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string): Promise<AuthResult> {
    try {
      const command = new InitiateAuthCommand({
        AuthFlow: 'REFRESH_TOKEN_AUTH',
        ClientId: this.clientId,
        AuthParameters: {
          REFRESH_TOKEN: refreshToken
        }
      });

      const result = await this.client.send(command);

      if (result.AuthenticationResult) {
        this.logger.info('Token refresh successful');

        const tokens: Partial<TokenData> = {
          accessToken: result.AuthenticationResult.AccessToken || '',
          idToken: result.AuthenticationResult.IdToken || '',
          expiresIn: result.AuthenticationResult.ExpiresIn || 3600
        };

        return {
          success: true,
          data: { tokens }
        };
      }

      return {
        success: false,
        error: 'Token refresh failed'
      };

    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const errorName = error instanceof Error ? (error as any).name : 'UnknownError';
      
      this.logger.error('Token refresh failed', { 
        error: errorMessage, 
        code: errorName 
      });

      return {
        success: false,
        error: errorMessage,
        data: { code: errorName }
      };
    }
  }

  /**
   * Get user profile
   */
  async getUserProfile(accessToken: string): Promise<AuthResult> {
    try {
      const command = new GetUserCommand({
        AccessToken: accessToken
      });

      const result = await this.client.send(command);

      if (result.UserAttributes) {
        const email = result.UserAttributes.find(attr => attr.Name === 'email')?.Value || '';
        const firstName = result.UserAttributes.find(attr => attr.Name === 'given_name')?.Value || '';
        const lastName = result.UserAttributes.find(attr => attr.Name === 'family_name')?.Value || '';

        const profile: UserProfile = {
          id: result.Username || '',
          email,
          firstName,
          lastName,
          groups: [], // Cognito groups are typically handled via JWT claims
          username: result.Username || ''
        };

        return {
          success: true,
          data: { profile }
        };
      }

      return {
        success: false,
        error: 'Failed to get user profile'
      };

    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      this.logger.error('Get user profile failed', { 
        error: errorMessage 
      });

      return {
        success: false,
        error: errorMessage
      };
    }
  }

  /**
   * Logout user (revoke refresh token)
   */
  async logoutUser(refreshToken: string): Promise<AuthResult> {
    try {
      const command = new RevokeTokenCommand({
        ClientId: this.clientId,
        Token: refreshToken
      });

      await this.client.send(command);

      this.logger.info('User logout successful');

      return {
        success: true,
        data: { message: 'Logout successful' }
      };

    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const errorName = error instanceof Error ? (error as any).name : 'UnknownError';
      
      this.logger.error('User logout failed', { 
        error: errorMessage, 
        code: errorName 
      });

      return {
        success: false,
        error: errorMessage,
        data: { code: errorName }
      };
    }
  }

  /**
   * Change user password
   */
  async changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<AuthResult> {
    try {
      const command = new ChangePasswordCommand({
        AccessToken: accessToken,
        PreviousPassword: oldPassword,
        ProposedPassword: newPassword
      });

      await this.client.send(command);

      this.logger.info('Password change successful');

      return {
        success: true,
        data: { message: 'Password changed successfully' }
      };

    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const errorName = error instanceof Error ? (error as any).name : 'UnknownError';
      
      this.logger.error('Password change failed', { 
        error: errorMessage, 
        code: errorName 
      });

      return {
        success: false,
        error: errorMessage,
        data: { code: errorName }
      };
    }
  }

  /**
   * Get driver information
   */
  getDriverInfo(): { name: string; version: string; configured: boolean } {
    return {
      name: 'AWS Cognito',
      version: 'v3',
      configured: !!(this.userPoolId && this.clientId)
    };
  }
}
