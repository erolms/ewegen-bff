/**
 * Authentication configuration
 * Environment variables required for AWS Cognito integration with AWS SDK v3
 */

export interface AuthConfig {
  aws: {
    region: string;
  };
  cognito: {
    userPoolId: string;
    clientId: string;
    clientSecret?: string;
  };
  jwt: {
    issuer: string;
    algorithms: string[];
  };
  roles: {
    adminGroup: string;
    memberGroup: string;
    volunteerGroup: string;
  };
}

/**
 * Get authentication configuration from environment variables
 */
export function getAuthConfig(): AuthConfig {
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  const clientId = process.env.COGNITO_CLIENT_ID;
  const region = process.env.AWS_REGION || 'eu-central-1';

  if (!userPoolId) {
    throw new Error('COGNITO_USER_POOL_ID environment variable is required');
  }

  if (!clientId) {
    throw new Error('COGNITO_CLIENT_ID environment variable is required');
  }

  return {
    aws: {
      region,
    },
    cognito: {
      userPoolId,
      clientId,
      clientSecret: process.env.COGNITO_CLIENT_SECRET,
    },
    jwt: {
      issuer: `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`,
      algorithms: ['RS256'],
    },
    roles: {
      adminGroup: process.env.COGNITO_ADMIN_GROUP || 'admin-group',
      memberGroup: process.env.COGNITO_MEMBER_GROUP || 'member-group',
      volunteerGroup: process.env.COGNITO_VOLUNTEER_GROUP || 'volunteer-group',
    },
  };
}

/**
 * Validate authentication configuration
 */
export function validateAuthConfig(): boolean {
  try {
    getAuthConfig();
    return true;
  } catch (error) {
    console.error('Authentication configuration validation failed:', error);
    return false;
  }
}

/**
 * Get required environment variables for authentication
 */
export function getRequiredEnvVars(): string[] {
  return [
    'COGNITO_USER_POOL_ID',
    'COGNITO_CLIENT_ID',
    'AWS_REGION',
  ];
}

/**
 * Get optional environment variables for authentication
 */
export function getOptionalEnvVars(): string[] {
  return [
    'COGNITO_CLIENT_SECRET',
    'COGNITO_ADMIN_GROUP',
    'COGNITO_MEMBER_GROUP',
    'COGNITO_VOLUNTEER_GROUP',
  ];
} 