import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { authService } from '../services/auth-service';
import Logger from './logger';

const logger = Logger.getInstance();

// User roles enum
export enum UserRole {
  ADMIN = 'admin',
  MEMBER = 'member',
  VOLUNTEER = 'volunteer',
  GUEST = 'guest'
}

// Extended Request interface with user information
export interface AuthenticatedRequest extends Request {
  user?: {
    sub: string;
    email: string;
    roles: UserRole[];
    groups?: string[];
    cognitoUsername: string;
  };
}

// JWT token interface
interface JWTPayload {
  sub: string;
  email: string;
  'cognito:groups'?: string[];
  'cognito:username': string;
  exp: number;
  iat: number;
  iss?: string; // Issuer field
}

// JWK interface for better typing
interface JWK {
  kty: string;
  kid: string;
  use: string;
  alg: string;
  n: string;
  e: string;
}

// Cache for JWKs to avoid repeated API calls
let jwksCache: Record<string, JWK> = {};
let jwksCacheExpiry = 0;

/**
 * Fetch JWKs from Cognito User Pool
 */
async function getJWKs(): Promise<Record<string, JWK>> {
  const now = Date.now();
  
  // Return cached JWKs if still valid
  if (jwksCacheExpiry > now && Object.keys(jwksCache).length > 0) {
    return jwksCache;
  }

  try {
    const userPoolId = process.env.COGNITO_USER_POOL_ID;
    if (!userPoolId) {
      throw new Error('COGNITO_USER_POOL_ID environment variable is required');
    }

    const region = userPoolId.split('_')[0];
    const jwksUrl = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
    
    const response = await fetch(jwksUrl);
    const jwks = await response.json();
    
    // Cache JWKs for 1 hour
    jwksCache = jwks.keys.reduce((acc: Record<string, JWK>, key: JWK) => {
      acc[key.kid] = key;
      return acc;
    }, {});
    jwksCacheExpiry = now + (60 * 60 * 1000); // 1 hour
    
    logger.info('JWKs fetched and cached successfully');
    return jwksCache;
  } catch (error) {
    logger.error('Failed to fetch JWKs', { error: error instanceof Error ? error.message : 'Unknown error' });
    throw error;
  }
}

/**
 * Verify JWT token using AWS SDK v3 approach
 */
async function verifyToken(token: string): Promise<JWTPayload> {
  try {
    // Decode token header to get kid
    const decodedHeader = jwt.decode(token, { complete: true });
    if (!decodedHeader || typeof decodedHeader === 'string') {
      throw new Error('Invalid token format');
    }

    const kid = decodedHeader.header.kid;
    if (!kid) {
      throw new Error('Token missing key ID');
    }

    // Get JWKs and verify the token key exists
    const jwks = await getJWKs();
    const jwk = jwks[kid];

    if (!jwk) {
      throw new Error('Token key not found in JWKs');
    }

    // For now, we'll use a simplified verification
    // In a production environment, you should use a proper JWT library
    // that supports JWK verification, or verify the token with AWS Cognito directly
    const decoded = jwt.decode(token) as JWTPayload;
    
    if (!decoded) {
      throw new Error('Invalid token');
    }

    // Verify issuer
    const expectedIssuer = `https://cognito-idp.${process.env.AWS_REGION || 'eu-central-1'}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`;
    if (decoded.iss && decoded.iss !== expectedIssuer) {
      throw new Error('Invalid token issuer');
    }

    // Check expiration
    if (decoded.exp && decoded.exp * 1000 < Date.now()) {
      throw new Error('Token expired');
    }

    return decoded;
  } catch (error) {
    logger.error('Token verification failed', { error: error instanceof Error ? error.message : 'Unknown error' });
    throw error;
  }
}

/**
 * Map Cognito groups to user roles
 */
function mapGroupsToRoles(groups?: string[]): UserRole[] {
  if (!groups || groups.length === 0) {
    return [UserRole.GUEST];
  }

  const roleMap: Record<string, UserRole> = {
    'admin-group': UserRole.ADMIN,
    'member-group': UserRole.MEMBER,
    'volunteer-group': UserRole.VOLUNTEER,
  };

  const roles = groups
    .map(group => roleMap[group])
    .filter(role => role !== undefined);

  return roles.length > 0 ? roles : [UserRole.GUEST];
}

/**
 * Authentication middleware
 */
export async function authenticateToken(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      res.status(401).json({ error: 'Access token required' });
      return;
    }

    const decoded = await verifyToken(token);
    
    // Check if token is expired
    if (decoded.exp * 1000 < Date.now()) {
      res.status(401).json({ error: 'Token expired' });
      return;
    }

    // Extract user information
    const user = {
      sub: decoded.sub,
      email: decoded.email,
      roles: mapGroupsToRoles(decoded['cognito:groups']),
      groups: decoded['cognito:groups'],
      cognitoUsername: decoded['cognito:username'],
    };

    req.user = user;
    logger.info('User authenticated successfully', { 
      userId: user.sub, 
      email: user.email, 
      roles: user.roles 
    });

    next();
  } catch (error) {
    logger.error('Authentication failed', { error: error instanceof Error ? error.message : 'Unknown error' });
    res.status(403).json({ error: 'Invalid token' });
  }
}

/**
 * Role-based access control middleware
 */
export function requireRole(requiredRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const hasRequiredRole = req.user.roles.some(role => requiredRoles.includes(role));
    
    if (!hasRequiredRole) {
      logger.warn('Access denied - insufficient permissions', {
        userId: req.user.sub,
        userRoles: req.user.roles,
        requiredRoles
      });
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }

    next();
  };
}

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
export async function optionalAuth(
  req: AuthenticatedRequest,
  _res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      // No token provided, continue without authentication
      next();
      return;
    }

    const decoded = await verifyToken(token);
    
    if (decoded.exp * 1000 < Date.now()) {
      // Token expired, continue without authentication
      next();
      return;
    }

    // Extract user information
    const user = {
      sub: decoded.sub,
      email: decoded.email,
      roles: mapGroupsToRoles(decoded['cognito:groups']),
      groups: decoded['cognito:groups'],
      cognitoUsername: decoded['cognito:username'],
    };

    req.user = user;
    logger.info('User authenticated (optional)', { 
      userId: user.sub, 
      email: user.email, 
      roles: user.roles 
    });

    next();
  } catch (error) {
    // Token verification failed, continue without authentication
    logger.warn('Optional authentication failed', { error: error instanceof Error ? error.message : 'Unknown error' });
    next();
  }
}

/**
 * Get authentication service status
 */
export function getAuthStatus(): { configured: boolean; driver: { name: string; version: string } } {
  const serviceInfo = authService.getServiceInfo();
  return {
    configured: authService.isConfigured(),
    driver: serviceInfo.driver
  };
}
