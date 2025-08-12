// Ensure required env vars are present before modules import
process.env.COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'eu-central-1_testpool123';
process.env.COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || 'test-client-id';
process.env.AWS_REGION = process.env.AWS_REGION || 'eu-central-1';

import { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { 
  authenticateToken, 
  requireRole, 
  optionalAuth, 
  getAuthStatus,
  UserRole,
  AuthenticatedRequest,
  __test__
} from '../../src/middlewares/auth';
import { authService } from '../../src/services/auth-service';
import { beforeEach, describe, expect, it, jest, afterEach } from '@jest/globals';

// Mock external dependencies
jest.mock('jsonwebtoken');
jest.mock('../../src/services/auth-service');
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

// Mock fetch globally
(global as unknown as { fetch: jest.MockedFunction<typeof fetch> }).fetch = jest.fn()

const mockJwt = jwt as jest.Mocked<typeof jwt>;
const mockAuthService = authService as jest.Mocked<typeof authService>;
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

describe('Auth Middleware', () => {
  let mockRequest: Partial<AuthenticatedRequest>;
  let mockResponse: Partial<Response>;
  let mockNext: jest.MockedFunction<NextFunction>;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Setup default mocks
    mockRequest = {
      headers: {},
      user: undefined
    };
    
    mockResponse = {
      status: jest.fn().mockReturnThis() as jest.MockedFunction<Response['status']>,
      json: jest.fn().mockReturnThis() as jest.MockedFunction<Response['json']>
    };
    
    mockNext = jest.fn() as unknown as jest.MockedFunction<NextFunction>;

    // Setup environment variables
    process.env.COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'eu-central-1_testpool123';
    process.env.COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || 'test-client-id';
    process.env.AWS_REGION = process.env.AWS_REGION || 'eu-central-1';
    
    // Setup default auth service mock
    mockAuthService.getServiceInfo.mockReturnValue({
      driver: { name: 'cognito', version: '1.0.0', configured: true }
    });
    mockAuthService.isConfigured.mockReturnValue(true);
  });

  afterEach(() => {
    delete process.env.COGNITO_USER_POOL_ID;
    delete process.env.AWS_REGION;
  });

  describe('authenticateToken', () => {
    const mockToken = 'mock.jwt.token';
    const mockDecodedToken = {
      sub: 'user123',
      email: 'test@example.com',
      'cognito:groups': ['admin-group', 'member-group'],
      'cognito:username': 'testuser',
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      iat: Math.floor(Date.now() / 1000),
      iss: 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_testpool123'
    };

    beforeEach(() => {
      // Setup JWT decode mock to return both header and payload (typed via jest.Mock)
      (mockJwt.decode as unknown as jest.Mock).mockImplementation((...args: unknown[]) => {
        const options = args[1] as { complete?: boolean } | undefined;
        if (options?.complete) {
          return {
            header: { kid: 'test-kid', alg: 'RS256', typ: 'JWT' },
            payload: mockDecodedToken,
            signature: 'mock-signature'
          } as unknown as jwt.Jwt;
        }
        return mockDecodedToken as unknown as jwt.JwtPayload;
      });

      // Setup fetch mock for JWKs
      mockFetch.mockResolvedValue({
        json: jest.fn().mockResolvedValue({
          keys: [
            {
              kty: 'RSA',
              kid: 'test-kid',
              use: 'sig',
              alg: 'RS256',
              n: 'test-n',
              e: 'AQAB'
            }
          ]
        } as never)
      } as unknown as globalThis.Response);
    });

    it('should authenticate valid token successfully', async () => {
      __test__.resetJwksCache();
      // Ensure JWKs are available for this test
      mockFetch.mockResolvedValue({
        json: jest.fn().mockResolvedValue({
          keys: [
            { kty: 'RSA', kid: 'test-kid', use: 'sig', alg: 'RS256', n: 'test-n', e: 'AQAB' }
          ]
        } as never)
      } as unknown as globalThis.Response);

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockRequest.user).toBeDefined();
      expect(mockRequest.user?.sub).toBe('user123');
      expect(mockRequest.user?.email).toBe('test@example.com');
      expect(mockRequest.user?.roles).toEqual([UserRole.ADMIN, UserRole.MEMBER]);
      expect(mockRequest.user?.cognitoUsername).toBe('testuser');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should return 401 when no authorization header', async () => {
      mockRequest.headers = {};

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Access token required' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 403 when authorization header is malformed', async () => {
      mockRequest.headers = {
        authorization: 'InvalidFormat token'
      };

      // Force decode to fail for this call
      (mockJwt.decode as unknown as jest.Mock).mockImplementationOnce(() => null);

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 403 when token is expired', async () => {
      const expiredToken = {
        ...mockDecodedToken,
        exp: Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
      };
      (mockJwt.decode as unknown as jest.Mock).mockImplementation((...args: unknown[]) => {
        const options = args[1] as { complete?: boolean } | undefined;
        if (options?.complete) {
          return {
            header: { kid: 'test-kid', alg: 'RS256', typ: 'JWT' },
            payload: expiredToken,
            signature: 'mock-signature'
          } as unknown as jwt.Jwt;
        }
        return expiredToken as unknown as jwt.JwtPayload;
      });

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 403 when token verification fails', async () => {
      (mockJwt.decode as unknown as jest.Mock).mockReturnValue(null);

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle users with no groups', async () => {
      const tokenWithoutGroups = {
        ...mockDecodedToken,
        'cognito:groups': undefined
      };
      (mockJwt.decode as unknown as jest.Mock).mockImplementation((...args: unknown[]) => {
        const options = args[1] as { complete?: boolean } | undefined;
        if (options?.complete) {
          return {
            header: { kid: 'test-kid', alg: 'RS256', typ: 'JWT' },
            payload: tokenWithoutGroups,
            signature: 'mock-signature'
          } as unknown as jwt.Jwt;
        }
        return tokenWithoutGroups as unknown as jwt.JwtPayload;
      });

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockRequest.user?.roles).toEqual([UserRole.GUEST]);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle users with unknown groups', async () => {
      const tokenWithUnknownGroups = {
        ...mockDecodedToken,
        'cognito:groups': ['unknown-group']
      };
      (mockJwt.decode as unknown as jest.Mock).mockImplementation((...args: unknown[]) => {
        const options = args[1] as { complete?: boolean } | undefined;
        if (options?.complete) {
          return {
            header: { kid: 'test-kid', alg: 'RS256', typ: 'JWT' },
            payload: tokenWithUnknownGroups,
            signature: 'mock-signature'
          } as unknown as jwt.Jwt;
        }
        return tokenWithUnknownGroups as unknown as jwt.JwtPayload;
      });

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockRequest.user?.roles).toEqual([UserRole.GUEST]);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle fetch errors for JWKs', async () => {
      __test__.resetJwksCache();
      mockFetch.mockRejectedValue(new Error('Network error'));

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle missing COGNITO_USER_POOL_ID environment variable', async () => {
      delete process.env.COGNITO_USER_POOL_ID;

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 403 when token header lacks kid', async () => {
      // First decode call with complete: true returns header without kid
      (mockJwt.decode as unknown as jest.Mock).mockImplementationOnce((...args: unknown[]) => {
        const options = args[1] as { complete?: boolean } | undefined;
        if (options?.complete) {
          return { header: { alg: 'RS256', typ: 'JWT' }, payload: mockDecodedToken, signature: 'sig' } as unknown as jwt.Jwt;
        }
        return mockDecodedToken as unknown as jwt.JwtPayload;
      });

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 403 when JWK for kid not found', async () => {
      // Ensure cache is clear so we read the mocked JWKs below
      __test__.resetJwksCache();

      // JWKs do not include matching kid
      mockFetch.mockResolvedValue({
        json: jest.fn().mockResolvedValue({
          keys: [{ kty: 'RSA', kid: 'another-kid', use: 'sig', alg: 'RS256', n: 'n', e: 'AQAB' }]
        } as never)
      } as unknown as globalThis.Response);

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 403 when issuer mismatches', async () => {
      const wrongIssuerPayload = { ...mockDecodedToken, iss: 'https://wrong-issuer.example.com' };
      (mockJwt.decode as unknown as jest.Mock).mockImplementation((...args: unknown[]) => {
        const options = args[1] as { complete?: boolean } | undefined;
        if (options?.complete) {
          return {
            header: { kid: 'test-kid', alg: 'RS256', typ: 'JWT' },
            payload: wrongIssuerPayload,
            signature: 'sig'
          } as unknown as jwt.Jwt;
        }
        return wrongIssuerPayload as unknown as jwt.JwtPayload;
      });

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 403 when decode returns a string for header', async () => {
      (mockJwt.decode as unknown as jest.Mock).mockImplementationOnce((...args: unknown[]) => {
        const options = args[1] as { complete?: boolean } | undefined;
        if (options?.complete) {
          return 'not-an-object' as unknown as jwt.Jwt;
        }
        return mockDecodedToken as unknown as jwt.JwtPayload;
      });

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('requireRole', () => {
    beforeEach(() => {
      mockRequest.user = {
        sub: 'user123',
        email: 'test@example.com',
        roles: [UserRole.ADMIN, UserRole.MEMBER],
        groups: ['admin-group', 'member-group'],
        cognitoUsername: 'testuser'
      };
    });

    it('should allow access when user has required role', () => {
      const middleware = requireRole([UserRole.ADMIN]);

      middleware(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should allow access when user has multiple required roles', () => {
      const middleware = requireRole([UserRole.ADMIN, UserRole.VOLUNTEER]);

      middleware(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should deny access when user lacks required role', () => {
      const middleware = requireRole([UserRole.VOLUNTEER]);

      middleware(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Insufficient permissions' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 when user is not authenticated', () => {
      mockRequest.user = undefined;
      const middleware = requireRole([UserRole.ADMIN]);

      middleware(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Authentication required' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle empty required roles array', () => {
      const middleware = requireRole([]);

      middleware(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Insufficient permissions' });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('optionalAuth', () => {
    const mockToken = 'mock.jwt.token';
    const mockDecodedToken = {
      sub: 'user123',
      email: 'test@example.com',
      'cognito:groups': ['admin-group'],
      'cognito:username': 'testuser',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      iss: 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_testpool123'
    };

    beforeEach(() => {
      // Provide complete:true header and payload behavior
      (mockJwt.decode as unknown as jest.Mock).mockImplementation((...args: unknown[]) => {
        const options = args[1] as { complete?: boolean } | undefined;
        if (options?.complete) {
          return {
            header: { kid: 'test-kid', alg: 'RS256', typ: 'JWT' },
            payload: mockDecodedToken,
            signature: 'sig'
          } as unknown as jwt.Jwt;
        }
        return mockDecodedToken as unknown as jwt.JwtPayload;
      });
      mockFetch.mockResolvedValue({
        json: jest.fn().mockResolvedValue({
          keys: [{ kty: 'RSA', kid: 'test-kid', use: 'sig', alg: 'RS256', n: 'test-n', e: 'AQAB' }]
        } as never)
      } as unknown as globalThis.Response);
    });

    it('should continue without authentication when no token provided', async () => {
      mockRequest.headers = {};

      await optionalAuth(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockRequest.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should authenticate when valid token provided', async () => {
      __test__.resetJwksCache();
      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await optionalAuth(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockRequest.user).toBeDefined();
      expect(mockRequest.user?.sub).toBe('user123');
      expect(mockRequest.user?.roles).toEqual([UserRole.ADMIN]);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should continue without authentication when token is expired', async () => {
      const expiredToken = {
        ...mockDecodedToken,
        exp: Math.floor(Date.now() / 1000) - 3600
      };
      mockJwt.decode.mockReturnValue(expiredToken);

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await optionalAuth(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockRequest.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should continue without authentication when token verification fails', async () => {
      mockJwt.decode.mockReturnValue(null);

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await optionalAuth(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockRequest.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle malformed authorization header', async () => {
      mockRequest.headers = {
        authorization: 'InvalidFormat token'
      };

      // Force decode failure to simulate invalid/malformed token handling
      (mockJwt.decode as unknown as jest.Mock).mockImplementationOnce(() => null);

      await optionalAuth(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockRequest.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle network errors gracefully', async () => {
      __test__.resetJwksCache();
      mockFetch.mockRejectedValue(new Error('Network error'));

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      await optionalAuth(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockRequest.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('getAuthStatus', () => {
    it('should return auth service status when configured', () => {
      mockAuthService.isConfigured.mockReturnValue(true);
      mockAuthService.getServiceInfo.mockReturnValue({
        driver: { name: 'cognito', version: '1.0.0', configured: true }
      });

      const status = getAuthStatus();

      expect(status).toEqual({
        configured: true,
        driver: { name: 'cognito', version: '1.0.0', configured: true }
      });
    });

    it('should return auth service status when not configured', () => {
      mockAuthService.isConfigured.mockReturnValue(false);
      mockAuthService.getServiceInfo.mockReturnValue({
        driver: { name: 'cognito', version: '1.0.0', configured: false }
      });

      const status = getAuthStatus();

      expect(status).toEqual({
        configured: false,
        driver: { name: 'cognito', version: '1.0.0', configured: false }
      });
    });
  });

  describe('JWK caching', () => {
    const mockToken = 'mock.jwt.token';
    const mockDecodedToken = {
      sub: 'user123',
      email: 'test@example.com',
      'cognito:groups': ['admin-group'],
      'cognito:username': 'testuser',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      iss: 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_testpool123'
    };

    beforeEach(() => {
      // Proper decode behavior: header when complete, payload otherwise
      (mockJwt.decode as unknown as jest.Mock).mockImplementation((...args: unknown[]) => {
        const options = args[1] as { complete?: boolean } | undefined;
        if (options?.complete) {
          return {
            header: { kid: 'test-kid', alg: 'RS256', typ: 'JWT' },
            payload: mockDecodedToken,
            signature: 'sig'
          } as unknown as jwt.Jwt;
        }
        return mockDecodedToken as unknown as jwt.JwtPayload;
      });
    });

    it('should cache JWKs and reuse them for subsequent requests', async () => {
      __test__.resetJwksCache();
      const mockJwksResponse = {
        keys: [
          {
            kty: 'RSA',
            kid: 'test-kid',
            use: 'sig',
            alg: 'RS256',
            n: 'test-n',
            e: 'AQAB'
          }
        ]
      };

      mockFetch.mockResolvedValue({
        json: jest.fn().mockResolvedValue(mockJwksResponse as never)
      } as unknown as globalThis.Response);

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      };

      // First request - should fetch JWKs
      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Reset only fetch call count; keep decode and cache intact
      mockFetch.mockClear();

      // Second request - should use cached JWKs
      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should refetch JWKs after cache expiry', async () => {
      __test__.resetJwksCache();
      jest.useFakeTimers();
      jest.setSystemTime(new Date('2025-01-01T00:00:00Z'));

      mockFetch.mockResolvedValue({
        json: jest.fn().mockResolvedValue({
          keys: [{ kty: 'RSA', kid: 'test-kid', use: 'sig', alg: 'RS256', n: 'n1', e: 'AQAB' }]
        } as never)
      } as unknown as globalThis.Response);

      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`
      } as Record<string, string>;

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Advance time beyond 1 hour
      jest.setSystemTime(new Date('2025-01-01T01:01:00Z'));

      // Next call should refetch
      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockFetch).toHaveBeenCalledTimes(2);
      jest.useRealTimers();
    });
  });

  describe('Error handling', () => {
    it('should handle JWT decode errors gracefully', async () => {
      mockJwt.decode.mockImplementation(() => {
        throw new Error('JWT decode error');
      });

      mockRequest.headers = {
        authorization: 'Bearer invalid.token'
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
    });

    it('should handle fetch timeout errors', async () => {
      mockFetch.mockRejectedValue(new Error('Timeout'));

      mockRequest.headers = {
        authorization: 'Bearer valid.token'
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
    });

    it('should handle invalid JWK response format', async () => {
      mockFetch.mockResolvedValue({
        json: jest.fn().mockResolvedValue({ invalid: 'format' } as never)
      } as unknown as globalThis.Response);

      mockRequest.headers = {
        authorization: 'Bearer valid.token'
      };

      await authenticateToken(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Invalid token' });
    });
  });
});
