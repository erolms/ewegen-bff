// Ensure required env vars are present before modules import
process.env.COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'eu-central-1_testpool123';
process.env.COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || 'test-client-id';
process.env.AWS_REGION = process.env.AWS_REGION || 'eu-central-1';

import { Response, NextFunction } from 'express';
import { AuthenticatedRequest, UserRole } from '../../src/middlewares/auth';
import { beforeEach, describe, expect, it, jest, afterEach } from '@jest/globals';

// Mock dependencies
jest.mock('../../src/middlewares/auth', () => ({
  __esModule: true,
  authenticateToken: jest.fn(),
  requireRole: jest.fn((requiredRoles: UserRole[]) => {
    return jest.fn((req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      if (!req.user) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const hasRequiredRole = req.user.roles.some((role: UserRole) => requiredRoles.includes(role));
      
      if (!hasRequiredRole) {
        res.status(403).json({ error: 'Insufficient permissions' });
        return;
      }

      next();
    });
  }),
  UserRole: {
    ADMIN: 'admin',
    MEMBER: 'member',
    VOLUNTEER: 'volunteer',
    GUEST: 'guest'
  }
}));

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

// Import after mocking
import { authenticateToken, requireRole } from '../../src/middlewares/auth';
import { _test } from '../../src/routes/protected';

const mockAuthenticateToken = authenticateToken as jest.MockedFunction<typeof authenticateToken>;
const mockRequireRole = requireRole as jest.MockedFunction<typeof requireRole>;

describe('Protected Routes', () => {
  let mockRequest: Partial<AuthenticatedRequest>;
  let mockResponse: Partial<Response>;

  const mockUser = {
    sub: 'user123',
    email: 'test@example.com',
    roles: [UserRole.ADMIN],
    cognitoUsername: 'testuser',
    groups: ['admin-group']
  };

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockRequest = {
      headers: {},
      method: 'GET',
      url: '/protected/user-info',
      user: mockUser
    };
    
    mockResponse = {
      status: jest.fn().mockReturnThis() as jest.MockedFunction<Response['status']>,
      json: jest.fn().mockReturnThis() as jest.MockedFunction<Response['json']>
    };

    // Setup default middleware mocks
    mockAuthenticateToken.mockImplementation(async (req, res, next) => {
      if (req.user) {
        next();
      } else {
        res.status(401).json({ error: 'Access token required' });
      }
    });


    mockRequireRole.mockImplementation((requiredRoles) => {
      return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
          res.status(401).json({ error: 'Authentication required' });
          return;
        }

        const hasRequiredRole = req.user.roles.some(role => requiredRoles.includes(role));
        
        if (!hasRequiredRole) {
          res.status(403).json({ error: 'Insufficient permissions' });
          return;
        }

        next();
      };
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /protected/user-info', () => {
    it('should return user info successfully', async () => {
      await _test.handleUserInfo(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Protected user information',
        user: {
          id: 'user123',
          email: 'test@example.com',
          roles: [UserRole.ADMIN],
          username: 'testuser',
          groups: ['admin-group']
        },
        timestamp: expect.any(String)
      });
    });

    it('should return 401 when user not authenticated', async () => {
      mockRequest.user = undefined;

      await _test.handleUserInfo(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'User not authenticated' });
    });
  });

  describe('GET /protected/admin-dashboard', () => {
    it('should return admin dashboard data successfully', async () => {
      await _test.handleAdminDashboard(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Admin dashboard data',
        data: {
          totalUsers: 150,
          activeProjects: 25,
          totalDonations: 50000,
          recentActivity: expect.arrayContaining([
            expect.objectContaining({
              action: expect.any(String),
              timestamp: expect.any(String)
            })
          ])
        },
        timestamp: expect.any(String)
      });
    });
  });

  describe('GET /protected/member-profile', () => {
    it('should return member profile data successfully for admin user', async () => {
      await _test.handleMemberProfile(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Member profile data',
        profile: {
          memberId: 'user123',
          email: 'test@example.com',
          membershipLevel: 'Premium',
          joinDate: '2024-01-15',
          totalDonations: 2500,
          activeProjects: 3,
          preferences: {
            newsletter: true,
            notifications: true,
            language: 'de'
          }
        },
        timestamp: expect.any(String)
      });
    });

    it('should return member profile data successfully for member user', async () => {
      mockRequest.user = {
        ...mockUser,
        roles: [UserRole.MEMBER]
      };

      await _test.handleMemberProfile(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Member profile data',
        profile: expect.objectContaining({
          memberId: 'user123',
          email: 'test@example.com',
          membershipLevel: 'Premium'
        }),
        timestamp: expect.any(String)
      });
    });
  });

  describe('GET /protected/volunteer-tasks', () => {
    it('should return volunteer tasks data successfully for admin user', async () => {
      await _test.handleVolunteerTasks(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Volunteer tasks data',
        tasks: expect.arrayContaining([
          expect.objectContaining({
            id: 'task-001',
            title: 'Food Bank Distribution',
            description: 'Help distribute food packages to families in need',
            location: 'Community Center',
            date: '2024-02-15',
            duration: '4 hours',
            status: 'assigned'
          }),
          expect.objectContaining({
            id: 'task-002',
            title: 'Elderly Care Visit',
            description: 'Visit elderly community members for companionship',
            location: 'Various homes',
            date: '2024-02-20',
            duration: '2 hours',
            status: 'available'
          })
        ]),
        timestamp: expect.any(String)
      });
    });

    it('should return volunteer tasks data successfully for volunteer user', async () => {
      mockRequest.user = {
        ...mockUser,
        roles: [UserRole.VOLUNTEER]
      };

      await _test.handleVolunteerTasks(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Volunteer tasks data',
        tasks: expect.arrayContaining([
          expect.objectContaining({
            id: 'task-001',
            title: 'Food Bank Distribution'
          }),
          expect.objectContaining({
            id: 'task-002',
            title: 'Elderly Care Visit'
          })
        ]),
        timestamp: expect.any(String)
      });
    });
  });

  describe('GET /protected/community-events', () => {
    it('should return community events data successfully for admin user', async () => {
      await _test.handleCommunityEvents(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Community events data',
        events: expect.arrayContaining([
          expect.objectContaining({
            id: 'event-001',
            title: 'Charity Fundraiser',
            description: 'Annual fundraising event for local charities',
            date: '2024-03-15',
            location: 'Town Hall',
            attendees: 45,
            maxCapacity: 100
          }),
          expect.objectContaining({
            id: 'event-002',
            title: 'Volunteer Training',
            description: 'Training session for new volunteers',
            date: '2024-03-20',
            location: 'Community Center',
            attendees: 12,
            maxCapacity: 25
          })
        ]),
        userRole: [UserRole.ADMIN],
        timestamp: expect.any(String)
      });
    });

    it('should return community events data successfully for member user', async () => {
      mockRequest.user = {
        ...mockUser,
        roles: [UserRole.MEMBER]
      };

      await _test.handleCommunityEvents(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Community events data',
        events: expect.arrayContaining([
          expect.objectContaining({
            id: 'event-001',
            title: 'Charity Fundraiser'
          }),
          expect.objectContaining({
            id: 'event-002',
            title: 'Volunteer Training'
          })
        ]),
        userRole: [UserRole.MEMBER],
        timestamp: expect.any(String)
      });
    });

    it('should return community events data successfully for volunteer user', async () => {
      mockRequest.user = {
        ...mockUser,
        roles: [UserRole.VOLUNTEER]
      };

      await _test.handleCommunityEvents(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Community events data',
        events: expect.arrayContaining([
          expect.objectContaining({
            id: 'event-001',
            title: 'Charity Fundraiser'
          }),
          expect.objectContaining({
            id: 'event-002',
            title: 'Volunteer Training'
          })
        ]),
        userRole: [UserRole.VOLUNTEER],
        timestamp: expect.any(String)
      });
    });
  });

  describe('GET /protected/health', () => {
    it('should return health status successfully for authenticated user', async () => {
      await _test.handleHealth(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'ok',
        service: 'eWegen BFF Protected Routes',
        authenticated: true,
        userRoles: [UserRole.ADMIN],
        timestamp: expect.any(String)
      });
    });

    it('should return health status for unauthenticated user', async () => {
      mockRequest.user = undefined;

      await _test.handleHealth(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'ok',
        service: 'eWegen BFF Protected Routes',
        authenticated: false,
        userRoles: [],
        timestamp: expect.any(String)
      });
    });

    it('should handle user with no roles', async () => {
      mockRequest.user = {
        ...mockUser,
        roles: []
      };

      await _test.handleHealth(mockRequest as AuthenticatedRequest, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'ok',
        service: 'eWegen BFF Protected Routes',
        authenticated: true,
        userRoles: [],
        timestamp: expect.any(String)
      });
    });
  });

  describe('Role-based access control', () => {
    it('should allow admin access to all routes', async () => {
      const adminUser = {
        ...mockUser,
        roles: [UserRole.ADMIN]
      };

      // Test all protected routes with admin user
      const handlers = [
        _test.handleUserInfo,
        _test.handleAdminDashboard,
        _test.handleMemberProfile,
        _test.handleVolunteerTasks,
        _test.handleCommunityEvents,
        _test.handleHealth
      ];

      for (const handler of handlers) {
        mockRequest.user = adminUser;
        await handler(mockRequest as AuthenticatedRequest, mockResponse as Response);
        expect(mockResponse.status).toHaveBeenCalledWith(200);
      }
    });

    it('should allow member access to member and community routes', async () => {
      const memberUser = {
        ...mockUser,
        roles: [UserRole.MEMBER]
      };

      const allowedHandlers = [
        _test.handleUserInfo,
        _test.handleMemberProfile,
        _test.handleCommunityEvents,
        _test.handleHealth
      ];

      for (const handler of allowedHandlers) {
        mockRequest.user = memberUser;
        await handler(mockRequest as AuthenticatedRequest, mockResponse as Response);
        expect(mockResponse.status).toHaveBeenCalledWith(200);
      }
    });

    it('should allow volunteer access to volunteer and community routes', async () => {
      const volunteerUser = {
        ...mockUser,
        roles: [UserRole.VOLUNTEER]
      };

      const allowedHandlers = [
        _test.handleUserInfo,
        _test.handleVolunteerTasks,
        _test.handleCommunityEvents,
        _test.handleHealth
      ];

      for (const handler of allowedHandlers) {
        mockRequest.user = volunteerUser;
        await handler(mockRequest as AuthenticatedRequest, mockResponse as Response);
        expect(mockResponse.status).toHaveBeenCalledWith(200);
      }
    });
  });
});
