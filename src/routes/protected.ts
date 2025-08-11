import { Router, Response } from 'express';
import { authenticateToken, requireRole, AuthenticatedRequest, UserRole } from '../middlewares/auth';
import Logger from '../middlewares/logger';

const router = Router();

const logger = Logger.getInstance();

/**
 * Protected route - requires authentication
 * GET /protected/user-info
 */
router.get('/user-info', authenticateToken, (req: AuthenticatedRequest, res: Response): void => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'User not authenticated' });
      return;
    }

    logger.info('User info accessed', { userId: req.user.sub, roles: req.user.roles });

    res.status(200).json({
      message: 'Protected user information',
      user: {
        id: req.user.sub,
        email: req.user.email,
        roles: req.user.roles,
        username: req.user.cognitoUsername,
        groups: req.user.groups
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Get user info failed', { error: error instanceof Error ? error.message : 'Unknown error' });
    res.status(500).json({ error: 'Failed to get user information' });
  }
});

/**
 * Admin-only route
 * GET /protected/admin-dashboard
 */
router.get('/admin-dashboard', 
  authenticateToken, 
  requireRole([UserRole.ADMIN]), 
  (req: AuthenticatedRequest, res: Response): void => {
    try {
      logger.info('Admin dashboard accessed', { userId: req.user?.sub });

      res.status(200).json({
        message: 'Admin dashboard data',
        data: {
          totalUsers: 150,
          activeProjects: 25,
          totalDonations: 50000,
          recentActivity: [
            { action: 'User registered', timestamp: new Date().toISOString() },
            { action: 'Payment processed', timestamp: new Date().toISOString() },
            { action: 'Project created', timestamp: new Date().toISOString() }
          ]
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Admin dashboard access failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      res.status(500).json({ error: 'Failed to access admin dashboard' });
    }
  }
);

/**
 * Member-only route
 * GET /protected/member-profile
 */
router.get('/member-profile', 
  authenticateToken, 
  requireRole([UserRole.MEMBER, UserRole.ADMIN]), 
  (req: AuthenticatedRequest, res: Response): void => {
    try {
      logger.info('Member profile accessed', { userId: req.user?.sub });

      res.status(200).json({
        message: 'Member profile data',
        profile: {
          memberId: req.user?.sub,
          email: req.user?.email,
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
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Member profile access failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      res.status(500).json({ error: 'Failed to access member profile' });
    }
  }
);

/**
 * Volunteer-only route
 * GET /protected/volunteer-tasks
 */
router.get('/volunteer-tasks', 
  authenticateToken, 
  requireRole([UserRole.VOLUNTEER, UserRole.ADMIN]), 
  (req: AuthenticatedRequest, res: Response): void => {
    try {
      logger.info('Volunteer tasks accessed', { userId: req.user?.sub });

      res.status(200).json({
        message: 'Volunteer tasks data',
        tasks: [
          {
            id: 'task-001',
            title: 'Food Bank Distribution',
            description: 'Help distribute food packages to families in need',
            location: 'Community Center',
            date: '2024-02-15',
            duration: '4 hours',
            status: 'assigned'
          },
          {
            id: 'task-002',
            title: 'Elderly Care Visit',
            description: 'Visit elderly community members for companionship',
            location: 'Various homes',
            date: '2024-02-20',
            duration: '2 hours',
            status: 'available'
          }
        ],
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Volunteer tasks access failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      res.status(500).json({ error: 'Failed to access volunteer tasks' });
    }
  }
);

/**
 * Multi-role route (accessible by members, volunteers, and admins)
 * GET /protected/community-events
 */
router.get('/community-events', 
  authenticateToken, 
  requireRole([UserRole.MEMBER, UserRole.VOLUNTEER, UserRole.ADMIN]), 
  (req: AuthenticatedRequest, res: Response): void => {
    try {
      logger.info('Community events accessed', { userId: req.user?.sub, roles: req.user?.roles });

      res.status(200).json({
        message: 'Community events data',
        events: [
          {
            id: 'event-001',
            title: 'Charity Fundraiser',
            description: 'Annual fundraising event for local charities',
            date: '2024-03-15',
            location: 'Town Hall',
            attendees: 45,
            maxCapacity: 100
          },
          {
            id: 'event-002',
            title: 'Volunteer Training',
            description: 'Training session for new volunteers',
            date: '2024-03-20',
            location: 'Community Center',
            attendees: 12,
            maxCapacity: 25
          }
        ],
        userRole: req.user?.roles,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Community events access failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      res.status(500).json({ error: 'Failed to access community events' });
    }
  }
);

/**
 * Health check for protected routes
 * GET /protected/health
 */
router.get('/health', authenticateToken, (req: AuthenticatedRequest, res: Response): void => {
  res.status(200).json({
    status: 'ok',
    service: 'eWegen BFF Protected Routes',
    authenticated: !!req.user,
    userRoles: req.user?.roles || [],
    timestamp: new Date().toISOString()
  });
});

export default router; 