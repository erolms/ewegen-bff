# eWegen BFF Authentication System

This document describes the authentication system proof-of-concept implemented in the eWegen BFF (Backend for Frontend) service, based on the project roadmap and architectural decisions.

## Overview

The authentication system integrates with AWS Cognito to provide secure user authentication and authorization for the eWegen platform. It implements JWT token validation, role-based access control (RBAC), and comprehensive user management features.

## Architecture

### Components

1. **Authentication Middleware** (`src/middlewares/auth.ts`)
   - JWT token validation
   - Role-based access control
   - User information extraction
   - Optional authentication for public endpoints

2. **Authentication Routes** (`src/routes/auth.ts`)
   - User registration and confirmation
   - Login and logout
   - Token refresh
   - Password management
   - User profile access

3. **Protected Routes** (`src/routes/protected.ts`)
   - Role-specific endpoints
   - Admin dashboard
   - Member profiles
   - Volunteer tasks
   - Community events

4. **Configuration** (`src/config/auth.ts`)
   - Environment variable management
   - AWS Cognito configuration
   - Role mapping

## Features

### Authentication Features

- ✅ User registration with email confirmation
- ✅ Secure login with JWT tokens
- ✅ Token refresh mechanism
- ✅ Password change functionality
- ✅ User logout with token revocation
- ✅ JWT token validation with AWS Cognito JWKs
- ✅ Token expiration handling

### Authorization Features

- ✅ Role-based access control (RBAC)
- ✅ Multiple role support per user
- ✅ Admin, Member, Volunteer, and Guest roles
- ✅ Flexible role requirements for endpoints
- ✅ Optional authentication for public endpoints

### Security Features

- ✅ JWT token verification using AWS Cognito public keys
- ✅ Token expiration validation
- ✅ Secure password requirements
- ✅ Comprehensive error handling
- ✅ Detailed logging for security events

## User Roles

The system supports four user roles:

1. **ADMIN** - Full system access
   - Access to admin dashboard
   - User management capabilities
   - System configuration access

2. **MEMBER** - Registered member access
   - Member profile management
   - Community events access
   - Payment and donation features

3. **VOLUNTEER** - Volunteer-specific access
   - Volunteer task management
   - Community events access
   - Task assignment and tracking

4. **GUEST** - Limited access
   - Public information access
   - Basic community features

## Setup

### Prerequisites

1. **AWS Cognito User Pool**
   - Create a Cognito User Pool in your AWS account
   - Configure user attributes (email, given_name, family_name)
   - Set up password policies
   - Create user groups for roles (admin-group, member-group, volunteer-group)

2. **AWS Cognito App Client**
   - Create an app client in your User Pool
   - Configure authentication flows
   - Set up callback URLs

### Environment Variables

#### Required Variables

```bash
COGNITO_USER_POOL_ID=eu-central-1_yourpoolid
COGNITO_CLIENT_ID=your-client-id
AWS_REGION=eu-central-1
```

#### Optional Variables

```bash
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
COGNITO_CLIENT_SECRET=your-client-secret
COGNITO_ADMIN_GROUP=admin-group
COGNITO_MEMBER_GROUP=member-group
COGNITO_VOLUNTEER_GROUP=volunteer-group
```

### Installation

1. Install dependencies:

   ```bash
   npm install
   ```

2. Set environment variables (see above)

3. Start the development server:

   ```bash
   npm run dev
   ```

## API Endpoints

### Authentication Endpoints

#### Health Check

```http
GET /auth/health
```

Returns authentication service status and configuration.

#### User Registration

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### User Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

#### Confirm Registration

```http
POST /auth/confirm
Content-Type: application/json

{
  "email": "user@example.com",
  "confirmationCode": "123456"
}
```

#### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### User Profile

```http
GET /auth/profile
Authorization: Bearer your-access-token
```

#### Change Password

```http
POST /auth/change-password
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "oldPassword": "OldPassword123!",
  "newPassword": "NewPassword123!"
}
```

#### Logout

```http
POST /auth/logout
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

### Protected Endpoints

#### User Information

```http
GET /protected/user-info
Authorization: Bearer your-access-token
```

#### Admin Dashboard (Admin only)

```http
GET /protected/admin-dashboard
Authorization: Bearer your-access-token
```

#### Member Profile (Member/Admin only)

```http
GET /protected/member-profile
Authorization: Bearer your-access-token
```

#### Volunteer Tasks (Volunteer/Admin only)

```http
GET /protected/volunteer-tasks
Authorization: Bearer your-access-token
```

#### Community Events (Member/Volunteer/Admin)

```http
GET /protected/community-events
Authorization: Bearer your-access-token
```

#### Protected Health Check

```http
GET /protected/health
Authorization: Bearer your-access-token
```

## Usage Examples

### Frontend Integration

```javascript
// Login example
const loginUser = async (email, password) => {
  const response = await fetch('/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });
  
  const data = await response.json();
  
  if (response.ok) {
    // Store tokens securely
    localStorage.setItem('accessToken', data.tokens.accessToken);
    localStorage.setItem('refreshToken', data.tokens.refreshToken);
    return data;
  } else {
    throw new Error(data.error);
  }
};

// Authenticated request example
const fetchUserInfo = async () => {
  const token = localStorage.getItem('accessToken');
  
  const response = await fetch('/protected/user-info', {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });
  
  if (response.status === 401) {
    // Token expired, try to refresh
    await refreshToken();
    return fetchUserInfo();
  }
  
  return response.json();
};

// Token refresh example
const refreshToken = async () => {
  const refreshToken = localStorage.getItem('refreshToken');
  
  const response = await fetch('/auth/refresh', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ refreshToken }),
  });
  
  const data = await response.json();
  
  if (response.ok) {
    localStorage.setItem('accessToken', data.tokens.accessToken);
    return data;
  } else {
    // Redirect to login
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    window.location.href = '/login';
  }
};
```

### Role-based Access Control

```javascript
// Check user roles
const checkUserRole = (user, requiredRoles) => {
  return user.roles.some(role => requiredRoles.includes(role));
};

// Example usage
const user = {
  id: 'user-123',
  email: 'user@example.com',
  roles: ['member', 'volunteer']
};

if (checkUserRole(user, ['admin'])) {
  // Show admin features
} else if (checkUserRole(user, ['member'])) {
  // Show member features
} else if (checkUserRole(user, ['volunteer'])) {
  // Show volunteer features
}
```

## Testing

### Run Tests

```bash
npm test
```

### Run Tests with Coverage

```bash
npm run test:coverage
```

### Test Structure

- **Configuration Tests**: Environment variable validation
- **Middleware Tests**: JWT validation and RBAC
- **Route Tests**: API endpoint functionality
- **Integration Tests**: End-to-end authentication flows

## Security Considerations

### Token Security

- JWT tokens are validated using AWS Cognito public keys
- Tokens have expiration times
- Refresh tokens are used for long-term sessions
- Tokens are revoked on logout

### Password Security

- Passwords must meet AWS Cognito requirements
- Password changes require old password verification
- Failed login attempts are logged

### Role Security

- Role assignments are managed through AWS Cognito groups
- Role validation happens on every protected request
- Access denied events are logged for security monitoring

### Error Handling

- Sensitive information is not exposed in error messages
- All authentication failures are logged
- Rate limiting should be implemented in production

## Monitoring and Logging

### Authentication Events

- User registration and confirmation
- Login and logout events
- Token refresh attempts
- Password change events
- Access denied events

### Security Monitoring

- Failed authentication attempts
- Token validation failures
- Role-based access violations
- Configuration errors

## Production Deployment

### Environment Setup

1. Configure production AWS Cognito User Pool
2. Set up proper IAM roles and permissions
3. Configure environment variables
4. Set up monitoring and alerting

### Security Hardening

1. Enable HTTPS only
2. Implement rate limiting
3. Set up security headers
4. Configure CORS properly
5. Enable audit logging

### Performance Optimization

1. Implement JWK caching
2. Use connection pooling for AWS SDK
3. Monitor token validation performance
4. Implement request caching where appropriate

## Troubleshooting

### Common Issues

1. **Configuration Errors**
   - Verify all required environment variables are set
   - Check AWS credentials and permissions
   - Validate Cognito User Pool and App Client configuration

2. **Token Validation Failures**
   - Check token expiration
   - Verify JWT signature
   - Ensure correct issuer and audience

3. **Role Access Issues**
   - Verify user is assigned to correct Cognito groups
   - Check role mapping configuration
   - Validate token contains group information

4. **AWS SDK Errors**
   - Check AWS credentials
   - Verify region configuration
   - Ensure proper IAM permissions

### Debug Mode

Enable debug logging by setting the environment variable:

```bash
DEBUG=ewegen-bff:*
npm run debug
```

## Future Enhancements

### Planned Features

- Multi-factor authentication (MFA)
- Social login integration
- Password reset functionality
- User session management
- Advanced role permissions
- Audit trail implementation

### Scalability Improvements

- Redis-based token caching
- Distributed session management
- Load balancing considerations
- Database integration for user profiles

## Contributing

When contributing to the authentication system:

1. Follow the existing code style and patterns
2. Add comprehensive tests for new features
3. Update documentation for API changes
4. Consider security implications of changes
5. Test with different user roles and scenarios

## References

- [AWS Cognito Documentation](https://docs.aws.amazon.com/cognito/)
- [JWT.io](https://jwt.io/) - JWT token debugging
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practices-security.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
