# eWegen BFF

Backend For Frontend component for the eWegen (Ehrenamtswegen - Mitglieder Management Plattform) project.

## Purpose

The eWegen BFF (Backend For Frontend) service serves as an intermediary layer between the frontend application and the backend microservices. It provides the following key functions:

- API aggregation and transformation
- Authentication and authorization handling
- Request/response caching
- Error handling and logging
- Rate limiting and request validation
- Session management

## General Guidance

### Architecture

The BFF follows a layered architecture:

- **API Layer**: Handles incoming HTTP requests and responses
- **Service Layer**: Contains business logic and orchestrates calls to backend services
- **Data Access Layer**: Manages data retrieval and persistence
- **Infrastructure Layer**: Provides cross-cutting concerns like logging, monitoring, and security

### Technology Stack

- **Runtime**: Node.js with TypeScript
- **Framework**: Express.js
- **Authentication**: AWS Cognito integration
- **Logging**: Winston with rotating file streams
- **Testing**: Jest with Supertest
- **Containerization**: Docker with multi-stage builds
- **CI/CD**: GitHub Actions

## Getting Started

### Prerequisites

- Node.js 20.x or higher
- npm 10.x or higher
- Docker and Docker Compose (for containerized development)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/ewegen.git
cd ewegen/ewegen-bff

# Install dependencies
npm install

# Start the development server
npm run dev
```

### Configuration

The application can be configured using environment variables:

- `NODE_ENV`: Environment (development, production)
- `PORT`: Port to listen on (default: 8080)
- `LOG_LEVEL`: Logging level (default: info)

## Testing

The BFF service includes comprehensive test coverage:

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test interactions between components
- **API Tests**: Test HTTP endpoints

For detailed information on testing, see [Tests README](./tests/README.md).

## CI/CD Setup

The project uses GitHub Actions for continuous integration and deployment:

- **Linting**: Code quality checks with ESLint
- **Testing**: Automated test execution
- **Static Analysis**: Code quality analysis with SonarCloud
- **Docker Build**: Multi-stage Docker image builds
- **Security Scanning**: Vulnerability scanning with Trivy

For detailed information on the CI/CD pipeline, see [CI/CD README](./.github/workflows/README.md).

## Docker Setup

The BFF service is containerized using Docker:

- **Multi-stage Builds**: Optimized for size and security
- **Development Mode**: Hot-reloading for local development
- **Production Mode**: Optimized for production deployment

For detailed information on Docker setup, see [Docker README](./DOCKER.md).

## Contributing

We welcome contributions to the eWegen BFF service. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow the ESLint configuration
- Use TypeScript for type safety
- Write tests for new features
- Update documentation as needed

### Commit Messages

We use conventional commits for our commit messages:

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
