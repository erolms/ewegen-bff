# eWegen BFF CI/CD Pipeline

This document describes the CI/CD pipeline for the eWegen BFF service.

## Pipeline Overview

The CI/CD pipeline consists of the following stages:

1. **Lint**: Checks code quality using ESLint
2. **Test**: Runs unit tests and uploads coverage reports
3. **Static Analysis**: Performs static code analysis using SonarCloud
4. **Build Development Image**: Builds and pushes the development Docker image
5. **Test Development Image**: Runs unit tests in the development container
6. **Build Production Image**: Builds and pushes the production Docker image
7. **Security Scan**: Scans the production image for vulnerabilities using Trivy

## Pipeline Flow

The pipeline follows a sequential flow, where each stage depends on the successful completion of the previous stage:

```text
Lint → Test → Static Analysis → Build Dev Image → Test Dev Image → Build Prod Image → Security Scan
```

## Docker Image Storage

Docker images are stored in the GitHub Container Registry (ghcr.io) under the repository namespace:

```text
ghcr.io/<github-username>/<repository-name>/bff
```

## Image Tagging Strategy

Images are tagged with the following strategy:

### Development Images (from develop branch)

- `dev`: Latest development image
- `latest-dev`: Alias for the latest development image
- `sha-<commit-sha>`: Specific commit SHA
- `<version>-dev`: Semantic version with dev suffix
- `<major>.<minor>-dev`: Major and minor version with dev suffix

### Production Images (from main branch)

- `prod`: Latest production image
- `latest`: Alias for the latest production image
- `sha-<commit-sha>`: Specific commit SHA
- `<version>`: Semantic version
- `<major>.<minor>`: Major and minor version

## Required Secrets

The following secrets are required for the pipeline to function correctly:

- `GITHUB_TOKEN`: Automatically provided by GitHub Actions
- `CODECOV_TOKEN`: Token for uploading coverage reports to Codecov
- `SONAR_TOKEN`: Token for SonarCloud static analysis

## Local Development

To run the pipeline locally, you can use [act](https://github.com/nektos/act):

```bash
# Install act
brew install act

# Run the pipeline locally
act -P ubuntu-latest
```

## Troubleshooting

If the pipeline fails, check the following:

1. **Lint Failures**: Fix ESLint errors in your code
2. **Test Failures**: Fix failing tests
3. **Static Analysis Issues**: Address SonarCloud issues
4. **Build Failures**: Check Docker build configuration
5. **Security Scan Failures**: Address critical or high vulnerabilities

## Best Practices

1. Always run the pipeline locally before pushing to the repository
2. Keep dependencies up to date to avoid security vulnerabilities
3. Maintain high test coverage to ensure code quality
4. Review security scan results regularly
5. Use semantic versioning for releases
