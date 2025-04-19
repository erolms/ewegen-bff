# Docker Setup for eWegen BFF

This document provides instructions for building and running the eWegen BFF service using Docker.

## Building the Docker Image

### Development Environment

```bash
# Build the development image
docker build -t ewegen-bff:dev --target development .

# Run the development container
docker run -p 8080:8080 -v $(pwd)/src:/app/src ewegen-bff:dev
```

### Production Environment

```bash
# Build the production image
docker build -t ewegen-bff:prod --target production .

# Run the production container
docker run -p 8080:8080 ewegen-bff:prod
```

## Using Docker Compose

Docker Compose provides a more convenient way to run the service:

```bash
# Run in development mode (default)
docker-compose up

# Run in production mode
NODE_ENV=production docker-compose up

# Run in detached mode
docker-compose up -d

# Stop the service
docker-compose down
```

## Environment Variables

You can customize the behavior of the container using environment variables:

- `NODE_ENV`: Set to `development` (default) or `production`
- `PORT`: The port to expose (default: 8080)

Example:

```bash
# Run with custom port
PORT=3000 docker-compose up

# Run in production mode with custom port
NODE_ENV=production PORT=3000 docker-compose up
```

## Security Considerations

The Docker image is designed with security in mind:

1. **Root-less Container**: The application runs as a non-root user (`appuser`)
2. **Multi-stage Build**: Reduces the attack surface by not including build tools in the final image
3. **Minimal Dependencies**: Only production dependencies are included in the production image
4. **Alpine-based**: Uses the lightweight Alpine Linux as the base image

## Best Practices

1. Always use the latest security patches by regularly updating the base image
2. Scan the image for vulnerabilities using tools like Trivy or Clair
3. Use specific version tags for the base image instead of `latest`
4. Consider using Docker Content Trust for signed images
5. Implement proper logging and monitoring in production environments
