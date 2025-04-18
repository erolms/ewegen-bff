# eWegen BFF Tests

This directory contains unit tests for the eWegen BFF service.

## Test Structure

- `app.test.ts`: Tests for the Express application
- `routes/index.test.ts`: Tests for the index route
- `ewegen-bff-service.test.ts`: Tests for the BFF service
- `utils.test.ts`: Tests for utility functions
- `error-handling.test.ts`: Tests for error handling middleware

## Running Tests

You can run the tests using the following npm scripts:

```bash
# Run all tests with coverage
npm test

# Run tests in watch mode (useful during development)
npm run test:watch
```

## Test Coverage

The tests are configured to generate coverage reports. After running the tests, you can find the coverage report in the `coverage` directory.

## Writing New Tests

When adding new features or fixing bugs, please add corresponding tests. Follow these guidelines:

1. Create a new test file in the appropriate directory
2. Use descriptive test names that explain what is being tested
3. Follow the pattern of grouping tests with `describe` blocks
4. Use `it` or `test` for individual test cases
5. Use Jest's expect API for assertions

## Mocking

For tests that require mocking, use Jest's mocking capabilities:

```typescript
// Mock a module
jest.mock('../src/module');

// Mock a function
const mockFn = jest.fn();
mockFn.mockReturnValue('mocked value');

// Mock an implementation
jest.spyOn(object, 'method').mockImplementation(() => 'mocked');
```

## Best Practices

1. Test one thing at a time
2. Use meaningful test descriptions
3. Keep tests independent
4. Avoid test interdependence
5. Clean up after tests
6. Use beforeEach and afterEach hooks for setup and teardown
