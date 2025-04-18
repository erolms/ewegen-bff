// @ts-check

import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  tseslint.configs.strict,
  tseslint.configs.stylistic,
  {
    // Lint the src and tests folder
    files: [
      'src/**/*.ts',
      'src/**/*.js',
      'tests/**/*.ts',
      'tests/**/*.js',
    ],
  },
  {
    // Exclude the dist folder from linting
    ignores: [
      'dist/**/*',
      './jest.config.js',
    ],
  },
  {
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          "args": "all",
          "argsIgnorePattern": "^_",
          "caughtErrors": "all",
          "caughtErrorsIgnorePattern": "^_",
          "destructuredArrayIgnorePattern": "^_",
          "varsIgnorePattern": "^_",
          "ignoreRestSiblings": true,
        }
      ],
    },
  },
);
