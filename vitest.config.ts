import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    // tests/fixtures/source-exclusion/src/handler.test.ts is a *fixture* -- content
    // MCP008's collector-level test-file exclusion is exercised against, not a real
    // suite -- and its basename otherwise matches `include` above and makes vitest
    // try (and fail) to run it as one.
    exclude: ['**/node_modules/**', 'tests/fixtures/**'],
  },
});
