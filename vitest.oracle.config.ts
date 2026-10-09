import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    allowOnly: false,
    name: 'oracle',
    include: ['test/oracle/**/*.test.ts'],
    passWithNoTests: false,
    globalSetup: ['test/global-setup.ts'],
    setupFiles: ['test/oracle/setup.ts'],
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
