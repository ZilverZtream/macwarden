import { defineConfig } from 'vitest/config';

// Rune comparison tests against the disposable regtest Core Lightning fixture (1.2.0):
//   npm run fixture:cln:up && npm run test:cln-oracle; npm run fixture:cln:down
export default defineConfig({
  test: {
    allowOnly: false,
    name: 'cln-oracle',
    include: ['test/cln-oracle/**/*.test.ts'],
    passWithNoTests: false,
    globalSetup: ['test/global-setup.ts'],
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
