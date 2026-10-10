import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    allowOnly: false,
    include: ['test/gitleaks/**/*.test.ts'],
    // The first test starts the pinned gitleaks container; the limit only stops a hang.
    testTimeout: 120_000,
  },
});
