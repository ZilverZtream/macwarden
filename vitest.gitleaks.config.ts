import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    allowOnly: false,
    include: ['test/gitleaks/**/*.test.ts'],
  },
});
