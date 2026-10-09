import { defineConfig } from 'vitest/config';
import { platformVariants, requiredPlatformFiles } from './scripts/platform-variants.mjs';

// Platform variants are selected by contract, never by a capability probe; the
// list lives in scripts/platform-variants.mjs, which full validation also reads.
const excluded = platformVariants(process.platform);

// Tests of the test tooling, documentation and repository configuration, plus a few
// product files that spawn their own build or Vitest processes.
const harness = [
  'test/harness/**/*.test.ts', 'test/docs/**/*.test.ts',
  'test/config.test.ts', 'test/fixture*.test.ts',
  'test/sentinel.test.ts', 'test/cp013-gitleaks-rules.test.ts',
  'test/cp015-facts.test.ts', 'test/cp015-review-repair.test.ts',
  'test/cp036-process.test.ts', 'test/cp036-scan-file-identity.test.ts',
  'test/cp037-reveal*.test.ts', 'test/cp037-scan-lint.test.ts',
];
const privateScratch = ['test/.tmp/**', 'test/.sentinels/**'];
const nonUnit = ['test/oracle/**', 'test/gitleaks/**', ...privateScratch];
const platformPolicy = { platform: process.platform, excluded, required: requiredPlatformFiles(process.platform) };

export default defineConfig({
  test: {
    allowOnly: false,
    passWithNoTests: false,
    // Harness files spawn their own build/Vitest processes. Bound the
    // shared pool with the same worker limit for both concurrent projects.
    maxWorkers: 6,
    // Tests that import modules inside the test body wait on
    // the shared transform queue during a full run. Measured worst case was about 5 s for
    // tests that take under 200 ms alone, so 15 s keeps a 3x margin and still fails a hang.
    testTimeout: 15_000,
    hookTimeout: 30_000,
    globalSetup: ['test/global-setup.ts'],
    provide: { platformPolicy },
    projects: [
      { extends: true, test: { name: 'product', allowOnly: false, include: ['test/**/*.test.ts'],
        exclude: [...nonUnit, ...harness, ...excluded.map(item => item.file)] } },
      { extends: true, test: { name: 'harness-docs', allowOnly: false, include: harness,
        fileParallelism: true,
        exclude: [...nonUnit, ...excluded.map(item => item.file)] } },
    ],
  },
});
