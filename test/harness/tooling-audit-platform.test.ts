import { readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { platformVariants, requiredPlatformFiles } from '../../scripts/platform-variants.mjs';
import { fullSuite, testFiles } from '../../scripts/validation-support.mjs';

const repo = resolve();
// A platform suffix: name.<platform or capability>.test.ts, such as .windows-fs or .posix.
const suffixed = readdirSync(join(repo, 'test')).filter(name => /\.(?:[a-z0-9]+-fs|posix|windows|linux)\.test\.ts$/.test(name))
  .map(name => `test/${name}`);

// Audit TOOLING-12: the required list was never enforced and omitted two Windows files. Each
// platform-suffixed file is now either required or excluded on each supported platform.
it.each(['win32', 'linux'] as const)('TOOLING-12 every platform-suffixed test file is registered for %s', platform => {
  expect(suffixed.length).toBeGreaterThan(10);
  const required = requiredPlatformFiles(platform), excluded = platformVariants(platform).map(item => item.file);
  for (const file of suffixed) {
    expect(required.includes(file) !== excluded.includes(file), `${file} is either required or excluded on ${platform}`).toBe(true);
  }
  for (const file of required) expect(suffixed.concat(testFiles(repo) as string[]), `${file} exists`).toContain(file);
});

it('TOOLING-12 full validation fails when a required platform file did not run', () => {
  const files = (testFiles(repo) as string[]).filter(file => !/^test\/(?:oracle|cln-oracle|gitleaks)\//.test(file)
    && !platformVariants(process.platform).some(item => item.file === file));
  const variants = platformVariants(process.platform);
  const suite = (file: string) => ({ name: join(repo, file), assertionResults: [
    { status: 'passed', fullName: `${file} case`, title: 'case' },
    ...variants.filter(item => item.counterpart === file).map(item => ({ status: 'passed', fullName: `${item.requiredCase} case`, title: 'case' })),
  ] });
  const report = (included: string[]) => {
    const testResults = included.map(suite);
    const total = testResults.reduce((sum, item) => sum + item.assertionResults.length, 0);
    return { success: true, numTotalTests: total, numPassedTests: total, numFailedTests: 0, numPendingTests: 0, testResults };
  };
  const status = (included: string[]) => {
    const checks: { name: string; status: string }[] = [];
    fullSuite(repo, 'unit', report(included), checks);
    return checks.find(check => check.name === 'platform-required')?.status;
  };
  expect(status(files), 'positive control').toBe('PASS');
  const dropped = requiredPlatformFiles(process.platform)[0];
  expect(status(files.filter(file => file !== dropped))).toBe('FAIL');
});
