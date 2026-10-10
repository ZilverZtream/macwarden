import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';

it('CP-040/A10-release package and lock identify the current release, 1.2.1', () => {
  const pkg = JSON.parse(readFileSync(resolve('package.json'), 'utf8')) as {version:string};
  const lock = JSON.parse(readFileSync(resolve('package-lock.json'), 'utf8')) as {version:string;packages:{'':{version:string}}};
  expect([pkg.version, lock.version, lock.packages[''].version]).toEqual(Array(3).fill('1.2.1'));
});
it('CP-040/B9-scratch-ignore legacy scratch directories are ignored by Git', () => {
  const run = spawnSync('git', ['check-ignore', '--no-index', 'test/.tmp/probe', 'test/.sentinels/probe'],
    { cwd: resolve(), encoding: 'utf8', timeout: 10000, env: childEnvironment() });
  expect(run.status).toBe(0);
  expect(run.stdout.trim().split(/\r?\n/)).toEqual(['test/.tmp/probe', 'test/.sentinels/probe']);
});

it('CP-040/B10-strict-platform the production test configuration enables strict checking', () => {
  const config = JSON.parse(readFileSync(resolve('tsconfig.test.json'), 'utf8')) as {
    compilerOptions: {strict?:boolean};
  };
  expect(config.compilerOptions.strict).toBe(true);
});

it('CP-040/A10-release the 1.0.0 release is recorded and the real-node field check is kept', () => {
  // 1.0.0 was released on 2026-10-08; the field report is produced with docs/field-check.md afterwards.
  const changelog = readFileSync(resolve('CHANGELOG.md'), 'utf8');
  expect(changelog).toMatch(/^## 1\.0\.0 \(2026-10-08\)$/m);
  const readme = readFileSync(resolve('README.md'), 'utf8');
  expect(readme).toContain('docs/field-check.md');
  const check = readFileSync(resolve('docs/field-check.md'), 'utf8');
  for (const step of ['inventory --verify', 'bake --label field-check', 'rotate field-check --finish', 'revoke field-check', 'Surprises'])
    expect(check).toContain(step);
  expect(readme).toContain('macwarden@1.2.1');
});
