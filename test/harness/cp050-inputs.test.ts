import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';

it('CP-050/B4 untracked validation configuration cannot reuse a clean candidate identity', () => {
  if (!process.env.MACWARDEN_TEST_TMP) throw new Error('Private test scratch is required');
  const root = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP, 'cp050-inputs-'));
  const put = (file: string, value: string) => { const target = join(root, file); mkdirSync(dirname(target), { recursive: true }); writeFileSync(target, value); };
  put('package.json', JSON.stringify({ name: 'cp050-inputs', version: '1.0.0' }));
  put('vitest.oracle.config.ts', 'export default {test:{include:["test/oracle/**/*.test.ts"]}};\n');
  put('src/input.ts', 'export const input = 1;\n');
  const git = (...args: string[]) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8', env: childEnvironment(), timeout: 15_000 });
    expect(result.status, `private input fixture git ${args[0]}`).toBe(0);
  };
  git('init', '-b', 'main'); git('config', 'user.name', 'Private Fixture'); git('config', 'user.email', 'fixture@example.invalid');
  git('add', '.'); git('commit', '-m', 'Independent candidate inputs');
  const clean = () => {
    const invoke = 'const {candidateInputsClean}=await import(process.argv[1]);process.stdout.write(JSON.stringify(await candidateInputsClean(process.argv[2])));';
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', invoke,
      pathToFileURL(resolve('scripts/validation-support.mjs')).href, root], { cwd: resolve(), encoding: 'utf8', env: childEnvironment(), timeout: 15_000 });
    expect(result.error).toBeUndefined(); expect(result.status, 'Public candidate input checker must execute').toBe(0);
    return JSON.parse(result.stdout) as boolean;
  };
  expect(clean(), 'Unchanged committed inputs are independently clean').toBe(true);
  put('vitest.untracked.config.ts', 'export default {test:{include:["test/oracle/only-one.test.ts"]}};\n');
  expect(clean(), 'An untracked configuration changes validation inputs').toBe(false);
}, 30_000);
