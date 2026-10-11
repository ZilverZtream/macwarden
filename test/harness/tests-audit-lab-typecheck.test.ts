import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';

// Audit 1.4.0: the payment lab's typecheck (examples/payment-lab/package.json "typecheck") ran
// nowhere, so its sources, scenarios and tests drifted from their own types unnoticed. It runs
// here with the repository's TypeScript, which is the version the lab pins.
const repo = resolve();

it('TESTS-AUDIT/lab-typecheck the payment lab type-checks with its own tsconfig', () => {
  const run = spawnSync(process.execPath, [join(repo, 'node_modules/typescript/bin/tsc'), '-p',
    join(repo, 'examples/payment-lab/tsconfig.json'), '--noEmit'],
  { cwd: repo, encoding: 'utf8', timeout: 240_000, windowsHide: true, env: childEnvironment() });
  expect(run.error).toBeUndefined();
  expect({ status: run.status, output: `${run.stdout}${run.stderr}`.trim() }).toEqual({ status: 0, output: '' });
}, 300_000);
