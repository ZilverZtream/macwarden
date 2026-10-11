import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { leakCampaign } from '../../scripts/rune-leak-fuzz.mjs';
import { childEnvironment } from '../helpers/environment.js';

const repo = resolve();
const run = (script: string, args: string[]) => spawnSync(process.execPath, [join(repo, 'scripts', script), ...args],
  { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 120_000 });

// Audit TOOLING-07: Number('abc') gave NaN cases (none run, exit 0), a null seed, and a batch of 0
// looped forever. Each bad value now stops the command before any work, with exit 1.
it.each([
  ['rune-leak-fuzz.mjs', ['--cases', 'abc']], ['rune-leak-fuzz.mjs', ['--cases']], ['rune-leak-fuzz.mjs', ['--cases', '0']],
  ['rune-leak-fuzz.mjs', ['--seed', 'abc']], ['rune-leak-fuzz.mjs', ['--batch', '0']], ['rune-leak-fuzz.mjs', ['--batch', '-1']],
  ['cln-rune-campaign.mjs', ['--runes', 'abc']], ['cln-rune-campaign.mjs', ['--seed', '1e3']],
  ['rune-false-positives.mjs', ['--per-class', 'x']], ['rune-false-positives.mjs', ['--seed']],
] as const)('TOOLING-07 %s %j is refused', (script, args) => {
  const result = run(script, [...args]);
  expect(result.error, 'the command ends').toBeUndefined();
  expect(result.status).toBe(1);
  expect(result.stderr).toMatch(/must be an integer of at least \d/);
});

// Audit TOOLING-08: a credential split across two outputs leaks only in the joined output; the
// campaign used to find it there, find nothing per output, and record no leak.
it('TOOLING-08 a leak found only in the joined outputs is recorded', async () => {
  let text = '', calls = 0;
  const api = {
    inspectRun: async (args: string[]) => { if (args.length === 1 && args[0] !== '-') text = args[0]; return { args }; },
    render: () => { calls++; return calls % 4 === 3 ? text.slice(0, 20) : calls % 4 === 0 ? text.slice(20) : ''; },
    scan: async () => ({}), renderChunks: () => [''], redactRuneContexts: () => '',
  };
  const report = await leakCampaign(api, { seed: 1, cases: 1, batch: 1, scratchRoot: process.env.MACWARDEN_TEST_TMP });
  expect(text.length, 'the case has a rune text').toBeGreaterThan(40);
  expect(report.cases).toBe(1);
  expect(report.leaks).toEqual([expect.objectContaining({ where: 'joined outputs' })]);
});
