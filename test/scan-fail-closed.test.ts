import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it, vi } from 'vitest';

// A bug in analysing a file's bytes must stop the scan as an internal error (exit 8), never be
// recorded as an "unreadable" skip with exit 0, which a CI gate would read as a clean scan.
vi.mock('../src/scan/runes.js', async importOriginal => {
  const actual = await importOriginal<typeof import('../src/scan/runes.js')>();
  return { ...actual, runeFindings: (text: string, ...rest: Parameters<typeof actual.runeFindings> extends [string, ...infer R] ? R : never) => {
    if (text.includes('TRIGGER_ANALYSIS_BUG')) throw new Error('simulated analysis bug');
    return actual.runeFindings(text, ...rest);
  } };
});

const { main } = await import('../src/cli.js');
const { captureMain } = await import('./support/capture.js');

it('SCAN/fail-closed an exception while analysing a file stops the scan with exit 8, not an unreadable skip', async () => {
  const dir = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP || tmpdir(), 'scan-fail-closed-'));
  writeFileSync(join(dir, 'ok.env'), 'NOTHING=here\n');
  writeFileSync(join(dir, 'bug.env'), 'RUNE=TRIGGER_ANALYSIS_BUG\n');
  const text = await captureMain(main, ['scan', dir]);
  expect(text.code).toBe(8);
  const json = await captureMain(main, ['scan', dir, '--json']);
  expect(json.code).toBe(8);
  const parsed = JSON.parse(json.stdout) as { ok: boolean; error: { code: number; step: string; message: string } };
  expect(parsed).toMatchObject({ ok: false, error: { code: 8, step: 'internal' } });
  // No path, input or stack reaches the output.
  expect(json.stdout + json.stderr).not.toContain('bug.env');
  expect(json.stdout + json.stderr).not.toContain('TRIGGER_ANALYSIS_BUG');
  expect(json.stdout + json.stderr).not.toMatch(/\n\s+at /);
});

it('SCAN/fail-closed a file that cannot be read is still a skip, not an internal error', async () => {
  const dir = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP || tmpdir(), 'scan-fail-closed-'));
  writeFileSync(join(dir, 'ok.env'), 'NOTHING=here\n');
  const json = await captureMain(main, ['scan', dir, '--json']);
  expect(json.code).toBe(0);
});
