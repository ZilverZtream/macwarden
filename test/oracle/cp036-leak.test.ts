import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from "../helpers/leak-check.js";

const repo = resolve();

it('CP-036/leak-check global sentinel stays absent from inspect output and owned temporary paths', () => {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const testTmp = mkdtempSync(join(base, 'cp036-oracle-leak-'));
  try {
    const path = join(repo, 'test', 'sentinels', 'sentinel.macaroon');
    const bytes = readFileSync(path);
    const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', path, '--json'],
      { cwd: repo, encoding: 'utf8', timeout: 10_000 });
    expect(run.status).toBe(0);
    const output = (run.stdout || '') + (run.stderr || '');
    expect(findLeaks({ sentinels: join(repo, 'test', 'sentinels.json'),
      commandOutput: output, paths: [testTmp], testTmp, root: repo })).toBeNull();
    expect(output).not.toContain(bytes.toString('hex'));
    expect(output).not.toContain(bytes.toString('base64'));
  } finally { rmSync(testTmp, { recursive: true, force: true }); }
});
