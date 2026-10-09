import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

const repo = resolve();

it('CP-036/B12-ratchet-lint generated .ratchet files are ignored while source parse errors still fail lint', () => {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'cp036-lint-'));
  const eslint = join(repo, 'node_modules', 'eslint', 'bin', 'eslint.js');
  const config = join(repo, 'eslint.config.js');
  const run = () => spawnSync(process.execPath, [eslint, '--config', config, '.'],
    { cwd: dir, encoding: 'utf8', timeout: 60_000 });
  try {
    writeFileSync(join(dir, 'source.js'), 'export const value = 1;\n');
    mkdirSync(join(dir, '.ratchet'));
    writeFileSync(join(dir, '.ratchet', 'packet.js'), 'const broken = ;\n');
    const clean = run();
    expect(clean.error).toBeUndefined();
    expect(clean.status, clean.stderr).toBe(0);
    writeFileSync(join(dir, 'source.js'), 'const broken = ;\n');
    expect(run().status).not.toBe(0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 130_000);
