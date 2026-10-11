import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';

const repo = resolve();

// Audit TOOLING-10: an evidence directory inside the candidate's work tree was excused from the
// clean-tree check, so its files could later be committed unnoticed. Unless git ignores it,
// validation now refuses to start.
it('TOOLING-10 full validation refuses an evidence directory inside the work tree that git does not ignore', () => {
  const root = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP ?? tmpdir(), 'tooling-evidence-'));
  try {
    const git = (...args: string[]) => spawnSync('git', args, { cwd: root, encoding: 'utf8', timeout: 30_000 });
    git('init', '-b', 'main'); git('config', 'user.name', 'Fixture'); git('config', 'user.email', 'fixture@example.invalid');
    writeFileSync(join(root, 'README.md'), 'fixture\n');
    git('add', '.'); expect(git('commit', '-m', 'fixture').status).toBe(0);
    const result = spawnSync(process.execPath, [join(repo, 'scripts/full-validation.mjs'), '--root', root,
      '--evidence-dir', join(root, 'evidence')], { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 60_000 });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('the evidence directory is inside the work tree and not ignored by git');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

it('TOOLING-10 the default evidence directory is one git ignores', () => {
  const ignored = spawnSync('git', ['check-ignore', '-q', '--', '.ratchet/evidence/full'], { cwd: repo, timeout: 30_000 });
  expect(ignored.status).toBe(0);
});
