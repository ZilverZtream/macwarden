import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

const repo = resolve();
const testTmp = join(repo, 'test', '.cp010-tmp');
process.env.MACWARDEN_TEST_TMP ??= testTmp;

function scratch<T>(body: (dir: string) => T): T {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'selection-'));
  try { return body(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function symlinksWork(): boolean {
  return scratch(dir => {
    const file = join(dir, 'file');
    const folder = join(dir, 'folder');
    writeFileSync(file, 'probe');
    mkdirSync(folder);
    try {
      symlinkSync(file, join(dir, 'file-link'), 'file');
      symlinkSync(folder, join(dir, 'dir-link'), process.platform === 'win32' ? 'junction' : 'dir');
      return true;
    } catch { return false; }
  });
}

function deniedDirectoriesWork(): boolean {
  return scratch(dir => {
    const denied = join(dir, 'denied');
    mkdirSync(denied);
    if (process.platform === 'win32') {
      const user = process.env.USERNAME;
      if (!user) return false;
      const applied = spawnSync('icacls', [denied, '/deny', `${user}:(R)`], { encoding: 'utf8' });
      if (applied.status !== 0) return false;
      let inaccessible = false;
      try { readdirSync(denied); } catch { inaccessible = true; }
      const restored = spawnSync('icacls', [denied, '/remove:d', user], { encoding: 'utf8' });
      if (restored.status !== 0) throw new Error('Could not restore scratch directory permissions');
      return inaccessible;
    }
    chmodSync(denied, 0o000);
    try {
      try { readdirSync(denied); return false; } catch { return true; }
    } finally { chmodSync(denied, 0o700); }
  });
}

function selected(suffix: string): boolean {
  const run = spawnSync(process.execPath,
    [join(repo, 'node_modules', 'vitest', 'vitest.mjs'), 'list', '--filesOnly', '--json'],
    { cwd: repo, encoding: 'utf8', timeout: 20_000 });
  expect(run.status, run.stderr).toBe(0);
  const files = (JSON.parse(run.stdout) as { file: string }[]).map(item => item.file.replace(/\\/g, '/'));
  return files.some(file => file.endsWith(suffix));
}

it('CP-010/B8 real symlink variant is selected whenever scratch links work', () => {
  expect(selected('test/scan-walk.symlink.real-fs.test.ts')).toBe(symlinksWork());
}, 30_000);

it('CP-010/B11 real permission variant is selected whenever scratch denial works', () => {
  expect(selected('test/scan-walk.permission.real-fs.test.ts')).toBe(deniedDirectoriesWork());
}, 30_000);
