import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { resolveUnprotectedPath } from '../src/protected-path.js';
import { openRegistry } from '../src/registry/index.js';
import { directory } from './helpers/cp026-revoke-support.mjs';

// SAFE-02: a path whose own name is harmless must still be refused when it resolves
// through a symlink to a protected name. Real symlinks on the real file system.
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function scratch() {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'protected-link-'));
  dirs.push(dir);
  return dir;
}
const canLink = (() => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'link-probe-'));
  try { writeFileSync(join(dir, 't'), ''); symlinkSync(join(dir, 't'), join(dir, 'l'), 'file'); return true; }
  catch { return false; }
  finally { rmSync(dir, { recursive: true, force: true }); }
})();

it.skipIf(!canLink)('PROTECTED/symlink a registry symlink to wallet.db is refused without reading wallet.db', async () => {
  const dir = scratch();
  const wallet = join(dir, 'wallet.db');
  writeFileSync(wallet, JSON.stringify({ schema: 1, entries: [] }));
  const link = join(dir, 'registry.json');
  symlinkSync(wallet, link, 'file');
  const reads: string[] = [];
  const io = { ...fs, readFile: (async (path: Parameters<typeof fs.readFile>[0], ...rest: unknown[]) => {
    reads.push(String(path));
    return (fs.readFile as (...args: unknown[]) => Promise<unknown>)(path, ...rest);
  }) as typeof fs.readFile };
  await expect(openRegistry(link, { fs: io })).rejects.toMatchObject({ code: 3, step: 'registry-read' });
  expect(reads).toEqual([]);
});

it.skipIf(!canLink)('PROTECTED/symlink an output path through a directory symlink to a protected name is refused', async () => {
  const dir = scratch();
  const protectedDir = join(dir, 'node.key');
  mkdirSync(protectedDir);
  const link = join(dir, 'outputs');
  symlinkSync(protectedDir, link, 'junction');
  await expect(resolveUnprotectedPath(join(link, 'new.macaroon'), fs)).rejects.toThrow('protected path');
  // The same layout with a harmless target directory resolves into it.
  const plain = join(dir, 'plain');
  mkdirSync(plain);
  const plainLink = join(dir, 'plain-outputs');
  symlinkSync(plain, plainLink, 'junction');
  expect(await resolveUnprotectedPath(join(plainLink, 'new.macaroon'), fs)).toBe(join(await fs.realpath(plain), 'new.macaroon'));
});

it.skipIf(!canLink)('PROTECTED/symlink a dangling output symlink is refused instead of becoming a creation path', async () => {
  const dir = scratch();
  const link = join(dir, 'new.macaroon');
  symlinkSync(join(dir, 'elsewhere', 'target.macaroon'), link, 'file');
  await expect(resolveUnprotectedPath(link, fs)).rejects.toThrow('unresolvable path');
});
