import { readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { expect, it, vi } from 'vitest';

const repo = resolve();
const manifest = JSON.parse(readFileSync(join(repo, 'test/scan-fixtures/protected/manifest.json'), 'utf8')) as {
  reference: string;
  protected: string[];
  resolvedTargets: { supplied: string; resolved: string }[];
  ordinary: string[];
};
const unsafeName = (component: string) => {
  const base = component.split(':', 1)[0];
  return /^(?:macaroons\.db|wallet\.db)$/i.test(base)
    || /\.key$/i.test(base)
    || /(^|[._-])(password|passwd|seed)([._-]|$)/i.test(base)
    || /^(?:wallet[-_.]?password(?:\..+)?|seeds?(?:\..+)?|tls[-_.]?(?:key|privkey)(?:\..+)?)$/i.test(base);
};
const unsafePath = (path: string) => path.split(/[\\/]/).some(unsafeName);
const slash = (path: string) => path.split(sep).join('/');

it('CP-036/protected-path-independent-manifest SAFE-02 names and boundaries have independent never-open entries', async () => {
  expect(manifest.reference).toBe('docs/spec.md#2-scan-offline-safe-07');
  const canonical = ['macaroons.db', 'wallet.db', 'tls.key', 'password', 'passwd', 'seed',
    'walletpassword', 'wallet-password.txt', 'seeds', 'seeds.txt', 'tls-privkey', 'tls.key.pem'];
  for (const name of canonical) expect(manifest.protected.map(value => value.toLowerCase())).toContain(name);
  for (const name of ['wallet.db:side', 'WALLET.DB:side', 'macaroons.db:side',
    'TLS.KEY:side', 'password:side', 'passwd:side', 'seed:side',
    'walletpassword:side', 'seeds:side', 'TLS-PRIVKEY:side']) {
    expect(manifest.protected).toContain(name);
  }
  for (const name of ['seedling.txt', 'passwords.txt', 'walletpasswords.txt',
    'seedsman.txt', 'tls-keyed']) expect(manifest.ordinary).toContain(name);
  expect(new Set([...manifest.protected, ...manifest.ordinary,
    ...manifest.resolvedTargets.map(item => item.supplied)]).size).toBe(
    manifest.protected.length + manifest.ordinary.length + manifest.resolvedTargets.length);
  for (const name of manifest.protected) expect(unsafePath(name), name).toBe(true);
  for (const name of manifest.ordinary) expect(unsafePath(name), name).toBe(false);
  for (const item of manifest.resolvedTargets) {
    expect(unsafePath(item.supplied), item.supplied).toBe(false);
    expect(unsafePath(item.resolved), item.resolved).toBe(true);
  }
});

it('CP-036/protected-path-independent-manifest explicit scan never opens manifest protected names', async () => {
  const { scan } = await import('../../src/scan/index.js');
  for (const item of [...manifest.protected.map(name => ({ supplied: name, resolved: name })),
    ...manifest.resolvedTargets]) {
    const supplied = join(repo, 'test/scan-fixtures/protected', item.supplied);
    const opened = vi.fn(async () => { throw new Error('protected fixture opened'); });
    const read = vi.fn(async () => { throw new Error('protected fixture read'); });
    const metadata = { dev: 37n, ino: 41n, size: 6,
      isFile: () => true, isDirectory: () => false, isSymbolicLink: (): boolean => false };
    const fake = { ...fs, stat: vi.fn(async () => metadata) as unknown as typeof fs.stat,
      lstat: vi.fn(async () => metadata) as unknown as typeof fs.lstat,
      realpath: vi.fn(async () => join(repo, 'test/scan-fixtures/protected', item.resolved)) as unknown as typeof fs.realpath,
      open: opened as unknown as typeof fs.open, readFile: read as unknown as typeof fs.readFile };
    let result: Awaited<ReturnType<typeof scan>> | undefined;
    let failed = false;
    try { result = await scan([supplied], { fs: fake }); }
    catch { failed = true; }
    expect.soft(failed, item.supplied).toBe(false);
    if (result) expect.soft(result.skipped, item.supplied).toEqual([
      { path: slash(supplied), reason: 'never-open' },
    ]);
    expect.soft(opened, item.supplied).not.toHaveBeenCalled();
    expect.soft(read, item.supplied).not.toHaveBeenCalled();
  }
});
