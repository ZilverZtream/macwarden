import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';

// The Windows owner-only check of an existing journal, observed without running its helper.
const verifyOwnerOnly = vi.hoisted(() => vi.fn<(path: string) => Promise<{ ownerOnly: boolean; noAcl: boolean } | null>>(async () => null));
vi.mock('../src/private-file.js', async importOriginal => ({ ...(await importOriginal<typeof import('../src/private-file.js')>()), verifyOwnerOnly }));

const { openJournal } = await import('./helpers/payment-journal.js');

const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');
const dirs: string[] = [];
afterEach(() => { verifyOwnerOnly.mockClear(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

/** fs whose descriptor stat reports an owner-only POSIX file of uid 1000 (any host). */
const ownerOnlyFs = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
  const handle = await fs.open(...args);
  return new Proxy(handle, { get(target, key) {
    if (key === 'stat') return async () => {
      const real = await target.stat();
      return { isFile: () => true, dev: real.dev, ino: real.ino, size: real.size, mode: 0o100600, uid: 1000 };
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
} } as typeof fs;

// 1.2.1: open() judged an existing journal's permissions by process.platform in one place and by
// the injected platform everywhere else, so the Windows check ran (or was skipped) by the host.
it('PAYJ/platform an existing journal is checked by the injected platform, not the host', async () => {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'payment-journal-platform-'));
  dirs.push(dir);
  const path = join(dir, 'payments.journal');
  await (await openJournal(path)).close();
  verifyOwnerOnly.mockClear();
  // Windows: the DACL check runs, and a journal whose permissions cannot be read is refused.
  await expect(openJournal(path, { fs: ownerOnlyFs, platform: 'win32', uid: 1000 }))
    .rejects.toThrow('cannot verify the payment journal permissions');
  expect(verifyOwnerOnly).toHaveBeenCalledTimes(1);
  verifyOwnerOnly.mockClear();
  // POSIX: no DACL check; the descriptor's mode and owner decide.
  const posix = await openJournal(path, { fs: ownerOnlyFs, platform: 'linux', uid: 1000 });
  await posix.close();
  expect(verifyOwnerOnly).not.toHaveBeenCalled();
});
