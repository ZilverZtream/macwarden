import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import * as realFs from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { reserveOut } from '../src/commands/bake/write-out.js';
import { Secret } from '../src/secret.js';
import { root } from './helpers/cp038-online.js';

// RO-3: on POSIX the credential file is created 0600 with O_EXCL, and the mode is then read
// back from the open descriptor. File systems that cannot store modes (WSL drvfs, vfat,
// exFAT, CIFS) report other bits: chmod is tried once, and a file that is still not private
// is removed before any byte is written. The file system is simulated through the handle,
// so this proof runs on every platform; the real drvfs case is in the 1.1.1 review record.
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
const getuid = Object.getOwnPropertyDescriptor(process, 'getuid');
const uid = 4242;
beforeEach(() => {
  Object.defineProperty(process, 'platform', { ...platform, value: 'linux' });
  Object.defineProperty(process, 'getuid', { configurable: true, writable: true, value: () => uid });
});
afterEach(() => {
  Object.defineProperty(process, 'platform', platform);
  if (getuid) Object.defineProperty(process, 'getuid', getuid); else delete (process as { getuid?: unknown }).getuid;
});

/** A file system whose new files report `modes` in turn (the last repeats) and the given owner. */
function simulated(modes: number[], owner = uid, only?: string) {
  const unlinked: string[] = [], chmods: number[] = [], writes: unknown[] = [];
  let index = 0;
  const fs = { ...realFs,
    async open(path: Parameters<typeof realFs.open>[0], flags?: string | number, mode?: number) {
      const handle = await realFs.open(path, flags as string, mode);
      if (flags !== 'wx' || (only !== undefined && String(path) !== only)) return handle;
      return Object.assign(handle, {
        stat: async () => ({ ...(await realFs.stat(path)), mode: 0o100000 | modes[Math.min(index++, modes.length - 1)], uid: owner }),
        chmod: async (value: number) => { chmods.push(value); },
        writeFile: async (data: Uint8Array) => { writes.push(data); return realFs.writeFile(path, data); },
        sync: async () => undefined,
      });
    },
    async unlink(path: Parameters<typeof realFs.unlink>[0]) { unlinked.push(String(path)); return realFs.unlink(path); },
  } as typeof realFs;
  return { fs, unlinked, chmods, writes };
}
const scratch = () => mkdtempSync(join(root('MACWARDEN_TEST_TMP'), 'out-mode-'));

it('RO-3/mode-verified a file system that keeps group or world bits fails closed: removed, nothing written', async () => {
  for (const mode of [0o777, 0o644, 0o640, 0o604]) {
    const out = join(scratch(), 'app.macaroon');
    const { fs, unlinked, chmods, writes } = simulated([mode]);
    await expect(reserveOut(out, fs)).rejects.toThrow(/did not keep owner-only mode 0600/);
    expect(chmods).toEqual([0o600]);
    expect(unlinked).toEqual([out]); expect(writes).toEqual([]); expect(existsSync(out)).toBe(false);
  }
});

it('RO-3/mode-verified a file another account owns fails closed', async () => {
  const out = join(scratch(), 'app.macaroon');
  const { fs, unlinked, writes } = simulated([0o600], uid + 1);
  await expect(reserveOut(out, fs)).rejects.toThrow(/did not keep owner-only mode 0600/);
  expect(unlinked).toEqual([out]); expect(writes).toEqual([]); expect(existsSync(out)).toBe(false);
});

it('RO-3/mode-verified extra bits that chmod removes are repaired before anything is written', async () => {
  const out = join(scratch(), 'app.macaroon');
  const { fs, chmods, writes } = simulated([0o666, 0o600]);
  const reserved = await reserveOut(out, fs);
  expect(reserved.aclWarning).toBe(false);
  expect(chmods).toEqual([0o600]); expect(writes).toEqual([]);
  await reserved.reservation.write(new Secret(Buffer.from('synthetic test bytes')));
  expect(readFileSync(out, 'utf8')).toBe('synthetic test bytes');
});

it('RO-3/mode-verified a private file is reserved without chmod', async () => {
  const out = join(scratch(), 'app.macaroon');
  const { fs, chmods } = simulated([0o600]);
  const reserved = await reserveOut(out, fs);
  expect(chmods).toEqual([]);
  await reserved.reservation.discard();
  expect(existsSync(out)).toBe(false);
});

it('RO-3/mode-verified attenuate refuses at A6 when the mode cannot be kept, and bake text states the verified mode', async () => {
  const { run: attenuate } = await import('../src/commands/attenuate.js');
  const { render } = await import('./helpers/render-adversarial.js');
  const out = join(scratch(), 'child.macaroon');
  const { fs, writes } = simulated([0o777], uid, out);
  const result = await attenuate([join('test', 'vectors', 'default-readonly.macaroon'), '--out', out, '--expires', '1h'],
    { stdin: process.stdin, fs, env: {}, clock: () => new Date() });
  expect(result.error).toMatchObject({ code: 3, step: 'A6' });
  expect(result.error!.message).toMatch(/^cannot create output file: the file system did not keep owner-only mode 0600/);
  expect(writes).toEqual([]); expect(existsSync(out)).toBe(false);
  // bake prints a mode only after reserveOut verified it (the line is unreachable otherwise).
  const entry = { nodePubkey: '02' + 'ab'.repeat(32), label: 'Bob', rootKeyId: '7', permissions: ['info:read'], caveats: [],
    grade: 'READ', fingerprint: 'fp:0123456789abcdef', outPath: '/tmp/bob.macaroon', createdAt: '2026-10-09T00:00:00Z',
    verified: true, status: 'active', revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null };
  expect(render({ schema: 1, command: 'bake', ok: true, warnings: [], result: entry, error: null }, 'text'))
    .toContain('wrote /tmp/bob.macaroon (0600, verified); registry updated');
});

// Audit O09: the output file was synced but its directory was not, so after a power loss the
// registry (whose save syncs its directory) could record a file whose name was lost.
it('RO-3/durable the written file is synced and then its directory, best effort', async () => {
  const out = join(scratch(), 'app.macaroon');
  const { fs: base } = simulated([0o600]);
  const events: string[] = [];
  const fs = { ...base,
    async open(path: Parameters<typeof realFs.open>[0], flags?: string | number, mode?: number) {
      if (String(path) !== dirname(out)) return base.open(path, flags as string, mode);
      events.push(`open ${String(flags)}`);
      return { sync: async () => { events.push(`sync ${existsSync(out) ? readFileSync(out, 'utf8') : ''}`); },
        close: async () => { events.push('close'); } } as unknown as realFs.FileHandle;
    },
  } as typeof realFs;
  const reserved = await reserveOut(out, fs);
  expect(events).toEqual([]);
  await reserved.reservation.write(new Secret(Buffer.from('synthetic test bytes')));
  expect(events).toEqual(['open r', 'sync synthetic test bytes', 'close']);
});

it('RO-3/durable a directory that cannot be opened or synced does not fail the written output', async () => {
  for (const failure of ['open', 'sync']) {
    const out = join(scratch(), 'app.macaroon');
    const { fs: base } = simulated([0o600]);
    let closed = false;
    const fs = { ...base,
      async open(path: Parameters<typeof realFs.open>[0], flags?: string | number, mode?: number) {
        if (String(path) !== dirname(out)) return base.open(path, flags as string, mode);
        if (failure === 'open') throw Object.assign(new Error('EISDIR: illegal operation on a directory'), { code: 'EISDIR' });
        return { sync: async () => { throw Object.assign(new Error('EINVAL'), { code: 'EINVAL' }); },
          close: async () => { closed = true; } } as unknown as realFs.FileHandle;
      },
    } as typeof realFs;
    const reserved = await reserveOut(out, fs);
    await reserved.reservation.write(new Secret(Buffer.from('synthetic test bytes')));
    expect(readFileSync(out, 'utf8')).toBe('synthetic test bytes');
    expect(closed).toBe(failure === 'sync');
    // Written output is kept: discard after a successful write removes nothing.
    await reserved.reservation.discard();
    expect(existsSync(out)).toBe(true);
  }
});

it('RO-3/durable Windows, which has no directory sync, never opens the directory', async () => {
  const out = join(scratch(), 'app.macaroon');
  const { fs: base } = simulated([0o600]);
  const opened: string[] = [];
  const fs = { ...base,
    async open(path: Parameters<typeof realFs.open>[0], flags?: string | number, mode?: number) {
      opened.push(String(path));
      return base.open(path, flags as string, mode);
    },
  } as typeof realFs;
  // Reserved through the simulated POSIX path, then written as on Windows.
  const reserved = await reserveOut(out, fs);
  Object.defineProperty(process, 'platform', { ...platform, value: 'win32' });
  await reserved.reservation.write(new Secret(Buffer.from('synthetic test bytes')));
  expect(readFileSync(out, 'utf8')).toBe('synthetic test bytes');
  expect(opened).toEqual([out]);
});
