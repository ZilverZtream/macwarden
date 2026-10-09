import { revealSecret } from './helpers/secret-bytes.js';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it } from 'vitest';

const repo = resolve();
const source = () => readFileSync(join(repo, 'test', 'vectors', 'default-readonly.macaroon'));

it('CP-036/B14-linux-real-fs owned symlink and denied file variants execute on a capable unprivileged filesystem', async () => {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'cp036-real-fs-'));
  const target = join(dir, 'ordinary.macaroon');
  const linked = join(dir, 'linked.macaroon');
  const denied = join(dir, 'denied.macaroon');
  const bytes = source();
  try {
    writeFileSync(target, bytes);
    writeFileSync(denied, bytes);
    symlinkSync(target, linked, 'file');
    chmodSync(denied, 0o000);
    const { readCredential } = await import('../src/input/index.js');
    const io = { stdin: Readable.from([]), fs };
    const throughLink = await readCredential(linked, io, { unsafeArg: false });
    expect(Buffer.from(revealSecret(throughLink.secret)).equals(bytes)).toBe(true);
    expect(throughLink.literal).toBe(false);
    expect(statSync(denied).mode & 0o777).toBe(0);
    let error: unknown;
    try { await readCredential(denied, io, { unsafeArg: false }); }
    catch (caught) { error = caught; }
    expect((error as { name?: string; stage?: string } | undefined)?.name).toBe('InputError');
    expect((error as { stage?: string } | undefined)?.stage).toBe('input-read');
  } finally {
    chmodSync(denied, 0o600);
    rmSync(dir, { recursive: true, force: true });
  }
});
