import { revealSecret } from './helpers/secret-bytes.js';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { expect, it, vi } from 'vitest';

const repo = resolve();
const bytes = () => readFileSync(join(repo, 'test', 'vectors', 'default-invoice.macaroon'));
const refusal = 'pass a file path or - (stdin); literal credentials end up in shell history and process listings';
const input = () => import('../src/input/index.js');
type InputFs = Pick<typeof fs, 'stat' | 'lstat' | 'realpath' | 'open' | 'readFile'>;

function protectedLookingBase64(malformed = false): { text: string; value: Buffer } {
  const value = Buffer.from(bytes());
  // Change only the signature packet's opaque bytes, leaving the vector's v2 structure intact.
  const offset = value.length - 30;
  if (value[0] !== 0x02 || offset < 0 || offset % 3 !== 0)
    throw new Error('vector signature alignment changed');
  Buffer.from('/seed/AA', 'base64').copy(value, offset);
  if (malformed) value[1] = 0xff;
  const text = value.toString('base64');
  if (!text.includes('/seed/') || Buffer.from(text, 'base64').compare(value) !== 0)
    throw new Error('canonical base64 construction failed');
  return { text, value };
}

function probeError(code: string): InputFs {
  const fail = vi.fn(async () => { throw Object.assign(new Error('path probe failed'), { code }); });
  return { stat: fail as unknown as typeof fs.stat, lstat: fail as unknown as typeof fs.lstat,
    realpath: fs.realpath, open: fs.open, readFile: fs.readFile };
}
async function rejection(work: () => Promise<unknown>): Promise<Error & { stage?: string }> {
  try { await work(); } catch (error) { return error as Error & { stage?: string }; }
  throw new Error('Expected rejection');
}

it('CP-036/A1-portable-literal path probe errors still classify credential literals and preserve existing read errors', async () => {
  const { readCredential } = await input();
  const source = bytes();
  const literals = [source.toString('hex'), source.toString('base64'),
    `lndconnect://h:10009/seed/route?macaroon=${source.toString('base64url')}`];
  for (const code of ['ENAMETOOLONG', 'ENOTDIR', 'EINVAL']) for (const literal of literals) {
    const fileSystem = probeError(code);
    const io = { stdin: Readable.from([]), fs: fileSystem };
    const denied = await rejection(() => readCredential(literal, io, { unsafeArg: false }));
    expect(denied.name, code).toBe('UsageError');
    expect(denied.message, code).toBe(refusal);
    expect(String(denied)).not.toContain(literal);
    const accepted = await readCredential(literal, io, { unsafeArg: true });
    expect(accepted.literal).toBe(true);
    expect(Buffer.from(revealSecret(accepted.secret)).equals(source)).toBe(true);
  }
  for (const code of ['ENAMETOOLONG', 'ENOTDIR', 'EINVAL']) {
    const io = { stdin: Readable.from([]), fs: probeError(code) };
    const missing = await rejection(() => readCredential('%%%malformed%%%', io, { unsafeArg: false }));
    expect(missing.name).toBe('InputError');
    expect(missing.stage).toBe('input-read');
    expect(missing.message).toBe('no such file');
    const malformed = await rejection(() => readCredential('%%%malformed%%%', io, { unsafeArg: true }));
    expect(malformed.name).toBe('InputError');
    expect(malformed.stage).toBe('input-form');
  }
  const present = {
    stat: vi.fn(async () => ({ isFile: () => true, isDirectory: () => false })) as unknown as typeof fs.stat,
    lstat: vi.fn(async () => ({ isFile: () => true, isDirectory: () => false,
      isSymbolicLink: () => false })) as unknown as typeof fs.lstat,
    realpath: vi.fn(async () => 'ordinary.macaroon') as unknown as typeof fs.realpath,
    open: vi.fn(async () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); }) as unknown as typeof fs.open,
    readFile: vi.fn(async () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); }) as unknown as typeof fs.readFile,
  };
  for (const unsafeArg of [false, true]) {
    const error = await rejection(() => readCredential('ordinary.macaroon',
      { stdin: Readable.from([]), fs: present }, { unsafeArg }));
    expect(error.name).toBe('InputError');
    expect(error.stage).toBe('input-read');
  }
});

it('CP-036/B14-linux-real-fs injected symlink and denied-file branches are collected on every platform', async () => {
  const { readCredential } = await input();
  const target = join(repo, 'test', 'vectors', 'default-invoice.macaroon');
  const linked = join(repo, 'test', 'vectors', 'virtual-link.macaroon');
  const protectedTarget = join(repo, 'test', 'vectors', 'macaroons.db');
  const denied = join(repo, 'test', 'vectors', 'virtual-denied.macaroon');
  const linkFs: InputFs = {
    lstat: vi.fn(async () => Object.assign(await fs.lstat(target), {
      isFile: () => false, isSymbolicLink: () => true,
    })) as unknown as typeof fs.lstat,
    stat: vi.fn(async () => fs.stat(target)) as unknown as typeof fs.stat,
    realpath: vi.fn(async () => protectedTarget) as unknown as typeof fs.realpath,
    open: vi.fn(async () => { throw new Error('protected symlink was opened'); }) as unknown as typeof fs.open,
    readFile: vi.fn(async () => { throw new Error('protected symlink was read'); }) as unknown as typeof fs.readFile,
  };
  const linkError = await rejection(() => readCredential(linked,
    { stdin: Readable.from([]), fs: linkFs }, { unsafeArg: false }));
  expect(linkError.name).toBe('InputError');
  expect(linkError.stage).toBe('input-read');
  expect(linkFs.realpath).toHaveBeenCalled();
  expect(linkFs.open).not.toHaveBeenCalled();
  expect(linkFs.readFile).not.toHaveBeenCalled();
  const deny = vi.fn(async () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); });
  const deniedFs: InputFs = {
    ...linkFs,
    lstat: vi.fn(async () => fs.lstat(target)) as unknown as typeof fs.lstat,
    realpath: vi.fn(async () => denied) as unknown as typeof fs.realpath,
    open: deny as unknown as typeof fs.open,
    readFile: deny as unknown as typeof fs.readFile,
  };
  const error = await rejection(() => readCredential(denied,
    { stdin: Readable.from([]), fs: deniedFs }, { unsafeArg: false }));
  expect(error.name).toBe('InputError');
  expect(error.stage).toBe('input-read');
  expect(deny).toHaveBeenCalled();
});

it('CP-036/A1-portable-literal inspect emits the exact refusal and unsafe warning without exposing the argument', () => {
  const source = bytes();
  for (const literal of [source.toString('hex'), source.toString('base64'),
    `lndconnect://h:10009/seed/route?macaroon=${source.toString('base64url')}`]) {
    const invoke = (unsafe: boolean) => spawnSync(process.execPath,
      [join(repo, 'dist', 'bin.js'), 'inspect', literal, ...(unsafe ? ['--unsafe-arg'] : []), '--json'],
      { cwd: repo, encoding: 'utf8', timeout: 10_000 });
    const refused = invoke(false);
    expect(refused.status).toBe(2);
    expect(JSON.parse(refused.stdout).error.message).toBe(refusal);
    expect(refused.stdout + refused.stderr).not.toContain(literal);
    const accepted = invoke(true);
    expect(accepted.status).toBe(0);
    const parsed = JSON.parse(accepted.stdout);
    expect(parsed.warnings).toContain('unsafe-arg');
    expect(accepted.stdout + accepted.stderr).not.toContain(literal);
  }
});

it('CP-036/A1-portable-literal protected-looking canonical base64 is classified as a literal', async () => {
  const { readCredential } = await input();
  const valid = protectedLookingBase64();
  const malformed = protectedLookingBase64(true);
  for (const code of ['ENAMETOOLONG', 'ENOTDIR', 'EINVAL']) {
    for (const item of [valid, malformed]) {
      const io = { stdin: Readable.from([]), fs: probeError(code) };
      const denied = await rejection(() => readCredential(item.text, io, { unsafeArg: false }));
      expect(denied.name).toBe('UsageError');
      expect(denied.message === refusal).toBe(true);
      expect(String(denied).includes(item.text)).toBe(false);
      const accepted = await readCredential(item.text, io, { unsafeArg: true });
      expect(accepted.literal).toBe(true);
      expect(Buffer.from(revealSecret(accepted.secret)).equals(item.value)).toBe(true);
    }
  }

  for (const item of [valid, malformed]) {
    const invoke = (unsafe: boolean) => spawnSync(process.execPath,
      [join(repo, 'dist', 'bin.js'), 'inspect', item.text,
        ...(unsafe ? ['--unsafe-arg'] : []), '--json'],
      { cwd: repo, encoding: 'utf8', timeout: 10_000 });
    const denied = invoke(false);
    expect(denied.status).toBe(2);
    expect(JSON.parse(denied.stdout).error.message === refusal).toBe(true);
    expect((denied.stdout + denied.stderr).includes(item.text)).toBe(false);
    const accepted = invoke(true);
    expect(accepted.status).toBe(item === valid ? 0 : 3);
    const document = JSON.parse(accepted.stdout);
    if (item === valid) expect(document.warnings).toContain('unsafe-arg');
    else expect(document.error.step).toBe('packet');
    expect((accepted.stdout + accepted.stderr).includes(item.text)).toBe(false);
  }
});

it('CP-036/A1-portable-literal an existing protected seed path is refused before open', async () => {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'cp036-literal-path-'));
  const path = join(dir, 'seed');
  try {
    writeFileSync(path, 'harmless protected-path control\n');
    const before = { content: readFileSync(path), mtime: statSync(path).mtimeMs };
    const fileSystem = { ...fs, open: vi.fn(fs.open) as unknown as typeof fs.open & ReturnType<typeof vi.fn>, readFile: vi.fn(fs.readFile) as unknown as typeof fs.readFile & ReturnType<typeof vi.fn> };
    for (const unsafeArg of [false, true]) {
      const error = await rejection(() => input().then(({ readCredential }) =>
        readCredential(path, { stdin: Readable.from([]), fs: fileSystem }, { unsafeArg })));
      expect(error.name).toBe('InputError');
      expect(error.stage).toBe('input-read');
      expect(String(error).includes(path)).toBe(false);
    }
    expect(fileSystem.open).not.toHaveBeenCalled();
    expect(fileSystem.readFile).not.toHaveBeenCalled();
    expect(readFileSync(path).equals(before.content)).toBe(true);
    expect(statSync(path).mtimeMs).toBe(before.mtime);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('CP-036/A8-protected-input-scan inspect rejects a protected substitution with colliding numeric file IDs before reading', async () => {
  const { readCredential } = await input();
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'cp036-input-identity-'));
  const ordinary = join(dir, 'ordinary.txt');
  const protectedTarget = join(dir, 'seeds.txt');
  const ordinaryId = 9007199254740992n;
  const protectedId = ordinaryId + 1n;
  const harmless = Buffer.from('aa');
  try {
    writeFileSync(ordinary, harmless);
    writeFileSync(protectedTarget, 'harmless protected target content\n');
    expect(ordinaryId).not.toBe(protectedId);
    expect(Number(ordinaryId)).toBe(Number(protectedId));

    // The same model answers ordinary and bigint stat calls without rounding bigint IDs.
    let substituted = false;
    const metadata = async (path: string, options?: { bigint?: boolean }, link = false) => {
      const isLink = link && path === ordinary && substituted;
      const target = path === ordinary && substituted && !isLink ? protectedTarget : path;
      const value = await fs.stat(target, options as never);
      const id = isLink ? protectedId + 1n : target === protectedTarget ? protectedId : ordinaryId;
      return Object.assign(value, {
        dev: options?.bigint ? 41n : 41,
        ino: options?.bigint ? id : Number(id),
        isFile: () => !isLink,
        isSymbolicLink: () => isLink,
      });
    };
    const contentRead = vi.fn(async () => Buffer.from('harmless protected target content\n'));
    const close = vi.fn(async () => {});
    const fileSystem = {
      ...fs,
      stat: vi.fn(async (path: string, options?: { bigint?: boolean }) =>
        metadata(String(path), options)),
      lstat: vi.fn(async (path: string, options?: { bigint?: boolean }) =>
        metadata(String(path), options, true)),
      realpath: vi.fn(async (path: string) =>
        String(path) === ordinary && substituted ? protectedTarget : String(path)),
      open: vi.fn(async () => {
        substituted = true;
        return { stat: (options?: { bigint?: boolean }) => metadata(protectedTarget, options),
          readFile: contentRead, close };
      }),
      readFile: vi.fn(async () => { throw new Error('path read bypassed the owned handle'); }),
    } as unknown as typeof fs;

    expect((await fileSystem.stat(ordinary)).ino).toBe(Number(ordinaryId));
    expect((await fileSystem.stat(ordinary, { bigint: true })).ino).toBe(ordinaryId);

    const normal = await readCredential(ordinary,
      { stdin: Readable.from([]), fs }, { unsafeArg: false });
    expect(Buffer.from(revealSecret(normal.secret)).equals(Buffer.from([0xaa]))).toBe(true);
    const literal = await readCredential('aa',
      { stdin: Readable.from([]), fs }, { unsafeArg: true });
    expect(literal.literal).toBe(true);
    expect(Buffer.from(revealSecret(literal.secret)).equals(Buffer.from([0xaa]))).toBe(true);
    const protectedError = await rejection(() => readCredential(protectedTarget,
      { stdin: Readable.from([]), fs: fileSystem }, { unsafeArg: false }));
    expect(protectedError.name).toBe('InputError');
    expect(protectedError.stage).toBe('input-read');
    expect(fileSystem.open).not.toHaveBeenCalled();

    const error = await rejection(() => readCredential(ordinary,
      { stdin: Readable.from([]), fs: fileSystem }, { unsafeArg: false }));
    expect(substituted).toBe(true);
    expect((await fileSystem.stat(ordinary)).ino).toBe(Number(ordinaryId));
    expect((await fileSystem.stat(ordinary, { bigint: true })).ino).toBe(protectedId);
    expect((await fileSystem.lstat(ordinary, { bigint: true })).isSymbolicLink()).toBe(true);
    expect(contentRead).not.toHaveBeenCalled();
    expect(error.name).toBe('InputError');
    expect(error.stage).toBe('input-read');
    expect(String(error)).not.toContain(ordinary);
    expect(String(error)).not.toContain(protectedTarget);
    expect(fileSystem.readFile).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('CP-036/C-stdin-readonly two offline stdin invocations equal file inspect and leave owned inputs unchanged', () => {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'cp036-stdin-'));
  const path = join(dir, 'reference.macaroon');
  const source = bytes();
  try {
    writeFileSync(path, source);
    const before = { names: readdirSync(dir), content: readFileSync(path), mtime: statSync(path).mtimeMs };
    chmodSync(dir, 0o555);
    const invoke = (arg: string, stdin?: Buffer) => spawnSync(process.execPath,
      ['--import', pathToFileURL(join(repo, 'test', 'preloads', 'offline.mjs')).href,
        join(repo, 'dist', 'bin.js'), 'inspect', arg, '--json'],
      { cwd: dir, input: stdin, encoding: 'utf8', timeout: 10_000 });
    const file = invoke(path);
    expect(file.status, file.stderr).toBe(0);
    const fileDoc = JSON.parse(file.stdout);
    for (let attempt = 0; attempt < 2; attempt++) {
      const piped = invoke('-', source);
      expect(piped.status).toBe(0);
      expect(JSON.parse(piped.stdout).result).toEqual(fileDoc.result);
      expect(piped.stderr).toBe('');
    }
    expect(readdirSync(dir)).toEqual(before.names);
    expect(readFileSync(path).equals(before.content)).toBe(true);
    expect(statSync(path).mtimeMs).toBe(before.mtime);
  } finally {
    chmodSync(dir, 0o700);
    rmSync(dir, { recursive: true, force: true });
  }
});
