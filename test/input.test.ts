import { revealSecret } from './helpers/secret-bytes.js';
import { spawnSync } from 'node:child_process';
import { constants, readFileSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { inspect } from 'node:util';
import { expect, it, vi } from 'vitest';
import { Secret } from '../src/secret.js';
import { decodeMacaroon } from '../src/decode/index.js';

const networkCalls = vi.hoisted(() => [] as string[]);
vi.mock('node:https', async importOriginal => {
  const original = await importOriginal<typeof import('node:https') & { default: typeof import('node:https') }>();
  const blocked = () => { networkCalls.push('https'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked,
    default: { ...original.default, request: blocked, get: blocked } };
});
vi.mock('node:http', async importOriginal => {
  const original = await importOriginal<typeof import('node:http') & { default: typeof import('node:http') }>();
  const blocked = () => { networkCalls.push('http'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked,
    default: { ...original.default, request: blocked, get: blocked } };
});
vi.mock('node:net', async importOriginal => {
  const original = await importOriginal<typeof import('node:net') & { default: typeof import('node:net') }>();
  const blocked = () => { networkCalls.push('net'); throw new Error('network called'); };
  return { ...original, connect: blocked, createConnection: blocked,
    default: { ...original.default, connect: blocked, createConnection: blocked } };
});

type InputModule = {
  readCredential: (arg: string, io: { stdin: Readable; fs: CredentialFs },
    opts: { unsafeArg: boolean }) => Promise<{ secret: Secret; literal: boolean }>;
};
type CredentialFs = Pick<typeof fs, 'stat' | 'lstat' | 'realpath' | 'open' | 'readFile'>;
const input = (): Promise<InputModule> => import(/* @vite-ignore */ '../src/input/index.js') as Promise<InputModule>;
const repo = resolve();
const vector = (name: string) => readFileSync(join(repo, 'test/vectors', `${name}.macaroon`));
const sameBytes = (actual: Secret, expected: Buffer) => Buffer.from(revealSecret(actual)).equals(expected);
const stdin = (data?: Buffer | string): Readable => Readable.from(data === undefined ? [] : [data]);
const io = (data?: Buffer | string, fileSystem: CredentialFs = fs) => ({ stdin: stdin(data), fs: fileSystem });
const refusal = 'pass a file path or - (stdin); literal credentials end up in shell history and process listings';

function inTemp<T>(action: (dir: string) => Promise<T>): Promise<T> {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'cp006-input-'));
  return action(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function fileForms(bytes: Buffer): Array<[string, Buffer]> {
  const hex = bytes.toString('hex');
  const b64 = bytes.toString('base64');
  const url = bytes.toString('base64url');
  const wrapped = b64.match(/.{1,76}/g)?.join('\n') || b64;
  const hexWrapped = hex.match(/.{1,76}/g)?.join('\r\n') || hex;
  const uri = `lndconnect://h:10009?cert=AAAA&macaroon=${url}`;
  const utf16be = Buffer.from(`\ufeff${hex}`, 'utf16le');
  for (let at = 0; at + 1 < utf16be.length; at += 2) [utf16be[at], utf16be[at + 1]] = [utf16be[at + 1], utf16be[at]];
  return [
    ['binary', bytes], ['hex-lf', Buffer.from(`${hex}\n`)],
    ['hex-upper-prefix', Buffer.from(`0x${hex.toUpperCase()}`)],
    ['base64-padded', Buffer.from(b64)], ['base64-unpadded', Buffer.from(b64.replace(/=+$/, ''))],
    ['base64url-padded', Buffer.from(b64.replace(/\+/g, '-').replace(/\//g, '_'))],
    ['base64url-unpadded', Buffer.from(url)], ['base64-wrapped', Buffer.from(wrapped)],
    ['utf8-bom-hex', Buffer.from(`\ufeff${hex}`)], ['utf16le-bom-base64', Buffer.from(`\ufeff${b64}`, 'utf16le')],
    ['utf16be-bom-hex', utf16be], ['hex-crlf', Buffer.from(hexWrapped)], ['lndconnect', Buffer.from(uri)],
  ];
}

async function caught(work: () => Promise<unknown>): Promise<Error & { stage?: string }> {
  try { await work(); } catch (error) {
    expect(error instanceof Error).toBe(true);
    return error as Error & { stage?: string };
  }
  throw new Error('Expected input rejection');
}
function checkError(error: Error & { stage?: string }, name: string, stage?: string, message?: string): void {
  expect(error.name).toBe(name);
  if (stage) expect(error.stage).toBe(stage);
  if (message) expect(error.message).toBe(message);
}

function protectedFs(resolvedPath: string, symlink: boolean) {
  const file = { dev: 1, ino: 10, isFile: () => true, isDirectory: () => false, isSymbolicLink: () => symlink };
  return {
    stat: vi.fn(async () => file) as unknown as typeof fs.stat,
    lstat: vi.fn(async () => file) as unknown as typeof fs.lstat,
    realpath: vi.fn(async () => resolvedPath) as unknown as typeof fs.realpath,
    open: vi.fn(async () => { throw new Error('protected file open attempted'); }) as unknown as typeof fs.open,
    readFile: vi.fn(async () => { throw new Error('protected file read attempted'); }) as unknown as typeof fs.readFile,
  };
}

function swappedFs(ordinary: string, protectedTarget: string) {
  let swapped = false;
  let protectedReads = 0;
  const ordinaryMeta = { dev: 1, ino: 10, isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false };
  const protectedMeta = { dev: 1, ino: 11, isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false };
  const linkMeta = { ...protectedMeta, isFile: () => false, isSymbolicLink: () => true };
  const blockedRead = vi.fn(async () => {
    swapped = true;
    protectedReads++;
    throw new Error('swapped target content read attempted');
  });
  const fileSystem = {
    stat: vi.fn(async () => swapped ? protectedMeta : ordinaryMeta) as unknown as typeof fs.stat,
    lstat: vi.fn(async () => swapped ? linkMeta : ordinaryMeta) as unknown as typeof fs.lstat,
    realpath: vi.fn(async () => {
      if (!swapped) { swapped = true; return ordinary; }
      return protectedTarget;
    }) as unknown as typeof fs.realpath,
    open: vi.fn(async (_path: unknown, flags: string | number) => {
      swapped = true;
      if (typeof flags === 'number' && (flags & constants.O_NOFOLLOW) !== 0) {
        throw Object.assign(new Error('symlink refused'), { code: 'ELOOP' });
      }
      return { fd: 42, stat: async () => protectedMeta, readFile: blockedRead,
        read: blockedRead, readv: blockedRead, close: async () => {} };
    }) as unknown as typeof fs.open,
    readFile: vi.fn(async (_path: unknown, options?: { flag?: string | number }) => {
      swapped = true;
      if (typeof options?.flag === 'number' && (options.flag & constants.O_NOFOLLOW) !== 0) {
        throw Object.assign(new Error('symlink refused'), { code: 'ELOOP' });
      }
      return blockedRead();
    }) as unknown as typeof fs.readFile,
  };
  return { fileSystem, swapped: () => swapped, protectedReads: () => protectedReads };
}

function eaccesFs(file: string) {
  const boundedRead = vi.fn(async () => {
    throw Object.assign(new Error('permission denied'), { code: 'EACCES' });
  });
  const unboundedRead = vi.fn(async () => { throw new Error('unbounded read attempted'); });
  const close = vi.fn(async () => {});
  const fileSystem: CredentialFs = {
    stat: fs.stat,
    lstat: fs.lstat,
    realpath: fs.realpath,
    open: vi.fn(async () => ({ stat: (options?: { bigint?: boolean }) => fs.stat(file, options), read: boundedRead,
      readFile: unboundedRead, close })) as unknown as typeof fs.open,
    readFile: unboundedRead as unknown as typeof fs.readFile,
  };
  return { fileSystem, boundedRead, unboundedRead, close };
}

function protectedPathCases(dir: string) {
  return [
    { supplied: join(dir, 'MaCaRoOnS.Db'), resolved: join(dir, 'MaCaRoOnS.Db'), symlink: false },
    { supplied: join(dir, 'wallet-password.txt'), resolved: join(dir, 'wallet-password.txt'), symlink: false },
    { supplied: join(dir, 'seed.txt'), resolved: join(dir, 'seed.txt'), symlink: false },
    { supplied: join(dir, 'TLS.KEY'), resolved: join(dir, 'TLS.KEY'), symlink: false },
    { supplied: join(dir, 'macaroons.db', 'input.mac'), resolved: join(dir, 'macaroons.db', 'input.mac'), symlink: false },
    { supplied: join(dir, 'ordinary.mac'), resolved: join(dir, 'private', 'MaCaRoOnS.Db'), symlink: true },
    { supplied: join(dir, 'linked.mac'), resolved: join(dir, 'private', 'tls.key', 'input.mac'), symlink: true },
  ];
}

it('CP-006/B1 every file form decodes readonly, invoice and maximum root ID bytes', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    for (const name of ['default-readonly', 'default-invoice', 'root-max']) {
      const original = vector(name);
      for (const [form, content] of fileForms(original)) {
        const path = join(dir, `${name}-${form}`);
        writeFileSync(path, content);
        const result = await readCredential(path, io(), { unsafeArg: false });
        expect(sameBytes(result.secret, original), `${name}/${form}`).toBe(true);
        expect(result.literal, `${name}/${form}`).toBe(false);
      }
    }
  });
});

it('CP-006/B1 an ordinary file reads through the complete injected filesystem', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    const file = join(dir, 'ordinary.mac');
    const original = vector('default-readonly');
    writeFileSync(file, original);
    const fileSystem: CredentialFs = {
      stat: vi.fn(fs.stat) as unknown as typeof fs.stat, lstat: vi.fn(fs.lstat) as unknown as typeof fs.lstat, realpath: vi.fn(fs.realpath) as unknown as typeof fs.realpath,
      open: vi.fn(fs.open) as unknown as typeof fs.open, readFile: vi.fn(fs.readFile) as unknown as typeof fs.readFile,
    };
    const result = await readCredential(file, io(undefined, fileSystem), { unsafeArg: false });
    expect(sameBytes(result.secret, original)).toBe(true);
    expect(result.literal).toBe(false);
    expect(vi.mocked(fileSystem.readFile).mock.calls.length + vi.mocked(fileSystem.open).mock.calls.length).toBeGreaterThan(0);
  });
});

it('CP-006/B2 non-TTY stdin accepts binary and line-ended hex', async () => {
  const { readCredential } = await input();
  const original = vector('default-readonly');
  for (const content of [original, `${original.toString('hex')}\n`]) {
    const result = await readCredential('-', io(content), { unsafeArg: false });
    expect(sameBytes(result.secret, original)).toBe(true);
    expect(result.literal).toBe(false);
  }
});

it('CP-006/B3 unsafe literal forms decode without using network modules', async () => {
  const original = vector('default-invoice');
  const b64 = original.toString('base64');
  const url = original.toString('base64url');
  const forms = [original.toString('hex'), b64, url,
    `lndconnect://h:10009?macaroon=${url}`,
    `LNDCONNECT://h:10009?macaroon=${url}`,
    `lndconnect://h:10009?macaroon=${encodeURIComponent(url)}`];
  networkCalls.length = 0;
  const { readCredential } = await input();
  for (const form of forms) {
    const result = await readCredential(form, io(), { unsafeArg: true });
    expect(sameBytes(result.secret, original)).toBe(true);
    expect(result.literal).toBe(true);
  }
  const synthetic = Buffer.concat([
    Buffer.from([0x02, 0x02, 0x01, 0x03, 0x00, 0x00, 0x06, 0x20]),
    Buffer.from([0x00, 0xfb, 0xff, 0xff]), Buffer.alloc(28),
  ]);
  const syntheticBase64 = synthetic.toString('base64');
  expect(syntheticBase64.includes('+')).toBe(true);
  expect(syntheticBase64.includes('/')).toBe(true);
  const syntheticUri = `lndconnect://h:10009?macaroon=${encodeURIComponent(syntheticBase64)}`;
  expect(syntheticUri.includes('%2B')).toBe(true);
  expect(syntheticUri.includes('%2F')).toBe(true);
  const syntheticError = await caught(() => readCredential(syntheticUri, io(), { unsafeArg: true }));
  checkError(syntheticError, 'InputError', 'input-form');
  expect(networkCalls).toHaveLength(0);
});

it('CP-006/B4 non-macaroon base64 is a missing path unless unsafe, then decoder rejects it', async () => {
  const { readCredential } = await input();
  const form = Buffer.from('test').toString('base64url');
  const denied = await caught(() => readCredential(form, io(), { unsafeArg: false }));
  checkError(denied, 'InputError', 'input-read');
  const result = await readCredential(form, io(), { unsafeArg: true });
  expect(result.literal).toBe(true);
  expect(revealSecret(result.secret).equals(Buffer.from('test'))).toBe(true);
  let error: unknown;
  try { decodeMacaroon(result.secret); } catch (caughtError) { error = caughtError; }
  expect((error as { stage?: string } | undefined)?.stage).toBe('v2-header');
});

it('CP-006/B5 an existing hex-named path wins over literal classification', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    const original = vector('default-readonly');
    writeFileSync(join(dir, 'deadbeef'), original.toString('base64'));
    const old = process.cwd();
    try {
      process.chdir(dir);
      const result = await readCredential('deadbeef', io(), { unsafeArg: false });
      expect(result.literal).toBe(false);
      expect(sameBytes(result.secret, original)).toBe(true);
    } finally { process.chdir(old); }
  });
});

it('CP-006/B6 empty and malformed file or stdin forms fail at input-form', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    const malformed = ['', ' \t\r\n ', 'abc', '%%not a macaroon%%',
      'lndconnect://h:1?cert=AAAA', 'lndconnect://h:1?macaroon=AA&macaroon=BB'];
    for (let index = 0; index < malformed.length; index++) {
      const path = join(dir, `malformed-${index}`);
      writeFileSync(path, malformed[index]);
      checkError(await caught(() => readCredential(path, io(), { unsafeArg: false })), 'InputError', 'input-form');
    }
    checkError(await caught(() => readCredential('-', io(), { unsafeArg: false })), 'InputError', 'input-form');
  });
});

it('CP-006/B7 directory and injected EACCES file read fail at input-read', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    const file = join(dir, 'denied');
    writeFileSync(file, vector('default-readonly'));
    checkError(await caught(() => readCredential(dir, io(), { unsafeArg: false })), 'InputError', 'input-read');
    const restricted = eaccesFs(file);
    checkError(await caught(() => readCredential(file, io(undefined, restricted.fileSystem), { unsafeArg: false })), 'InputError', 'input-read');
    expect(restricted.boundedRead).toHaveBeenCalled();
    expect(restricted.unboundedRead).not.toHaveBeenCalled();
    expect(restricted.close).toHaveBeenCalledOnce();
  });
});

it('CP-006/B7 a path swapped to a protected symlink never yields target content', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    const ordinary = join(dir, 'ordinary.mac');
    const target = join(dir, 'private', 'MaCaRoOnS.Db');
    const swapped = swappedFs(ordinary, target);
    const error = await caught(() => readCredential(ordinary, io(undefined, swapped.fileSystem), { unsafeArg: false }));
    checkError(error, 'InputError', 'input-read');
    expect(swapped.swapped()).toBe(true);
    expect(swapped.protectedReads()).toBe(0);
  });
});

it('CP-006/B9 swapped protected paths stay out of error representations', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    const ordinary = join(dir, 'ordinary.mac');
    const target = join(dir, 'private', 'MaCaRoOnS.Db');
    const swapped = swappedFs(ordinary, target);
    const error = await caught(() => readCredential(ordinary, io(undefined, swapped.fileSystem), { unsafeArg: false }));
    checkError(error, 'InputError', 'input-read');
    const output = [error.message, String(error), inspect(error)].join('\n');
    const sentinelDir = join(dir, 'sentinels');
    mkdirSync(sentinelDir);
    writeFileSync(join(sentinelDir, 'ordinary-path'), ordinary);
    writeFileSync(join(sentinelDir, 'target-path'), target);
    const captured = join(dir, 'captured-error');
    writeFileSync(captured, output);
    const run = spawnSync(process.execPath,
      [join(repo, 'scripts/leak-check.mjs'), '--sentinels', join(repo, 'test/sentinels.json'),
        '--sentinel-dir', sentinelDir, captured],
      { cwd: repo, encoding: 'utf8', timeout: 15_000 });
    expect(run.status).toBe(0);
  });
});

it('CP-006/B7 protected files and symlink targets are refused before any read', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    for (const { supplied, resolved, symlink } of protectedPathCases(dir)) {
      const fileSystem = protectedFs(resolved, symlink);
      const error = await caught(() => readCredential(supplied, io(undefined, fileSystem), { unsafeArg: false }));
      checkError(error, 'InputError', 'input-read');
      expect.soft(fileSystem.readFile, supplied).not.toHaveBeenCalled();
      if (symlink) expect.soft(fileSystem.realpath, supplied).toHaveBeenCalled();
    }
  });
});

it('CP-006/B9 protected path errors do not expose supplied paths', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    for (const { supplied, resolved, symlink } of protectedPathCases(dir)) {
      const error = await caught(() => readCredential(supplied, io(undefined, protectedFs(resolved, symlink)), { unsafeArg: false }));
      const output = [error.message, String(error), inspect(error)].join('\n');
      expect(output).not.toContain(supplied);
      const sentinelDir = join(dir, 'protected-sentinel');
      mkdirSync(sentinelDir);
      writeFileSync(join(sentinelDir, 'source'), supplied);
      const captured = join(dir, 'protected-error');
      writeFileSync(captured, output);
      const run = spawnSync(process.execPath,
        [join(repo, 'scripts/leak-check.mjs'), '--sentinels', join(repo, 'test/sentinels.json'),
          '--sentinel-dir', sentinelDir, captured],
        { cwd: repo, encoding: 'utf8', timeout: 15_000 });
      expect(run.status, supplied).toBe(0);
      rmSync(sentinelDir, { recursive: true, force: true });
      rmSync(captured);
    }
  });
});

it('CP-006/B8 TTY stdin is refused promptly without a read', async () => {
  const { readCredential } = await input();
  let reads = 0;
  const terminal = new Readable({ read() { reads++; } }) as Readable & { isTTY: boolean };
  terminal.isTTY = true;
  try {
    const error = await Promise.race([
      caught(() => readCredential('-', { stdin: terminal, fs }, { unsafeArg: false })),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('TTY input hung')), 900)),
    ]);
    checkError(error, 'UsageError');
    expect(reads).toBe(0);
  } finally { terminal.destroy(); }
}, 1500);

it('CP-006/B9 all input rejections remain clean under the standing leak checker', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    const invoice = vector('default-invoice');
    const b64 = invoice.toString('base64');
    const url = invoice.toString('base64url');
    const argCases: Array<[string, boolean]> = [
      [Buffer.from('test').toString('base64url'), false],
      [invoice.toString('hex'), false], [b64, false], [url, false],
      [`lndconnect://h:10009?macaroon=${url}`, false],
      ['lndconnect://h:1?cert=AAAA', false], ['lndconnect://h:1?cert=AAAA', true],
      ['%%not a macaroon%%', false], ['%%not a macaroon%%', true],
      ['admin', false], ['admin', true],
    ];
    const outputs: Array<[string, string]> = [];
    for (const [arg, unsafeArg] of argCases) {
      const error = await caught(() => readCredential(arg, io(), { unsafeArg }));
      outputs.push([arg, [error.message, String(error), inspect(error)].join('\n')]);
    }
    const shortForm = Buffer.from('test').toString('base64url');
    const shortResult = await readCredential(shortForm, io(), { unsafeArg: true });
    let decodeError: unknown;
    try { decodeMacaroon(shortResult.secret); } catch (error) { decodeError = error; }
    expect(decodeError instanceof Error).toBe(true);
    outputs.push([shortForm, [(decodeError as Error).message, String(decodeError), inspect(decodeError)].join('\n')]);
    const files = ['', ' \t\r\n ', 'abc', '%%not a macaroon%%',
      'lndconnect://h:1?cert=AAAA', 'lndconnect://h:1?macaroon=AA&macaroon=BB'];
    for (let index = 0; index < files.length; index++) {
      const path = join(dir, `bad-${index}`);
      writeFileSync(path, files[index]);
      const error = await caught(() => readCredential(path, io(), { unsafeArg: false }));
      outputs.push([files[index], [error.message, String(error), inspect(error)].join('\n')]);
    }
    for (const [arg, stream] of [[dir, io()], ['-', io()]] as const) {
      const error = await caught(() => readCredential(arg, stream, { unsafeArg: false }));
      outputs.push([arg, [error.message, String(error), inspect(error)].join('\n')]);
    }
    const denied = join(dir, 'denied');
    writeFileSync(denied, vector('default-readonly'));
    const restricted = eaccesFs(denied);
    const deniedError = await caught(() => readCredential(denied, io(undefined, restricted.fileSystem), { unsafeArg: false }));
    expect(restricted.boundedRead).toHaveBeenCalled();
    expect(restricted.unboundedRead).not.toHaveBeenCalled();
    expect(restricted.close).toHaveBeenCalledOnce();
    outputs.push([denied, [deniedError.message, String(deniedError), inspect(deniedError)].join('\n')]);
    const tty = new Readable({ read() { /* never yields */ } }) as Readable & { isTTY: boolean };
    tty.isTTY = true;
    try {
      const ttyError = await Promise.race([
        caught(() => readCredential('-', { stdin: tty, fs }, { unsafeArg: false })),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error('TTY input hung')), 900)),
      ]);
      outputs.push(['-', [ttyError.message, String(ttyError), inspect(ttyError)].join('\n')]);
    } finally { tty.destroy(); }
    for (let index = 0; index < outputs.length; index++) {
      const [source, output] = outputs[index];
      if (!source || source === '-' || !source.trim()) continue;
      const sentinel = join(dir, `sentinel-${index}`);
      mkdirSync(sentinel);
      writeFileSync(join(sentinel, 'source'), source);
      const captured = join(dir, `captured-${index}`);
      writeFileSync(captured, output);
      const run = spawnSync(process.execPath,
        [join(repo, 'scripts/leak-check.mjs'), '--sentinels', join(repo, 'test/sentinels.json'),
          '--sentinel-dir', sentinel, captured],
        { cwd: repo, encoding: 'utf8', timeout: 15_000 });
      expect(run.status, `rejection ${index}`).toBe(0);
      rmSync(sentinel, { recursive: true, force: true });
      rmSync(captured);
    }
  });
});

it('CP-006/B10 reading every file form leaves bytes and mtimes unchanged', async () => {
  const { readCredential } = await input();
  await inTemp(async dir => {
    for (const name of ['default-readonly', 'default-invoice', 'root-max']) {
      for (const [form, content] of fileForms(vector(name))) {
        const path = join(dir, `${name}-${form}`);
        writeFileSync(path, content);
        const before = { bytes: readFileSync(path), time: statSync(path).mtimeMs };
        await readCredential(path, io(), { unsafeArg: false });
        expect(readFileSync(path).equals(before.bytes), `${name}/${form}`).toBe(true);
        expect(statSync(path).mtimeMs, `${name}/${form}`).toBe(before.time);
      }
    }
  });
});

it('CP-006/B11 literal refusal and missing-path classification follow unsafe-arg rule', async () => {
  const { readCredential } = await input();
  const invoice = vector('default-invoice');
  const forms = [invoice.toString('hex'), invoice.toString('base64'), invoice.toString('base64url'),
    `lndconnect://h:10009?macaroon=${invoice.toString('base64url')}`,
    'lndconnect://h:1?cert=AAAA'];
  for (const form of forms) {
    checkError(await caught(() => readCredential(form, io(), { unsafeArg: false })), 'UsageError', undefined, refusal);
  }
  for (const form of ['%%not a macaroon%%', 'admin']) {
    checkError(await caught(() => readCredential(form, io(), { unsafeArg: false })), 'InputError', 'input-read', 'no such file');
  }
  for (const form of ['lndconnect://h:1?cert=AAAA', '%%not a macaroon%%', 'admin']) {
    checkError(await caught(() => readCredential(form, io(), { unsafeArg: true })), 'InputError', 'input-form');
  }
});
