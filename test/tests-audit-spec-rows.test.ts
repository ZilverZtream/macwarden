import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import { withCancellation } from '../src/cancellation.js';
import { run as reconcileRun } from '../src/commands/reconcile.js';
import { run as respondRun } from '../src/commands/respond.js';
import { run as verifyRun } from '../src/commands/verify.js';
import { run as watchRun, type Register } from '../src/commands/watch.js';
import { decodeNwc } from '../src/decode/index.js';
import type { LndAdapter } from '../src/lnd/index.js';
import { openRegistry, REGISTRY_FILE_LIMIT } from '../src/registry/index.js';
import { locateRepository } from '../src/scan/git-history.js';
import { Secret } from '../src/secret.js';
import snapshot from '../src/grade/lnd-permissions.json' with { type: 'json' };
import { adapter } from './helpers/adapter.js';
import { entry as onlineEntry, fixture, ownId, register as registerBytes, responseBytes, vector as onlineVector } from './helpers/cp038-online.js';
import { writeOwnerOnly } from './helpers/owner-only-fixture.js';
import { NODE, openJournal } from './helpers/payment-journal.js';

// Audit 1.4.0 (tests/spec-coverage.md): docs/spec.md rules that no test exercised. Each case
// is a refusal (or its boundary) with the exact exit code and step the spec names.
const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP!;
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function scratch(prefix: string): string {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, prefix));
  dirs.push(dir);
  return dir;
}
const vectorBytes = (name: string) => readFileSync(join(repo, 'test/vectors', `${name}.macaroon`));

// --- watch -----------------------------------------------------------------------------------

/** A watch tree: an owner-only registry, a certificate file and the default admin as own macaroon. */
async function watchTree(canary?: string | 'directory') {
  const dir = scratch('tests-audit-watch-');
  const registry = join(dir, 'registry.json');
  await writeOwnerOnly(registry, JSON.stringify({ schema: 1, entries: [] }));
  if (canary === 'directory') mkdirSync(`${registry}.canary.json`);
  else if (canary !== undefined) await writeOwnerOnly(`${registry}.canary.json`, canary);
  writeFileSync(join(dir, 'tls.cert'), 'not used by the fake adapter');
  await writeOwnerOnly(join(dir, 'own.macaroon'), vectorBytes('default-admin'));
  return { dir, registry, args: ['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', registry] };
}

function watchDeps(overrides: Record<string, unknown> = {}) {
  const calls: string[] = [];
  const register = (() => {
    calls.push('register');
    // A session that ends at once without registering: watch gives up after its attempts.
    return { ended: Promise.resolve({ registered: false, code: 4, stage: 'middleware-stream', message: 'injected', disabled: false }),
      close: () => undefined };
  }) as unknown as Register;
  const deps = {
    lnd: { getInfo: async () => { calls.push('GetInfo'); return { pubkey: NODE, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }; } } as never,
    register, fs, env: {} as Record<string, string>, clock: () => new Date('2026-10-08T12:00:00Z'), emit: () => undefined,
    alert: async () => undefined, sleep: async () => undefined, hostname: () => hostname(), pid: process.pid, ...overrides,
  };
  return { calls, deps };
}

describe('TESTS-AUDIT/watch W1 request rules', () => {
  // A request that passes W1 reaches the ENV step, which this unsafe setting refuses at W2.
  const unsafe = { env: { NODE_DEBUG: 'tls' } };
  it.each(['abcd', 'a'.repeat(49), 'bad name', 'bad/name', 'café-watch', ''])(
    'TESTS-AUDIT/watch --middleware-name %j is refused at W1 with exit 2', async name => {
      const tree = await watchTree();
      const { calls, deps } = watchDeps(unsafe);
      const result = await watchRun([...tree.args, '--middleware-name', name], deps as never);
      expect(result.error).toEqual({ code: 2, step: 'W1', message: '--middleware-name must be 5-48 letters, digits, dot, underscore or dash' });
      expect(calls).toEqual([]);
    });
  it.each(['abcde', 'a'.repeat(48), 'A.b_c-9'])('TESTS-AUDIT/watch --middleware-name %j passes W1', async name => {
    const tree = await watchTree();
    const { deps } = watchDeps(unsafe);
    expect((await watchRun([...tree.args, '--middleware-name', name], deps as never)).error).toMatchObject({ code: 2, step: 'W2' });
  });
  it('TESTS-AUDIT/watch --until 1000000s is refused at W1 and 999999s passes', async () => {
    const tree = await watchTree();
    const { deps } = watchDeps(unsafe);
    expect((await watchRun([...tree.args, '--until', '1000000s'], deps as never)).error).toEqual({ code: 2, step: 'W1',
      message: '--until must be a whole number followed by s, m, h or d' });
    expect((await watchRun([...tree.args, '--until', '999999s'], deps as never)).error).toMatchObject({ code: 2, step: 'W2' });
  });
  it('TESTS-AUDIT/watch a relative --alert-command is refused at W1', async () => {
    const tree = await watchTree();
    const { deps } = watchDeps(unsafe);
    expect((await watchRun([...tree.args, '--alert-command', process.platform === 'win32' ? 'alert.exe' : 'alert'], deps as never)).error)
      .toEqual({ code: 2, step: 'W1', message: '--alert-command must be an absolute path to an executable' });
  });
});

describe('TESTS-AUDIT/watch W4 registry and canary configuration', () => {
  it('TESTS-AUDIT/watch a registry path that is a directory exits 3 at W4 before LND', async () => {
    const tree = await watchTree();
    const registry = join(tree.dir, 'as-directory.json');
    mkdirSync(registry);
    const { calls, deps } = watchDeps();
    const args = [...tree.args.slice(0, -1), registry];
    expect((await watchRun(args, deps as never)).error).toEqual({ code: 3, step: 'W4', message: 'unreadable or invalid registry' });
    expect(calls).toEqual([]);
  });
  it('TESTS-AUDIT/watch an invalid registry exits 3 at W4 before LND', async () => {
    const tree = await watchTree();
    rmSync(tree.registry);
    await writeOwnerOnly(tree.registry, '{"schema":1,"entries":');
    const { calls, deps } = watchDeps();
    expect((await watchRun(tree.args, deps as never)).error).toEqual({ code: 3, step: 'W4', message: 'unreadable or invalid registry' });
    expect(calls).toEqual([]);
  });
  it.each([['invalid JSON', '{"schema":1,'], ['a directory', 'directory']])(
    'TESTS-AUDIT/watch a canary configuration that is %s exits 3 at W4 before LND', async (_kind, content) => {
      const tree = await watchTree(content);
      const { calls, deps } = watchDeps();
      expect((await watchRun(tree.args, deps as never)).error).toEqual({ code: 3, step: 'W4',
        message: 'unreadable or invalid canary configuration' });
      expect(calls).toEqual([]);
    });
});

describe('TESTS-AUDIT/watch payment journal path rules (spec: a symlink is refused, exit 3 at W6)', () => {
  // A directory junction on Windows (no symlink privilege needed), a directory symlink elsewhere:
  // lstat reports both as symbolic links.
  const link = (target: string, path: string) => symlinkSync(target, path, 'junction');

  it('TESTS-AUDIT/watch a journal path that is a link exits 3 at W6 and registers nothing', async () => {
    const tree = await watchTree();
    const target = join(tree.dir, 'elsewhere');
    mkdirSync(target);
    const journal = join(tree.dir, 'payments.journal');
    link(target, journal);
    const { calls, deps } = watchDeps();
    const result = await watchRun([...tree.args, '--payment-journal', journal], deps as never);
    expect(result.error).toMatchObject({ code: 3, step: 'W6' });
    expect(calls).toEqual(['GetInfo']);
    expect(existsSync(`${tree.registry}.watch.lock`)).toBe(false);
  });

  it('TESTS-AUDIT/watch a journal lock path that is a link exits 3 at W6 and registers nothing', async () => {
    const tree = await watchTree();
    const target = join(tree.dir, 'elsewhere');
    mkdirSync(target);
    const journal = join(tree.dir, 'payments.journal');
    link(target, `${journal}.lock`);
    const { calls, deps } = watchDeps();
    const result = await watchRun([...tree.args, '--payment-journal', journal], deps as never);
    expect(result.error).toMatchObject({ code: 3, step: 'W6' });
    expect(calls).toEqual(['GetInfo']);
  });

  it('TESTS-AUDIT/watch a journal path that is a symbolic link to a valid journal exits 3 at W6', async () => {
    const tree = await watchTree();
    const real = join(tree.dir, 'real.journal');
    await (await openJournal(real)).close();
    const journal = join(tree.dir, 'payments.journal');
    // The file system as it is with a symbolic link at `journal` naming `real` (portable: no
    // symlink privilege): lstat sees the link, realpath and every open follow it.
    const same = (path: unknown) => resolve(String(path)) === resolve(journal);
    const io = { ...fs,
      lstat: (async (path: string, ...rest: unknown[]) => {
        const meta = await (fs.lstat as (...args: unknown[]) => Promise<import('node:fs').Stats>)(same(path) ? real : path, ...rest);
        return same(path) ? Object.assign(Object.create(Object.getPrototypeOf(meta)), meta,
          { isFile: () => false, isSymbolicLink: () => true }) : meta;
      }) as typeof fs.lstat,
      realpath: (async (path: string, ...rest: unknown[]) =>
        (fs.realpath as (...args: unknown[]) => Promise<string>)(same(path) ? real : path, ...rest)) as typeof fs.realpath,
      stat: (async (path: string, ...rest: unknown[]) =>
        (fs.stat as (...args: unknown[]) => Promise<unknown>)(same(path) ? real : path, ...rest)) as typeof fs.stat,
      open: (async (path: string, ...rest: unknown[]) =>
        (fs.open as (...args: unknown[]) => Promise<unknown>)(same(path) ? real : path, ...rest)) as typeof fs.open,
    } as typeof fs;
    const { calls, deps } = watchDeps({ fs: io });
    const result = await watchRun([...tree.args, '--payment-journal', journal], deps as never);
    expect(result.error).toMatchObject({ code: 3, step: 'W6' });
    expect(calls).toEqual(['GetInfo']);
  });
});

// --- respond -----------------------------------------------------------------------------------

describe('TESTS-AUDIT/respond P1 and P6', () => {
  function staging() {
    const f = fixture();
    f.lnd.ids = [0n, ownId, BigInt(f.old.rootKeyId)];
    // Not a TTY and no --yes: a request that passes P6 stops at P7 (exit 6) before anything is baked.
    f.deps.stdin = Object.assign(Readable.from([]), { isTTY: false });
    return f;
  }
  const mutations = (f: ReturnType<typeof fixture>) => f.lnd.calls.filter(call => call === 'BakeMacaroon' || call === 'DeleteMacaroonID');

  it.each([['--out-dir', 'x'], ['--allow-admin']])('TESTS-AUDIT/respond --finish with %s is refused at P1 with exit 2', async (...extra) => {
    const f = staging();
    const args = extra[0] === '--out-dir' ? ['--out-dir', join(f.dir, 'out')] : ['--allow-admin'];
    expect((await respondRun(['--finish', ...args, ...f.flags], f.deps as never)).error).toEqual({ code: 2, step: 'P1',
      message: '--finish takes neither --out-dir nor --allow-admin' });
    expect(f.lnd.calls).toEqual([]);
  });

  it('TESTS-AUDIT/respond a missing --out-dir is created owner-only (0700) before the confirmation', async () => {
    const f = staging();
    const outDir = join(f.dir, 'replacements');
    expect((await respondRun(['--out-dir', outDir, ...f.flags], f.deps as never)).error).toMatchObject({ code: 6, step: 'P7' });
    expect(statSync(outDir).isDirectory()).toBe(true);
    // Mode bits are what POSIX enforces; Windows ignores them (the directory holds only owner-only files).
    if (process.platform !== 'win32') expect(statSync(outDir).mode & 0o777).toBe(0o700);
    expect(mutations(f)).toEqual([]);
  });

  it('TESTS-AUDIT/respond an --out-dir that is a regular file exits 3 at P6', async () => {
    const f = staging();
    const outDir = join(f.dir, 'a-file');
    writeFileSync(outDir, 'not a directory');
    expect((await respondRun(['--out-dir', outDir, ...f.flags], f.deps as never)).error).toMatchObject({ code: 3, step: 'P6',
      message: 'output path is not a directory' });
    expect(mutations(f)).toEqual([]);
  });

  it('TESTS-AUDIT/respond a protected --out-dir exits 3 at P6 and is never created', async () => {
    const f = staging();
    const outDir = join(f.dir, 'seed');
    expect((await respondRun(['--out-dir', outDir, ...f.flags], f.deps as never)).error).toMatchObject({ code: 3, step: 'P6',
      message: 'protected output directory' });
    expect(existsSync(outDir)).toBe(false);
    expect(mutations(f)).toEqual([]);
  });
});

// --- verify ----------------------------------------------------------------------------------

describe('TESTS-AUDIT/verify C5 and cancellation', () => {
  const own = registerBytes(responseBytes(ownId, onlineVector('default-admin').permissions));
  function fake(onInfo?: () => void) {
    const calls: string[] = [];
    const lnd = adapter({
      getInfo: async () => { calls.push('GetInfo'); onInfo?.(); return { pubkey: NODE, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }; },
      listPermissions: async () => { calls.push('ListPermissions'); return snapshot.methods as Record<string, string[]>; },
      listMacaroonIds: async () => { calls.push('ListMacaroonIDs'); return [0n, ownId]; },
      checkMacaroon: async () => { calls.push('CheckMacaroonPermissions'); return { valid: true as const }; },
    });
    return { calls, lnd };
  }
  const args = (registry: string) => [resolve('test/vectors/default-readonly.macaroon'), '--registry', registry, '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', own];
  const deps = (lnd: LndAdapter) => ({ lnd, fs: { ...fs }, env: {}, clock: () => new Date('2026-10-04T00:00:00Z'),
    stdin: Object.assign(Readable.from([]), { isTTY: true }) });

  it.each(['invalid', 'directory'])('TESTS-AUDIT/verify an %s registry exits 3 at C5 before LND', async kind => {
    const dir = scratch('tests-audit-verify-');
    const registry = join(dir, 'registry.json');
    if (kind === 'directory') mkdirSync(registry); else writeFileSync(registry, '{"schema":1,"entries":[{}]}', { mode: 0o600 });
    const { calls, lnd } = fake();
    expect((await verifyRun(args(registry), deps(lnd))).error).toEqual({ code: 3, step: 'C5', message: 'unreadable or invalid registry' });
    expect(calls).toEqual([]);
  });

  it('TESTS-AUDIT/verify an interrupt while LND answers exits 6 at cancelled', async () => {
    const dir = scratch('tests-audit-verify-');
    const registry = join(dir, 'registry.json');
    writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }), { mode: 0o600 });
    const controller = new AbortController();
    const { calls, lnd } = fake(() => controller.abort());
    const result = await withCancellation(controller.signal, () => verifyRun(args(registry), deps(lnd)));
    expect(result.error).toEqual({ code: 6, step: 'cancelled', message: 'interrupted' });
    expect(calls).not.toContain('CheckMacaroonPermissions');
  });
});

// --- reconcile -------------------------------------------------------------------------------

describe('TESTS-AUDIT/reconcile Q1 relative windows and cancellation', () => {
  function tree() {
    const dir = scratch('tests-audit-reconcile-');
    writeFileSync(join(dir, 'tls.cert'), 'not used by the fake adapter');
    writeFileSync(join(dir, 'own.macaroon'), vectorBytes('default-readonly'));
    const registry = join(dir, 'registry.json');
    writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }));
    const journal = join(dir, 'payments.journal');
    writeFileSync(journal, `${JSON.stringify({ v: 1, type: 'run-start', time: '2026-10-09T10:00:00.000Z',
      run: '11111111-2222-4333-8444-555555555555', node: NODE, version: '1.2.0', repairedTail: false })}\n`);
    return ['--payment-journal', journal, '--lnd-rest', 'localhost:8080', '--tls-cert', join(dir, 'tls.cert'),
      '--macaroon', join(dir, 'own.macaroon'), '--registry', registry];
  }
  function lnd(onInfo?: () => void): LndAdapter {
    const unexpected = (): never => { throw new Error('unexpected adapter call'); };
    return { getInfo: async () => { onInfo?.(); return { pubkey: NODE, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }; },
      listPermissions: async () => snapshot.methods as Record<string, string[]>, listMacaroonIds: unexpected, bakeMacaroon: unexpected,
      deleteMacaroonId: unexpected, checkMacaroon: unexpected,
      listPayments: async () => ({ payments: [], lastIndexOffset: 0n }), trackPayment: async () => null } as unknown as LndAdapter;
  }
  const deps = (adapter: LndAdapter) => ({ lnd: adapter, fs, env: {}, clock: () => new Date('2026-10-09T12:00:00.000Z') });
  const SINCE = '--since must be a UTC time (YYYY-MM-DDThh:mm:ssZ) or <n>(m|h|d) before now';

  it.each([['--since', '0h'], ['--since', '1000000m'], ['--until', '0d'], ['--until', '1000000h']])(
    'TESTS-AUDIT/reconcile %s %s is refused at Q1 with exit 2', async (flag, value) => {
      expect((await reconcileRun([...tree(), flag, value], deps(lnd()) as never)).error).toEqual({ code: 2, step: 'Q1',
        message: flag === '--since' ? SINCE : SINCE.replace('--since', '--until') });
    });
  it('TESTS-AUDIT/reconcile --since 999999m and 1m pass Q1', async () => {
    for (const value of ['999999m', '1m']) {
      const output = await reconcileRun([...tree(), '--since', value], deps(lnd()) as never);
      expect(output.error?.step ?? null, value).not.toBe('Q1');
    }
  });
  it('TESTS-AUDIT/reconcile an interrupt while LND answers exits 6 at cancelled', async () => {
    const controller = new AbortController();
    const output = await withCancellation(controller.signal, () => reconcileRun(tree(), deps(lnd(() => controller.abort())) as never));
    expect(output.error).toEqual({ code: 6, step: 'cancelled', message: 'operation interrupted; nothing was changed' });
  });
});

// --- registry --------------------------------------------------------------------------------

describe('TESTS-AUDIT/registry read rules', () => {
  it.each(['revoked-later', 'REJECTED', ''])('TESTS-AUDIT/registry revokeEvidence %j is refused on read with exit 3', async evidence => {
    const dir = scratch('tests-audit-registry-');
    const path = join(dir, 'registry.json');
    const row = { ...onlineEntry(4294967341n), status: 'revoked', revokedAt: '2026-10-05T12:00:00Z', revokeEvidence: evidence };
    await writeOwnerOnly(path, JSON.stringify({ schema: 1, entries: [row] }));
    await expect(openRegistry(path)).rejects.toMatchObject({ name: 'RegistryInputError', code: 3 });
    // The same row with a valid value opens.
    rmSync(path);
    await writeOwnerOnly(path, JSON.stringify({ schema: 1, entries: [{ ...row, revokeEvidence: 'rejected' }] }));
    expect((await openRegistry(path)).entries).toHaveLength(1);
  });

  it('TESTS-AUDIT/registry a registry file of 64 MiB + 1 byte is refused on read with exit 3', async () => {
    expect(REGISTRY_FILE_LIMIT).toBe(67_108_864);
    const dir = scratch('tests-audit-registry-');
    const path = join(dir, 'registry.json');
    const body = JSON.stringify({ schema: 1, entries: [] });
    await writeOwnerOnly(path, body + ' '.repeat(67_108_865 - body.length));
    await expect(openRegistry(path)).rejects.toMatchObject({ name: 'RegistryInputError', code: 3 });
  }, 60_000);
});

// --- NWC -------------------------------------------------------------------------------------

it('TESTS-AUDIT/nwc a lud16 of 320 characters decodes and one of 321 is refused at nwc-lud16', () => {
  // Synthetic NIP-47 connection: random keys per run, never real.
  const uri = (lud16: string) => new Secret(Buffer.from(`nostr+walletconnect://${randomBytes(32).toString('hex')}?relay=wss%3A%2F%2Fr.example.com`
    + `&secret=${randomBytes(32).toString('hex')}&lud16=${encodeURIComponent(lud16)}`, 'utf8'));
  const address = (length: number) => `${'a'.repeat(length - '@example.com'.length)}@example.com`;
  expect(decodeNwc(uri(address(320))).lud16).toBe(address(320));
  let refused: unknown;
  try { decodeNwc(uri(address(321))); } catch (error) { refused = error; }
  expect(refused).toMatchObject({ name: 'DecodeError', code: 3, stage: 'nwc-lud16' });
});

// --- git history repository locations --------------------------------------------------------

describe('TESTS-AUDIT/git-history location bounds (checked before any git process starts)', () => {
  /** A work tree whose .git holds `alternates` chained `levels` deep through sibling objects directories. */
  function alternatesChain(levels: number): string {
    const dir = scratch('tests-audit-githist-');
    const objects = (index: number) => index === 0 ? join(dir, 'work', '.git', 'objects') : join(dir, `objects-${index}`);
    mkdirSync(join(dir, 'work', '.git', 'objects', 'info'), { recursive: true });
    for (let index = 0; index <= levels; index++) mkdirSync(join(objects(index), 'info'), { recursive: true });
    for (let index = 0; index < levels; index++) writeFileSync(join(objects(index), 'info', 'alternates'), `${objects(index + 1)}\n`);
    return join(dir, 'work');
  }
  /** A work tree whose .git/config includes a chain of `levels` config files. */
  function includeChain(levels: number): string {
    const dir = scratch('tests-audit-githist-');
    mkdirSync(join(dir, 'work', '.git', 'objects'), { recursive: true });
    const config = (index: number) => index === 0 ? join(dir, 'work', '.git', 'config') : join(dir, `include-${index}.cfg`);
    for (let index = 0; index <= levels; index++)
      writeFileSync(config(index), index < levels ? `[include]\n\tpath = ${config(index + 1).replace(/\\/g, '/')}\n` : '[core]\n');
    return join(dir, 'work');
  }
  const UNREADABLE = 'git history could not be read';

  it('TESTS-AUDIT/git-history alternates nested 5 levels are followed and 6 levels are refused', async () => {
    await expect(locateRepository(alternatesChain(5))).resolves.toMatchObject({ workTree: expect.any(String) });
    await expect(locateRepository(alternatesChain(6))).rejects.toMatchObject({ name: 'GitHistoryError', message: UNREADABLE });
  });

  it('TESTS-AUDIT/git-history includes nested 10 levels are followed and 11 levels are refused', async () => {
    await expect(locateRepository(includeChain(10))).resolves.toMatchObject({ workTree: expect.any(String) });
    await expect(locateRepository(includeChain(11))).rejects.toMatchObject({ name: 'GitHistoryError', message: UNREADABLE });
  });

  it('TESTS-AUDIT/git-history a location file of 64 KiB is read and one of 64 KiB + 1 byte is refused', async () => {
    const sized = (size: number) => {
      const work = alternatesChain(0);
      const comment = '#'.repeat(size - 1) + '\n';
      writeFileSync(join(work, '.git', 'objects', 'info', 'alternates'), comment);
      return work;
    };
    await expect(locateRepository(sized(65_536))).resolves.toMatchObject({ workTree: expect.any(String) });
    await expect(locateRepository(sized(65_537))).rejects.toMatchObject({ name: 'GitHistoryError' });
  });
});
