import { adapter } from './helpers/adapter.js';
import type { LndAdapter } from '../src/lnd/index.js';
import { LndError } from '../src/errors.js';
import { childEnvironment } from './helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it, vi } from 'vitest';
import { render } from './helpers/render-adversarial.js';
import { findLeaks } from "./helpers/leak-check.js";

// This is the approved command boundary. Keep the import inside each test so a
// missing command makes each behaviour case fail independently before CP-018 code exists.
const commandModule = '../src/commands/inventory.js';
const repo = resolve();
const cert = resolve('test/fixture/wrong-tls.cert');
const own = resolve('test/vectors/default-readonly.macaroon');
const noMacaroonRead = resolve('test/vectors/preset-read-only.macaroon');
const noInfoRead = resolve('test/vectors/grade-uri-add-invoice.macaroon');
const flags = ['--lnd-rest', '127.0.0.1:1', '--tls-cert', cert, '--macaroon', own];

function registryArgs(args: string[]): string[] {
  const testTmp = process.env.MACWARDEN_TEST_TMP;
  if (!testTmp) throw new Error('MACWARDEN_TEST_TMP is required');
  let path: string;
  do { path = join(resolve(testTmp), `cp018-registry-${randomUUID()}.json`); }
  while (existsSync(path));
  return ['--registry', path, ...args];
}
const snapshot = JSON.parse(readFileSync(resolve('src/grade/lnd-permissions.json'), 'utf8')) as {
  methods: Record<string, string[]>;
};

type Envelope = {
  schema: number; command: string | null; ok: boolean;
  warnings: Array<string | { code: string }>;
  result: { node: { alias: string }; rootKeys: Array<{
    rootKeyId: string; inLnd: boolean; flags: string[]; entry: unknown; verify: string;
  }> } | null;
  error: { code: number; step: string | null; message: string } | null;
};

function permissions(methods = snapshot.methods) { return methods; }

function fixture() {
  const calls: string[] = [];
  const lnd = {
    ...adapter({}),
    getInfo: vi.fn(async () => {
      calls.push('GetInfo');
      return { alias: 'alice', version: '0.21.4-beta', pubkey: '02' + 'ab'.repeat(32), network: 'regtest' };
    }),
    listPermissions: vi.fn(async () => {
      calls.push('ListPermissions');
      return permissions();
    }),
    listMacaroonIds: vi.fn(async () => {
      calls.push('ListMacaroonIDs');
      return (['0', '9007199254740993']).map(BigInt);
    }),
  } satisfies LndAdapter;
  const deps = {
    lnd,
    fs: { ...fs, readFile: vi.fn((...args: Parameters<typeof fs.readFile>) => fs.readFile(...args)) },
    env: {} as Record<string, string>,
    clock: () => new Date('2026-10-04T00:00:00.000Z'),
  };
  return { calls, lnd, deps };
}

async function invoke(args: string[], deps: ReturnType<typeof fixture>['deps']): Promise<Envelope> {
  const command = await import(commandModule) as { run: (args: string[], deps: unknown) => Promise<Envelope> };
  expect(typeof command.run).toBe('function');
  const output = await command.run(registryArgs(args), deps);
  expect(output).toMatchObject({ schema: 1, command: 'inventory' });
  expect(output.ok).toBe(output.error === null);
  return output;
}

function codes(result: Envelope) {
  return result.warnings.map(warning => typeof warning === 'string' ? warning : warning.code);
}

function containsCredential(output: string, bytes: Buffer) {
  return [bytes.toString('utf8'), bytes.toString('latin1'), bytes.toString('hex'),
    bytes.toString('hex').toUpperCase(), bytes.toString('base64'),
    bytes.toString('base64url'), bytes.toString('base64').replace(/=+$/, ''),
    bytes.toString('base64url').replace(/=+$/, '')]
    .filter(value => value.length > 0).some(value => output.includes(value));
}

const ownUriMethods = [
  '/lnrpc.Lightning/GetInfo',
  '/lnrpc.Lightning/ListPermissions',
  '/lnrpc.Lightning/ListMacaroonIDs',
] as const;

// Hand-made v2 macaroon wire format: identifier version 3, protobuf nonce,
// decimal storage ID and one "uri" operation with repeated method actions.
// Its throwaway signing key is not an LND root key; this tests offline OWN only.
function handMadeUriMacaroon(methods: readonly string[]): Buffer {
  const varint = (value: number): Buffer => {
    const digits: number[] = [];
    do {
      digits.push((value & 127) | (value >= 128 ? 128 : 0));
      value = Math.floor(value / 128);
    } while (value);
    return Buffer.from(digits);
  };
  const field = (number: number, value: Buffer) =>
    Buffer.concat([varint((number << 3) | 2), varint(value.length), value]);
  const packet = (kind: number, value: Buffer) =>
    Buffer.concat([varint(kind), varint(value.length), value]);
  const operation = Buffer.concat([field(1, Buffer.from('uri')),
    ...methods.map(method => field(2, Buffer.from(method)))]);
  const identifier = Buffer.concat([Buffer.from([3]), field(1, randomBytes(16)),
    field(2, Buffer.from('42018')), field(3, operation)]);
  const signature = createHmac('sha256', randomBytes(32)).update(identifier).digest();
  return Buffer.concat([Buffer.from([2]), packet(1, Buffer.from('lnd')),
    packet(2, identifier), Buffer.from([0, 0]), packet(6, signature)]);
}

async function withHandMadeUriOwn(
  label: string, methods: readonly string[], work: (path: string, bytes: Buffer) => Promise<void>,
) {
  const testTmpValue = process.env.MACWARDEN_TEST_TMP;
  const sentinelDirValue = process.env.MACWARDEN_SENTINEL_DIR;
  if (!testTmpValue || !sentinelDirValue) throw new Error('Leak-test temporary directories are required');
  const testTmp = resolve(testTmpValue);
  const sentinelDir = resolve(sentinelDirValue);
  mkdirSync(testTmp, { recursive: true, mode: 0o700 });
  mkdirSync(sentinelDir, { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(testTmp, 'cp018-uri-own-'));
  try {
    const path = join(dir, 'hand-made.macaroon');
    const bytes = handMadeUriMacaroon(methods);
    writeFileSync(path, bytes, { mode: 0o600 });
    copyFileSync(path, join(sentinelDir, `cp018-uri-own-${label}.macaroon`));
    await work(path, bytes);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

it.each([
  ['REST', 'MACWARDEN_LND_REST', '--lnd-rest', 'invalid-port:abc', '127.0.0.1:1'],
  ['TLS', 'MACWARDEN_TLS_CERT', '--tls-cert', resolve('test/cp018-no-such-cert'), cert],
  ['macaroon', 'MACWARDEN_MACAROON', '--macaroon',
    resolve('test/cp018-no-such-macaroon'), own],
] as const)('CP-018/B1 %s flag never combines with the other settings from the environment (RO-4)',
  async (_case, envName, flag, badValue, goodValue) => {
  const { calls, deps } = fixture();
  deps.env = { MACWARDEN_LND_REST: '127.0.0.1:1', MACWARDEN_TLS_CERT: cert,
    MACWARDEN_MACAROON: own, [envName]: badValue };
  // One flag with the rest in the environment: refused before LND, naming the variables only.
  const mixed = await invoke([flag, goodValue], deps);
  expect(mixed.error).toMatchObject({ code: 2, step: null });
  expect(mixed.error!.message).toMatch(new RegExp(`^${flag} given on the command line, so .*from the environment is not used`));
  expect(mixed.error!.message).not.toContain(envName);
  expect(mixed.error!.message).not.toContain(badValue);
  expect(calls).toEqual([]);
  // All three flags: the environment, including the bad value, is ignored entirely.
  const flagged = await invoke([...flags], deps);
  expect(flagged.error).toBeNull();
  expect(calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
});

it('CP-018/B1 complete environment fallback succeeds without flags', async () => {
  const { calls, deps } = fixture();
  deps.env = { MACWARDEN_LND_REST: '127.0.0.1:1', MACWARDEN_TLS_CERT: cert,
    MACWARDEN_MACAROON: own };
  const output = await invoke([], deps);
  expect(output.error).toBeNull();
  expect(calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
});

it.each([
  ['missing values', []],
  ['unknown flag', [...flags, '--unknown'] ],
  ['missing flag argument', [...flags, '--tls-cert']],
] as const)('CP-018/B1 %s exits two before LND and echoes no argument', async (_case, args) => {
  const { calls, deps } = fixture();
  const output = await invoke([...args], deps);
  expect(output.error).toMatchObject({ code: 2, step: null });
  expect(JSON.stringify(output).includes('--unknown')).toBe(false);
  expect(calls).toEqual([]);
});

it.each([
  ['hex', 'flag'], ['base64', 'flag'], ['lndconnect', 'flag'],
  ['hex', 'environment'], ['base64', 'environment'], ['lndconnect', 'environment'],
] as const)('CP-018/B2 %s credential in %s is refused before LND without echo',
  async (form, source) => {
  const bytes = readFileSync(own);
  const credential = form === 'hex' ? bytes.toString('hex') : form === 'base64'
    ? bytes.toString('base64') : `lndconnect://localhost:10009?macaroon=${bytes.toString('base64url')}`;
  const { calls, deps } = fixture();
  const args = [...flags.slice(0, 4)];
  if (source === 'flag') args.push('--macaroon', credential);
  else deps.env.MACWARDEN_MACAROON = credential;
  const output = await invoke([...args, '--json'], deps);
  expect(containsCredential(JSON.stringify(output), bytes)).toBe(false);
  expect(output.error).toMatchObject({ code: 2, step: null });
  expect(calls).toEqual([]);
});

it.each([
  ['TLS certificate', own, resolve('test/cp018-no-such-cert'), /tls|cert/i],
  ['macaroon decode', cert, cert, /macaroon|credential|decode/i],
  ['info:read', noInfoRead, cert, /info:read|GetInfo|ListPermissions/i],
  ['macaroon:read', noMacaroonRead, cert, /macaroon:read|ListMacaroonIDs/i],
] as const)('CP-018/B4 OWN refuses %s before any LND call', async (label, macaroon, tls, message) => {
  const { calls, deps } = fixture();
  const output = await invoke(['--lnd-rest', '127.0.0.1:1', '--tls-cert', tls,
    '--macaroon', macaroon], deps);
  expect(output.error?.code, label).toBe(4);
  expect(output.error?.message, label).toMatch(message);
  expect(calls, label).toEqual([]);
});

it('CP-018/B4 hand-made exact URI set passes OWN and reaches all injected reads', async () => {
  await withHandMadeUriOwn('complete', ownUriMethods, async (macaroon, bytes) => {
    const { calls, deps } = fixture();
    const output = await invoke(['--lnd-rest', '127.0.0.1:1', '--tls-cert', cert,
      '--macaroon', macaroon], deps);
    expect(containsCredential(JSON.stringify(output), bytes)).toBe(false);
    expect(output.error).toBeNull();
    expect(calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
  });
});

it.each(ownUriMethods)('CP-018/B4 hand-made URI set missing %s fails OWN without LND calls',
  async missing => {
  await withHandMadeUriOwn(missing.split('/').at(-1)!,
    ownUriMethods.filter(method => method !== missing), async (macaroon, bytes) => {
    const { calls, deps } = fixture();
    const output = await invoke(['--lnd-rest', '127.0.0.1:1', '--tls-cert', cert,
      '--macaroon', macaroon], deps);
    expect(containsCredential(JSON.stringify(output), bytes)).toBe(false);
    expect(output.error?.code).toBe(4);
    const required = missing.endsWith('/ListMacaroonIDs')
      ? /ListMacaroonIDs|macaroon:read/i : missing.endsWith('/ListPermissions')
        ? /ListPermissions|info:read/i : /GetInfo|info:read/i;
    expect(output.error?.message).toMatch(required);
    expect(calls).toEqual([]);
  });
});

it.each([
  ['http', 'NODE_DEBUG', 'http'],
  ['https', 'NODE_DEBUG', 'https'],
  ['tls', 'NODE_DEBUG', 'tls'],
  ['net', 'NODE_DEBUG', 'net'],
  ['fs,net', 'NODE_DEBUG', 'fs,net'],
  ['report', 'NODE_OPTIONS', '--report-on-fatalerror'],
] as const)('CP-018/B3 ENV %s refuses before OWN or LND calls', async (_case, key, value) => {
  const { calls, deps } = fixture();
  deps.env[key] = value;
  const output = await invoke(['--lnd-rest', '127.0.0.1:1', '--tls-cert',
    resolve('test/cp018-no-such-cert'), '--macaroon', own], deps);
  expect(output.error?.code).toBe(2);
  expect(deps.fs.readFile).not.toHaveBeenCalled();
  expect(calls).toEqual([]);
});

it('CP-018/B3 fs-only NODE_DEBUG passes ENV and reaches LND', async () => {
  const { calls, deps } = fixture();
  deps.env.NODE_DEBUG = 'fs';
  const output = await invoke(flags, deps);
  expect(output.error).toBeNull();
  expect(calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
});

it('CP-018/B5 own root key zero warns in both modes and still lists IDs', async () => {
  for (const mode of [[], ['--json']]) {
    const { calls, deps } = fixture();
    const output = await invoke([...mode, ...flags], deps);
    expect(output.error).toBeNull();
    expect(codes(output)).toContain('own-root-key-0');
    expect(calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
    if (mode.length) expect(render(output, 'json')).toContain('own-root-key-0');
  }
});

it.each([
  ['equal', structuredClone(snapshot.methods), false],
  ['added', { ...snapshot.methods, '/cp018.Extra/Read': ['info:read'] }, true],
  ['removed', Object.fromEntries(Object.entries(snapshot.methods)
    .filter(([key]) => key !== '/lnrpc.Lightning/GetInfo')), true],
  ['changed', { ...snapshot.methods, '/lnrpc.Lightning/GetInfo': ['info:write'] }, true],
] as Array<[string, Record<string, string[]>, boolean]>)('CP-018/B6 %s permissions set snapshot-drift correctly', async (name, methods, drift) => {
  const { calls, deps, lnd } = fixture();
  lnd.listPermissions.mockImplementation(async () => {
    calls.push('ListPermissions');
    return permissions(methods);
  });
  const output = await invoke(flags, deps);
  expect(output.error, name).toBeNull();
  expect(codes(output).includes('snapshot-drift'), name).toBe(drift);
  expect(calls, name).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
});

const failures: Array<[string, string, Error, number]> =
  (['GetInfo', 'ListPermissions', 'ListMacaroonIDs'] as const).flatMap(stage => [
    [stage, 'transport', new LndError(4, 'transport', 'connect ECONNREFUSED'), 4],
    [stage, 'TLS', new LndError(4, 'transport', 'certificate verification failed'), 4],
    [stage, 'HTTP 401', new LndError(4, 'transport', 'unauthorized'), 4],
    [stage, 'HTTP 403', new LndError(4, 'transport', 'forbidden'), 4],
    [stage, 'LND', new LndError(5, 'lnd', 'LND request failed'), 5],
  ] as Array<[string, string, LndError, number]>);

it.each(failures)('CP-018/B7 %s %s failure classification and follow-up count',
  async (stage, kind, error, code) => {
  const { calls, deps, lnd } = fixture();
  const method = stage === 'GetInfo' ? lnd.getInfo : stage === 'ListPermissions'
    ? lnd.listPermissions : lnd.listMacaroonIds;
  method.mockImplementationOnce(async () => {
    calls.push(stage);
    throw error;
  });
  const output = await invoke([...flags, '--json'], deps);
  expect(containsCredential(JSON.stringify(output), readFileSync(own)), `${stage}/${kind}`).toBe(false);
  expect(output.error?.code, `${stage}/${kind}`).toBe(code);
  const stages = ['GetInfo', 'ListPermissions', 'ListMacaroonIDs'];
  const before = stages.slice(0, stages.indexOf(stage) + 1);
  expect(calls.slice(0, before.length), `${stage}/${kind}`).toEqual(before);
  expect(calls.slice(before.length).every(call => call === 'ListMacaroonIDs'), `${stage}/${kind}`).toBe(true);
  expect(calls.filter(call => call === 'ListMacaroonIDs').length, `${stage}/${kind}`).toBeLessThanOrEqual(1);
});

it('CP-018/B9 command rows come only from LND and preserve large decimal IDs', async () => {
  const { calls, deps, lnd } = fixture();
  lnd.listMacaroonIds.mockImplementation(async () => {
    calls.push('ListMacaroonIDs');
    return (['9007199254740993', '0']).map(BigInt);
  });
  lnd.getInfo.mockImplementation(async () => {
    calls.push('GetInfo');
    return { alias: 'alice\u001b\u0085', version: '0.21.4-beta', pubkey: '02' + 'ab'.repeat(32), network: 'regtest' };
  });
  const output = await invoke(flags, deps);
  expect(output.error).toBeNull();
  expect(output.result?.rootKeys.map(row => row.rootKeyId)).toEqual(['0', '9007199254740993']);
  expect(output.result?.rootKeys.every(row => row.inLnd && row.entry === null &&
    row.verify === 'not-checked')).toBe(true);
  expect(render(output, 'text')).toContain('\\x1b\\x85');
  const json = JSON.parse(render(output, 'json')) as Envelope;
  expect(json.result?.rootKeys[1].rootKeyId).toBe('9007199254740993');
  expect(calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
});

it.each([
  ['wrong TLS certificate', 'text', new LndError(4, 'transport', 'certificate rejected')],
  ['wrong TLS certificate', 'json', new LndError(4, 'transport', 'certificate rejected')],
  ['unreachable port', 'text', new LndError(4, 'transport', 'connect ECONNREFUSED')],
  ['unreachable port', 'json', new LndError(4, 'transport', 'connect ECONNREFUSED')],
] as const)('CP-018/B10 %s exits four in %s mode', async (kind, mode, error) => {
  const { calls, deps, lnd } = fixture();
  lnd.getInfo.mockImplementationOnce(async () => {
    calls.push('GetInfo');
    throw error;
  });
  const output = await invoke([...flags, ...(mode === 'json' ? ['--json'] : [])], deps);
  const rendered = render(output, mode);
  expect(containsCredential(rendered, readFileSync(own)), kind).toBe(false);
  expect(output.error?.code, kind).toBe(4);
  if (mode === 'json') expect((JSON.parse(rendered) as Envelope).error?.code).toBe(4);
  expect(calls.filter(call => call !== 'GetInfo' && call !== 'ListMacaroonIDs'), kind).toEqual([]);
  expect(calls.filter(call => call === 'ListMacaroonIDs').length, kind).toBeLessThanOrEqual(1);
});

it('CP-018/B8 bounded mid-request crash exits internal and registered sentinel never leaks', () => {
  const testTmpValue = process.env.MACWARDEN_TEST_TMP;
  const sentinelDirValue = process.env.MACWARDEN_SENTINEL_DIR;
  if (!testTmpValue || !sentinelDirValue) throw new Error('Leak-test temporary directories are required');
  const testTmp = resolve(testTmpValue);
  const sentinelDir = resolve(sentinelDirValue);
  mkdirSync(testTmp, { recursive: true, mode: 0o700 });
  const crashTmp = mkdtempSync(join(testTmp, 'cp018-crash-'));
  mkdirSync(sentinelDir, { recursive: true, mode: 0o700 });
  const registered = join(sentinelDir, 'cp018-injected-own.macaroon');
  copyFileSync(own, registered);
  const bytes = readFileSync(registered);
  const preload = pathToFileURL(join(repo, 'test/preloads/cp018-crash.mjs')).href;
  const outputs: string[] = [];
  for (const json of [false, true]) {
    const env: NodeJS.ProcessEnv = childEnvironment({ NODE_OPTIONS: '',
      MACWARDEN_TEST_TMP: crashTmp,
      MACWARDEN_CRASH_MARKER: 'cp018 mid-request fault' });
    delete env.NODE_DEBUG;
    const child = spawnSync(process.execPath, ['--import', preload, join(repo, 'dist/bin.js'), 'inventory',
      ...registryArgs([...(json ? ['--json'] : []), '--lnd-rest', '127.0.0.1:1',
        '--tls-cert', cert, '--macaroon', registered])],
    { cwd: repo, env, encoding: 'utf8', timeout: 10_000, maxBuffer: 1_000_000 });
    expect(child.error).toBeUndefined();
    outputs.push(child.stdout, child.stderr);
    const mode = json ? 'json' : 'text';
    writeFileSync(join(crashTmp, `${mode}.stdout.txt`), child.stdout, { mode: 0o600 });
    writeFileSync(join(crashTmp, `${mode}.stderr.txt`), child.stderr, { mode: 0o600 });
    expect(containsCredential(child.stdout + child.stderr, bytes)).toBe(false);
    expect(child.status).toBe(8);
    expect(child.stdout + child.stderr).not.toMatch(/^\s+at /m);
    expect(child.stdout + child.stderr).not.toMatch(/run.*inventory/i);
    if (json) {
      expect(child.stderr).toBe('');
      const output = JSON.parse(child.stdout) as Envelope;
      expect(output.error).toMatchObject({ code: 8, step: 'internal' });
    } else expect(child.stderr).toMatch(/internal/i);
  }
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    paths: [crashTmp], commandOutput: outputs.join('\n'), testTmp: crashTmp, root: repo })).toBeNull();
}, 25_000);
