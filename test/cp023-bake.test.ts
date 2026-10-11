import { adapter } from './helpers/adapter.js';
import type { LndAdapter } from '../src/lnd/index.js';
import { LndError } from '../src/errors.js';
import { appendFileSync, constants, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHmac, randomBytes } from 'node:crypto';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { render } from './helpers/render-adversarial.js';
import { onRegistryOpen } from './helpers/integration-registry-read.js';
import { findLeaks } from "./helpers/leak-check.js";
import { isolateLeakSuite } from './helpers/leak-suite.js';
import { expectSchemaValid } from './helpers/output-schema.js';

isolateLeakSuite('cp023');

const repo = resolve();
const cert = resolve('test/fixture/wrong-tls.cert');
const own = resolve('test/vectors/default-admin.macaroon');
const snapshot = JSON.parse(readFileSync(resolve('src/grade/lnd-permissions.json'), 'utf8')) as {
  methods: Record<string, string[]>;
};
const commandModule = '../src/commands/bake/index.js';
const nodePubkey = '02' + 'ab'.repeat(32);

type Envelope = {
  schema: number; command: string; ok: boolean;
  warnings: Array<string | { code: string; message?: string }>;
  result: Record<string, unknown> | null;
  error: { code: number; step: string | null; message: string } | null;
};

function testTmp(): string {
  if (!process.env.MACWARDEN_TEST_TMP) throw new Error('MACWARDEN_TEST_TMP is required');
  const path = resolve(process.env.MACWARDEN_TEST_TMP);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}

function sentinelDir(): string {
  if (!process.env.MACWARDEN_SENTINEL_DIR) throw new Error('MACWARDEN_SENTINEL_DIR is required');
  const path = resolve(process.env.MACWARDEN_SENTINEL_DIR);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}

function ownWithPermissions(name: string, requested: string[]): string {
  const varint = (value: number): Buffer => {
    const digits: number[] = [];
    do { digits.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); }
    while (value);
    return Buffer.from(digits);
  };
  const field = (number: number, value: Buffer) =>
    Buffer.concat([varint((number << 3) | 2), varint(value.length), value]);
  const packet = (kind: number, value: Buffer) =>
    Buffer.concat([varint(kind), varint(value.length), value]);
  const operations = requested.map(value => {
    const at = value.indexOf(':');
    return field(3, Buffer.concat([field(1, Buffer.from(value.slice(0, at))),
      field(2, Buffer.from(value.slice(at + 1)))]));
  });
  const identifier = Buffer.concat([Buffer.from([3]), field(1, randomBytes(16)),
    field(2, Buffer.from('23023')), ...operations]);
  const signature = createHmac('sha256', randomBytes(32)).update(identifier).digest();
  const bytes = Buffer.concat([Buffer.from([2]), packet(1, Buffer.from('lnd')),
    packet(2, identifier), Buffer.from([0, 0]), packet(6, signature)]);
  const path = join(sentinelDir(), `cp023-own-${name}.macaroon`);
  writeFileSync(path, bytes, { mode: 0o600 });
  appendFileSync(join(testTmp(), 'declared-out.txt'), `${path}\n`);
  return path;
}

async function inScratch(work: (path: string) => Promise<void>): Promise<void> {
  const path = mkdtempSync(join(testTmp(), 'cp023-bake-'));
  await work(path);
}

function permissions(methods = snapshot.methods) { return methods; }

function fixture(path: string) {
  const calls: string[] = [];
  const registry = join(path, 'registry.json');
  const out = join(path, 'candidate.macaroon');
  const lnd = {
    ...adapter({}),
    getInfo: vi.fn(async () => { calls.push('GetInfo'); return { alias: 'fixture', version: '0.21.4-beta', pubkey: nodePubkey, network: 'regtest' }; }),
    listPermissions: vi.fn(async () => { calls.push('ListPermissions'); return permissions(); }),
    listMacaroonIds: vi.fn(async () => { calls.push('ListMacaroonIDs'); return (['0']).map(BigInt); }),
    bakeMacaroon: vi.fn(async () => { calls.push('BakeMacaroon'); throw new Error('B10 is outside CP-023'); }),
  } satisfies LndAdapter;
  const deps = { lnd, fs: { ...fs }, env: {} as Record<string, string>,
    clock: () => new Date('2026-10-04T00:00:00.000Z') };
  const args = ['--label', 'Alice', '--preset', 'invoice-only', '--out', out,
    '--registry', registry, '--lnd-rest', '127.0.0.1:1', '--tls-cert', cert, '--macaroon', own];
  return { calls, lnd, deps, args, registry, out };
}

async function invoke(args: string[], deps: ReturnType<typeof fixture>['deps']): Promise<Envelope> {
  const command = await import(/* @vite-ignore */ commandModule) as {
    run: (args: string[], deps: unknown) => Promise<Envelope>;
  };
  expect(typeof command.run).toBe('function');
  const result = await command.run(args, deps);
  expect(result).toMatchObject({ schema: 1, command: 'bake' });
  expect(result.ok).toBe(result.error === null);
  expectSchemaValid(result);
  return result;
}

function warningCodes(result: Envelope): string[] {
  return result.warnings.map(warning => typeof warning === 'string' ? warning : warning.code);
}

function refusal(result: Envelope, code: number, step: string) {
  expect(result.error).toMatchObject({ code, step });
  expect(result.result).toBeNull();
}

function safe(result: Envelope): void {
  const shown = `${JSON.stringify(result)}${render(result, 'text')}${render(result, 'json')}`;
  const bytes = readFileSync(own);
  for (const value of [bytes.toString('utf8'), bytes.toString('latin1'), bytes.toString('hex'),
    bytes.toString('hex').toUpperCase(), bytes.toString('base64'), bytes.toString('base64url'),
    bytes.toString('base64').replace(/=+$/, ''), bytes.toString('base64url').replace(/=+$/, '')]) {
    if (value) expect(shown).not.toContain(value);
  }
}

it.each([
  ['preset with permissions', ['--permissions', 'info:read']],
  ['preset with URI', ['--uri', '/lnrpc.Lightning/GetInfo']],
  ['unknown preset', ['--preset', 'not-a-preset']],
  ['missing label', ['--label']],
  ['missing out', ['--out']],
  ['numeric label', ['--label', '123']],
  ['digit-first label', ['--label', '1abc']],
  ['hyphen-first label', ['--label', '-x']],
  ['space in label', ['--label', 'a b']],
  ['65-character label', ['--label', 'a'.repeat(65)]],
  ['empty permission list', ['--preset', '--permissions', '']],
  ['zero-day expiry', ['--expires', '0d']],
  ['overlong expiry', ['--expires', '100000d']],
  ['unsupported expiry unit', ['--expires', '5w']],
] as const)('CP-023/B1 %s is refused before file or network access', async (_name, replacement) => {
  await inScratch(async path => {
    const { calls, deps, args, out } = fixture(path);
    const request = [...args];
    if (replacement[0] === '--label' || replacement[0] === '--out' || replacement[0] === '--preset') {
      const at = request.indexOf(replacement[0]);
      request.splice(at, 2, ...replacement);
    } else request.push(...replacement);
    if (_name === 'preset with permissions' || _name === 'preset with URI') {
      expect(request).toContain('--preset');
      expect(request).toContain(replacement[0]);
    }
    const result = await invoke(request, deps);
    refusal(result, 2, 'B1');
    expect(calls).toEqual([]);
    expect(existsSync(out)).toBe(false);
    safe(result);
  });
});

it('CP-023/B1 credential-like argument is refused without echo in text or JSON', async () => {
  await inScratch(async path => {
    const { calls, deps, args } = fixture(path);
    const marker = readFileSync(own).toString('hex');
    const request = [...args, '--json'];
    request[request.indexOf('--label') + 1] = marker;
    const result = await invoke(request, deps);
    refusal(result, 2, 'B1');
    expect(`${JSON.stringify(result)}${render(result, 'text')}${render(result, 'json')}`)
      .not.toContain(marker);
    expect(calls).toEqual([]);
  });
});

it.each([
  ['NODE_DEBUG http', 'NODE_DEBUG', 'fs,http'],
  ['NODE_DEBUG tls', 'NODE_DEBUG', 'tls'],
  ['NODE_OPTIONS report', 'NODE_OPTIONS', '--report-on-fatalerror'],
] as const)('CP-023/B2 %s is refused before OWN and network', async (_name, key, value) => {
  await inScratch(async path => {
    const { calls, deps, args, out } = fixture(path);
    deps.env[key] = value;
    const readFile = vi.fn();
    deps.fs.readFile = readFile as typeof fs.readFile;
    const result = await invoke(args, deps);
    refusal(result, 2, 'B2');
    expect(deps.fs.readFile).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
    expect(existsSync(out)).toBe(false);
  });
});

it.each([
  ['unknown entity', ['--permissions', 'info:read,loop:write'], /loop:write/],
  ['unknown URI', ['--uri', '/example.Unknown/Method'], /uri:\/example.Unknown\/Method/],
  ['unknown action', ['--permissions', 'info:delete'], /info:delete/],
  ['admin without consent', ['--permissions', 'macaroon:generate'], /admin/i],
  ['admin with unassessed permission', ['--permissions', 'macaroon:generate,loop:write', '--allow-admin'], /loop:write/],
] as const)('CP-023/B3 %s is refused with offending permission and zero LND calls',
  async (_name, form, message) => {
  await inScratch(async path => {
    const { calls, deps, args, out } = fixture(path);
    const request = [...args];
    request.splice(request.indexOf('--preset'), 2, ...form);
    const result = await invoke(request, deps);
    refusal(result, 2, 'B3');
    expect(result.error?.message).toMatch(message);
    expect(calls).toEqual([]);
    expect(existsSync(out)).toBe(false);
    safe(result);
  });
});

it('CP-023/B4 existing out is untouched and precedes OWN or registry refusal', async () => {
  await inScratch(async path => {
    const { calls, deps, args, out, registry } = fixture(path);
    writeFileSync(out, 'existing operator file');
    writeFileSync(registry, '{invalid');
    const request = [...args];
    request.splice(request.indexOf('--tls-cert') + 1, 1, join(path, 'absent.cert'));
    const result = await invoke(request, deps);
    refusal(result, 3, 'B4');
    expect(readFileSync(out, 'utf8')).toBe('existing operator file');
    expect(calls).toEqual([]);
  });
});

it('CP-023/B4 numbered refusal order is B1 then B2 then B3 then B4', async () => {
  await inScratch(async path => {
    const { calls, deps, args, out } = fixture(path);
    writeFileSync(out, 'existing operator file');
    deps.env.NODE_DEBUG = 'http';
    const invalid = [...args, '--expires', '0d'];
    refusal(await invoke(invalid, deps), 2, 'B1');
    invalid.splice(-2);
    refusal(await invoke(invalid, deps), 2, 'B2');
    delete deps.env.NODE_DEBUG;
    invalid.splice(invalid.indexOf('--preset'), 2, '--permissions', 'loop:write');
    refusal(await invoke(invalid, deps), 2, 'B3');
    invalid.splice(invalid.indexOf('--permissions'), 2, '--permissions', 'info:read');
    refusal(await invoke(invalid, deps), 3, 'B4');
    expect(calls).toEqual([]);
    expect(readFileSync(out, 'utf8')).toBe('existing operator file');
  });
});

it.each([
  ['unreadable TLS certificate', 'tls', 'missing', /tls|cert/i],
  ['undecodable OWN macaroon', 'own', 'invalid', /macaroon|decode/i],
  ['missing generate', 'own', 'test/vectors/default-readonly.macaroon', /macaroon:generate|BakeMacaroon/i],
  ['missing macaroon read', 'own', 'test/vectors/grade-admin-set.macaroon', /macaroon:read|ListMacaroonIDs/i],
  ['missing info read', 'own', 'generated-no-info', /info:read|GetInfo|ListPermissions/i],
] as const)('CP-023/B5 %s fails OWN without LND calls', async (_name, kind, value, message) => {
  await inScratch(async path => {
    const { calls, deps, args, out } = fixture(path);
    const request = [...args];
    const at = request.indexOf(kind === 'tls' ? '--tls-cert' : '--macaroon') + 1;
    request[at] = kind === 'tls' ? join(path, 'absent.cert') :
      value === 'invalid' ? join(path, 'invalid.macaroon') :
        value === 'generated-no-info' ? ownWithPermissions('no-info',
          ['macaroon:generate', 'macaroon:read']) : resolve(value);
    if (value === 'invalid') writeFileSync(request[at], 'not a macaroon');
    const result = await invoke(request, deps);
    refusal(result, 4, 'B5');
    expect(result.error?.message).toMatch(message);
    expect(calls).toEqual([]);
    expect(existsSync(out)).toBe(false);
    safe(result);
  });
});

it.each(['invalid registry', 'held lock'] as const)(
  'CP-023/B6 %s refuses before LND and leaves out absent', async kind => {
  await inScratch(async path => {
    const { calls, deps, args, out, registry } = fixture(path);
    const lock = `${registry}.lock`;
    if (kind === 'invalid registry') writeFileSync(registry, '{invalid');
    else {
      writeFileSync(registry, '{"schema":1,"entries":[]}');
      writeFileSync(lock, JSON.stringify({ pid: 12345, hostname: 'other-host',
        startedAt: '2026-10-04T00:00:00Z' }));
    }
    const before = kind === 'held lock' ? readFileSync(lock) : null;
    const result = await invoke(args, deps);
    refusal(result, 3, 'B6');
    expect(calls).toEqual([]);
    expect(existsSync(out)).toBe(false);
    if (before) expect(readFileSync(lock).equals(before)).toBe(true);
  });
});

it('CP-023/B6 unreadable registry exits three before any lock, out or LND call', async () => {
  await inScratch(async path => {
    const { calls, deps, args, out, registry } = fixture(path);
    writeFileSync(registry, '{"schema":1,"entries":[]}');
    deps.fs.open = onRegistryOpen(deps.fs, registry, () => {
      throw Object.assign(new Error('denied'), { code: 'EACCES' });
    });
    const result = await invoke(args, deps);
    refusal(result, 3, 'B6');
    expect(calls).toEqual([]);
    expect(existsSync(out)).toBe(false);
    expect(existsSync(`${registry}.lock`)).toBe(false);
  });
});

it('CP-023/B7 out creation is exclusive and failure releases the acquired lock before LND', async () => {
  await inScratch(async path => {
    const { calls, deps, args, out, registry } = fixture(path);
    writeFileSync(registry, '{"schema":1,"entries":[]}');
    const original = deps.fs.open;
    const seen: Array<{ flags: unknown; mode: unknown }> = [];
    deps.fs.open = vi.fn(async (...params: Parameters<typeof fs.open>) => {
      if (params[0] === out) {
        seen.push({ flags: params[1], mode: params[2] });
        throw Object.assign(new Error('creation denied'), { code: 'EACCES' });
      }
      return original(...params);
    }) as typeof fs.open;
    const result = await invoke(args, deps);
    refusal(result, 3, 'B7');
    // On Windows the System32 helper creates the file owner-only; macwarden's only open is the
    // exclusive one, and its failure removes the empty file (SAFE-06).
    expect(seen).toEqual([process.platform === 'win32'
      ? { flags: constants.O_RDWR | 0x10000000, mode: undefined } : { flags: 'wx', mode: 0o600 }]);
    expect(calls).toEqual([]);
    expect(existsSync(out)).toBe(false);
    expect(existsSync(`${registry}.lock`)).toBe(false);
  });
});

it('CP-023/B7 reserved out is empty and open before GetInfo, then removed on GetInfo failure', async () => {
  await inScratch(async path => {
    const { calls, deps, args, out, registry, lnd } = fixture(path);
    writeFileSync(registry, '{"schema":1,"entries":[]}');
    const originalOpen = deps.fs.open;
    let reserved: Awaited<ReturnType<typeof fs.open>> | undefined;
    const opens: Array<{ flags: unknown; mode: unknown }> = [];
    deps.fs.open = vi.fn(async (...params: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...params);
      if (params[0] === out) {
        reserved = handle;
        opens.push({ flags: params[1], mode: params[2] });
      }
      return handle;
    }) as typeof fs.open;
    let observed = false;
    lnd.getInfo.mockImplementationOnce(async () => {
      calls.push('GetInfo');
      observed = existsSync(out) && statSync(out).size === 0 &&
        existsSync(`${registry}.lock`) && (reserved?.fd ?? -1) >= 0;
      throw new LndError(4, 'transport', 'unauthorized');
    });
    const result = await invoke(args, deps);
    refusal(result, 4, 'B8');
    expect(observed).toBe(true);
    // On Windows the System32 helper creates the file owner-only and the bytes go to one
    // exclusive open (SAFE-06); POSIX creates it with O_EXCL 0600.
    expect(opens).toEqual([process.platform === 'win32'
      ? { flags: constants.O_RDWR | 0x10000000, mode: undefined } : { flags: 'wx', mode: 0o600 }]);
    expect(reserved?.fd).toBe(-1);
    expect(calls).toEqual(['GetInfo']);
    expect(existsSync(out)).toBe(false);
    expect(existsSync(`${registry}.lock`)).toBe(false);
  });
});

it.each([[401, 4], [500, 5]] as const)(
  'CP-023/B8 GetInfo HTTP %i exits %i and cleans the out and lock', async (status, code) => {
  await inScratch(async path => {
    const { calls, deps, args, out, registry, lnd } = fixture(path);
    writeFileSync(registry, '{"schema":1,"entries":[]}');
    lnd.getInfo.mockImplementationOnce(async () => {
      calls.push('GetInfo');
      throw new LndError(status === 401 ? 4 : 5, status === 401 ? 'transport' : 'lnd', 'LND request failed');
    });
    const result = await invoke(args, deps);
    refusal(result, code, 'B8');
    expect(calls).toEqual(['GetInfo']);
    expect(existsSync(out)).toBe(false);
    expect(existsSync(`${registry}.lock`)).toBe(false);
  });
});

it.each([
  ['same node', nodePubkey, 2],
  ['other node', '03' + 'cd'.repeat(32), 0],
] as const)('CP-023/B8 active label on %s is node-scoped', async (_name, pubkey, code) => {
  await inScratch(async path => {
    const { calls, deps, args, out, registry } = fixture(path);
    const template = JSON.parse(readFileSync(resolve('test/registry-fixtures/registry.json'), 'utf8'));
    template.entries = [template.entries[0]];
    template.entries[0].nodePubkey = pubkey;
    template.entries[0].label = 'Alice';
    writeFileSync(registry, JSON.stringify(template));
    const result = await invoke([...args, '--dry-run'], deps);
    if (code) refusal(result, code, 'B8');
    else expect(result.error).toBeNull();
    expect(calls).toEqual(['GetInfo', 'ListPermissions']);
    expect(existsSync(out)).toBe(false);
    expect(existsSync(`${registry}.lock`)).toBe(false);
  });
});

it('CP-023/B8 changed live permission snapshot warns while grade remains bundled', async () => {
  await inScratch(async path => {
    const { calls, deps, args, lnd } = fixture(path);
    lnd.listPermissions.mockImplementationOnce(async () => {
      calls.push('ListPermissions');
      return permissions({ ...snapshot.methods, '/example.Extra/Method': ['info:read'] });
    });
    const result = await invoke([...args, '--dry-run'], deps);
    expect(result.error).toBeNull();
    expect(warningCodes(result)).toContain('snapshot-drift');
    expect(result.result?.grade).toBe('RECEIVE');
    expect(calls).toEqual(['GetInfo', 'ListPermissions']);
  });
});

it.each([
  ['read-only', 'READ', ['info:read', 'onchain:read', 'offchain:read',
    'address:read', 'invoices:read', 'peers:read']],
  ['invoice-only', 'RECEIVE', ['info:read', 'invoices:read', 'invoices:write']],
  ['pay-only', 'SPEND', ['info:read', 'uri:/routerrpc.Router/SendPaymentV2',
    'uri:/routerrpc.Router/TrackPaymentV2', 'uri:/lnrpc.Lightning/DecodePayReq']],
] as const)('CP-023/B9 %s dry-run prints the reference plan without mutation',
  async (preset, grade, requested) => {
  await inScratch(async path => {
    const { calls, deps, args, registry, out, lnd } = fixture(path);
    writeFileSync(registry, '{"schema":1,"entries":[]}');
    const before = readFileSync(registry);
    const mtime = statSync(registry).mtimeMs;
    const request = [...args, '--dry-run'];
    request[request.indexOf('--preset') + 1] = preset;
    const result = await invoke(request, deps);
    expect(result.error).toBeNull();
    expect(result.result).toMatchObject({ dryRun: true, label: 'Alice', grade, caveats: [] });
    expect(result.result?.permissions).toEqual(requested);
    const text = render(result, 'text');
    for (const expected of ['Alice', grade, ...requested, 'root key ID: allocated at bake time'])
      expect(text).toContain(expected);
    expect(calls).toEqual(['GetInfo', 'ListPermissions']);
    expect(lnd.listMacaroonIds).not.toHaveBeenCalled();
    expect(lnd.bakeMacaroon).not.toHaveBeenCalled();
    expect(readFileSync(registry).equals(before)).toBe(true);
    expect(statSync(registry).mtimeMs).toBe(mtime);
    expect(existsSync(out)).toBe(false);
    expect(existsSync(`${registry}.lock`)).toBe(false);
    safe(result);
  });
});

it('CP-023/B9 JSON dry-run contains one schema envelope and a computed expiry plan', async () => {
  await inScratch(async path => {
    const { calls, deps, args, out, registry } = fixture(path);
    const result = await invoke([...args, '--expires', '1d', '--dry-run', '--json'], deps);
    expect(result.error).toBeNull();
    const text = render(result, 'json');
    expect(JSON.parse(text)).toMatchObject({ schema: 1, command: 'bake', ok: true,
      result: { dryRun: true, label: 'Alice', grade: 'RECEIVE',
        permissions: ['info:read', 'invoices:read', 'invoices:write'],
        caveats: [{ type: 'time-before', value: '2026-10-05T00:00:00Z' }] }, error: null });
    expect(text.trim().split('\n')).toHaveLength(1);
    expect(calls).toEqual(['GetInfo', 'ListPermissions']);
    expect(existsSync(out)).toBe(false);
    expect(existsSync(registry)).toBe(false);
    expect(existsSync(`${registry}.lock`)).toBe(false);
    safe(result);
  });
});

it.each([
  ['entity plus URI', ['--permissions', 'invoices:write', '--uri', '/lnrpc.Lightning/GetInfo'],
    ['invoices:write', 'uri:/lnrpc.Lightning/GetInfo'], 'RECEIVE'],
  ['URI only', ['--uri', '/lnrpc.Lightning/GetInfo'],
    ['uri:/lnrpc.Lightning/GetInfo'], 'READ'],
] as const)('CP-023/B9 %s form remains distinct in a dry-run plan', async (_name, form, expected, grade) => {
  await inScratch(async path => {
    const { calls, deps, args, registry, out } = fixture(path);
    const request = [...args, '--dry-run'];
    request.splice(request.indexOf('--preset'), 2, ...form);
    const result = await invoke(request, deps);
    expect(result.error).toBeNull();
    expect(result.result).toMatchObject({ dryRun: true, label: 'Alice', grade,
      permissions: expected, caveats: [] });
    expect(calls).toEqual(['GetInfo', 'ListPermissions']);
    expect(existsSync(registry)).toBe(false);
    expect(existsSync(`${registry}.lock`)).toBe(false);
    expect(existsSync(out)).toBe(false);
  });
});

it('CP-023/leak-check registered OWN fixtures do not leak into temporary outputs', () => {
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: sentinelDir(),
    paths: [testTmp()], testTmp: testTmp(), root: repo })).toBeNull();
});
