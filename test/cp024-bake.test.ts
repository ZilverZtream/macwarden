import { adapter } from './helpers/adapter.js';
import { LndError } from '../src/errors.js';
import type { LndAdapter } from '../src/lnd/index.js';
import { revealSecret } from './helpers/secret-bytes.js';
import { appendFileSync, constants, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { userInfo } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { Secret } from '../src/secret.js';
import { addFirstPartyCaveat } from '../src/decode/index.js';
import { decodeMacaroon } from '../src/decode/index.js';
import { render } from './helpers/render-adversarial.js';
import { findLeaks } from "./helpers/leak-check.js";
import { isolateLeakSuite } from './helpers/leak-suite.js';
import { expectSchemaValid } from './helpers/output-schema.js';

const exclusiveReopen = constants.O_RDWR | 0x10000000;
function expectOutOpen(count: number, flags: unknown[]): void {
  // POSIX creates the file with O_EXCL 0600. On Windows the System32 helper creates it owner-only
  // and the only open by macwarden is the exclusive one that receives the bytes (SAFE-06).
  expect(count).toBe(1);
  expect(flags).toEqual(process.platform === 'win32' ? [exclusiveReopen] : ['wx', 0o600]);
}


isolateLeakSuite('cp024');

// Control only the random source, never allocation, decoding, attenuation or run.
const entropy = vi.hoisted(() => ({ id: 4294967296n, draws: 0 }));
vi.mock('node:crypto', async importOriginal => {
  const real = await importOriginal<typeof import('node:crypto')>();
  return { ...real, randomBytes: (size: number) => {
    if (size !== 8) return real.randomBytes(size);
    entropy.draws++;
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(entropy.id);
    return bytes;
  } };
});

export type Envelope = {
  schema: 1; command: 'bake'; ok: boolean;
  warnings: Array<string | { code: string; message?: string }>;
  result: Record<string, unknown> | null;
  error: { code: number; step: string | null; message: string } | null;
};
const repo = resolve();
const own = resolve('test/vectors/default-admin.macaroon');
const cert = resolve('test/fixture/wrong-tls.cert');
const pubkey = '02' + 'ab'.repeat(32);
const fixedClock = () => new Date('2026-10-02T09:00:00.789Z');
const snapshot = JSON.parse(readFileSync(resolve('src/grade/lnd-permissions.json'), 'utf8')) as {
  methods: Record<string, string[]>;
};
const presets = {
  'read-only': { grade: 'READ', permissions: ['info:read', 'onchain:read', 'offchain:read',
    'address:read', 'invoices:read', 'peers:read'] },
  'invoice-only': { grade: 'RECEIVE', permissions: ['info:read', 'invoices:read', 'invoices:write'] },
  'pay-only': { grade: 'SPEND', permissions: ['info:read', 'uri:/routerrpc.Router/SendPaymentV2',
    'uri:/routerrpc.Router/TrackPaymentV2', 'uri:/lnrpc.Lightning/DecodePayReq'] },
};
type Preset = keyof typeof presets;
function directory(variable: string): string {
  const value = process.env[variable];
  if (!value) throw new Error(`${variable} is required`);
  const path = resolve(value);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}
function declare(path: string): void {
  appendFileSync(join(directory('MACWARDEN_TEST_TMP'), 'declared-out.txt'), `${path}\n`);
}
let serial = 0;
function register(bytes: Buffer): string {
  const path = join(directory('MACWARDEN_SENTINEL_DIR'), `cp024-unit-${serial++}.macaroon`);
  writeFileSync(path, bytes, { mode: 0o600 });
  declare(path);
  return path;
}
function fingerprint(bytes: Buffer): string {
  return `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
}
function varint(value: number): Buffer {
  const digits: number[] = [];
  do { digits.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); }
  while (value);
  return Buffer.from(digits);
}
function field(kind: number, bytes: Buffer): Buffer {
  return Buffer.concat([varint(kind), varint(bytes.length), bytes]);
}
function proto(kind: number, bytes: Buffer): Buffer { return field((kind << 3) | 2, bytes); }
// Independent v2 wire data for a faulty adapter. The signature is copied from a
// committed vector: no claim of LND acceptance is made by these unit fixtures.
function responseBytes(id: string, permissions: string[]): Buffer {
  const source = readFileSync(resolve('test/vectors/preset-invoice-only.macaroon'));
  const operations = permissions.map(permission => {
    const at = permission.indexOf(':');
    return proto(3, Buffer.concat([proto(1, Buffer.from(permission.slice(0, at))),
      proto(2, Buffer.from(permission.slice(at + 1)))]));
  });
  const identifier = Buffer.concat([Buffer.from([3]), proto(1, Buffer.alloc(16, 24)),
    proto(2, Buffer.from(id)), ...operations]);
  return Buffer.concat([Buffer.from([2]), field(1, Buffer.from('lnd')), field(2, identifier),
    Buffer.from([0, 0]), field(6, source.subarray(source.length - 32))]);
}
function permissionResponse() { return snapshot.methods; }
type WriteFault = 'write' | 'flush' | 'close';
function fixture(path: string, preset: Preset = 'invoice-only') {
  entropy.id = 4294967296n;
  entropy.draws = 0;
  const calls: string[] = [], events: string[] = [];
  const registry = join(path, 'registry.json'), out = join(path, 'candidate.macaroon');
  declare(out);
  const ownSentinel = join(directory('MACWARDEN_SENTINEL_DIR'), 'cp024-unit-own.macaroon');
  writeFileSync(ownSentinel, readFileSync(own), { mode: 0o600 }); declare(ownSentinel);
  writeFileSync(registry, '{"schema":1,"entries":[]}', { mode: 0o600 });
  // Check fixture construction independently before invoking the command. These
  // expected facts come from the wire input and committed printmacaroon data.
  const sample = decodeMacaroon(new Secret(responseBytes('4294967296', presets[preset].permissions)));
  expect(sample.rootKeyId.toString()).toBe('4294967296');
  expect(sample.permissions.slice().sort()).toEqual(presets[preset].permissions.slice().sort());
  expect(sample.caveats).toEqual([]);
  const state = { chosen: '', issued: Buffer.alloc(0) as Buffer, checked: Buffer.alloc(0) as Buffer,
    checkedPermissions: [] as string[], accepted: false, writeFault: null as WriteFault | null,
    registryFails: false, writes: 0, flushed: false, closed: false,
    responseId: null as string | null, responsePermissions: null as string[] | null, responseCaveat: null as string | null,
    corrupt: false, handle: undefined as Awaited<ReturnType<typeof fs.open>> | undefined };
  const lnd = {
    ...adapter({}),
    getInfo: vi.fn(async () => { calls.push('GetInfo'); return { alias: 'fixture', version: '0.21.4-beta', pubkey: pubkey, network: 'regtest' }; }),
    listPermissions: vi.fn(async () => { calls.push('ListPermissions'); return permissionResponse(); }),
    listMacaroonIds: vi.fn(async () => { calls.push('ListMacaroonIDs');
      return (state.chosen ? ['0', state.chosen] : ['0']).map(BigInt); }),
    bakeMacaroon: vi.fn(async (requested: string[], id: bigint) => {
      calls.push('BakeMacaroon'); events.push('bake');
      expect(requested).toEqual(presets[preset].permissions);
      expect(typeof id).toBe('bigint');
      expect(id >= 4294967296n && id <= 9223372036854775807n).toBe(true);
      state.chosen = id.toString();
      state.issued = state.corrupt ? readFileSync(resolve('test/vectors/negative/truncated-protobuf.macaroon')) :
        responseBytes(state.responseId ?? state.chosen, state.responsePermissions ?? requested);
      // Audit 1.2.1: a response carrying a caveat (BakeMacaroon never adds one) is refused at B12.
      if (state.responseCaveat) state.issued = Buffer.from(revealSecret(addFirstPartyCaveat(new Secret(state.issued), state.responseCaveat)));
      register(state.issued);
      return new Secret(state.issued);
    }),
    checkMacaroon: vi.fn<LndAdapter['checkMacaroon']>(async (mac: Secret, requested: string[]) => {
      calls.push('CheckMacaroonPermissions'); events.push('verify');
      state.checked = Buffer.from(revealSecret(mac)); register(state.checked);
      state.checkedPermissions = [...requested];
      state.accepted = true;
      return { valid: true as const };
    }),
  } satisfies LndAdapter;
  const deps = { lnd: { ...lnd,
    // Preserve the transport spelling established by CP-023 and the normalized
    // adapter spelling in the published interface, with one shared observation.

  }, env: {} as Record<string, string>, clock: fixedClock, fs: { ...fs } };
  deps.fs.rename = vi.fn(async (...params: Parameters<typeof fs.rename>) => {
    if (params[1] === registry) {
      events.push('save');
      if (state.registryFails && events.includes('bake')) throw Object.assign(new Error('registry unavailable'), { code: 'EACCES' });
    }
    return fs.rename(...params);
  }) as typeof fs.rename;
  let outOpens = 0;
  deps.fs.open = vi.fn(async (...params: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...params);
    if (params[0] !== out) return handle;
    expectOutOpen(++outOpens, params.slice(1));
    state.handle = handle;
    return new Proxy(handle, { get(target, key) {
      const value = Reflect.get(target, key, target);
      if (['write', 'writeFile', 'writev'].includes(String(key))) return async (...args: unknown[]) => {
        events.push('write'); state.writes++;
        expect(state.accepted, 'credential write must follow final-byte acceptance').toBe(true);
        if (state.writeFault === 'write') {
          await target.write(state.checked.subarray(0, 8));
          throw Object.assign(new Error('partial write'), { code: 'EIO' });
        }
        return Reflect.apply(value, target, args);
      };
      if (key === 'sync' || key === 'datasync') return async () => {
        events.push('flush');
        if (state.writeFault === 'flush') throw Object.assign(new Error('flush failed'), { code: 'EIO' });
        state.flushed = true; return Reflect.apply(value, target, []);
      };
      if (key === 'close') return async () => {
        events.push('close'); await target.close(); state.closed = true;
        if (state.writeFault === 'close' && state.accepted) {
          state.writeFault = null;
          throw Object.assign(new Error('close failed'), { code: 'EIO' });
        }
      };
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  }) as typeof fs.open;
  const args = ['--label', 'Alice', '--preset', preset, '--out', out, '--registry', registry,
    '--lnd-rest', '127.0.0.1:1', '--tls-cert', cert, '--macaroon', own];
  return { calls, events, registry, out, state, lnd, deps, args };
}
type Fixture = ReturnType<typeof fixture>;
async function scratch(work: (path: string) => Promise<void>) {
  const path = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'cp024-unit-'));
  await work(path);
}
async function invoke(f: Fixture, extra: string[] = []): Promise<Envelope> {

  const command = await import('../src/commands/bake/index.js') as {
    run: (args: string[], deps: unknown) => Promise<Envelope>;
  };
  const result = await command.run([...f.args, ...extra], f.deps);
  expect(result).toMatchObject({ schema: 1, command: 'bake' });
  expect(result.ok).toBe(result.error === null);
  safe(f, result);
  expectSchemaValid(result);
  return result;
}
function safe(f: Fixture, result: Envelope) {
  for (const mode of ['text', 'json'] as const) {
    const output = render(result, mode);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'),
      sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), root: repo, commandOutput: output })).toBeNull();
    expect(output).not.toMatch(/^\s+at\s+.*:\d+/m);
    if (mode === 'json') {
      expect(JSON.parse(output)).toEqual(result);
      expect(output.trim().split('\n')).toHaveLength(1);
      expect(Object.keys(JSON.parse(output)).sort()).toEqual(
        ['command', 'error', 'ok', 'result', 'schema', 'warnings']);
    }
  }
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'),
    sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), root: repo,
    paths: [dirname(f.registry)], testTmp: directory('MACWARDEN_TEST_TMP') })).toBeNull();
}
function stopped(f: Fixture, result: Envelope, code: number, step: string, keepFile = false) {
  expect(result.error).toMatchObject({ code, step });
  expect(result.result).toBeNull();
  expect(existsSync(f.out)).toBe(keepFile);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
  expect(f.state.handle?.fd).toBe(-1);
}
function afterFailure(f: Fixture, failedCall: string) {
  const tail = f.calls.slice(f.calls.indexOf(failedCall) + 1);
  expect(tail.every(call => call === 'ListMacaroonIDs')).toBe(true);
  expect(tail.length).toBeLessThanOrEqual(1);
}
function entries(f: Fixture): Array<Record<string, unknown>> {
  return JSON.parse(readFileSync(f.registry, 'utf8')).entries;
}
function unverified(f: Fixture, result: Envelope) {
  const observed = entries(f);
  expect(observed).toHaveLength(1);
  if (f.state.registryFails) expect(observed[0]).toMatchObject({ nodePubkey: pubkey,
    label: 'Alice', rootKeyId: f.state.chosen, status: 'active', verified: false,
    fingerprint: null, outPath: null });
  if (!f.state.registryFails) expect(observed[0]).toMatchObject({ nodePubkey: pubkey,
    label: 'Alice', rootKeyId: f.state.chosen, status: 'active', verified: false, outPath: null });
  const recovery = `macwarden revoke ${f.state.chosen}`;
  for (const mode of ['text', 'json'] as const) {
    const shown = render(result, mode);
    expect(shown).toContain(recovery);
    expect(shown).not.toContain('--unregistered');
    expect(shown).not.toContain('macwarden revoke Alice');
    expect(shown).toMatch(/LND|root key|issued/i);
    expect(shown).toContain(result.error!.step!);
  }
  const failureAt = f.calls.includes('CheckMacaroonPermissions') ? 'CheckMacaroonPermissions' : 'BakeMacaroon';
  afterFailure(f, failureAt);
}
const failures = [
  ['transport', () => new LndError(4, 'transport', 'connection lost'), 4],
  ['LND', () => new LndError(5, 'lnd', 'LND refusal'), 5],
] as const;

it('CP-040/B11-meaningful-tests bake refuses a failed preflight journal save before issuing authority', async () => scratch(async path => {
  const f = fixture(path);
  const before = readFileSync(f.registry);
  f.deps.fs.rename = vi.fn(async (...params: Parameters<typeof fs.rename>) => {
    if (params[1] === f.registry) throw Object.assign(new Error('preflight journal unavailable'), { code: 'EACCES' });
    return fs.rename(...params);
  }) as typeof fs.rename;
  const result = await invoke(f);
  expect(result.error).toMatchObject({ code: 3 });
  expect(result.result).toBeNull();
  expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  expect(f.state.issued.length).toBe(0);
  expect(readFileSync(f.registry).equals(before)).toBe(true);
  expect(existsSync(f.out)).toBe(false);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
}));

for (const mode of ['text', 'json'] as const) {
  it.each(failures)(`CP-024/B1 B10 %s failure exits before issuance and cleans resources (${mode})`,
    async (_kind, error, code) => scratch(async path => {
      const f = fixture(path);
      f.lnd.listMacaroonIds.mockImplementationOnce(async () => { f.calls.push('ListMacaroonIDs'); throw error(); });
      const result = await invoke(f, mode === 'json' ? ['--json'] : []);
      stopped(f, result, code, 'B10');
      expect(f.calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
      expect(entries(f)).toEqual([]);
      expect(f.state.issued.length).toBe(0); expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
    }));

  it(`CP-024/B1 B10 exhausts sixteen unusable draws before BakeMacaroon (${mode})`, async () => scratch(async path => {
    const f = fixture(path);
    f.lnd.listMacaroonIds.mockImplementation(async () => { f.calls.push('ListMacaroonIDs');
      return (['0', entropy.id.toString()]).map(BigInt); });
    const result = await invoke(f, mode === 'json' ? ['--json'] : []);
    stopped(f, result, 5, 'B10');
    expect(entropy.draws).toBe(16);
    expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
    expect(entries(f)).toEqual([]);
    expect(f.state.issued.length).toBe(0); expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  }));

  for (const observation of ['absent', 'present', 'unreadable'] as const) {
    it.each(failures)(`CP-024/B2 B11 %s failure with ${observation} chosen ID reconciles once (${mode})`,
      async (_kind, error, code) => scratch(async path => {
        const f = fixture(path);
        f.lnd.bakeMacaroon.mockImplementationOnce(async (_requested, id) => {
          f.calls.push('BakeMacaroon'); f.state.chosen = id.toString(); throw error();
        });
        f.lnd.listMacaroonIds.mockImplementation(async () => {
          f.calls.push('ListMacaroonIDs');
          if (!f.state.chosen) return (['0']).map(BigInt);
          if (observation === 'unreadable') throw Object.assign(new Error('observation failed'), { code: 'ETIMEDOUT' });
          return (observation === 'present' ? ['0', f.state.chosen] : ['0']).map(BigInt);
        });
        const result = await invoke(f, mode === 'json' ? ['--json'] : []);
        stopped(f, result, observation === 'absent' ? code : 7, 'B11');
        expect(f.calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'BakeMacaroon', 'ListMacaroonIDs']);
        if (observation === 'absent') expect(entries(f)).toEqual([]);
        else expect(entries(f)).toEqual([expect.objectContaining({ nodePubkey: pubkey,
          label: 'Alice', rootKeyId: f.state.chosen, status: 'active',
          verified: false, fingerprint: null, outPath: null })]);
        const shown = render(result, mode);
        if (observation === 'absent') expect(shown).toMatch(/no change|unchanged|nothing changed/i);
        if (observation === 'present') {
          expect(shown).toContain(`macwarden revoke ${f.state.chosen}`);
          expect(shown).not.toContain('--unregistered');
          expect(shown).not.toContain('macwarden revoke Alice');
          expect(shown).toMatch(/present|exists|created|issued/i);
        }
        if (observation === 'unreadable') {
          expect(shown).toContain('macwarden inventory'); expect(shown).toMatch(/LND state unknown/i);
        }
      }));
  }
}

type AfterMutationFault = 'wrong ID' | 'wrong permissions' | 'undecodable response' | 'extra caveat' |
  'rejected' | 'error' | 'timeout' | WriteFault;
function inject(f: Fixture, fault: AfterMutationFault) {
  if (fault === 'wrong ID') f.state.responseId = '4294967399';
  else if (fault === 'wrong permissions') f.state.responsePermissions = ['info:read'];
  else if (fault === 'extra caveat') f.state.responseCaveat = 'lnd-custom tenant-00000000 3a1e61423be44eaf';
  else if (fault === 'undecodable response') f.state.corrupt = true;
  else if (fault === 'write' || fault === 'flush' || fault === 'close') f.state.writeFault = fault;
  else f.lnd.checkMacaroon.mockImplementationOnce(async (mac, requested) => {
    f.calls.push('CheckMacaroonPermissions');
    f.state.checked = Buffer.from(revealSecret(mac)); register(f.state.checked);
    f.state.checkedPermissions = requested;
    if (fault === 'rejected') return { valid: false as const, reason: 'other' as const, message: 'injected verification refusal' };
    throw new LndError(5, 'lnd', 'verification failed');
  });
}
const afterMutationCases: Array<[string, AfterMutationFault, string, string]> = [
  ['B3', 'wrong ID', 'B12', 'decoded root ID differs'],
  ['B3', 'wrong permissions', 'B12', 'decoded permissions differ'],
  ['B3', 'undecodable response', 'B12', 'response cannot decode'],
  ['B3', 'extra caveat', 'B12', 'response carries a caveat'],
  ['B5', 'rejected', 'B14', 'final credential rejected'],
  ['B5', 'error', 'B14', 'final check returns LND error'],
  ['B5', 'timeout', 'B14', 'final check times out'],
  ['B6', 'write', 'B15', 'partial credential write fails'],
  ['B6', 'flush', 'B15', 'durable flush fails'],
  ['B6', 'close', 'B15', 'reserved handle close fails'],
];
for (const mode of ['text', 'json'] as const) {
  for (const registryFails of [false, true]) {
    for (const [id, fault, step, description] of afterMutationCases) {
      it(`CP-024/${id} ${description}; registry ${registryFails ? 'unwritable' : 'writable'} (${mode})`, async () => scratch(async path => {
        const f = fixture(path); f.state.registryFails = registryFails; inject(f, fault);
        const result = await invoke(f, mode === 'json' ? ['--json'] : []);
        stopped(f, result, 7, step); unverified(f, result);
        if (step === 'B12') expect(f.lnd.checkMacaroon).not.toHaveBeenCalled();
        if (step !== 'B15') expect(f.state.writes).toBe(0);
      }));
    }
  }
  it(`CP-024/B7 B16 registry save failure retains valid file and prints recovery entry (${mode})`, async () => scratch(async path => {
    const f = fixture(path); f.state.registryFails = true;
    const result = await invoke(f, mode === 'json' ? ['--json'] : []);
    stopped(f, result, 7, 'B16', true);
    expect(f.state.flushed && f.state.closed).toBe(true);
    expect(readFileSync(f.out).equals(f.state.checked)).toBe(true);
    expect(entries(f)).toEqual([expect.objectContaining({rootKeyId:f.state.chosen,
      verified:false,fingerprint:null,outPath:null})]);
    for (const expected of ['Alice', f.state.chosen, fingerprint(readFileSync(f.out)),
      'nodePubkey', 'permissions', 'verified', 'outPath']) expect(result.error?.message).toContain(expected);
    expect(result.error?.message).toMatch(/file.*valid|valid.*file/i);
    expect(result.error?.message).toMatch(/LND|root key|issued/i);
    afterFailure(f, 'CheckMacaroonPermissions');
  }));

  it(`CP-024/B9 recovery records unverified entry before rendering exact registered ID command (${mode})`, async () => scratch(async path => {
    const f = fixture(path); inject(f, 'wrong permissions');
    const result = await invoke(f, mode === 'json' ? ['--json'] : []);
    stopped(f, result, 7, 'B12'); unverified(f, result);
    expect(f.events).toContain('save');
    expect(entries(f)[0]).toMatchObject({ verified: false, outPath: null });
    expect(render(result, mode)).toContain(`macwarden revoke ${f.state.chosen}`);
  }));

  it(`CP-024/B10 unexpected exception after bake send exits internal and prescribes inventory (${mode})`, async () => scratch(async path => {
    const f = fixture(path);
    f.lnd.bakeMacaroon.mockImplementationOnce(async (_permissions, id) => {
      f.calls.push('BakeMacaroon');
      f.state.chosen = id.toString();
      throw new TypeError(`unexpected fault ${readFileSync(own).toString('hex')}`);
    });
    const result = await invoke(f, mode === 'json' ? ['--json'] : []);
    stopped(f, result, 8, 'internal');
    expect(result.error?.message).toContain('macwarden inventory');
    afterFailure(f, 'BakeMacaroon');
    expect(entries(f)).toEqual([expect.objectContaining({rootKeyId:f.state.chosen,
      verified:false,fingerprint:null,outPath:null})]);
  }));

  it(`CP-024/B10 unexpected clock exception during B13 attenuation cleans reservation and prescribes inventory (${mode})`, async () => scratch(async path => {
    const f = fixture(path);
    f.deps.clock = () => {
      if (f.state.chosen) throw new TypeError('unexpected clock fault after issuance');
      return fixedClock();
    };
    const result = await invoke(f, ['--expires', '90d', ...(mode === 'json' ? ['--json'] : [])]);
    stopped(f, result, 8, 'internal');
    expect(result.error?.message).toContain('macwarden inventory');
    expect(f.state.writes).toBe(0);
    expect(f.lnd.checkMacaroon).not.toHaveBeenCalled();
    afterFailure(f, 'BakeMacaroon');
  }));
}

// Audit 1.3.2: as rotate and revoke, an unexpected failure after the send names the allocated root key ID and its recovery.
it('CP-024/B10 audit-1.3.2 unexpected exception after bake send names the allocated root key ID and its revoke command', async () => scratch(async path => {
  const f = fixture(path);
  f.deps.clock = () => {
    if (f.state.chosen) throw new TypeError('unexpected clock fault after issuance');
    return fixedClock();
  };
  const result = await invoke(f, ['--expires', '90d']);
  stopped(f, result, 8, 'internal');
  expect(result.error?.message).toContain(`LND may have changed; root key ID ${f.state.chosen}`);
  expect(result.error?.message).toContain('macwarden inventory');
  expect(result.error?.message).toContain(`recover with macwarden revoke ${f.state.chosen}`);
}));

it('CP-024/B4 ninety-day expiry drops fractional seconds, records request and is visible in inspect', async () => scratch(async path => {
  const f = fixture(path);
  const result = await invoke(f, ['--expires', '90d']);
  expect(result.error).toBeNull();
  expect(f.state.checked.equals(f.state.issued)).toBe(false);
  expect(readFileSync(f.out).equals(f.state.checked)).toBe(true);
  expect(entries(f)[0].caveats).toEqual([{ type: 'time-before', value: '2026-12-31T09:00:00Z', requested: '90d' }]);
  expect(decodeMacaroon(new Secret(readFileSync(f.out))).caveats.at(-1)).toMatchObject({
    type: 'time-before', value: '2026-12-31T09:00:00Z' });
  const inspected = spawnSync(process.execPath, [resolve('dist/bin.js'), 'inspect', f.out, '--json'],
    { cwd: repo, encoding: 'utf8', timeout: 10_000 });
  expect(inspected.status).toBe(0);
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'),
    sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), root: repo,
    commandOutput: inspected.stdout + inspected.stderr })).toBeNull();
  expect(JSON.parse(inspected.stdout).result.caveats).toContainEqual(expect.objectContaining({
    type: 'time-before', value: '2026-12-31T09:00:00Z' }));
  expect(f.state.checkedPermissions).toEqual(['info:read', 'invoices:read', 'invoices:write']);
}));

it('CP-024/B5 clock two days back with one-day expiry rejects final bytes before writing', async () => scratch(async path => {
  const f = fixture(path);
  f.deps.clock = () => new Date('2026-09-30T09:00:00.789Z');
  inject(f, 'rejected');
  const result = await invoke(f, ['--expires', '1d']);
  stopped(f, result, 7, 'B14'); unverified(f, result);
  expect(decodeMacaroon(new Secret(f.state.checked)).caveats.at(-1)).toMatchObject({
    type: 'time-before', value: '2026-10-01T09:00:00Z' });
  expect(f.state.writes).toBe(0);
}));

for (const mode of ['text', 'json'] as const) {
  for (const preset of Object.keys(presets) as Preset[]) {
    it(`CP-024/B8 ${preset} success writes verified final bytes and complete credential-free entry (${mode})`, async () => scratch(async path => {
      const f = fixture(path, preset);
      const result = await invoke(f, [...(mode === 'json' ? ['--json'] : []), '--expires', '90d']);
      expect(result.error).toBeNull();
      expect(f.calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'BakeMacaroon', 'CheckMacaroonPermissions']);
      expect(f.state.checkedPermissions.slice().sort()).toEqual(presets[preset].permissions.slice().sort());
      expect(f.state.checkedPermissions.length).toBeGreaterThan(0);
      expect(f.state.checked.equals(f.state.issued)).toBe(false);
      expect(readFileSync(f.out).equals(f.state.checked)).toBe(true);
      expect(f.state.flushed && f.state.closed).toBe(true);
      expect(f.events.indexOf('verify')).toBeLessThan(f.events.indexOf('write'));
      expect(f.events.indexOf('write')).toBeLessThan(f.events.indexOf('flush'));
      expect(f.events.indexOf('flush')).toBeLessThan(f.events.indexOf('close'));
      expect(f.events.indexOf('save')).toBeLessThan(f.events.indexOf('bake'));
      expect(f.events.indexOf('close')).toBeLessThan(f.events.lastIndexOf('save'));
      const entry = entries(f)[0];
      expect(entries(f)).toHaveLength(1);
      expect(entry).toEqual({ nodePubkey: pubkey, label: 'Alice', rootKeyId: f.state.chosen,
        permissions: f.state.checkedPermissions, caveats: [{ type: 'time-before',
          value: '2026-12-31T09:00:00Z', requested: '90d' }], grade: presets[preset].grade,
        fingerprint: fingerprint(readFileSync(f.out)), outPath: f.out,
        createdAt: expect.any(String), verified: true, status: 'active',
        revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null });
      expect(result.result).toEqual(entry);
      expect(Math.floor(Date.parse(String(entry.createdAt)) / 1000)).toBe(
        Math.floor(fixedClock().getTime() / 1000));
      expect(existsSync(`${f.registry}.lock`)).toBe(false);
      if (process.platform !== 'win32') {
        expect(statSync(f.out).mode & 0o777).toBe(0o600);
        expect(statSync(f.registry).mode & 0o777).toBe(0o600);
        expect(statSync(path).mode & 0o777).toBe(0o700);
      } else {
        const acl = spawnSync('icacls', [f.out], { encoding: 'utf8', timeout: 10_000 });
        expect(acl.status).toBe(0);
        expect(acl.stdout.includes('(I)')).toBe(false);
        expect(acl.stdout.includes(userInfo().username)).toBe(true);
      }
      if (mode === 'text') for (const expected of [f.state.chosen, presets[preset].grade,
        String(entry.fingerprint), 'time-before 2026-12-31T09:00:00Z', f.out, 'registry updated'])
        expect(render(result, mode)).toContain(expected);
      expect(decodeMacaroon(new Secret(readFileSync(f.out))).fingerprint).toBe(entry.fingerprint);
    }));
  }
}

it('CP-024/B8 explicit permissions and URI request preserves exact requested authority', async () => scratch(async path => {
  const f = fixture(path, 'pay-only');
  const requested = presets['pay-only'].permissions;
  f.args.splice(f.args.indexOf('--preset'), 2, '--permissions', 'info:read', '--uri',
    requested.filter(value => value.startsWith('uri:')).map(value => value.slice(4)).join(','));
  const result = await invoke(f, ['--json']);
  expect(result.error).toBeNull();
  expect(f.state.checkedPermissions.slice().sort()).toEqual(requested.slice().sort());
  expect(entries(f)[0]).toMatchObject({ verified: true, status: 'active', grade: 'SPEND', caveats: [] });
}));

it.each(Object.keys(presets) as Preset[])('CP-024/B11 %s sends preset authority unchanged to the issuer', async preset => scratch(async path => {
  const f = fixture(path, preset);
  const printed = JSON.parse(readFileSync(resolve(`test/vectors/preset-${preset}.printmacaroon.json`), 'utf8')) as {
    permissions: string[];
  };
  expect(presets[preset].permissions.slice().sort()).toEqual(printed.permissions.slice().sort());
  const result = await invoke(f);
  expect(result.error).toBeNull();
  expect(f.lnd.bakeMacaroon).toHaveBeenCalledTimes(1);
  expect(f.lnd.bakeMacaroon.mock.calls[0][0]).toEqual(presets[preset].permissions);
  // Actual authorization is established separately by the live lncli tests.
}));

it('CP-024/leak-check all unit credentials remain in registered or declared product files only', () => {
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'),
    sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), paths: [directory('MACWARDEN_TEST_TMP')],
    testTmp: directory('MACWARDEN_TEST_TMP'), root: repo })).toBeNull();
});
