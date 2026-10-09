import { adapter } from './adapter.js';
import { LndError } from '../../src/errors.js';
import type { LndAdapter } from '../../src/lnd/index.js';
import { revealSecret } from './secret-bytes.js';
import { constants, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { expect, vi } from 'vitest';
import { Secret } from '../../src/secret.js';
import { decodeMacaroon } from '../../src/decode/index.js';
import { render } from './render-adversarial.js';
import { findLeaks } from "./leak-check.js";
import { declare, directory, entry, ownId, permissionsResponse, pubkey, register, wireFixture } from './cp026-revoke-support.mjs';
import { expectSchemaValid } from './output-schema.js';

const exclusiveReopen = constants.O_RDWR | 0x10000000;
function expectOutOpen(count: number, flags: unknown[]): void {
  // POSIX creates the file with O_EXCL 0600. On Windows the System32 helper creates it owner-only
  // and the only open by macwarden is the exclusive one that receives the bytes (SAFE-06).
  expect(count).toBe(1);
  expect(flags).toEqual(process.platform === 'win32' ? [exclusiveReopen] : ['wx', 0o600]);
}


export type Envelope = { schema: number; command: string; ok: boolean;
  warnings: Array<string | { code: string; message?: string }>;
  result: Record<string, unknown> | null; error: { code: number; step: string; message: string } | null };
export const instant = '2026-10-05T09:00:00.789Z';
export const oldId = '4294967328', newId = '4294967390';
export const fault = (kind = 'transport') => new LndError(kind === 'transport' ? 4 : 5, kind === 'transport' ? 'transport' : 'lnd', 'injected stage fault');
export const fingerprint = (bytes: Buffer) => 'fp:' + createHash('sha256').update(bytes).digest('hex').slice(0, 16);
export function fixture(dir: string, name = 'preset-invoice-only') {
  const registry = join(dir, 'registry.json'), out = join(dir, 'replacement.macaroon');
  declare(out);
  const old = entry(name, oldId), other = entry('preset-read-only', '4294967329', { label: 'Bob' });
  const own = register(wireFixture('default-admin', ownId));
  const oldBytesPath = old.outPath;
  const calls: string[] = [], events: string[] = [], outputs: string[] = [];
  const state = { ids: ['0', old.rootKeyId, other.rootKeyId], chosen: '',
    issued: Buffer.alloc(0), checked: Buffer.alloc(0), accepted: false,
    responseId: null as string | null, responsePermissions: null as string[] | null, corrupt: false,
    registryFails: false, writeFault: null as 'write' | 'flush' | 'close' | null,
    failedAt: null as number | null,
    handle: undefined as Awaited<ReturnType<typeof fs.open>> | undefined };
  const lnd = {
    ...adapter({}),
    getInfo: vi.fn(async () => { calls.push('GetInfo');
      const dry = args.includes('--dry-run');
      if (!dry) expect(existsSync(`${registry}.lock`)).toBe(true);
      expect(existsSync(out)).toBe(!dry);
      if (!dry) { expect(statSync(out).size).toBe(0); expect(state.handle!.fd).toBeGreaterThanOrEqual(0); }
      return { alias: 'fixture', version: '0.21.4-beta', pubkey: pubkey, network: 'regtest' };
    }),
    listPermissions: vi.fn(async () => { calls.push('ListPermissions'); return permissionsResponse(); }),
    listMacaroonIds: vi.fn(async () => { calls.push('ListMacaroonIDs'); return ([...state.ids]).map(BigInt); }),
    bakeMacaroon: vi.fn(async (requested: string[], id: bigint, ...extra: unknown[]) => {
      calls.push('BakeMacaroon'); events.push('bake');
      expect(requested.slice().sort()).toEqual(old.permissions.slice().sort());
      expect(typeof id).toBe('bigint'); expect(id >= 4294967296n && id <= 9223372036854775807n).toBe(true);
      expect(state.ids).not.toContain(String(id));
      expect(rows().find(row => row.rootKeyId === String(id))).toMatchObject({
        verified: false, fingerprint: null, outPath: null, replaces: old.rootKeyId });
      expect(extra).not.toContain(true);
      state.chosen = String(id); state.ids.push(state.chosen);
      state.issued = state.corrupt ? readFileSync(resolve('test/vectors/negative/truncated-protobuf.macaroon')) :
        wireFixture(name, state.responseId ?? state.chosen, state.responsePermissions ?? requested);
      register(state.issued); return new Secret(state.issued);
    }),
    checkMacaroon: vi.fn<LndAdapter['checkMacaroon']>(async (mac: Secret, permissions: string[], ...extra: unknown[]) => {
      calls.push('CheckMacaroonPermissions');
      const bytes = Buffer.from(revealSecret(mac)); register(bytes);
      expect(permissions.slice().sort()).toEqual(old.permissions.slice().sort());
      expect(permissions.length).toBeGreaterThan(0); expect(extra).toEqual([]);
      const decoded = decodeMacaroon(mac);
      expect(decoded.permissions.slice().sort()).toEqual(permissions.slice().sort());
      if (bytes.equals(readFileSync(oldBytesPath))) {
        expect(String(decoded.rootKeyId)).toBe(old.rootKeyId);
        expect(decoded.fingerprint).toBe(old.fingerprint);
        return { valid: true as const };
      }
      expect(state.chosen).not.toBe('');
      expect(String(decoded.rootKeyId)).toBe(state.chosen);
      expect(state.ids).toContain(state.chosen);
      events.push('verify'); state.checked = bytes;
      state.accepted = true; return { valid: true as const };
    }),
    deleteMacaroonId: vi.fn(async () => { calls.push('DeleteMacaroonID'); throw new Error('Stage must never delete'); }),
  } satisfies LndAdapter;
  const deps = { lnd: { ...lnd,  },
    fs: { ...fs }, env: {} as Record<string, string>, clock: () => new Date(instant) };
  let outOpens = 0;
  deps.fs.open = vi.fn(async (...params: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...params);
    if (params[0] !== out) return handle;
    if (++outOpens === 1) events.push('reserve');
    expectOutOpen(outOpens, params.slice(1));
    state.handle = handle;
    return new Proxy(handle, { get(target, key) {
      const value = Reflect.get(target, key, target);
      if (['write', 'writeFile', 'writev'].includes(String(key))) return async (...values: unknown[]) => {
        events.push('write'); expect(state.accepted).toBe(true);
        if (state.writeFault === 'write') { await target.write(state.checked.subarray(0, 8)); state.failedAt = calls.length - 1; throw Object.assign(new Error('partial write fault'), { code: 'EIO' }); }
        return Reflect.apply(value, target, values);
      };
      if (key === 'sync' || key === 'datasync') return async () => {
        events.push('flush'); if (state.writeFault === 'flush') { state.failedAt = calls.length - 1; throw Object.assign(new Error('flush fault'), { code: 'EIO' }); }
        return Reflect.apply(value, target, []);
      };
      if (key === 'close') return async () => {
        events.push('close'); await target.close();
        if (state.writeFault === 'close') { state.failedAt = calls.length - 1; state.writeFault = null; throw Object.assign(new Error('close fault'), { code: 'EIO' }); }
      };
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  }) as typeof fs.open;
  deps.fs.rename = vi.fn(async (...params: Parameters<typeof fs.rename>) => {
    if (params[1] === registry) {
      events.push('save'); if (state.registryFails && events.includes('bake')) throw Object.assign(new Error('registry save fault'), { code: 'EACCES' });
    }
    return fs.rename(...params);
  }) as typeof fs.rename;
  const args = ['Alice', '--out', out, '--registry', registry, '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', own];
  function rows(): Array<Record<string, unknown>> { return JSON.parse(readFileSync(registry, 'utf8')).entries; }
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [old, other] }), { mode: 0o600 });
  return { dir, registry, out, old, oldBytesPath, other, own, calls, events, outputs, state, lnd, deps, args, rows };
}
export type Fixture = ReturnType<typeof fixture>;
export async function scratch(work: (f: Fixture) => Promise<void>, name = 'preset-invoice-only') {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'cp028-unit-'));
  const f = fixture(dir, name);
  try {
    const decoded = decodeMacaroon(new Secret(readFileSync(f.old.outPath)));
    expect(String(decoded.rootKeyId)).toBe(f.old.rootKeyId);
    expect(decoded.permissions.slice().sort()).toEqual(f.old.permissions.slice().sort());
    expect(decoded.fingerprint).toBe(f.old.fingerprint);
    await work(f);
  } finally {
    if (f.state.handle && f.state.handle.fd !== -1) await f.state.handle.close();
  }
}
export function save(f: Fixture, entries = [f.old, f.other]) {
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
}
export function safe(output: string, paths: string[]) {
  expect(findLeaks({ root: resolve(), sentinels: resolve('test/sentinels.json'),
    sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), testTmp: directory('MACWARDEN_TEST_TMP'), commandOutput: output, paths })).toBeNull();
}
export async function invoke(f: Fixture, flags: string[] = []): Promise<Envelope> {
  f.args.push(...flags);

  const command = await import('../../src/commands/rotate.js') as { run(args: string[], deps: unknown): Promise<Envelope> };
  const before = readFileSync(f.oldBytesPath);
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((value: unknown) => { f.outputs.push(String(value)); return true; }) as typeof process.stdout.write);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((value: unknown) => { f.outputs.push(String(value)); return true; }) as typeof process.stderr.write);
  let result: Envelope;
  try { result = await command.run(f.args, f.deps); } finally { stdout.mockRestore(); stderr.mockRestore(); }
  expect(result).toMatchObject({ schema: 1, command: 'rotate', ok: result.error === null });
  expectSchemaValid(result);
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
  expect(f.state.ids).toContain(oldId); expect(readFileSync(f.oldBytesPath).equals(before)).toBe(true);
  safe(f.outputs.join('') + render(result, 'text') + render(result, 'json'), [f.dir]);
  return result;
}
export function failure(f: Fixture, result: Envelope, code: number, step: string, keepOut = false) {
  expect(result.error).toMatchObject({ code, step }); expect(result.result).toBeNull();
  expect(result.error!.message.length).toBeGreaterThan(0); expect(render(result, 'text')).toContain(step);
  expect(existsSync(f.out)).toBe(keepOut); expect(existsSync(`${f.registry}.lock`)).toBe(false);
  if (f.state.handle) expect(f.state.handle.fd).toBe(-1);
}
export function unchanged(f: Fixture, bytes: Buffer) { expect(readFileSync(f.registry).equals(bytes)).toBe(true); }
export function recovery(f: Fixture, result: Envelope) {
  const rows = f.rows(); expect(rows).toContainEqual(f.old); expect(rows).toContainEqual(f.other);
  const next = rows.find(row => row.rootKeyId === f.state.chosen);
  if (f.state.registryFails) expect(next).toMatchObject({ nodePubkey: pubkey,
    label: f.old.label, rootKeyId: f.state.chosen, status: 'active', verified: false,
    fingerprint: null, outPath: null, replaces: f.old.rootKeyId });
  else expect(next).toMatchObject({ nodePubkey: pubkey, label: f.old.label, rootKeyId: f.state.chosen,
    status: 'active', verified: false, outPath: null, replaces: f.old.rootKeyId });
  const command = `macwarden revoke ${f.state.chosen}`;
  expect(render(result, 'text')).toContain(command); expect(render(result, 'json')).toContain(command);
  expect(result.error!.message).not.toContain('macwarden revoke Alice');
}
export function afterFailure(f: Fixture, name: string) {
  const index = f.state.failedAt ?? f.calls.indexOf(name);
  expect(index).toBeGreaterThanOrEqual(0);
  const tail = f.calls.slice(index + 1);
  expect(tail.length).toBeLessThanOrEqual(1); expect(tail.every(call => call === 'ListMacaroonIDs')).toBe(true);
}
