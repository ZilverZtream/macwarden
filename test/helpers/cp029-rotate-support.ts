import { adapter } from './adapter.js';
import { LndError } from '../../src/errors.js';
import type { LndAdapter } from '../../src/lnd/index.js';
import { revealSecret } from './secret-bytes.js';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { hostname } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { Readable } from 'node:stream';
import { expect, vi } from 'vitest';
import { Secret } from '../../src/secret.js';
import { decodeMacaroon } from '../../src/decode/index.js';
import { render } from './render-adversarial.js';
import { directory, entry, ownId, permissionsResponse, pubkey, register, wireFixture } from './cp026-revoke-support.mjs';
import { safe, scope, type Envelope } from './cp027-revoke-support.js';
import { expectSchemaValid } from './output-schema.js';

export { safe, scope, type Envelope };
export const instant = '2026-10-05T09:00:00.000Z';
export const oldId = '4294967328', newId = '4294967390';
export const prefix = ['GetInfo', 'ListPermissions', 'ListMacaroonIDs'];
export const fault = (kind = 'transport') => new LndError(kind === 'transport' ? 4 : 5,
  kind === 'transport' ? 'transport' : 'lnd', 'injected finish fault');
export function fixture(dir: string, name = 'preset-invoice-only') {
  const registry = join(dir, 'registry.json');
  const old = entry(name, oldId), next = entry(name, newId, { replaces: oldId });
  const other = entry('preset-read-only', '4294967329', { label: 'Bob' });
  const own = register(wireFixture('default-admin', ownId));
  const oldPath = old.outPath;
  const ids = ['0', oldId, newId, other.rootKeyId], calls: string[] = [], outputs: string[] = [];
  const state = { registryFails: false };
  const prompt = Object.assign(vi.fn(async (question: string) => {
    expect(existsSync(`${registry}.lock`)).toBe(false); outputs.push(question); return 'Alice' as string | null;
  }), { isTTY: true });
  const stdin = Object.assign(Readable.from(['Alice\n']), { isTTY: true });
  const listMacaroonIds = vi.fn(async () => {
    calls.push('ListMacaroonIDs'); return ([...ids]).map(BigInt);
  });
  // This is an injected dependency, not the acceptance oracle. Live tests use lncli.
  const checkMacaroon = vi.fn<LndAdapter['checkMacaroon']>(async (mac: Secret, permissions: string[], ...extra: unknown[]) => {
    const bytes = Buffer.from(revealSecret(mac)), decoded = decodeMacaroon(mac), id = String(decoded.rootKeyId);
    const row = id === oldId ? old : id === newId ? next : other;
    calls.push(`Check:${id}`);
    expect(bytes.equals(readFileSync(row.outPath))).toBe(true);
    expect(permissions).toEqual(decoded.permissions); expect(permissions.length).toBeGreaterThan(0);
    expect(extra).toEqual([]);
    return ids.includes(id) ? { valid: true as const } : { valid: false as const, reason: 'root-key-missing' as const,
      message: `root key with id ${id} doesn't exist` };
  });
  const lnd = {
    ...adapter({}),
    getInfo: vi.fn(async () => { calls.push('GetInfo'); return { alias: 'fixture', version: '0.21.4-beta', pubkey: pubkey, network: 'regtest' }; }),
    listPermissions: vi.fn(async () => { calls.push('ListPermissions'); return permissionsResponse(); }),
    listMacaroonIds,
    checkMacaroon,
    deleteMacaroonId: vi.fn(async (id: bigint) => {
      calls.push('DeleteMacaroonID'); expect(typeof id).toBe('bigint'); expect(id).not.toBe(0n);
      expect(existsSync(`${registry}.lock`)).toBe(true);
      expect(JSON.parse(readFileSync(`${registry}.lock`, 'utf8'))).toMatchObject({ pid: process.pid, hostname: hostname() });
      const index = ids.indexOf(String(id)); expect(index).toBeGreaterThanOrEqual(0);
      ids.splice(index, 1); return { deleted: true };
    }),
    bakeMacaroon: vi.fn(async () => { throw new Error('Finish and abandon must never bake'); }),
  } satisfies LndAdapter;
  const deps = { lnd, fs: { ...fs }, env: {} as Record<string, string>, clock: () => new Date(instant),
    prompt, stdin, stdout: { write: (text: string) => { outputs.push(text); return true; } } };
  deps.fs.open = vi.fn(fs.open);
  deps.fs.rename = vi.fn(async (...params: Parameters<typeof fs.rename>) => {
    if (params[1] === registry && state.registryFails) throw Object.assign(new Error('registry save fault'), { code: 'EACCES' });
    return fs.rename(...params);
  }) as typeof fs.rename;
  const args = ['Alice', '--finish', '--registry', registry, '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', own];
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [old, other, next] }), { mode: 0o600 });
  const rows = (): Array<Record<string, unknown>> => JSON.parse(readFileSync(registry, 'utf8')).entries;
  return { dir, registry, old, oldPath, next, other, own, ids, calls, outputs, state, prompt, stdin, lnd, deps, args, rows };
}
export type Fixture = ReturnType<typeof fixture>;
export async function scratch(work: (f: Fixture) => Promise<void>, name = 'preset-invoice-only') {
  const root = resolve(directory('MACWARDEN_TEST_TMP')), dir = mkdtempSync(join(root, 'cp029-unit-'));
  try { await work(fixture(dir, name)); } finally { cleanupScratch(dir, root); }
}
function cleanupScratch(dir: string, root: string) {
  if (!resolve(dir).startsWith(root + sep)) throw new Error('Unsafe scratch cleanup');
  rmSync(dir, { recursive: true, force: true });
}
export function save(f: Fixture, rows = [f.old, f.other, f.next]) {
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: rows }), { mode: 0o600 });
}
export function absent(f: Fixture, id = oldId) {
  const index = f.ids.indexOf(id); if (index >= 0) f.ids.splice(index, 1);
}
export function unchanged(f: Fixture, before: Buffer) { expect(readFileSync(f.registry).equals(before)).toBe(true); }
export function released(f: Fixture) { expect(existsSync(`${f.registry}.lock`)).toBe(false); }
export function failure(result: Envelope, code: number, step: string) {
  expect(result.error).toMatchObject({ code, step }); expect(result.result).toBeNull();
  expect(result.error!.message.length).toBeGreaterThan(0); expect(render(result, 'text')).toContain(step);
}
export async function invoke(f: Fixture, flags = ['--yes'], command = 'rotate', target = 'Alice'): Promise<Envelope> {
  const path = `../../src/commands/${command}.js`;
  const module = await import(/* @vite-ignore */ path) as { run(args: string[], deps: unknown): Promise<Envelope> };
  const args = command === 'rotate' ? [...f.args, ...flags] :
    [target, ...f.args.slice(2), ...flags];
  const oldBytes = readFileSync(f.oldPath), newPath = f.next.outPath;
  const newBytes = newPath && existsSync(newPath) ? readFileSync(newPath) : null;
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((value: unknown) => {
    f.outputs.push(String(value)); return true;
  }) as typeof process.stdout.write);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((value: unknown) => {
    f.outputs.push(String(value)); return true;
  }) as typeof process.stderr.write);
  let result: Envelope;
  try { result = await module.run(args, f.deps); } finally { stdout.mockRestore(); stderr.mockRestore(); }
  expect(result).toMatchObject({ schema: 1, command, ok: result.error === null });
  expectSchemaValid(result);
  expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  expect(f.lnd.deleteMacaroonId.mock.calls.length).toBeLessThanOrEqual(1);
  for (const [id] of f.lnd.deleteMacaroonId.mock.calls) expect(id).toBe(BigInt(command === 'revoke' ? newId : oldId));
  expect(readFileSync(f.oldPath).equals(oldBytes)).toBe(true);
  if (newBytes) expect(readFileSync(newPath).equals(newBytes)).toBe(true);
  safe(f.outputs.join('') + render(result, 'text') + render(result, 'json'), [f.dir]);
  return result;
}
export function success(f: Fixture, result: Envelope, evidence = 'rejected', repaired = false) {
  expect(result.error).toBeNull();
  const old = { ...f.old, status: 'revoked', revokedAt: instant, revokeEvidence: evidence, replacedBy: newId };
  expect(result.result).toEqual({ stage: 'finished', old, new: f.next, evidence, repaired });
  expect(f.rows()).toEqual([old, f.other, f.next]);
  expect(f.ids).not.toContain(oldId); expect(f.ids).toContain(newId);
  const text = render(result, 'text'); expect(text.trimEnd().endsWith(scope)).toBe(true);
  for (const value of [oldId, newId]) expect(text).toContain(value);
  expect(JSON.parse(render(result, 'json'))).toEqual(result); released(f);
}
export function afterFailure(f: Fixture, call: string) {
  const tail = f.calls.slice(f.calls.indexOf(call) + 1);
  expect(tail.length).toBeLessThanOrEqual(1); expect(tail.every(name => name === 'ListMacaroonIDs')).toBe(true);
}
