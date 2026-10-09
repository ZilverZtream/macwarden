import { adapter } from './adapter.js';
import { LndError } from '../../src/errors.js';
import type { LndAdapter } from '../../src/lnd/index.js';
import type { Secret } from '../../src/secret.js';
import { revealSecret } from './secret-bytes.js';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { hostname } from 'node:os';
import { Readable } from 'node:stream';
import { join, resolve } from 'node:path';
import { expect, vi } from 'vitest';
import { render } from './render-adversarial.js';
import { findLeaks } from "./leak-check.js";
import { expectSchemaValid } from './output-schema.js';
import { directory, entry, maxId, ownId, permissionsResponse, pubkey, register,
  wireFixture } from './cp026-revoke-support.mjs';

export type Envelope = { schema: number; command: string; ok: boolean; warnings: Array<string | {code:string;message?:string}>;
  result: Record<string, unknown> | null; error: { code: number; step: string | null; message: string } | null };
export const instant = '2026-10-05T00:00:00.000Z';
export const scope = 'New requests with this macaroon are now rejected. Streams opened before the revoke stay open until they disconnect; if the credential may be compromised, restart LND.';
export const prefix = ['GetInfo', 'ListPermissions', 'ListMacaroonIDs'];
export const onlineFault = () => new LndError(4, 'transport', 'injected connection loss');
export function fixture(dir: string) {
  const registry = join(dir, 'registry.json'), target = entry();
  const own = register(wireFixture('default-admin', ownId));
  const other = entry('preset-invoice-only', '9007199254740993', { label: 'Bob' });
  const ids = ['0', maxId, other.rootKeyId], calls: string[] = [], outputs: string[] = [];
  const prompt = Object.assign(vi.fn(async (question: string) => {
    expect(existsSync(`${registry}.lock`)).toBe(false); outputs.push(question); return 'Alice' as string | null;
  }), { isTTY: true });
  const stdin = Object.assign(Readable.from(['Alice\n']), { isTTY: true });
  const listMacaroonIds = vi.fn(async () => {
    calls.push('ListMacaroonIDs'); return ([...ids]).map(BigInt);
  });
  const checkMacaroon = vi.fn<LndAdapter['checkMacaroon']>(async (mac: Secret, perms: string[], ...extra: unknown[]) => {
    calls.push('CheckMacaroonPermissions');
    expect(Buffer.from(revealSecret(mac)).equals(readFileSync(target.outPath))).toBe(true);
    expect(perms).toEqual(target.permissions); expect(perms.length).toBeGreaterThan(0); expect(extra).toEqual([]);
    return ids.includes(target.rootKeyId) ? { valid: true as const } :
      { valid: false as const, reason: 'root-key-missing' as const, message: `root key with id ${target.rootKeyId} doesn't exist` };
  });
  const deleteMacaroonId = vi.fn(async (id: bigint) => {
    calls.push('DeleteMacaroonID');
    expect(typeof id).toBe('bigint'); expect(String(id)).toBe(target.rootKeyId); expect(id).not.toBe(0n);
    expect(existsSync(`${registry}.lock`)).toBe(true);
    const lock = JSON.parse(readFileSync(`${registry}.lock`, 'utf8'));
    expect(lock).toMatchObject({ pid: process.pid, hostname: hostname() });
    expect(Number.isFinite(Date.parse(lock.startedAt))).toBe(true);
    expect(JSON.parse(readFileSync(registry, 'utf8')).entries.find((row: Record<string, unknown>) =>
      row.rootKeyId === target.rootKeyId && row.nodePubkey === pubkey).status).toBe('active');
    ids.splice(ids.indexOf(String(id)), 1); return { deleted: true };
  });
  const lnd = {
    ...adapter({}),
    getInfo: vi.fn(async () => { calls.push('GetInfo'); return { alias: 'fixture', network: 'regtest', version: '0.21.4-beta', pubkey: pubkey }; }),
    listPermissions: vi.fn(async () => { calls.push('ListPermissions'); return permissionsResponse(); }),
    listMacaroonIds,
    checkMacaroon, deleteMacaroonId,
    bakeMacaroon: vi.fn(async () => { throw new Error('Revoke must never bake'); }),
  } satisfies LndAdapter;
  const deps = { lnd, fs: { ...fs }, env: {} as Record<string, string>, clock: () => new Date(instant),
    prompt, stdin, stdout: { write: (text: string) => { outputs.push(text); return true; } } };
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [target, other] }), { mode: 0o600 });
  return { dir, registry, target, other, own, ids, calls, outputs, prompt, stdin, lnd, deps };
}
export type Fixture = ReturnType<typeof fixture>;
export async function scratch(work: (f: Fixture) => Promise<void>) {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'cp027-unit-'));
  try { await work(fixture(dir)); } finally { rmSync(dir, { recursive: true, force: true }); }
}
export function save(f: Fixture, rows = [f.target, f.other]) {
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: rows }), { mode: 0o600 });
}
export function absent(f: Fixture) { f.ids.splice(f.ids.indexOf(f.target.rootKeyId), 1); }
export function bytes(f: Fixture) { return readFileSync(f.registry); }
export function unchanged(f: Fixture, before: Buffer) { expect(bytes(f).equals(before)).toBe(true); }
export async function invoke(f: Fixture, flags = ['--yes'], target = 'Alice'): Promise<Envelope> {

  const command = await import('../../src/commands/revoke.js') as { run(args: string[], deps: unknown): Promise<Envelope> };
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((value: unknown) => {
    f.outputs.push(String(value)); return true;
  }) as typeof process.stdout.write);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((value: unknown) => {
    f.outputs.push(String(value)); return true;
  }) as typeof process.stderr.write);
  let result: Envelope;
  try { result = await command.run([target, '--registry', f.registry, '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', f.own, ...flags], f.deps); }
  finally { stdout.mockRestore(); stderr.mockRestore(); }
  expect(result).toMatchObject({ schema: 1, command: 'revoke', ok: result.error === null });
  expectSchemaValid(result);
  expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  expect(f.lnd.deleteMacaroonId.mock.calls.length).toBeLessThanOrEqual(1);
  for (const [id] of f.lnd.deleteMacaroonId.mock.calls) expect(id).toBe(BigInt(f.target.rootKeyId));
  safe(f.outputs.join('') + render(result, 'text') + render(result, 'json'), [f.dir]);
  return result;
}
export function safe(output: string, paths: string[]) {
  expect(findLeaks({ root: resolve(), sentinels: resolve('test/sentinels.json'),
    sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), testTmp: directory('MACWARDEN_TEST_TMP'),
    commandOutput: output, paths })).toBeNull();
}
export function failure(result: Envelope, code: number, step: string) {
  expect(result.error).toMatchObject({ code, step }); expect(result.result).toBeNull();
  expect(result.error!.message.length).toBeGreaterThan(0);
  const text = render(result, 'text'); expect(text).toContain(step);
  expect(text).not.toMatch(/^\s+at\s+.*:\d+/m);
}
export function released(f: Fixture) { expect(existsSync(`${f.registry}.lock`)).toBe(false); }
export function success(f: Fixture, result: Envelope, evidence = 'rejected', repaired = false, label: string | null = 'Alice') {
  expect(result.error).toBeNull();
  expect(result.result).toMatchObject({ rootKeyId: f.target.rootKeyId, label, evidence, repaired });
  const row = result.result!.entry as Record<string, unknown>;
  expect(row).toMatchObject({ nodePubkey: pubkey, rootKeyId: f.target.rootKeyId, label,
    status: 'revoked', revokedAt: expect.any(String), revokeEvidence: evidence });
  expect(Date.parse(String(row.revokedAt))).toBe(Date.parse(instant));
  const stored = JSON.parse(bytes(f).toString('utf8')).entries;
  expect(stored.find((item: Record<string, unknown>) => item.rootKeyId === row.rootKeyId && item.nodePubkey === pubkey)).toEqual(row);
  expect(stored.find((item: Record<string, unknown>) => item.rootKeyId === f.other.rootKeyId)).toEqual(f.other);
  expect(f.ids).not.toContain(f.target.rootKeyId); expect(f.ids).toContain(f.other.rootKeyId);
  const text = render(result, 'text'); expect(text.trimEnd().endsWith(scope)).toBe(true);
  expect(text).toContain(f.target.rootKeyId);
  expect(text.split('\n')).toContain(evidence === 'rejected' ? 'proof    ID absent from LND; macaroon rejected' : 'proof    ID absent from LND (verified by ID only)');
  if (repaired) expect(text).toMatch(/already absent/i);
  expect(JSON.parse(render(result, 'json'))).toMatchObject({ schema: 1, command: 'revoke', ok: true, error: null, result: result.result });
  released(f);
}
