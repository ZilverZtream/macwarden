import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { isAbsolute, join, resolve } from 'node:path';
import { Secret } from '../../src/secret.js';
import { decodeMacaroon } from '../../src/decode/index.js';
import { Readable } from 'node:stream';
import type { LndAdapter } from '../../src/lnd/index.js';
// Independent v2 wire response for injected unit adapters, derived from stored lncli facts.
export function responseBytes(id: bigint, permissions: string[]): Buffer {
  function varint(value: number): Buffer {
    const result: number[] = [];
    do { result.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value);
    return Buffer.from(result);
  }
  const field = (tag: number, value: Buffer) => Buffer.concat([varint(tag), varint(value.length), value]);
  const proto = (tag: number, value: Buffer) => field((tag << 3) | 2, value);
  const operations = permissions.map(permission => {
    const at = permission.indexOf(':');
    return proto(3, Buffer.concat([proto(1, Buffer.from(permission.slice(0, at))), proto(2, Buffer.from(permission.slice(at + 1)))]));
  });
  const identifier = Buffer.concat([Buffer.from([3]), proto(1, Buffer.alloc(16, 38)), proto(2, Buffer.from(String(id))), ...operations]);
  const source = vector('preset-invoice-only').bytes;
  return Buffer.concat([Buffer.from([2]), field(1, Buffer.from('lnd')), field(2, identifier), Buffer.from([0, 0]), field(6, source.subarray(source.length - 32))]);
}

export const pubkey = '02' + 'ab'.repeat(32);
export const ownId = 23038n, oldId = 4294967341n, nextId = 4294967342n;
export const instant = '2026-10-05T12:00:00Z';
export type Entry = {
  nodePubkey: string; label: string | null; rootKeyId: string; permissions: string[];
  caveats: { type: string; value: string; requested?: string }[]; grade: string;
  fingerprint: string | null; outPath: string | null; createdAt: string; verified: boolean;
  status: 'active' | 'revoked'; revokedAt: string | null; revokeEvidence: string | null;
  replaces: string | null; replacedBy: string | null;
};
type Vector = { name: string; file: string; expectedGrade: string; fingerprint: string };
export function vector(name: string) {
  const manifest = JSON.parse(readFileSync(resolve('test/vectors/manifest.json'), 'utf8')) as { vectors: Vector[] };
  const row = manifest.vectors.find(item => item.name === name);
  if (!row) throw new Error('Missing committed reference');
  const printed = JSON.parse(readFileSync(resolve('test/vectors', name + '.printmacaroon.json'), 'utf8')) as {
    root_key_id: string; permissions: string[];
  };
  return { ...row, ...printed, bytes: readFileSync(resolve('test/vectors', row.file)) };
}
export function root(variable: 'MACWARDEN_TEST_TMP' | 'MACWARDEN_SENTINEL_DIR'): string {
  const supplied = process.env[variable];
  if (!supplied || !isAbsolute(supplied)) throw new Error('Required absolute harness root missing');
  mkdirSync(supplied, { recursive: true, mode: 0o700 });
  return resolve(supplied);
}
export function declare(path: string): void {
  appendFileSync(join(root('MACWARDEN_TEST_TMP'), 'declared-out.txt'), path + '\n');
}
export function register(bytes: Uint8Array): string {
  const hash = createHash('sha256').update(bytes).digest('hex').slice(0, 16);
  const path = join(root('MACWARDEN_SENTINEL_DIR'), `cp038-${process.pid}-${hash}.macaroon`);
  writeFileSync(path, bytes, { mode: 0o600 });
  declare(path);
  return path;
}
// Only normalized public adapter shapes. Unit acceptance is injected, never an oracle claim.
export class FakeLnd implements LndAdapter {
  calls: string[] = [];
  ids: bigint[] = [0n, oldId, nextId];
  baked: bigint[] = [];
  deleted: bigint[] = [];
  info = { pubkey, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' };
  infoFault: Error | null = null;
  verificationFault: Error | null = null;
  verifyValid = true;
  onBake: ((id: bigint) => void | Promise<void>) | null = null;
  async getInfo(): ReturnType<LndAdapter['getInfo']> {
    this.calls.push('GetInfo');
    if (this.infoFault) throw this.infoFault;
    return { ...this.info };
  }
  async listMacaroonIds(): ReturnType<LndAdapter['listMacaroonIds']> {
    this.calls.push('ListMacaroonIDs'); return [...this.ids];
  }
  async listPermissions(): ReturnType<LndAdapter['listPermissions']> {
    this.calls.push('ListPermissions');
    return { '/lnrpc.Lightning/GetInfo': ['info:read'] };
  }
  async bakeMacaroon(perms: string[], id: bigint): ReturnType<LndAdapter['bakeMacaroon']> {
    this.calls.push('BakeMacaroon'); this.baked.push(id); this.ids.push(id);
    await this.onBake?.(id);
    const bytes = responseBytes(id, perms) as Buffer;
    register(bytes); return new Secret(bytes);
  }
  async deleteMacaroonId(id: bigint): ReturnType<LndAdapter['deleteMacaroonId']> {
    this.calls.push('DeleteMacaroonID'); this.deleted.push(id);
    this.ids = this.ids.filter(item => item !== id); return { deleted: true };
  }
  async checkMacaroon(_mac: Secret, perms: string[]): ReturnType<LndAdapter['checkMacaroon']> {
    this.calls.push('CheckMacaroonPermissions');
    if (!perms.length) throw new Error('Empty verification permission list');
    if (this.verificationFault) throw this.verificationFault;
    if (!this.ids.includes(decodeMacaroon(_mac).rootKeyId))
      return { valid: false as const, reason: 'root-key-missing', message: 'injected missing target root key' };
    return this.verifyValid ? { valid: true } : { valid: false as const, reason: 'other' as const, message: 'injected verification refusal' };
  }
}
export function entry(id: bigint, label = 'Alice', replaces: string | null = null): Entry {
  const reference = vector('preset-invoice-only');
  const bytes = responseBytes(id, reference.permissions) as Buffer;
  return { nodePubkey: pubkey, label, rootKeyId: String(id), permissions: reference.permissions,
    caveats: [], grade: reference.expectedGrade,
    fingerprint: 'fp:' + createHash('sha256').update(bytes).digest('hex').slice(0, 16),
    outPath: register(bytes), createdAt: instant, verified: true, status: 'active',
    revokedAt: null, revokeEvidence: null, replaces, replacedBy: null };
}
export function fixture() {
  const dir = mkdtempSync(join(root('MACWARDEN_TEST_TMP'), 'cp038-'));
  const registry = join(dir, 'registry.json'), out = join(dir, 'replacement.macaroon');
  declare(out);
  const own = register(responseBytes(ownId, vector('default-admin').permissions) as Buffer);
  const old = entry(oldId), next = entry(nextId, 'Alice', String(oldId));
  const lnd = new FakeLnd();
  const deps = { lnd, fs: { ...fs }, env: {}, clock: () => new Date(instant),
    prompt: Object.assign(async (_question: string) => { void _question; return 'Alice'; }, { isTTY: true }),
    stdin: Object.assign(Readable.from([]), { isTTY: true }) };
  const flags = ['--registry', registry, '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', own];
  function save(entries: Entry[] = [old]) {
    writeFileSync(registry, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
  }
  function rows(): Entry[] { return (JSON.parse(readFileSync(registry, 'utf8')) as { entries: Entry[] }).entries; }
  save();
  return { dir, registry, out, own, old, next, flags, lnd, deps, save, rows };
}
export type Fixture = ReturnType<typeof fixture>;

const stagingDirs = new Set<string>();
/** Registers a directory that respond or rotate writes replacement credentials into. */
export function declareStaging(dir: string): string { stagingDirs.add(dir); return dir; }
/** Declares every credential file left in a registered staging directory (call after each test). */
export function declareStagedFiles(): void {
  for (const dir of stagingDirs) {
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir)) if (name.endsWith('.macaroon')) declare(join(dir, name));
  }
  stagingDirs.clear();
}
