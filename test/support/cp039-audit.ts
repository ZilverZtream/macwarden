import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { expect } from 'vitest';
import { Secret } from '../../src/secret.js';
import type { LndAdapter } from '../../src/lnd/index.js';
import { root, scratchDirectory } from './cp039-scratch.js';
export { root } from './cp039-scratch.js';

export const repo = resolve();
export const pubkey = '02' + 'ab'.repeat(32);
export const now = '2026-10-05T09:00:00.000Z';
export const sentinelPath = join(repo, 'test/sentinels/sentinel.macaroon');
export const sentinelList = join(repo, 'test/sentinels.json');
export const sentinel = () => readFileSync(sentinelPath);
export const fingerprint = (bytes: Uint8Array) => 'fp:' + createHash('sha256').update(bytes).digest('hex').slice(0, 16);
export async function scratch<T>(work: (dir: string) => T | Promise<T>): Promise<T> {
  const { dir, cleanup } = scratchDirectory();
  try { return await work(dir); }
  finally { cleanup(); }
}
export function declare(path: string): void { appendFileSync(join(root(), 'declared-out.txt'), path + '\n'); }
export function register(bytes: Buffer): string {
  const path = join(root('MACWARDEN_SENTINEL_DIR'), `cp039-${fingerprint(bytes).slice(3)}-${randomUUID()}.macaroon`);
  writeFileSync(path, bytes, { mode: 0o600, flag: 'wx' });
  return path;
}
// Structural fixture from ARCHITECTURE's v2/protobuf layout, with no LND acceptance claim.
export function wireMacaroon(permissions: string[], id: bigint): Buffer {
  const number = (value: number) => {
    const bytes: number[] = [];
    do { bytes.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value);
    return Buffer.from(bytes);
  };
  const field = (kind: number, bytes: Buffer) => Buffer.concat([number(kind), number(bytes.length), bytes]);
  const proto = (kind: number, bytes: Buffer) => field(kind * 8 + 2, bytes);
  const ops = permissions.map(permission => {
    const at = permission.indexOf(':');
    return proto(3, Buffer.concat([proto(1, Buffer.from(permission.slice(0, at))), proto(2, Buffer.from(permission.slice(at + 1)))]));
  });
  const identifier = Buffer.concat([Buffer.from([3]), proto(1, Buffer.alloc(16, 39)), proto(2, Buffer.from(String(id))), ...ops]);
  return Buffer.concat([Buffer.from([2]), field(1, Buffer.from('lnd')), field(2, identifier),
    Buffer.from([0, 0]), field(6, Buffer.alloc(32, 39))]);
}
type Vector = { name: string; file: string; fingerprint: string; canonicalLength: number; expectedGrade: string };
export function vector(name: string) {
  const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as { vectors: Vector[] };
  const row = manifest.vectors.find(v => v.name === name);
  if (!row) throw new Error('Missing committed vector metadata');
  const printed = JSON.parse(readFileSync(join(repo, 'test/vectors', `${name}.printmacaroon.json`), 'utf8')) as {
    root_key_id: string; permissions: string[]; caveats: string[] | null;
  };
  return { ...row, printed, bytes: readFileSync(join(repo, 'test/vectors', row.file)) };
}

// Independent audit encodings. No product parser or encoder defines these controls.
export function auditEncodings(bytes: Buffer): Array<[string, string | Buffer]> {
  const b64 = bytes.toString('base64');
  const separated = (separator: string) => [...bytes].map(b => b.toString(16).padStart(2, '0')).join(separator);
  const escape = (prefix: string, radix: number, width: number) => [...bytes].map(b => prefix + b.toString(radix).padStart(width, '0')).join('');
  return [
    ['latin1', bytes.toString('latin1')],
    ['JSON latin1', JSON.stringify(bytes.toString('latin1'))],
    ['unicode escapes', escape('\\u00', 16, 2)],
    ['hex escapes', escape('\\x', 16, 2)],
    ['octal escapes', escape('\\', 8, 3)],
    ['dash hex', separated('-')], ['comma hex', separated(',')], ['semicolon hex', separated(';')],
    ['indented base64', b64.match(/.{1,12}/g)!.map(line => '    ' + line).join('\n')],
    ...(['hex', 'base64'] as const).flatMap(encoding => {
      const le = Buffer.from(bytes.toString(encoding), 'utf16le');
      return [[`UTF16LE ${encoding}`, Buffer.concat([Buffer.from([255, 254]), le])],
        [`UTF16BE ${encoding}`, Buffer.concat([Buffer.from([254, 255]), Buffer.from(le).swap16()])]] as Array<[string, Buffer]>;
    }),
  ];
}
export function noCredential(text: string, bytes = sentinel(), soft = false): void {
  const assertion = soft ? expect.soft : expect;
  for (const [, value] of auditEncodings(bytes)) {
    if (typeof value === 'string') assertion(text.includes(value), 'recoverable credential encoding').toBe(false);
    else assertion(text.includes(value.toString('latin1')), 'recoverable UTF16 credential encoding').toBe(false);
  }
  for (const encoding of ['hex', 'base64', 'base64url'] as const)
    assertion(text.includes(bytes.toString(encoding)), 'credential bytes absent').toBe(false);
}

export class FakeLnd implements LndAdapter {
  calls: string[] = [];
  ids: bigint[] = [0n, 9001n, 9002n];
  info = { pubkey, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' };
  async getInfo() { this.calls.push('GetInfo'); return { ...this.info }; }
  async listPermissions(): Promise<Record<string, string[]>> { this.calls.push('ListPermissions'); return {}; }
  async listMacaroonIds() { this.calls.push('ListMacaroonIDs'); return [...this.ids]; }
  async bakeMacaroon(_permissions: string[], _id: bigint): Promise<Secret> {
    void _permissions; void _id;
    this.calls.push('BakeMacaroon'); throw new Error('Unexpected mutation in audit control');
  }
  async deleteMacaroonId(_id: bigint) { void _id; this.calls.push('DeleteMacaroonID'); return { deleted: false }; }
  async checkMacaroon(_mac: Secret, _permissions: string[]): ReturnType<LndAdapter['checkMacaroon']> {
    void _mac; void _permissions;
    this.calls.push('CheckMacaroonPermissions'); return { valid: true };
  }
}
export function entry(changes: Record<string, unknown> = {}) {
  const v = vector('preset-invoice-only');
  return { nodePubkey: pubkey, label: 'Alice', rootKeyId: '9001', permissions: v.printed.permissions,
    caveats: [], grade: v.expectedGrade, fingerprint: v.fingerprint, outPath: null,
    createdAt: '2026-10-02T09:00:00.000Z', verified: true, status: 'active', revokedAt: null,
    revokeEvidence: null, replaces: null, replacedBy: null, ...changes };
}
export function context(dir: string, entries: ReturnType<typeof entry>[] = []) {
  const registry = join(dir, 'registry.json'), out = join(dir, 'issued.macaroon');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
  declare(out);
  const lnd = new FakeLnd();
  const deps = { lnd, fs: { ...fs }, env: {} as Record<string, string>, clock: () => new Date(now),
    stdin: Object.assign(Readable.from([]), { isTTY: false }) };
  const online = ['--registry', registry, '--lnd-rest', 'localhost:1', '--tls-cert',
    join(repo, 'test/fixture/wrong-tls.cert'), '--macaroon', join(repo, 'test/vectors/default-admin.macaroon')];
  return { registry, out, lnd, deps, online };
}
