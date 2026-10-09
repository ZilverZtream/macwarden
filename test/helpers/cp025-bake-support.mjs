import { revealSecret } from '../../src/secret-capability.js';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';

export const pubkey = '02' + 'ab'.repeat(32);
export const permissions = JSON.parse(readFileSync(resolve('test/vectors/preset-invoice-only.printmacaroon.json'), 'utf8')).permissions;
export function directory(variable) {
  if (!process.env[variable]) throw new Error(`${variable} is required`);
  const path = resolve(process.env[variable]);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}
export function declare(path) {
  appendFileSync(join(directory('MACWARDEN_TEST_TMP'), 'declared-out.txt'), `${path}\n`);
}
export function register(bytes) {
  const fingerprint = createHash('sha256').update(bytes).digest('hex').slice(0, 16);
  const path = join(directory('MACWARDEN_SENTINEL_DIR'), `cp025-${process.pid}-${fingerprint}.macaroon`);
  writeFileSync(path, bytes, { mode: 0o600 });
  declare(path);
  return path;
}
function varint(value) {
  const bytes = [];
  do { bytes.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value);
  return Buffer.from(bytes);
}
function field(kind, bytes) { return Buffer.concat([varint(kind), varint(bytes.length), bytes]); }
function proto(kind, bytes) { return field((kind << 3) | 2, bytes); }
// Independent faulty-adapter wire fixture. Only the live lncli probe proves acceptance.
export function responseBytes(id, requested = permissions) {
  const source = readFileSync(resolve('test/vectors/preset-invoice-only.macaroon'));
  const ops = requested.map(permission => {
    const at = permission.indexOf(':');
    return proto(3, Buffer.concat([proto(1, Buffer.from(permission.slice(0, at))),
      proto(2, Buffer.from(permission.slice(at + 1)))]));
  });
  const identifier = Buffer.concat([Buffer.from([3]), proto(1, Buffer.alloc(16, 25)),
    proto(2, Buffer.from(String(id))), ...ops]);
  return Buffer.concat([Buffer.from([2]), field(1, Buffer.from('lnd')), field(2, identifier),
    Buffer.from([0, 0]), field(6, source.subarray(source.length - 32))]);
}
export function fixture(path, Secret, label = 'Alice', filename = 'candidate.macaroon') {
  const registry = join(path, 'registry.json'), out = join(path, filename);
  declare(out);
  const own = register(readFileSync(resolve('test/vectors/default-admin.macaroon')));
  const snapshot = JSON.parse(readFileSync(resolve('src/grade/lnd-permissions.json'), 'utf8'));
  /** @type {{ids:string[], issued:Buffer|null, checked:Buffer|null, calls:string[], handle:import('node:fs/promises').FileHandle|null, lockAtNetwork:{pid:number,hostname:string,startedAt:string}|null, reservedAtNetwork:boolean}} */
  const state = { ids: ['0'], issued: null, checked: null, calls: [], handle: null,
    lockAtNetwork: null, reservedAtNetwork: false };
  /** @type {import('../../src/lnd/index.js').LndAdapter} */
  const lnd = {
    getInfo: async () => {
      state.calls.push('GetInfo');
      state.lockAtNetwork = JSON.parse(await fs.readFile(`${registry}.lock`, 'utf8'));
      state.reservedAtNetwork = (await fs.stat(out)).size === 0 && state.handle?.fd >= 0;
      return { alias: 'fixture', version: '0.21.4-beta', pubkey: pubkey, network: 'regtest' };
    },
    listPermissions: async () => {
      state.calls.push('ListPermissions');
      return snapshot.methods;
    },
    listMacaroonIds: async () => { state.calls.push('ListMacaroonIDs'); return ([...state.ids]).map(BigInt); },
    bakeMacaroon: async (requested, id) => {
      state.calls.push('BakeMacaroon'); state.ids.push(String(id));
      state.issued = responseBytes(id, requested); register(state.issued);
      return new Secret(state.issued);
    },
    checkMacaroon: async mac => {
      state.calls.push('CheckMacaroonPermissions'); state.checked = Buffer.from(revealSecret(mac));
      register(state.checked); return { valid: true };
    },
    deleteMacaroonId: async () => { throw new Error('Bake must never delete'); },
  };

  const deps = { lnd, fs: { ...fs }, env: {}, clock: () => new Date('2026-10-05T00:00:00Z') };
  deps.fs.open = async (...args) => {
    const handle = await fs.open(...args);
    if (args[0] === out) state.handle = handle;
    return handle;
  };
  const args = ['--label', label, '--preset', 'invoice-only', '--out', out, '--registry', registry,
    '--lnd-rest', '127.0.0.1:1', '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', own];
  return { registry, out, state, lnd, deps, args };
}
