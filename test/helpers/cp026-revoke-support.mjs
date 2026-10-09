import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

export const pubkey = '02' + 'ab'.repeat(32);
export const otherPubkey = '03' + 'cd'.repeat(32);
export const maxId = '18446744073709551615';
export const ownId = '23026';
export const snapshot = JSON.parse(readFileSync(resolve('src/grade/lnd-permissions.json'), 'utf8'));
export const manifest = JSON.parse(readFileSync(resolve('test/vectors/manifest.json'), 'utf8')).vectors;
export const template = JSON.parse(readFileSync(resolve('test/registry-fixtures/registry.json'), 'utf8')).entries[0];
export function directory(variable) {
  const roots = Object.fromEntries(['MACWARDEN_TEST_TMP', 'MACWARDEN_SENTINEL_DIR'].map(name => {
    const supplied = process.env[name];
    if (!supplied) throw new Error(`${name} is required`);
    if (!isAbsolute(supplied)) throw new Error(`${name} must be absolute`);
    return [name, resolve(supplied)];
  }));
  const contains = (parent, child) => {
    const path = relative(parent, child);
    return path === '' || (!isAbsolute(path) && path !== '..' && !path.startsWith('..' + sep));
  };
  if (contains(roots.MACWARDEN_TEST_TMP, roots.MACWARDEN_SENTINEL_DIR) ||
      contains(roots.MACWARDEN_SENTINEL_DIR, roots.MACWARDEN_TEST_TMP))
    throw new Error('Harness temporary and sentinel roots must be separate');
  const path = roots[variable];
  if (!path) throw new Error('Unknown harness root');
  // The harness owns these roots, which may be outside the candidate worktree.
  // Callers clean only their mkdtemp directories and retain registered sentinels.
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}
export function declare(path) {
  appendFileSync(join(directory('MACWARDEN_TEST_TMP'), 'declared-out.txt'), `${path}\n`);
}
export function register(bytes) {
  const fingerprint = createHash('sha256').update(bytes).digest('hex').slice(0, 16);
  const path = join(directory('MACWARDEN_SENTINEL_DIR'), `cp026-${process.pid}-${fingerprint}.macaroon`);
  writeFileSync(path, bytes, { mode: 0o600 });
  declare(path);
  return path;
}
export function vector(name) {
  const reference = manifest.find(row => row.name === name);
  if (!reference) throw new Error('Missing committed vector reference');
  return { ...reference,
    bytes: readFileSync(resolve('test/vectors', reference.file)),
    printed: JSON.parse(readFileSync(resolve('test/vectors', `${name}.printmacaroon.json`), 'utf8')) };
}
function varint(value) {
  const bytes = [];
  do { bytes.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value);
  return Buffer.from(bytes);
}
function field(kind, bytes) { return Buffer.concat([varint(kind), varint(bytes.length), bytes]); }
function proto(kind, bytes) { return field((kind << 3) | 2, bytes); }
// Offline wire fixture derived from stored lncli facts, never a claim of LND acceptance.
// A supplied permission override is used only for faulty OWN/empty-list cases.
export function wireFixture(name, id, override) {
  const source = vector(name), permissions = override ?? source.printed.permissions;
  const operations = permissions.map(permission => {
    const at = permission.indexOf(':');
    return proto(3, Buffer.concat([proto(1, Buffer.from(permission.slice(0, at))),
      proto(2, Buffer.from(permission.slice(at + 1)))]));
  });
  const identifier = Buffer.concat([Buffer.from([3]), proto(1, randomBytes(16)),
    proto(2, Buffer.from(String(id))), ...operations]);
  const caveats = (source.printed.caveats ?? []).flatMap(caveat =>
    [field(2, Buffer.from(caveat)), Buffer.from([0])]);
  return Buffer.concat([Buffer.from([2]), field(1, Buffer.from('lnd')), field(2, identifier),
    Buffer.from([0]), ...caveats, Buffer.from([0]), field(6, randomBytes(32))]);
}
export function entry(name = 'root-max', id, overrides = {}) {
  const v = vector(name);
  const bytes = id === undefined || id === v.printed.root_key_id ? v.bytes : wireFixture(name, id);
  const path = register(bytes);
  return { ...template, nodePubkey: pubkey, label: 'Alice',
    rootKeyId: id ?? v.printed.root_key_id, permissions: [...v.printed.permissions],
    caveats: (v.printed.caveats ?? []).map(caveat => {
      const at = caveat.indexOf(' ');
      return { type: caveat.slice(0, at), value: caveat.slice(at + 1) };
    }), grade: v.expectedGrade,
    fingerprint: 'fp:' + createHash('sha256').update(bytes).digest('hex').slice(0, 16),
    outPath: path, ...overrides };
}
export function permissionsResponse(methods = snapshot.methods) { return methods; }
