import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = dirname(fileURLToPath(import.meta.url));
const bytes = (...values) => Buffer.from(values);
const ascii = value => Buffer.from(value, 'ascii');
function varint(value) {
  const out = [];
  do { const digit = value % 128; value = Math.floor(value / 128); out.push(digit | (value ? 128 : 0)); } while (value);
  return bytes(...out);
}
const packet = (type, value) => Buffer.concat([varint(type), varint(value.length), value]);
const proto = (field, value) => packet(field * 8 + 2, value);
const op = (entity, actions) => Buffer.concat([proto(1, ascii(entity)), ...actions.map(action => proto(2, ascii(action)))]);
const identifier = (storage = '0', operation = op('info', ['read'])) =>
  Buffer.concat([bytes(3), proto(2, Buffer.isBuffer(storage) ? storage : ascii(storage)), proto(3, operation)]);
const signature = packet(6, Buffer.alloc(32, 0));
const header = id => Buffer.concat([bytes(2), packet(1, ascii('lnd')), packet(2, id), bytes(0)]);
const valid = id => Buffer.concat([header(id), bytes(0), signature]);
const entries = [
  ['v1-binary', 'v2-header', ascii('001a')],
  ['v1-base64-decoded', 'v2-header', Buffer.from('MDAxYQ==', 'base64')],
  ['empty', 'v2-header', bytes()],
  ['wrong-first-byte', 'v2-header', bytes(1)],
  ['unknown-packet-type', 'packet', Buffer.concat([bytes(2), packet(3, bytes(1))])],
  ['overlong-varint', 'packet', Buffer.concat([bytes(2), Buffer.alloc(11, 0x80)])],
  ['length-past-end', 'packet', bytes(2, 2, 100, 1)],
  ['fields-out-of-order', 'packet', Buffer.concat([bytes(2), packet(2, identifier()), packet(1, ascii('lnd')), bytes(0, 0), signature])],
  ['header-without-identifier', 'packet', Buffer.concat([bytes(2), packet(1, ascii('lnd')), bytes(0, 0), signature])],
  ['caveat-vid-without-identifier', 'packet', Buffer.concat([header(identifier()), packet(4, bytes(1)), bytes(0, 0), signature])],
  ['missing-final-eos', 'packet', Buffer.concat([header(identifier()), signature])],
  ['missing-signature', 'packet', Buffer.concat([header(identifier()), bytes(0)])],
  ['short-signature', 'packet', Buffer.concat([header(identifier()), bytes(0), packet(6, Buffer.alloc(31, 0))])],
  ['identifier-version-02', 'identifier-version', valid(Buffer.concat([bytes(2), identifier().subarray(1)]))],
  ['truncated-protobuf', 'identifier-proto', valid(bytes(3, 0x12, 5, 0x61))],
  ['protobuf-wire-3', 'identifier-proto', valid(Buffer.concat([identifier(), bytes(0x0b)]))],
  ['protobuf-wire-4', 'identifier-proto', valid(Buffer.concat([identifier(), bytes(0x0c)]))],
  ['op-first-empty', 'identifier-proto', valid(identifier('0', Buffer.alloc(0)))],
  ['op-zero-actions', 'identifier-proto', valid(identifier('0', op('info', [])))],
  ['storage-empty', 'identifier-root-key-id', valid(identifier(''))],
  ['storage-nondigits', 'identifier-root-key-id', valid(identifier('abc'))],
  ['storage-high-bit-zero', 'identifier-root-key-id', valid(identifier(bytes(0xb0)))],
  ['storage-high-bit-nine', 'identifier-root-key-id', valid(identifier(bytes(0xb9)))],
  ['storage-unicode-digit', 'identifier-root-key-id', valid(identifier(Buffer.from('\u0661', 'utf8')))],
  ['storage-leading-zeroes', 'identifier-root-key-id', valid(identifier('007'))],
  ['storage-over-uint64', 'identifier-root-key-id', valid(identifier('18446744073709551616'))],
];

mkdirSync(dir, { recursive: true });
for (const [name, , value] of entries) writeFileSync(join(dir, `${name}.macaroon`), value);
writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ vectors: entries.map(([name, stage]) => ({ name, file: `${name}.macaroon`, stage })) }, null, 2) + '\n');
