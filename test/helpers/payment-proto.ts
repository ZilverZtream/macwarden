// Test-only encoders, written independently of src/: protobuf messages for the journaled
// requests (field numbers from lnrpc/routerrpc/router.proto and lnrpc/lightning.proto,
// v0.21.4-beta), a BOLT11 invoice with a valid bech32 checksum, and an RPCMiddlewareRequest
// frame carrying a serialized request.
import { createHash } from 'node:crypto';

export function varint(value: bigint | number): Buffer {
  let rest = BigInt.asUintN(64, BigInt(value));
  const bytes: number[] = [];
  do {
    let byte = Number(rest & 0x7fn);
    rest >>= 7n;
    if (rest) byte |= 0x80;
    bytes.push(byte);
  } while (rest);
  return Buffer.from(bytes);
}
export const tag = (field: number, wire: number) => varint((field << 3) | wire);
export const uint = (field: number, value: bigint | number) => Buffer.concat([tag(field, 0), varint(value)]);
export const bytes = (field: number, value: Buffer | string) => {
  const data = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
  return Buffer.concat([tag(field, 2), varint(data.length), data]);
};
export const message = (...parts: Buffer[]) => Buffer.concat(parts);

/** A keysend-style custom record entry (map<uint64, bytes> as repeated key/value messages). */
export const customRecord = (field: number, key: bigint, value: Buffer) => bytes(field, message(uint(1, key), bytes(2, value)));

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(values: number[]): number {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = (((checksum & 0x1ffffff) << 5) ^ value) >>> 0;
    for (let bit = 0; bit < 5; bit++) if ((top >>> bit) & 1) checksum = (checksum ^ generators[bit]) >>> 0;
  }
  return checksum;
}
function toGroups(data: Buffer): number[] {
  const out: number[] = [];
  let accumulator = 0, bits = 0;
  for (const byte of data) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) { bits -= 5; out.push((accumulator >> bits) & 31); }
    accumulator &= (1 << bits) - 1;
  }
  if (bits) out.push((accumulator << (5 - bits)) & 31);
  return out;
}
/** bech32 text for an HRP and 5-bit groups, with its checksum. */
export function bech32(hrp: string, groups: number[]): string {
  const expanded = [...[...hrp].map(char => char.charCodeAt(0) >> 5), 0, ...[...hrp].map(char => char.charCodeAt(0) & 31)];
  const value = polymod([...expanded, ...groups, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, index) => (value >> (5 * (5 - index))) & 31);
  return `${hrp}1${[...groups, ...checksum].map(group => CHARSET[group]).join('')}`;
}
function field(type: number, groups: number[]): number[] { return [type, groups.length >> 5, groups.length & 31, ...groups]; }

/**
 * A BOLT11 invoice: timestamp, a description, the payment hash (unless omitted), optional
 * extra fields before it, and a filler signature of 104 groups (the signature is not checked by
 * the journal, only by LND). `amount` is the HRP amount text, such as "2500u".
 */
export function invoice(options: { hash?: Buffer | null; amount?: string; network?: string; before?: number[][]; hashGroups?: number[] } = {}): string {
  const hash = options.hash === undefined ? createHash('sha256').update('test-invoice').digest() : options.hash;
  const groups = [0, 0, 0, 0, 0, 0, 1, ...(options.before ?? []).flat(),
    ...field(13, toGroups(Buffer.from('journal test'))),
    ...(hash ? field(1, options.hashGroups ?? toGroups(hash)) : []),
    ...Array<number>(104).fill(3)];
  return bech32(`ln${options.network ?? 'bcrt'}${options.amount ?? ''}`, groups);
}
export { toGroups, field };

/** RPCMiddlewareRequest{request_id 1, raw_macaroon 2, msg_id 7, request 5: RPCMessage{method 1, stream_rpc 2, type_name 3, serialized 4}}. */
export function middlewareRequest(options: { requestId?: number; msgId?: number; method: string; serialized: Buffer;
  macaroon?: Buffer; kind?: 'request' | 'response' | 'stream_auth' }): Buffer {
  const kindField = options.kind === 'response' ? 6 : options.kind === 'stream_auth' ? 4 : 5;
  const rpc = options.kind === 'stream_auth' ? bytes(1, options.method)
    : message(bytes(1, options.method), uint(2, 0), bytes(3, 'routerrpc.SendPaymentRequest'), bytes(4, options.serialized));
  return message(uint(1, options.requestId ?? 7), ...(options.macaroon ? [bytes(2, options.macaroon)] : []),
    bytes(kindField, rpc), uint(7, options.msgId ?? 9));
}
