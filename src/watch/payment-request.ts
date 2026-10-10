// What `watch --payment-journal` reads from an intercepted payment request: the payment
// hash, the requested amount and the fee limit, nothing else. The request payload is a
// protobuf message (LND v0.21.4-beta, lnrpc/routerrpc/router.proto and lnrpc/lightning.proto);
// only the fields named below are read, every other field (custom records, which carry a
// keysend preimage, route hints, destination features, first-hop records) is skipped by wire
// type and never copied. A BOLT11 payment request is decoded only far enough to take its
// payment hash and amount; the invoice text itself is never kept.
import snapshot from '../grade/lnd-permissions.json' with { type: 'json' };

/** Payment-initiating methods of the pinned LND (ListPermissions snapshot). */
export const PAYMENT_METHODS = ['/routerrpc.Router/SendPaymentV2', '/routerrpc.Router/SendToRouteV2'] as const;
/** Methods that delete LND's payment records (evidence a reconciliation depends on). */
export const DELETION_METHODS = ['/lnrpc.Lightning/DeletePayment', '/lnrpc.Lightning/DeleteAllPayments'] as const;
/**
 * Lightning's SendPayment, SendPaymentSync, SendToRoute and SendToRouteSync are not methods of
 * LND v0.21.4-beta (the pinned snapshot has none of them), so they are not journaled; a test
 * keeps this list in step with the snapshot.
 */
export const REMOVED_PAYMENT_METHODS = ['/lnrpc.Lightning/SendPayment', '/lnrpc.Lightning/SendPaymentSync',
  '/lnrpc.Lightning/SendToRoute', '/lnrpc.Lightning/SendToRouteSync'] as const;

export type JournaledMethod = typeof PAYMENT_METHODS[number] | typeof DELETION_METHODS[number];

const known = new Set<string>(Object.keys(snapshot.methods));
/** Every journaled method, restricted to those the pinned LND actually has. */
export const JOURNALED_METHODS: ReadonlySet<string> = new Set<string>([...PAYMENT_METHODS, ...DELETION_METHODS]
  .filter(method => known.has(method)));

/**
 * Largest request payload copied and decoded (MAX_PAYLOAD_BYTES, 64 KiB, in middleware-proto.ts).
 * A SendPaymentV2 request is an invoice (LND's zpay32 refuses invoices above 7,089
 * characters) plus a few scalars and route hints; a SendToRouteV2 request is one route. Both
 * are far below it. A larger payload is not copied: the call is journaled with
 * `extraction: "payload-too-large"` and no hash.
 */
export { MAX_PAYLOAD_BYTES } from '../lnd/middleware-proto.js';
/** Largest BOLT11 text decoded (characters); above it the hash is not taken. */
export const MAX_INVOICE_CHARS = 8 * 1024;

export type Extraction = 'complete' | 'no-hash' | 'amp' | 'payload-too-large' | 'malformed' | 'invoice-invalid' | 'invoice-too-long';

export type PaymentFacts = {
  /** Lower-case hex SHA-256 payment hash, or null when the request names none that could be read. */
  paymentHash: string | null;
  /** Requested amount in millisatoshi as a canonical decimal string, or null when absent or invalid. */
  amountMsat: string | null;
  amountSource: 'request' | 'invoice' | 'route' | null;
  /** Fee limit in millisatoshi (for SendToRouteV2: the route's own fee), or null when absent or invalid. */
  feeLimitMsat: string | null;
  /** True when SendPaymentV2 asked for an AMP payment: LND chooses the hash, so none is recorded. */
  amp: boolean;
  extraction: Extraction;
};

export type DeletionFacts = {
  paymentHash: string | null;
  scope: 'payment' | 'failed-htlcs' | 'all-payments' | 'failed-payments' | 'none';
  extraction: 'complete' | 'payload-too-large' | 'malformed';
};

class Malformed extends Error {}
const MAX_UINT64 = (1n << 64n) - 1n;
const INT64_SIGN = 1n << 63n;

function varint(data: Buffer, start: number): [bigint, number] {
  let value = 0n;
  let shift = 0n;
  let position = start;
  for (;;) {
    if (position >= data.length || shift > 63n) throw new Malformed();
    const byte = data[position++];
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  if (value > MAX_UINT64) throw new Malformed();
  return [value, position];
}

type Field = { number: number; wire: number; value: bigint; bytes: Buffer | null };

/**
 * Top-level fields of one message, in order; one pass, linear in its length. Length-delimited
 * values are views. Groups (wire types 3 and 4) are refused: no field of these messages is a
 * group and no client sends one.
 */
function* fields(data: Buffer): Generator<Field> {
  let position = 0;
  while (position < data.length) {
    const [tag, afterTag] = varint(data, position);
    position = afterTag;
    const number = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (number < 1 || number > 536_870_911) throw new Malformed();
    if (wire === 0) {
      const [value, next] = varint(data, position);
      position = next;
      yield { number, wire, value, bytes: null };
    } else if (wire === 2) {
      const [length, next] = varint(data, position);
      if (length > BigInt(data.length - next)) throw new Malformed();
      const end = next + Number(length);
      yield { number, wire, value: length, bytes: data.subarray(next, end) };
      position = end;
    } else if (wire === 1) {
      if (position + 8 > data.length) throw new Malformed();
      position += 8;
      yield { number, wire, value: 0n, bytes: null };
    } else if (wire === 5) {
      if (position + 4 > data.length) throw new Malformed();
      position += 4;
      yield { number, wire, value: 0n, bytes: null };
    } else throw new Malformed();
  }
}

/** proto3 int64: the varint is the two's complement; a negative amount is no amount. */
function int64(value: bigint): bigint | null { return value >= INT64_SIGN ? null : value; }
// The journal records millisatoshi amounts up to int64 (LND's own range). A satoshi amount times
// 1,000, or an invoice amount, can exceed it: such a value is no amount (1.2.1), never a record
// the journal reader refuses.
const MSAT_MAX = INT64_SIGN - 1n;
function bounded(value: bigint | null): bigint | null { return value === null || value < 0n || value > MSAT_MAX ? null : value; }

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
function text(bytes: Buffer): string {
  try { return utf8.decode(bytes); } catch { throw new Malformed(); }
}

function hashHex(bytes: Buffer): string | null { return bytes.length === 32 ? bytes.toString('hex') : null; }

/**
 * routerrpc.SendPaymentRequest: dest 1, amt 2, payment_hash 3, payment_request 5,
 * fee_limit_sat 7, dest_custom_records 11 (skipped), amt_msat 12, fee_limit_msat 13, amp 22.
 * Scalars follow proto3's last-one-wins; a field with an unexpected wire type is skipped as
 * the Go decoder skips it.
 */
function sendPayment(payload: Buffer): PaymentFacts {
  let amt: bigint | null = 0n, amtMsat: bigint | null = 0n;
  let feeSat: bigint | null = 0n, feeMsat: bigint | null = 0n;
  let hash: Buffer | null = null;
  let invoice: string | null = null;
  let invoiceTooLong = false;
  let amp = false;
  for (const field of fields(payload)) {
    switch (field.number) {
      case 2: if (field.wire === 0) amt = int64(field.value); break;
      case 3: if (field.wire === 2) hash = field.bytes; break;
      case 5:
        if (field.wire !== 2) break;
        // proto3: an explicitly empty string is the same as an absent one, and LND then pays the
        // hash of field 3 (audit 1.2.1).
        if (field.bytes!.length === 0) { invoiceTooLong = false; invoice = null; break; }
        // A UTF-8 character is at most 4 bytes: anything longer is over the character limit.
        if (field.bytes!.length > MAX_INVOICE_CHARS * 4) { invoiceTooLong = true; invoice = null; }
        else { invoiceTooLong = false; invoice = text(field.bytes!); }
        break;
      case 7: if (field.wire === 0) feeSat = int64(field.value); break;
      case 12: if (field.wire === 0) amtMsat = int64(field.value); break;
      case 13: if (field.wire === 0) feeMsat = int64(field.value); break;
      case 22: if (field.wire === 0) amp = field.value !== 0n; break;
      default: break;
    }
  }
  // Zero means unset in proto3; LND refuses a request that sets both units, or a negative value.
  const requested = bounded(amtMsat === null || amt === null ? null : amtMsat > 0n ? amtMsat : amt > 0n ? amt * 1000n : null);
  // Both unset: SendPaymentV2 considers only zero-fee routes, so the limit is 0.
  const feeLimit = bounded(feeMsat === null || feeSat === null ? null : feeMsat > 0n ? feeMsat : feeSat * 1000n);
  const result: PaymentFacts = { paymentHash: null, amountMsat: null, amountSource: null,
    feeLimitMsat: feeLimit === null ? null : feeLimit.toString(), amp, extraction: 'complete' };
  if (invoiceTooLong) result.extraction = 'invoice-too-long';
  else if (invoice !== null) {
    const decoded = decodeBolt11(invoice);
    if (decoded === 'too-long') result.extraction = 'invoice-too-long';
    else if (decoded === null) result.extraction = 'invoice-invalid';
    else {
      result.paymentHash = decoded.paymentHash;
      const invoiceAmount = bounded(decoded.amountMsat);
      if (invoiceAmount !== null) { result.amountMsat = invoiceAmount.toString(); result.amountSource = 'invoice'; }
    }
  } else if (hash) {
    result.paymentHash = hashHex(hash);
    if (result.paymentHash === null) result.extraction = 'malformed';
  } else result.extraction = 'no-hash';
  if (result.amountSource === null && requested !== null) {
    result.amountMsat = requested.toString();
    result.amountSource = 'request';
  }
  // LND chooses the identifier of an AMP payment itself, so a hash the caller sent names no record.
  if (amp) { result.paymentHash = null; result.extraction = 'amp'; }
  return result;
}

/**
 * routerrpc.SendToRouteRequest: payment_hash 1, route 2 (lnrpc.Route: total_amt_msat 6,
 * hops 4, each lnrpc.Hop with amt_to_forward_msat 6). LND sends total_amt_msat to the first
 * hop and the last hop forwards amt_to_forward_msat to the destination: that is the amount
 * this attempt delivers, and the difference is the route's fee. Repeated route fields merge
 * as protobuf merges them (scalars last-one-wins, hops appended).
 */
function sendToRoute(payload: Buffer): PaymentFacts {
  let hash: Buffer | null = null;
  let total: bigint | null | undefined;
  let lastHopAmount: bigint | null | undefined;
  for (const field of fields(payload)) {
    if (field.number === 1 && field.wire === 2) hash = field.bytes;
    else if (field.number === 2 && field.wire === 2) {
      for (const routeField of fields(field.bytes!)) {
        if (routeField.number === 6 && routeField.wire === 0) total = int64(routeField.value);
        else if (routeField.number === 4 && routeField.wire === 2) {
          // Each hop message replaces the previous one as "last"; only the amount is read.
          lastHopAmount = 0n;
          for (const hopField of fields(routeField.bytes!))
            if (hopField.number === 6 && hopField.wire === 0) lastHopAmount = int64(hopField.value);
        }
      }
    }
  }
  const paymentHash = hash ? hashHex(hash) : null;
  const delivered = lastHopAmount !== undefined && lastHopAmount !== null && lastHopAmount > 0n ? lastHopAmount : null;
  const fee = delivered !== null && total !== undefined && total !== null && total >= delivered ? total - delivered : null;
  return { paymentHash, amountMsat: delivered === null ? null : delivered.toString(), amountSource: delivered === null ? null : 'route',
    feeLimitMsat: fee === null ? null : fee.toString(), amp: false,
    extraction: hash === null ? 'no-hash' : paymentHash === null ? 'malformed' : 'complete' };
}

/** Extracts the payment facts of one journaled payment request; never throws. */
export function paymentFacts(method: string, payload: Buffer | null, oversized: boolean): PaymentFacts {
  const empty: PaymentFacts = { paymentHash: null, amountMsat: null, amountSource: null, feeLimitMsat: null, amp: false, extraction: 'malformed' };
  if (oversized) return { ...empty, extraction: 'payload-too-large' };
  const data = payload ?? Buffer.alloc(0);
  try {
    if (method === '/routerrpc.Router/SendPaymentV2') return sendPayment(data);
    if (method === '/routerrpc.Router/SendToRouteV2') return sendToRoute(data);
  } catch { return empty; }
  return empty;
}

/**
 * lnrpc.DeletePaymentRequest: payment_hash 1, failed_htlcs_only 2.
 * lnrpc.DeleteAllPaymentsRequest: failed_payments_only 1, failed_htlcs_only 2, all_payments 3.
 */
export function deletionFacts(method: string, payload: Buffer | null, oversized: boolean): DeletionFacts {
  if (oversized) return { paymentHash: null, scope: 'none', extraction: 'payload-too-large' };
  const data = payload ?? Buffer.alloc(0);
  try {
    const flags = new Map<number, boolean>();
    let hash: Buffer | null = null;
    for (const field of fields(data)) {
      if (field.wire === 0) flags.set(field.number, field.value !== 0n);
      else if (field.number === 1 && field.wire === 2) hash = field.bytes;
    }
    if (method === '/lnrpc.Lightning/DeletePayment') {
      const paymentHash = hash ? hashHex(hash) : null;
      return { paymentHash, scope: flags.get(2) ? 'failed-htlcs' : 'payment',
        extraction: hash !== null && paymentHash === null ? 'malformed' : 'complete' };
    }
    // DeleteAllPayments (LND v0.21.4 rpcserver.go DeleteAllPayments): failed_htlcs_only removes
    // the failed attempts of every payment, alone or with failed_payments_only (then of failed
    // payments only), so it is a deletion of its own, `failed-htlcs` (1.2.1: alone it was `none`).
    // LND refuses a request that selects nothing (`none`), and all_payments with either other flag.
    const scope = flags.get(2) ? 'failed-htlcs' : flags.get(3) ? 'all-payments' : flags.get(1) ? 'failed-payments' : 'none';
    return { paymentHash: null, scope, extraction: 'complete' };
  } catch { return { paymentHash: null, scope: 'none', extraction: 'malformed' }; }
}

// BOLT11 (bech32 without the 90-character limit). Linear in the text length: one pass for the
// checksum, one over the 5-bit data for the tagged fields.
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const CHARSET_INDEX = new Map([...CHARSET].map((char, index) => [char, index]));
const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const SIGNATURE_GROUPS = 104;
const CHECKSUM_GROUPS = 6;
const TIMESTAMP_GROUPS = 7;
const MSAT_PER_BTC = 100_000_000_000n;

function polymodStep(checksum: number, value: number): number {
  const top = checksum >>> 25;
  let next = ((checksum & 0x1ffffff) << 5) ^ value;
  for (let bit = 0; bit < 5; bit++) if ((top >>> bit) & 1) next ^= GENERATORS[bit];
  return next >>> 0;
}

/** HRP amount: digits and an optional multiplier, in millisatoshi; 'invalid' when malformed. */
function hrpAmount(value: string): bigint | 'invalid' {
  const match = /^([1-9][0-9]{0,19})([munp]?)$/.exec(value);
  if (!match) return 'invalid';
  const digits = BigInt(match[1]);
  switch (match[2]) {
    case 'm': return digits * MSAT_PER_BTC / 1_000n;
    case 'u': return digits * MSAT_PER_BTC / 1_000_000n;
    case 'n': return digits * MSAT_PER_BTC / 1_000_000_000n;
    // A pico-bitcoin amount must be a whole number of millisatoshi.
    case 'p': return digits % 10n === 0n ? digits / 10n : 'invalid';
    default: return digits * MSAT_PER_BTC;
  }
}

/**
 * The payment hash and amount of a BOLT11 payment request, 'too-long' above MAX_INVOICE_CHARS,
 * or null when it is not a well-formed invoice (a character outside printable US-ASCII, mixed case, bad checksum, no
 * 52-group `p` field, nonzero padding). The signature is not verified: LND does that and refuses
 * the payment otherwise; the hash is what LND would pay. The first `p` field of the right
 * length is used, as LND's zpay32 uses it.
 */
export function decodeBolt11(input: string): { paymentHash: string; amountMsat: bigint | null } | 'too-long' | null {
  if (input.length > MAX_INVOICE_CHARS) return 'too-long';
  // Printable US-ASCII only, checked before any case folding (PF-1): Unicode case mappings turn
  // the Kelvin sign U+212A into 'k', U+0130 into 'i' plus a combining dot, and leave U+017F,
  // U+0131 and fullwidth letters unchanged by one of the two foldings, so a non-ASCII character
  // could pass the one-case check or fold into a bech32 character. LND's decoder refuses them.
  for (let index = 0; index < input.length; index++) {
    const code = input.charCodeAt(index);
    if (code < 33 || code > 126) return null;
  }
  const lower = input.toLowerCase();
  if (lower !== input && input.toUpperCase() !== input) return null;
  const separator = lower.lastIndexOf('1');
  if (separator < 3) return null;
  const hrp = lower.slice(0, separator);
  const dataLength = lower.length - separator - 1;
  if (dataLength < TIMESTAMP_GROUPS + SIGNATURE_GROUPS + CHECKSUM_GROUPS) return null;
  const data = new Uint8Array(dataLength);
  for (let index = 0; index < dataLength; index++) {
    const value = CHARSET_INDEX.get(lower[separator + 1 + index]);
    if (value === undefined) return null;
    data[index] = value;
  }
  let checksum = 1;
  for (let index = 0; index < hrp.length; index++) checksum = polymodStep(checksum, hrp.charCodeAt(index) >> 5);
  checksum = polymodStep(checksum, 0);
  for (let index = 0; index < hrp.length; index++) checksum = polymodStep(checksum, hrp.charCodeAt(index) & 31);
  for (const value of data) checksum = polymodStep(checksum, value);
  if (checksum !== 1) return null;
  const prefix = /^ln([a-z]+)([0-9]*[munp]?)$/.exec(hrp);
  if (!prefix) return null;
  // The currency prefix ends where the amount's digits begin; the regex is greedy on letters,
  // so a multiplier letter without digits stays part of the currency, which zpay32 refuses too.
  const parsed = prefix[2] === '' ? null : hrpAmount(prefix[2]);
  if (parsed === 'invalid') return null;
  const amount = parsed;
  const end = dataLength - SIGNATURE_GROUPS - CHECKSUM_GROUPS;
  let position = TIMESTAMP_GROUPS;
  let paymentHash: string | null = null;
  while (position < end) {
    if (position + 3 > end) return null;
    const type = data[position];
    const length = data[position + 1] * 32 + data[position + 2];
    position += 3;
    if (position + length > end) return null;
    if (type === 1 && length === 52 && paymentHash === null) {
      const bytes = Buffer.alloc(32);
      let accumulator = 0, bits = 0, out = 0;
      for (let index = position; index < position + 52; index++) {
        accumulator = (accumulator << 5) | data[index];
        bits += 5;
        if (bits >= 8) { bits -= 8; bytes[out++] = (accumulator >> bits) & 0xff; }
        accumulator &= (1 << bits) - 1;
      }
      // 260 bits carry 256: the 4 padding bits must be zero.
      if (accumulator !== 0) return null;
      paymentHash = bytes.toString('hex');
    }
    position += length;
  }
  return paymentHash === null ? null : { paymentHash, amountMsat: amount };
}
