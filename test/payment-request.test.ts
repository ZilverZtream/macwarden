import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import snapshot from '../src/grade/lnd-permissions.json' with { type: 'json' };
import { decodeMiddlewareRequest, MAX_PAYLOAD_BYTES } from '../src/lnd/middleware-proto.js';
import { DELETION_METHODS, JOURNALED_METHODS, MAX_INVOICE_CHARS, PAYMENT_METHODS, REMOVED_PAYMENT_METHODS, decodeBolt11,
  deletionFacts, paymentFacts } from '../src/watch/payment-request.js';
import { bech32, bytes, customRecord, field, invoice, message, middlewareRequest, tag, toGroups, uint, varint } from './helpers/payment-proto.js';

const SEND = '/routerrpc.Router/SendPaymentV2';
const ROUTE = '/routerrpc.Router/SendToRouteV2';
const hash = (text: string) => createHash('sha256').update(text).digest();
const KEYSEND_RECORD = 5482373484n;

it('PAYJ/methods the journaled set is exactly the payment and deletion methods of the pinned snapshot', () => {
  const methods = Object.keys(snapshot.methods);
  expect([...JOURNALED_METHODS].sort()).toEqual([...PAYMENT_METHODS, ...DELETION_METHODS].sort());
  for (const method of JOURNALED_METHODS) expect(methods, method).toContain(method);
  // The deprecated Lightning payment RPCs are absent from v0.21.4-beta: if a new snapshot lists one,
  // this fails and the journal must learn its request message.
  for (const method of REMOVED_PAYMENT_METHODS) expect(methods, method).not.toContain(method);
  // Every other method that needs offchain:write and names a payment: none is missing from the set.
  const paymentLike = methods.filter(method => /Send(?:Payment|ToRoute)|DeletePayment|DeleteAllPayments/.test(method));
  expect(paymentLike.sort()).toEqual([...JOURNALED_METHODS].sort());
});

it('PAYJ/send-payment an invoice gives its hash and amount; the request amount and fee limit are read', () => {
  const paymentHash = hash('invoice-a');
  const text = invoice({ hash: paymentHash, amount: '2500u' });
  const facts = paymentFacts(SEND, message(bytes(5, text), uint(13, 7_000), uint(6, 60)), false);
  expect(facts).toEqual({ paymentHash: paymentHash.toString('hex'), amountMsat: '250000000', amountSource: 'invoice',
    feeLimitMsat: '7000', amp: false, extraction: 'complete' });
  // A zero-amount invoice takes the amount from the request: amt_msat first, else amt in satoshi.
  const open = invoice({ hash: paymentHash });
  expect(paymentFacts(SEND, message(bytes(5, open), uint(12, 1_234_567)), false))
    .toMatchObject({ amountMsat: '1234567', amountSource: 'request', feeLimitMsat: '0' });
  expect(paymentFacts(SEND, message(bytes(5, open), uint(2, 21), uint(7, 3)), false))
    .toMatchObject({ amountMsat: '21000', amountSource: 'request', feeLimitMsat: '3000' });
});

it('PAYJ/send-payment HRP multipliers convert exactly to millisatoshi; a fractional millisatoshi is invalid', () => {
  const cases: [string, string][] = [['1', '100000000000'], ['5m', '500000000'], ['250u', '25000000'], ['7n', '700'], ['30p', '3']];
  for (const [amount, msat] of cases) {
    const decoded = decodeBolt11(invoice({ amount }));
    expect(decoded, amount).not.toBeNull();
    expect((decoded as { amountMsat: bigint }).amountMsat.toString(), amount).toBe(msat);
  }
  expect(decodeBolt11(invoice({ amount: '15p' }))).toBeNull();
  expect(decodeBolt11(invoice({ amount: '010u' }))).toBeNull();
});

it('PAYJ/keysend a payment hash from the request is used; custom records, including a preimage, are never read into the facts', () => {
  const preimage = Buffer.from('aa'.repeat(32), 'hex');
  const paymentHash = createHash('sha256').update(preimage).digest();
  const payload = message(bytes(1, Buffer.alloc(33, 2)), uint(2, 1_000), bytes(3, paymentHash), customRecord(11, KEYSEND_RECORD, preimage),
    uint(7, 10));
  const facts = paymentFacts(SEND, payload, false);
  expect(facts).toEqual({ paymentHash: paymentHash.toString('hex'), amountMsat: '1000000', amountSource: 'request',
    feeLimitMsat: '10000', amp: false, extraction: 'complete' });
  expect(JSON.stringify(facts)).not.toContain(preimage.toString('hex'));
});

it('PAYJ/send-payment AMP, a missing hash and a wrong-length hash are recorded without a hash', () => {
  expect(paymentFacts(SEND, message(bytes(3, hash('x')), uint(22, 1), uint(2, 5)), false))
    .toMatchObject({ paymentHash: null, amp: true, extraction: 'amp', amountMsat: '5000' });
  expect(paymentFacts(SEND, message(uint(2, 5)), false)).toMatchObject({ paymentHash: null, extraction: 'no-hash' });
  expect(paymentFacts(SEND, message(bytes(3, Buffer.alloc(31, 1))), false)).toMatchObject({ paymentHash: null, extraction: 'malformed' });
});

it('PAYJ/send-payment proto3 rules: last one wins, a wrong wire type is skipped, a negative amount is no amount', () => {
  const first = hash('first'), second = hash('second');
  expect(paymentFacts(SEND, message(bytes(3, first), bytes(3, second)), false).paymentHash).toBe(second.toString('hex'));
  // Field 3 sent as a varint is not a payment hash: skipped, as the Go decoder skips it.
  expect(paymentFacts(SEND, message(uint(3, 5), bytes(3, first)), false).paymentHash).toBe(first.toString('hex'));
  expect(paymentFacts(SEND, message(bytes(3, first), uint(3, 5)), false).paymentHash).toBe(first.toString('hex'));
  expect(paymentFacts(SEND, message(bytes(3, first), uint(12, -5n), uint(13, -1n)), false))
    .toMatchObject({ amountMsat: null, amountSource: null, feeLimitMsat: null });
  // Fixed-width fields of other numbers are skipped.
  const fixed64 = Buffer.concat([tag(23, 1), Buffer.alloc(8, 0xff)]);
  const fixed32 = Buffer.concat([tag(24, 5), Buffer.alloc(4, 0xff)]);
  expect(paymentFacts(SEND, message(fixed64, fixed32, bytes(3, first)), false).paymentHash).toBe(first.toString('hex'));
});

it('PAYJ/malformed truncated messages, over-long varints, groups and invalid UTF-8 give no hash and never throw', () => {
  const good = message(bytes(3, hash('m')));
  const cases = [
    good.subarray(0, good.length - 1),
    Buffer.concat([tag(2, 0), Buffer.alloc(11, 0xff)]),
    Buffer.concat([tag(2, 0), Buffer.from([0x80])]),
    Buffer.concat([tag(3, 2), varint(1_000)]),
    Buffer.concat([tag(9, 3), tag(9, 4)]),
    Buffer.from([0x00]),
    message(bytes(5, Buffer.from([0xc3, 0x28]))),
    Buffer.concat([tag(5, 2), varint(2n ** 62n)]),
  ];
  for (const payload of cases) {
    const facts = paymentFacts(SEND, payload, false);
    expect(facts.paymentHash, payload.toString('hex')).toBeNull();
    expect(facts.extraction).toBe('malformed');
    expect(paymentFacts(ROUTE, payload, false).paymentHash).toBeNull();
  }
  expect(paymentFacts(SEND, null, true)).toMatchObject({ paymentHash: null, extraction: 'payload-too-large' });
  expect(paymentFacts('/lnrpc.Lightning/GetInfo', good, false)).toMatchObject({ paymentHash: null, extraction: 'malformed' });
});

it('PAYJ/send-to-route the hash, the amount the last hop delivers and the route fee', () => {
  const paymentHash = hash('route');
  const hop = (forward: number) => bytes(4, message(uint(1, 123), uint(6, forward), uint(7, 10), bytes(8, '02'.repeat(33))));
  const route = message(uint(1, 500), hop(100_500), hop(100_000), uint(5, 1_000), uint(6, 101_000));
  expect(paymentFacts(ROUTE, message(bytes(1, paymentHash), bytes(2, route), uint(3, 1)), false)).toEqual({
    paymentHash: paymentHash.toString('hex'), amountMsat: '100000', amountSource: 'route', feeLimitMsat: '1000', amp: false, extraction: 'complete' });
  // Two route fields merge: hops are appended, scalars last-one-wins.
  const merged = message(bytes(1, paymentHash), bytes(2, message(hop(5_000), uint(6, 5_100))), bytes(2, message(hop(4_000), uint(6, 4_050))));
  expect(paymentFacts(ROUTE, merged, false)).toMatchObject({ amountMsat: '4000', feeLimitMsat: '50' });
  // No hops: no amount; a total below the delivered amount: no fee.
  expect(paymentFacts(ROUTE, message(bytes(1, paymentHash), bytes(2, uint(6, 10))), false)).toMatchObject({ amountMsat: null, feeLimitMsat: null });
  expect(paymentFacts(ROUTE, message(bytes(1, paymentHash), bytes(2, message(hop(10), uint(6, 5)))), false))
    .toMatchObject({ amountMsat: '10', feeLimitMsat: null });
  expect(paymentFacts(ROUTE, bytes(2, message(hop(10), uint(6, 12))), false)).toMatchObject({ paymentHash: null, extraction: 'no-hash' });
});

it('PAYJ/deletions DeletePayment names its hash and scope; DeleteAllPayments its scope', () => {
  const paymentHash = hash('deleted');
  expect(deletionFacts('/lnrpc.Lightning/DeletePayment', message(bytes(1, paymentHash)), false))
    .toEqual({ paymentHash: paymentHash.toString('hex'), scope: 'payment', extraction: 'complete' });
  expect(deletionFacts('/lnrpc.Lightning/DeletePayment', message(bytes(1, paymentHash), uint(2, 1)), false)).toMatchObject({ scope: 'failed-htlcs' });
  expect(deletionFacts('/lnrpc.Lightning/DeletePayment', message(bytes(1, Buffer.alloc(3))), false)).toMatchObject({ paymentHash: null, extraction: 'malformed' });
  const all = '/lnrpc.Lightning/DeleteAllPayments';
  expect(deletionFacts(all, uint(3, 1), false)).toEqual({ paymentHash: null, scope: 'all-payments', extraction: 'complete' });
  expect(deletionFacts(all, uint(1, 1), false)).toMatchObject({ scope: 'failed-payments' });
  expect(deletionFacts(all, message(uint(1, 1), uint(2, 1)), false)).toMatchObject({ scope: 'failed-htlcs' });
  // failed_htlcs_only alone is a valid request (LND v0.21.4 removes every payment's failed attempts): its own scope, never `none` (audit F09).
  expect(deletionFacts(all, uint(2, 1), false)).toEqual({ paymentHash: null, scope: 'failed-htlcs', extraction: 'complete' });
  expect(deletionFacts(all, message(uint(2, 1), uint(2, 0)), false)).toMatchObject({ scope: 'none' });
  expect(deletionFacts(all, Buffer.alloc(0), false)).toMatchObject({ scope: 'none' });
  expect(deletionFacts(all, null, true)).toMatchObject({ extraction: 'payload-too-large' });
  expect(deletionFacts(all, Buffer.from([0x08]), false)).toMatchObject({ extraction: 'malformed' });
});

it('PAYJ/bolt11 a checksum, character, case or padding error, or a missing p field, is no hash', () => {
  const paymentHash = hash('bolt11');
  const text = invoice({ hash: paymentHash, amount: '10n' });
  expect(decodeBolt11(text)).toEqual({ paymentHash: paymentHash.toString('hex'), amountMsat: 1000n });
  expect(decodeBolt11(text.toUpperCase())).toEqual({ paymentHash: paymentHash.toString('hex'), amountMsat: 1000n });
  const flipped = text.slice(0, -1) + (text.endsWith('q') ? 'p' : 'q');
  expect(decodeBolt11(flipped)).toBeNull();
  const letter = [...text].findIndex((char, index) => index > 10 && /[a-z]/.test(char));
  expect(decodeBolt11(text.slice(0, letter) + text[letter].toUpperCase() + text.slice(letter + 1))).toBeNull();
  expect(decodeBolt11(text.replace(/1(?=[^1]*$)/, 'b'))).toBeNull();
  expect(decodeBolt11(invoice({ hash: null }))).toBeNull();
  expect(decodeBolt11(invoice({ network: 'bc', hashGroups: [...toGroups(paymentHash).slice(0, 51), 1] }))).toBeNull();
  expect(decodeBolt11('lnbc1qqqq')).toBeNull();
  expect(decodeBolt11(bech32('xxbc', Array<number>(140).fill(0)))).toBeNull();
  // A p field of another length is skipped; the first one of 52 groups is the hash.
  const other = hash('second');
  const skipped = invoice({ hash: other, before: [field(1, Array<number>(10).fill(2))] });
  expect((decodeBolt11(skipped) as { paymentHash: string }).paymentHash).toBe(other.toString('hex'));
  const twice = invoice({ hash: other, before: [field(1, toGroups(paymentHash))] });
  expect((decodeBolt11(twice) as { paymentHash: string }).paymentHash).toBe(paymentHash.toString('hex'));
});

it('PAYJ/bolt11 non-ASCII characters are invalid before case folding: Kelvin sign, long s, dotted and dotless I, fullwidth (PF-1)', () => {
  // A hash whose invoice has every substituted letter in its data part.
  let n = 0;
  const dataPart = (candidate: string) => candidate.slice(candidate.lastIndexOf('1') + 1);
  while (!['k', 's', 'l', 'q'].every(letter => dataPart(invoice({ hash: hash(`pf1-${n}`), amount: '10u' })).includes(letter))) n++;
  const paymentHash = hash(`pf1-${n}`);
  const text = invoice({ hash: paymentHash, amount: '10u' });
  const upper = text.toUpperCase();
  expect(decodeBolt11(upper)).toEqual({ paymentHash: paymentHash.toString('hex'), amountMsat: 1_000_000n });
  // Each replaces one data character with a look-alike that a Unicode case mapping folds onto, or
  // leaves beside, an ASCII bech32 character.
  const swaps: [string, string, string][] = [
    [upper, 'K', 'K'], // KELVIN SIGN: toLowerCase gives 'k', toUpperCase leaves it
    [text, 's', 'ſ'], // LATIN SMALL LETTER LONG S: toUpperCase gives 'S'
    [text, 'l', 'ı'], // LATIN SMALL LETTER DOTLESS I: toUpperCase gives 'I'
    [upper, 'L', 'İ'], // LATIN CAPITAL LETTER I WITH DOT ABOVE: toLowerCase gives 'i' + U+0307
    [upper, 'Q', 'Ｑ'], // FULLWIDTH LATIN CAPITAL LETTER Q: toLowerCase gives U+FF51
    [text, 'q', 'ｑ'],
  ];
  for (const [base, ascii, lookalike] of swaps) {
    const at = base.indexOf(ascii, base.lastIndexOf('1') + 1);
    expect(at, `${ascii} in the data part`).toBeGreaterThan(0);
    const swapped = `${base.slice(0, at)}${lookalike}${base.slice(at + 1)}`;
    expect(decodeBolt11(swapped), `U+${lookalike.charCodeAt(0).toString(16)}`).toBeNull();
    expect(paymentFacts(SEND, bytes(5, swapped), false)).toMatchObject({ paymentHash: null, extraction: 'invoice-invalid' });
  }
  // In the human-readable part too, and a non-ASCII character anywhere else.
  expect(decodeBolt11(`K${upper.slice(1)}`)).toBeNull();
  expect(decodeBolt11(`${text}é`)).toBeNull();
});

it('PAYJ/bolt11 bounds: above the character limit is too long, and decoding stays linear in the length', () => {
  const long = invoice({ before: Array.from({ length: 1_950 }, () => field(13, [1])) });
  expect(long.length).toBeLessThanOrEqual(MAX_INVOICE_CHARS);
  expect(decodeBolt11(long)).not.toBeNull();
  const tooLong = invoice({ before: Array.from({ length: 2_100 }, () => field(13, [1])) });
  expect(tooLong.length).toBeGreaterThan(MAX_INVOICE_CHARS);
  expect(decodeBolt11(tooLong)).toBe('too-long');
  expect(paymentFacts(SEND, bytes(5, tooLong), false)).toMatchObject({ paymentHash: null, extraction: 'invoice-too-long' });
  // More than 4 bytes per allowed character is refused before it is decoded as text.
  expect(paymentFacts(SEND, bytes(5, Buffer.alloc(MAX_INVOICE_CHARS * 4 + 1, 0x61)), false)).toMatchObject({ extraction: 'invoice-too-long' });
  // Linear: an invoice 8 times longer takes well under 64 times as long (quadratic) to decode.
  const short = invoice({ before: Array.from({ length: 250 }, () => field(13, [1])) });
  const time = (text: string) => {
    const samples: number[] = [];
    for (let round = 0; round < 5; round++) {
      const start = performance.now();
      for (let i = 0; i < 200; i++) decodeBolt11(text);
      samples.push(performance.now() - start);
    }
    return samples.sort((a, b) => a - b)[2];
  };
  time(long);
  expect(time(long) / Math.max(time(short), 0.01)).toBeLessThan(24);
});

it('PAYJ/middleware only a selected method\'s request payload is passed on, as a bounded view', () => {
  const serialized = message(bytes(3, hash('selected')), uint(2, 9));
  const selected = new Set([SEND]);
  const request = decodeMiddlewareRequest(middlewareRequest({ method: SEND, serialized }), selected);
  expect(request.kind).toBe('request');
  expect(request.payload.equals(serialized)).toBe(true);
  expect(request.oversizedPayload).toBe(false);
  // Without a selection, for another method, for a response and for stream authentication: nothing.
  expect(decodeMiddlewareRequest(middlewareRequest({ method: SEND, serialized })).payload.length).toBe(0);
  expect(decodeMiddlewareRequest(middlewareRequest({ method: '/lnrpc.Lightning/GetInfo', serialized }), selected).payload.length).toBe(0);
  expect(decodeMiddlewareRequest(middlewareRequest({ method: SEND, serialized, kind: 'response' }), selected).payload.length).toBe(0);
  expect(decodeMiddlewareRequest(middlewareRequest({ method: SEND, serialized, kind: 'stream_auth' }), selected).payload.length).toBe(0);
  const oversized = decodeMiddlewareRequest(middlewareRequest({ method: SEND, serialized: Buffer.alloc(MAX_PAYLOAD_BYTES + 1, 1) }), selected);
  expect(oversized.payload.length).toBe(0);
  expect(oversized.oversizedPayload).toBe(true);
  const exact = decodeMiddlewareRequest(middlewareRequest({ method: SEND, serialized: Buffer.alloc(MAX_PAYLOAD_BYTES, 1) }), selected);
  expect(exact.payload.length).toBe(MAX_PAYLOAD_BYTES);
});

// 1.2.1: a satoshi amount or fee limit times 1,000, or an invoice amount, can exceed the int64
// millisatoshi range the journal records; such a value is no amount, never a record the reader refuses.
it('PAYJ/bounds amounts above the int64 millisatoshi range are no amount; the range itself is kept', () => {
  const h = hash('bounds');
  const max = (1n << 63n) - 1n;
  const over = paymentFacts(SEND, message(bytes(3, h), uint(2, 1n << 62n), uint(7, max)), false);
  expect(over).toMatchObject({ paymentHash: h.toString('hex'), amountMsat: null, amountSource: null, feeLimitMsat: null, extraction: 'complete' });
  const atMax = paymentFacts(SEND, message(bytes(3, h), uint(12, max), uint(13, max)), false);
  expect(atMax).toMatchObject({ amountMsat: max.toString(), amountSource: 'request', feeLimitMsat: max.toString() });
  const satMax = paymentFacts(SEND, message(bytes(3, h), uint(2, 9_223_372_036_854_775n), uint(7, 9_223_372_036_854_775n)), false);
  expect(satMax).toMatchObject({ amountMsat: '9223372036854775000', feeLimitMsat: '9223372036854775000' });
  // An invoice amount of 21 million bitcoin fits; one of 10 billion bitcoin does not.
  expect(paymentFacts(SEND, message(bytes(5, invoice({ hash: h, amount: '21000000' }))), false).amountMsat).toBe('2100000000000000000');
  expect(paymentFacts(SEND, message(bytes(5, invoice({ hash: h, amount: '10000000000' }))), false))
    .toMatchObject({ paymentHash: h.toString('hex'), amountMsat: null, amountSource: null, extraction: 'complete' });
});

// 1.2.1: proto3 treats an explicitly empty string as absent, and LND then pays the request's hash.
it('PAYJ/send-payment an explicitly empty payment_request with a valid hash is journaled with the hash', () => {
  const h = hash('empty-invoice');
  expect(paymentFacts(SEND, message(bytes(3, h), bytes(5, Buffer.alloc(0)), uint(2, 7)), false))
    .toMatchObject({ paymentHash: h.toString('hex'), amountMsat: '7000', amountSource: 'request', extraction: 'complete' });
});
