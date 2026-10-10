import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { LndError, UsageError } from '../src/errors.js';
import { createLndAdapter } from '../src/lnd/index.js';
// The adapter's bound for one ListPayments page or TrackPaymentV2 update (8 MiB, src/lnd/index.ts).
const PAYMENT_RESPONSE_LIMIT = 8 * 1024 * 1024;
import { Secret } from '../src/secret.js';

// ListPayments and TrackPaymentV2 over REST (reconcile): only the documented fields are read,
// the preimage and payment request LND also returns are never kept, responses are bounded,
// and a streaming lookup ends after its first message.
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');
const own = () => new Secret(readFileSync(join(resolve(), 'test/sentinels/sentinel.macaroon')));
const HASH = 'ab'.repeat(32);
const PREIMAGE = 'cd'.repeat(32);
const INVOICE = 'lnbcrt10u1pjtestinvoicetextthatmustneverbekept';

type Seen = { method: string; path: string; headers: Record<string, string | string[] | undefined> };
type Answer = { status?: number; body?: string; open?: boolean };

function certificate(dir: string) {
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const key = join(dir, 'local.key'), cert = join(dir, 'local.crt');
  const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-config', config,
    '-keyout', key, '-out', cert, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8', timeout: 20_000 });
  if (made.status !== 0) throw new Error('Local HTTPS certificate generation failed');
  return { key: readFileSync(key), ca: readFileSync(cert) };
}

async function withServer(answer: (request: Seen) => Answer, work: (adapter: ReturnType<typeof createLndAdapter>, seen: Seen[],
  open: () => number) => Promise<void>): Promise<void> {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'payment-adapter-'));
  const { key, ca } = certificate(dir);
  const seen: Seen[] = [];
  let streams = 0;
  const server: Server = createServer({ key, cert: ca }, (request, response) => {
    const entry = { method: request.method ?? '', path: request.url ?? '', headers: request.headers };
    seen.push(entry);
    const reply = answer(entry);
    response.writeHead(reply.status ?? 200, { 'content-type': 'application/json' });
    if (reply.open) {
      // A stream that stays open after its first message, as TrackPaymentV2 does for a payment in flight.
      streams += 1;
      response.write(reply.body ?? '');
      response.on('close', () => { streams -= 1; });
      return;
    }
    response.end(reply.body ?? '{}');
  });
  try {
    await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
    const port = (server.address() as AddressInfo).port;
    await work(createLndAdapter({ restUrl: `https://127.0.0.1:${port}`, tlsCert: ca, macaroon: own() }), seen, () => streams);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    rmSync(dir, { recursive: true, force: true });
  }
}

const lndPayment = (overrides: Record<string, unknown> = {}) => ({
  payment_hash: HASH, value: '1000', creation_date: '1791540000', fee: '2', payment_preimage: PREIMAGE, value_sat: '1000',
  value_msat: '1000000', payment_request: INVOICE, status: 'SUCCEEDED', fee_sat: '2', fee_msat: '2500', creation_time_ns: '1791540000123456789',
  htlcs: [
    { attempt_id: '1', status: 'FAILED', route: { total_time_lock: 100, total_fees: '1', total_amt: '1001', hops: [], total_fees_msat: '1200',
      total_amt_msat: '1001200' }, attempt_time_ns: '1', resolve_time_ns: '2', failure: { code: 'TEMPORARY_CHANNEL_FAILURE' }, preimage: '' },
    { attempt_id: '2', status: 'SUCCEEDED', route: { total_time_lock: 100, total_fees: '2', total_amt: '1002', hops: [], total_fees_msat: '2500',
      total_amt_msat: '1002500' }, attempt_time_ns: '3', resolve_time_ns: '4', failure: null, preimage: PREIMAGE },
  ],
  payment_index: '7', failure_reason: 'FAILURE_REASON_NONE', ...overrides });

it('PAYADAPTER/list-payments queries the window with incomplete payments and reads only the settlement fields', async () => {
  await withServer(() => ({ body: JSON.stringify({ payments: [lndPayment(), lndPayment({ payment_hash: 'ef'.repeat(32), status: 'INITIATED',
    htlcs: [], payment_index: '8' }), lndPayment({ payment_hash: '01'.repeat(32), status: 'FAILED', htlcs: [], payment_index: '9',
    failure_reason: 'FAILURE_REASON_INSUFFICIENT_BALANCE' })], first_index_offset: '7', last_index_offset: '9', total_num_payments: '0' }) }),
  async (adapter, seen) => {
    const page = await adapter.listPayments({ startSeconds: 1_791_539_940, endSeconds: 1_791_543_660, indexOffset: 6n, max: 100 });
    expect(seen).toHaveLength(1);
    const url = new URL(seen[0].path, 'https://localhost');
    expect(seen[0].method).toBe('GET');
    expect(url.pathname).toBe('/v1/payments');
    expect(Object.fromEntries(url.searchParams)).toEqual({ include_incomplete: 'true', index_offset: '6', max_payments: '100', reversed: 'false',
      count_total_payments: 'false', creation_date_start: '1791539940', creation_date_end: '1791543660' });
    expect(seen[0].headers['grpc-metadata-macaroon']).toBeDefined();
    expect(page.lastIndexOffset).toBe(9n);
    // The attempts are summed by status while parsing, never kept (audit 1.2.1: 100,000 payments of 1,000 attempts were ~10 GiB).
    expect(page.payments[0]).toEqual({ paymentHash: HASH, status: 'succeeded', createdAtNs: 1791540000123456789n, valueMsat: 1000000n,
      feeMsat: 2500n, attempts: 2, succeededAttempts: 1, succeededMsat: 1000000n, succeededFeesMsat: 2500n, inFlightMsat: 0n,
      failureReason: null, index: 7n });
    expect(page.payments[1]).toMatchObject({ status: 'in-flight', attempts: 0, inFlightMsat: 0n });
    expect(page.payments[2]).toMatchObject({ status: 'failed', failureReason: 'insufficient-balance' });
    const kept = JSON.stringify(page, (_key, value) => typeof value === 'bigint' ? value.toString() : value);
    expect(kept).not.toContain(PREIMAGE);
    expect(kept).not.toContain(INVOICE);
  });
});

it('PAYADAPTER/list-payments refuses invalid responses and queries, and bounds the response size', async () => {
  const invalid = [
    { payments: [lndPayment({ payment_hash: 'zz' })] },
    { payments: [lndPayment({ creation_time_ns: 12.5 })] },
    { payments: [lndPayment({ value_msat: '1e3' })] },
    { payments: [lndPayment({ htlcs: [{ status: 'SUCCEEDED', route: { total_fees_msat: '5', total_amt_msat: '4' } }] })] },
    { payments: [lndPayment({ failure_reason: 'free text' })] },
    // Audit 1.2.1: values outside LND's own types would reach the output outside its schema.
    { payments: [lndPayment({ value_msat: '-5000' })] },
    { payments: [lndPayment({ fee_msat: '-1' })] },
    { payments: [lndPayment({ creation_time_ns: '-1' })] },
    { payments: [lndPayment({ creation_time_ns: '100000000000000000000' })] },
    { payments: [lndPayment({ payment_index: '18446744073709551616' })] },
    { payments: [], last_index_offset: '18446744073709551616' },
    { payments: 'none' },
    { payments: [lndPayment(), lndPayment()], last_index_offset: '2' },
    { payments: [], last_index_offset: '-1' },
  ];
  let index = 0;
  await withServer(() => ({ body: JSON.stringify(invalid[index++]) }), async adapter => {
    for (let i = 0; i < invalid.length; i++) {
      const error = await adapter.listPayments({ startSeconds: 0, endSeconds: 10, indexOffset: 0n, max: 1 }).then(() => null, failure => failure);
      expect(error, JSON.stringify(invalid[i])).toBeInstanceOf(LndError);
      expect((error as LndError).code).toBe(5);
    }
  });
  await withServer(() => ({ body: JSON.stringify({ payments: [], padding: 'x'.repeat(PAYMENT_RESPONSE_LIMIT) }) }), async adapter => {
    const error = await adapter.listPayments({ startSeconds: 0, endSeconds: 10, indexOffset: 0n, max: 10 }).then(() => null, failure => failure);
    expect(error).toBeInstanceOf(LndError);
    expect((error as LndError).message).toBe('LND response too large');
  });
  await withServer(() => ({ status: 401, body: '{"message":"denied"}' }), async adapter => {
    const error = await adapter.listPayments({ startSeconds: 0, endSeconds: 10, indexOffset: 0n, max: 10 }).then(() => null, failure => failure);
    expect((error as LndError).code).toBe(4);
  });
  await withServer(() => ({ body: '{}' }), async (adapter, seen) => {
    for (const query of [{ startSeconds: 10, endSeconds: 5, indexOffset: 0n, max: 10 }, { startSeconds: 0, endSeconds: 5, indexOffset: -1n, max: 10 },
      { startSeconds: 0, endSeconds: 5, indexOffset: 0n, max: 0 }, { startSeconds: 0, endSeconds: 5, indexOffset: 0n, max: 1_001 },
      { startSeconds: -1, endSeconds: 5, indexOffset: 0n, max: 1 }])
      await expect(adapter.listPayments(query)).rejects.toBeInstanceOf(UsageError);
    expect(seen).toEqual([]);
  });
});

it('PAYADAPTER/sums attempt amounts summed past an int64 for one payment are not an LND record (audit 1.2.1 N1)', async () => {
  const MAX = '9223372036854775807';
  const attempt = (status: string, total: string, fees: string) => ({ status, route: { total_fees_msat: fees, total_amt_msat: total } });
  // Each attempt is within LND's int64 type; only their sum is impossible (21 million bitcoin is 2.1e18 msat).
  // Each page is valid but for the sums (last_index_offset included), so only the sum check can refuse it.
  const invalid = [
    [attempt('SUCCEEDED', MAX, '0'), attempt('SUCCEEDED', '1', '0')],
    Array.from({ length: 1_000 }, () => attempt('SUCCEEDED', MAX, '0')),
    [attempt('SUCCEEDED', MAX, MAX), attempt('SUCCEEDED', '1', '1')],
    [attempt('IN_FLIGHT', MAX, '0'), attempt('IN_FLIGHT', MAX, '0')],
  ].map(htlcs => ({ payments: [lndPayment({ htlcs })], last_index_offset: '7' }));
  let index = 0;
  await withServer(() => ({ body: JSON.stringify(invalid[index++]) }), async adapter => {
    for (let i = 0; i < invalid.length; i++) {
      const error = await adapter.listPayments({ startSeconds: 0, endSeconds: 10, indexOffset: 0n, max: 1 }).then(() => null, failure => failure);
      expect(error, `case ${i}`).toBeInstanceOf(LndError);
      expect((error as LndError).message).toBe('invalid LND response');
      expect((error as LndError).code).toBe(5);
    }
  });
  // At the bound exactly, the sums are still LND's: one attempt of 2^63-1 and failed attempts that are not summed.
  await withServer(() => ({ body: JSON.stringify({ payments: [lndPayment({ htlcs: [attempt('SUCCEEDED', MAX, '0'), attempt('FAILED', MAX, '0'),
    attempt('FAILED', MAX, '0')] })], last_index_offset: '7' }) }), async adapter => {
    const page = await adapter.listPayments({ startSeconds: 0, endSeconds: 10, indexOffset: 0n, max: 1 });
    expect(page.payments[0]).toMatchObject({ succeededMsat: BigInt(MAX), attempts: 3 });
  });
});

it('PAYADAPTER/track-payment reads the first streamed update and closes the stream; the hash is base64url in the path', async () => {
  await withServer(() => ({ open: true, body: `${JSON.stringify({ result: lndPayment({ status: 'IN_FLIGHT', htlcs: [{ status: 'IN_FLIGHT',
    route: { total_fees_msat: '10', total_amt_msat: '5010' } }] }) })}\n` }), async (adapter, seen, open) => {
    const found = await adapter.trackPayment(HASH);
    expect(seen[0].path).toBe(`/v2/router/track/${Buffer.from(HASH, 'hex').toString('base64url')}`);
    expect(found).toMatchObject({ paymentHash: HASH, status: 'in-flight', attempts: 1, succeededAttempts: 0, inFlightMsat: 5000n });
    // The stream is not kept open after its first message.
    for (let i = 0; i < 50 && open() > 0; i++) await new Promise(done => setTimeout(done, 20));
    expect(open()).toBe(0);
  });
});

it('PAYADAPTER/track-payment an unknown hash is not found; other errors fail without echoing LND text', async () => {
  const answers: Answer[] = [
    { status: 500, body: '{"code":2,"message":"payment isn\'t initiated","details":[]}' },
    { status: 200, body: '{"error":{"code":2,"message":"payment isn\'t initiated","details":[]}}\n' },
    { status: 500, body: '{"error":{"code":2,"message":"payment isn\'t initiated"}}' },
  ];
  let index = 0;
  await withServer(() => answers[index++], async adapter => {
    for (let i = 0; i < answers.length; i++) expect(await adapter.trackPayment(HASH)).toBeNull();
  });
  const failures: Answer[] = [
    { status: 500, body: '{"code":2,"message":"router shutting down"}' },
    { status: 200, body: '{"error":{"code":13,"message":"internal"}}\n' },
    { status: 200, body: `${JSON.stringify({ result: lndPayment({ payment_hash: 'ef'.repeat(32) }) })}\n` },
    { status: 200, body: 'not json\n' },
  ];
  index = 0;
  await withServer(() => failures[index++], async adapter => {
    for (let i = 0; i < failures.length; i++) {
      const error = await adapter.trackPayment(HASH).then(() => null, failure => failure);
      expect(error, failures[i].body).toBeInstanceOf(LndError);
      expect((error as LndError).code).toBe(5);
      expect((error as LndError).message).not.toContain('router shutting down');
    }
  });
  await withServer(() => ({ status: 403, body: '{"message":"permission denied"}' }), async adapter => {
    expect(((await adapter.trackPayment(HASH).then(() => null, failure => failure)) as LndError).code).toBe(4);
  });
  await withServer(() => ({ body: '{}' }), async (adapter, seen) => {
    await expect(adapter.trackPayment('AB'.repeat(32))).rejects.toBeInstanceOf(UsageError);
    await expect(adapter.trackPayment('ab')).rejects.toBeInstanceOf(UsageError);
    expect(seen).toEqual([]);
  });
});
