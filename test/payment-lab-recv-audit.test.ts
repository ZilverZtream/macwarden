import { createHash } from 'node:crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { preimageFor, tempDirectory, type Invoice, type Payment, type RawDb } from './helpers/payment-lab-modules.js';

/**
 * Regressions for the pre-1.4 audit of the payment lab's receiver (examples/payment-lab/src/receiver)
 * and its analysis commands (src/analysis): a lookup or create answer for another payment hash, an
 * invoice LND deleted, a late invoice LND deleted, the deliveries log growing with every repeat, payment
 * preimages and requests in `analysis payments`, a paged scan that stopped early reported complete, a
 * hold invoice LND returned from ACCEPTED to OPEN, an underpaid order that could never be paid, and a
 * SETTLED report with nothing paid. The lab's real stores and workflows run against a scripted invoice
 * API; no node, no Docker, no credential.
 */

/** Where the lab's modules are loaded from (a computed specifier, as in helpers/payment-lab-modules.ts). */
const SRC = '../examples/payment-lab/src/';

async function load<T>(relative: string): Promise<T> {
  return await import(/* @vite-ignore */ `${SRC}${relative}`) as T;
}

interface InvoiceRecord {
  paymentHash: string; orderId: string; state: string; paymentRequest: string | undefined; amtPaidMsat: bigint | undefined;
  lateLndState: string | undefined;
}
interface ReceiverStore {
  readonly db: RawDb;
  close(): void;
  invoice(paymentHash: string): InvoiceRecord | undefined;
  order(orderId: string): { state: string } | undefined;
  recordInvoiceIntent(input: { orderId: string; amountMsat: bigint; kind: 'standard' | 'hold'; preimage: string; paymentHash: string }):
    { outcome: string; reason?: string };
  markCreated(paymentHash: string, paymentRequest: string, addIndex: bigint): string | undefined;
  markNotCreated(paymentHash: string, createdBefore?: string): boolean;
  applyInvoice(invoice: Invoice, source: string): string;
  cursor(): { addIndex: bigint; settleIndex: bigint };
  setCursor(settleIndex: bigint, addIndex: bigint): void;
  deliveries(paymentHash: string): { source: string; lndState: string; outcome: string }[];
  journal(orderId: string): { event: string }[];
}
type Emit = (event: Record<string, unknown>) => void;
interface Deps { api: FakeInvoiceApi; store: ReceiverStore; emit: Emit }
interface Receiver {
  createInvoice(deps: Deps, input: { orderId: string; amountMsat: bigint; hold: boolean; memo: string; expirySeconds: number }):
    Promise<{ kind: string; paymentHash?: string; paymentRequest?: string; reason?: string }>;
  settleHoldInvoice(deps: Deps, orderId: string): Promise<{ kind: string; reason?: string }>;
  cancelHoldInvoice(deps: Deps, orderId: string): Promise<{ kind: string; reason?: string }>;
  reconcileInvoices(deps: Deps, onlyOrder?: string): Promise<{ resolved: number; open: number; unknown: number }>;
}
interface ForwardingEvent { timestampNs: bigint }
interface ReadStub {
  listPaymentsPage(offset: bigint, max: number): Promise<{ payments: Payment[]; lastIndexOffset: bigint }>;
  forwardingHistory(since: bigint, until: bigint, offset: number, max: number): Promise<{ events: ForwardingEvent[]; lastOffsetIndex: number }>;
}
interface Analysis {
  paymentsForHash(read: ReadStub, paymentHash: string): Promise<{ payments: Record<string, unknown>[]; scanned: number; complete: boolean }>;
  forwardsSince(read: ReadStub, since: bigint): Promise<{ events: ForwardingEvent[]; complete: boolean }>;
}
interface Diagnose {
  diagnose(read: unknown, input: { amountMsat: bigint; destination: string; payment?: unknown; paymentScan?: { complete: boolean; scanned: number } }):
    Promise<{ findings: string[] }>;
}
interface Lab {
  ReceiverStore: new (path: string) => ReceiverStore;
  LndError: new (message: string, grpcCode: number | undefined, httpStatus: number | undefined) => Error;
  TransportError: new (message: string, phase: 'connect' | 'request' | 'response') => Error;
  receiver: Receiver;
  analysis: Analysis;
  diagnose: Diagnose;
}

let lab: Lab;
const dir = tempDirectory();
const opened: ReceiverStore[] = [];

beforeAll(async () => {
  // One after another, errors.ts first, so every module shares one instance of the error classes.
  const errors = await load<Pick<Lab, 'LndError' | 'TransportError'>>('lnd/errors.ts');
  const store = await load<Pick<Lab, 'ReceiverStore'>>('receiver/store.ts');
  const receiver = await load<Receiver>('receiver/receiver.ts');
  const analysis = await load<Analysis>('analysis/payments.ts');
  const diagnose = await load<Diagnose>('analysis/diagnose.ts');
  lab = { ...errors, ...store, receiver, analysis, diagnose };
});
afterEach(() => {
  for (const store of opened.splice(0)) {
    try { store.close(); } catch { /* already closed */ }
  }
});
afterAll(() => dir.remove());

let files = 0;
function receiverStore(): ReceiverStore {
  files += 1;
  const store = new lab.ReceiverStore(dir.path(`recv-audit-${files}.db`));
  opened.push(store);
  return store;
}

// ------------------------------------------------------------------------------------------
// A synthetic BOLT11 string: bech32 with a timestamp, a payment-hash (`p`) field and a zero
// signature. Nothing reads its signature; it is never an invoice anyone could pay.

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let bit = 0; bit < 5; bit += 1) if ((top >>> bit) & 1) checksum ^= GENERATOR[bit] ?? 0;
  }
  return checksum;
}

function syntheticBolt11(paymentHash: string): string {
  const hrp = 'lnbcrt';
  const words: number[] = [0, 0, 0, 0, 0, 0, 1]; // timestamp
  let bits = BigInt(`0x${paymentHash}`) << 4n; // 256 bits and 4 padding bits: 52 words
  const hashWords: number[] = [];
  for (let index = 0; index < 52; index += 1) { hashWords.unshift(Number(bits & 31n)); bits >>= 5n; }
  words.push(1, 1, 20, ...hashWords); // type p, length 52
  words.push(...new Array<number>(104).fill(0)); // signature and recovery id
  const expanded = [...hrp].map(char => char.charCodeAt(0) >> 5).concat([0], [...hrp].map(char => char.charCodeAt(0) & 31));
  const mod = polymod([...expanded, ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [0, 1, 2, 3, 4, 5].map(index => (mod >>> (5 * (5 - index))) & 31);
  return `${hrp}1${[...words, ...checksum].map(word => CHARSET[word]).join('')}`;
}

const sha256 = (preimageHex: string): string => createHash('sha256').update(Buffer.from(preimageHex, 'hex')).digest('hex');

// ------------------------------------------------------------------------------------------
// A scripted invoice API (the pattern of the audit's fake): LND's invoices in a map, a lookup
// override for a proxy that answers with another invoice, and the calls made.

function lndInvoice(paymentHash: string, state: string, extra: Partial<Invoice> = {}): Invoice {
  return { paymentHash, state, memo: '', valueMsat: 4000n, amtPaidMsat: state === 'SETTLED' || state === 'ACCEPTED' ? 4000n : 0n,
    addIndex: 1n, settleIndex: state === 'SETTLED' ? 1n : 0n, paymentRequest: syntheticBolt11(paymentHash), htlcs: [], ...extra };
}

class FakeInvoiceApi {
  readonly invoices = new Map<string, Invoice>();
  readonly calls: string[] = [];
  lookupOverride: ((paymentHash: string) => Invoice | undefined) | undefined;
  createAnswer: ((paymentHash: string) => { paymentHash?: string; paymentRequest: string } | Error) | undefined;
  /** CancelInvoice deletes the invoice (LND's gc-canceled-invoices-on-the-fly). */
  deleteOnCancel = false;

  addInvoice(request: { preimage: string; valueMsat: bigint }): Promise<{ paymentHash: string; paymentRequest: string; addIndex: bigint }> {
    this.calls.push('AddInvoice');
    const paymentHash = sha256(request.preimage);
    this.invoices.set(paymentHash, lndInvoice(paymentHash, 'OPEN', { valueMsat: request.valueMsat }));
    const answer = this.createAnswer?.(paymentHash) ?? { paymentHash, paymentRequest: syntheticBolt11(paymentHash) };
    if (answer instanceof Error) return Promise.reject(answer);
    return Promise.resolve({ paymentHash: answer.paymentHash ?? paymentHash, paymentRequest: answer.paymentRequest, addIndex: 1n });
  }

  addHoldInvoice(request: { paymentHash: string; valueMsat: bigint }): Promise<{ paymentRequest: string; addIndex: bigint }> {
    this.calls.push('AddHoldInvoice');
    this.invoices.set(request.paymentHash, lndInvoice(request.paymentHash, 'OPEN', { valueMsat: request.valueMsat }));
    const answer = this.createAnswer?.(request.paymentHash) ?? { paymentRequest: syntheticBolt11(request.paymentHash) };
    if (answer instanceof Error) return Promise.reject(answer);
    return Promise.resolve({ paymentRequest: answer.paymentRequest, addIndex: 1n });
  }

  lookupInvoice(paymentHash: string): Promise<Invoice> {
    this.calls.push('LookupInvoice');
    const override = this.lookupOverride?.(paymentHash);
    if (override !== undefined) return Promise.resolve({ ...override });
    const found = this.invoices.get(paymentHash);
    if (found === undefined) return Promise.reject(new lab.LndError('unable to locate invoice', 5, 404));
    return Promise.resolve({ ...found });
  }

  settleInvoice(preimage: string): Promise<void> {
    this.calls.push('SettleInvoice');
    const found = this.invoices.get(sha256(preimage));
    if (found?.state !== 'ACCEPTED') return Promise.reject(new lab.LndError('invoice still open', 2, 500));
    found.state = 'SETTLED';
    found.settleIndex = 1n;
    return Promise.resolve();
  }

  cancelInvoice(paymentHash: string): Promise<void> {
    this.calls.push('CancelInvoice');
    const found = this.invoices.get(paymentHash);
    if (found === undefined) return Promise.reject(new lab.LndError('unable to locate invoice', 5, 404));
    if (found.state === 'SETTLED') return Promise.reject(new lab.LndError('invoice already settled', 2, 500));
    found.state = 'CANCELED';
    found.amtPaidMsat = 0n;
    if (this.deleteOnCancel) this.invoices.delete(paymentHash);
    return Promise.resolve();
  }

  subscribeInvoices(): Promise<void> {
    return Promise.reject(new Error('not used here'));
  }
}

function receiver(store = receiverStore(), api = new FakeInvoiceApi()): Deps & { api: FakeInvoiceApi; events: Record<string, unknown>[] } {
  const events: Record<string, unknown>[] = [];
  return { api, store, emit: event => { events.push(event); }, events };
}

async function created(deps: Deps, orderId: string, hold = false): Promise<string> {
  const outcome = await lab.receiver.createInvoice(deps, { orderId, amountMsat: 4000n, hold, memo: orderId, expirySeconds: 3600 });
  expect(outcome.kind).toBe('created');
  return outcome.paymentHash ?? '';
}

const deliveryCount = (store: ReceiverStore, paymentHash: string): number =>
  Number(store.db.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE payment_hash = ?').all(paymentHash)[0]?.n);

// ------------------------------------------------------------------------------------------

describe('payment lab receiver audit: an answer about another invoice', () => {
  const other = preimageFor('recv-audit-someone-else').paymentHash;

  it('a lookup that answers with another hash\'s SETTLED invoice does not settle the order (settle is unresolved, nothing is settled)', async () => {
    const deps = receiver();
    const hash = await created(deps, 'O-01A', true);
    deps.api.lookupOverride = () => lndInvoice(other, 'SETTLED');
    const outcome = await lab.receiver.settleHoldInvoice(deps, 'O-01A');
    expect(outcome.kind).toBe('unresolved');
    expect(deps.store.invoice(hash)?.state).toBe('open');
    expect(deps.store.order('O-01A')?.state).toBe('awaiting-payment');
    expect(deps.store.journal('O-01A')).toEqual([]);
    expect(deps.api.calls).not.toContain('SettleInvoice');
    expect(deps.events).toContainEqual(expect.objectContaining({ event: 'lookup-failed', paymentHash: hash,
      error: expect.stringMatching(/^ProtocolError: LND answered for payment hash/) as unknown }));
  });

  it('a lookup that answers with a payment request for another hash is refused too', async () => {
    const deps = receiver();
    const hash = await created(deps, 'O-01A2', true);
    deps.api.lookupOverride = hashAsked => lndInvoice(hashAsked, 'SETTLED', { paymentRequest: syntheticBolt11(other) });
    expect((await lab.receiver.settleHoldInvoice(deps, 'O-01A2')).kind).toBe('unresolved');
    expect(deps.store.invoice(hash)?.state).toBe('open');
    expect(deps.store.journal('O-01A2')).toEqual([]);
  });

  it('reconciliation counts such an answer unknown and leaves the record open', async () => {
    const deps = receiver();
    const hash = await created(deps, 'O-01B');
    deps.api.lookupOverride = () => lndInvoice(other, 'CANCELED');
    expect(await lab.receiver.reconcileInvoices(deps)).toEqual({ resolved: 0, open: 0, unknown: 1 });
    expect(deps.store.invoice(hash)?.state).toBe('open');
    expect(deps.store.order('O-01B')?.state).toBe('awaiting-payment');
  });

  it('a lost create answer resolved by a lookup that answers with another invoice is unresolved, and no payment request is stored', async () => {
    const deps = receiver();
    deps.api.createAnswer = () => new lab.TransportError('socket hang up', 'response');
    deps.api.lookupOverride = () => lndInvoice(other, 'OPEN');
    const outcome = await lab.receiver.createInvoice(deps, { orderId: 'O-01C', amountMsat: 4000n, hold: false, memo: 'x', expirySeconds: 3600 });
    expect(outcome.kind).toBe('unresolved');
    expect(outcome.paymentRequest).toBeUndefined();
    const record = deps.store.invoice(outcome.paymentHash ?? '');
    expect(record?.state).toBe('creating');
    expect(record?.paymentRequest).toBeUndefined();
  });

  for (const hold of [false, true]) {
    it(`${hold ? 'AddHoldInvoice' : 'AddInvoice'}: an answer whose payment request is for another hash is not recorded as created`, async () => {
      const deps = receiver();
      deps.api.createAnswer = () => ({ paymentRequest: syntheticBolt11(other) });
      // The lookup of the hash that follows answers with the other invoice too (a proxy that mixes them up).
      deps.api.lookupOverride = () => lndInvoice(other, 'OPEN');
      const outcome = await lab.receiver.createInvoice(deps, { orderId: `O-01D-${hold}`, amountMsat: 4000n, hold, memo: 'x', expirySeconds: 3600 });
      expect(outcome.kind).toBe('unresolved');
      expect(outcome.paymentRequest).toBeUndefined();
      expect(deps.store.invoice(outcome.paymentHash ?? '')?.paymentRequest).toBeUndefined();
      expect(deps.store.invoice(outcome.paymentHash ?? '')?.state).toBe('creating');
    });

    it(`${hold ? 'AddHoldInvoice' : 'AddInvoice'}: a wrong create answer is resolved by a correct lookup of the hash`, async () => {
      const deps = receiver();
      deps.api.createAnswer = () => ({ paymentRequest: syntheticBolt11(other) });
      const outcome = await lab.receiver.createInvoice(deps, { orderId: `O-01E-${hold}`, amountMsat: 4000n, hold, memo: 'x', expirySeconds: 3600 });
      expect(outcome.kind).toBe('created');
      expect(outcome.paymentRequest).toBe(syntheticBolt11(outcome.paymentHash ?? ''));
      expect(deps.store.invoice(outcome.paymentHash ?? '')?.paymentRequest).toBe(syntheticBolt11(outcome.paymentHash ?? ''));
    });
  }
});

describe('payment lab receiver audit: invoices LND deleted', () => {
  it('an open invoice LND no longer holds (deleted once canceled) is recorded canceled and counted resolved, once', async () => {
    const deps = receiver();
    const hash = await created(deps, 'O-02');
    deps.api.invoices.delete(hash);
    expect(await lab.receiver.reconcileInvoices(deps)).toEqual({ resolved: 1, open: 0, unknown: 0 });
    expect(deps.store.invoice(hash)?.state).toBe('canceled');
    expect(deps.store.order('O-02')?.state).toBe('canceled');
    expect(deps.events).toContainEqual(expect.objectContaining({ event: 'invoice-not-found', paymentHash: hash }));
    // Nothing is left to look up.
    const lookups = deps.api.calls.filter(call => call === 'LookupInvoice').length;
    expect(await lab.receiver.reconcileInvoices(deps)).toEqual({ resolved: 0, open: 0, unknown: 0 });
    expect(deps.api.calls.filter(call => call === 'LookupInvoice').length).toBe(lookups);
  });

  it('an accepted hold invoice canceled with "receiver cancel" that LND deletes at once is canceled', async () => {
    const deps = receiver();
    const hash = await created(deps, 'O-02B', true);
    const held = deps.api.invoices.get(hash);
    if (held !== undefined) { held.state = 'ACCEPTED'; held.amtPaidMsat = 4000n; }
    deps.api.deleteOnCancel = true;
    expect(await lab.receiver.cancelHoldInvoice(deps, 'O-02B')).toEqual({ kind: 'canceled' });
    expect(deps.store.invoice(hash)?.state).toBe('canceled');
  });

  it('a creating invoice LND has no record of stays creating inside the creation window (unchanged rule)', async () => {
    const deps = receiver();
    const { preimage, paymentHash } = preimageFor('recv-audit-02c');
    expect(deps.store.recordInvoiceIntent({ orderId: 'O-02C', amountMsat: 4000n, kind: 'standard', preimage, paymentHash }).outcome).toBe('recorded');
    expect(await lab.receiver.reconcileInvoices(deps)).toEqual({ resolved: 0, open: 0, unknown: 1 });
    expect(deps.store.invoice(paymentHash)?.state).toBe('creating');
  });

  /** A not-created invoice LND holds OPEN while its order has another live invoice: late_lnd_state OPEN. */
  function lateInvoice(deps: ReturnType<typeof receiver>, orderId: string): string {
    const first = preimageFor(`${orderId}-first`);
    const second = preimageFor(`${orderId}-second`);
    expect(deps.store.recordInvoiceIntent({ orderId, amountMsat: 4000n, kind: 'standard', ...first }).outcome).toBe('recorded');
    expect(deps.store.markNotCreated(first.paymentHash)).toBe(true);
    expect(deps.store.recordInvoiceIntent({ orderId, amountMsat: 4000n, kind: 'standard', ...second }).outcome).toBe('recorded');
    expect(deps.store.markCreated(second.paymentHash, syntheticBolt11(second.paymentHash), 2n)).toBe('open');
    deps.api.invoices.set(second.paymentHash, lndInvoice(second.paymentHash, 'OPEN'));
    expect(deps.store.markCreated(first.paymentHash, syntheticBolt11(first.paymentHash), 1n)).toBe('not-created');
    expect(deps.store.invoice(first.paymentHash)?.lateLndState).toBe('OPEN');
    return first.paymentHash;
  }

  it('a late invoice recorded OPEN that LND no longer holds is recorded CANCELED and no longer looked up', async () => {
    const deps = receiver();
    const late = lateInvoice(deps, 'O-03A');
    expect(await lab.receiver.reconcileInvoices(deps)).toEqual({ resolved: 1, open: 1, unknown: 0 });
    expect(deps.store.invoice(late)?.lateLndState).toBe('CANCELED');
    expect(deps.store.invoice(late)?.state).toBe('not-created');
    const before = deps.api.calls.length;
    await lab.receiver.reconcileInvoices(deps);
    // Only the order's live invoice is looked up.
    expect(deps.api.calls.slice(before)).toEqual(['LookupInvoice']);
  });

  it('a late invoice whose CancelInvoice is followed by NotFound (LND deleted it) is canceled, not a failed cancel', async () => {
    const deps = receiver();
    const late = lateInvoice(deps, 'O-03B');
    deps.api.invoices.set(late, lndInvoice(late, 'OPEN'));
    deps.api.deleteOnCancel = true;
    expect(await lab.receiver.reconcileInvoices(deps)).toEqual({ resolved: 1, open: 1, unknown: 0 });
    expect(deps.store.invoice(late)?.lateLndState).toBe('CANCELED');
    expect(deps.events.map(event => event.event)).toContain('late-invoice-canceled');
    expect(deps.events.map(event => event.event)).not.toContain('late-invoice-cancel-failed');
  });
});

describe('payment lab receiver audit: the deliveries log', () => {
  it('repeated lookups of an open invoice log one delivery; a change of state is logged', async () => {
    const deps = receiver();
    const hash = await created(deps, 'O-04');
    for (let pass = 0; pass < 100; pass += 1) await lab.receiver.reconcileInvoices(deps);
    expect(deliveryCount(deps.store, hash)).toBe(1);
    const held = deps.api.invoices.get(hash);
    if (held !== undefined) { held.state = 'SETTLED'; held.amtPaidMsat = 4000n; held.settleIndex = 1n; }
    await lab.receiver.reconcileInvoices(deps);
    expect(deps.store.deliveries(hash).map(item => `${item.source} ${item.lndState} ${item.outcome}`))
      .toEqual(['lookup OPEN unchanged', 'lookup SETTLED fulfilled']);
  });

  it('repeated subscription messages about another receiver\'s invoice log one delivery and still move the cursor', () => {
    const store = receiverStore();
    const foreign = preimageFor('recv-audit-04-foreign').paymentHash;
    for (let index = 1n; index <= 50n; index += 1n) {
      expect(store.applyInvoice(lndInvoice(foreign, 'OPEN', { addIndex: index }), 'subscription')).toBe('unknown-invoice');
    }
    expect(deliveryCount(store, foreign)).toBe(1);
    expect(store.cursor().addIndex).toBe(50n);
  });

  it('a repeat is logged again after another delivery came between', async () => {
    const deps = receiver();
    const hash = await created(deps, 'O-04B');
    deps.store.applyInvoice(lndInvoice(hash, 'OPEN'), 'lookup');
    deps.store.applyInvoice(lndInvoice(hash, 'OPEN'), 'subscription');
    deps.store.applyInvoice(lndInvoice(hash, 'OPEN'), 'lookup');
    deps.store.applyInvoice(lndInvoice(hash, 'OPEN'), 'lookup');
    expect(deps.store.deliveries(hash).map(item => item.source)).toEqual(['lookup', 'subscription', 'lookup']);
  });
});

describe('payment lab receiver audit: the settle cursor', () => {
  const settled = (label: string, settleIndex: bigint, addIndex: bigint): Invoice =>
    lndInvoice(preimageFor(`recv-audit-cursor-${label}`).paymentHash, 'SETTLED', { settleIndex, addIndex });

  it('settle 3 delivered before settle 2 leaves the cursor at 1; settle 2 then moves it to 3', () => {
    const store = receiverStore();
    store.setCursor(1n, 1n);
    store.applyInvoice(settled('three', 3n, 5n), 'subscription');
    expect(store.cursor()).toEqual({ settleIndex: 1n, addIndex: 5n });
    store.applyInvoice(settled('two', 2n, 4n), 'subscription');
    expect(store.cursor()).toEqual({ settleIndex: 3n, addIndex: 5n });
  });

  it('a lookup delivery never moves it, and a later subscription delivery extends over indexes the subscription delivered only', () => {
    const store = receiverStore();
    store.setCursor(1n, 1n);
    store.applyInvoice(settled('lookup-two', 2n, 2n), 'lookup');
    store.applyInvoice(settled('sub-three', 3n, 3n), 'subscription');
    expect(store.cursor().settleIndex).toBe(1n);
  });

  it('from zero (LND replays nothing) the first settle index delivered becomes the cursor, and it moves on from there', () => {
    const store = receiverStore();
    store.applyInvoice(lndInvoice(preimageFor('recv-audit-cursor-open').paymentHash, 'OPEN', { addIndex: 40n }), 'subscription');
    expect(store.cursor()).toEqual({ settleIndex: 0n, addIndex: 40n });
    store.applyInvoice(settled('first-live', 17n, 41n), 'subscription');
    expect(store.cursor().settleIndex).toBe(17n);
    store.applyInvoice(settled('next-live', 18n, 42n), 'subscription');
    expect(store.cursor().settleIndex).toBe(18n);
  });
});

describe('payment lab receiver audit: hold invoice ACCEPTED then OPEN', () => {
  it('LND returning a hold invoice from ACCEPTED to OPEN makes the record open with nothing paid; canceled and settled stay final', async () => {
    const deps = receiver();
    const hash = await created(deps, 'O-07', true);
    expect(deps.store.applyInvoice(lndInvoice(hash, 'ACCEPTED'), 'lookup')).toBe('state-updated');
    expect(deps.store.invoice(hash)).toMatchObject({ state: 'accepted', amtPaidMsat: 4000n });
    expect(deps.store.applyInvoice(lndInvoice(hash, 'OPEN'), 'lookup')).toBe('state-updated');
    expect(deps.store.invoice(hash)).toMatchObject({ state: 'open', amtPaidMsat: 0n });
    expect(deps.store.applyInvoice(lndInvoice(hash, 'ACCEPTED'), 'lookup')).toBe('state-updated');
    expect(deps.store.applyInvoice(lndInvoice(hash, 'CANCELED'), 'lookup')).toBe('state-updated');
    expect(deps.store.applyInvoice(lndInvoice(hash, 'OPEN'), 'lookup')).toBe('unchanged');
    expect(deps.store.applyInvoice(lndInvoice(hash, 'ACCEPTED'), 'lookup')).toBe('unchanged');
    expect(deps.store.invoice(hash)?.state).toBe('canceled');

    const paid = await created(deps, 'O-07B', true);
    expect(deps.store.applyInvoice(lndInvoice(paid, 'SETTLED'), 'lookup')).toBe('fulfilled');
    expect(deps.store.applyInvoice(lndInvoice(paid, 'OPEN'), 'lookup')).toBe('unchanged');
    expect(deps.store.invoice(paid)).toMatchObject({ state: 'settled', amtPaidMsat: 4000n });
  });
});

describe('payment lab receiver audit: an underpaid settlement', () => {
  it('the order of an underpaid invoice still awaits payment and takes a replacement invoice, which fulfills it', async () => {
    const deps = receiver();
    const short = await created(deps, 'O-08');
    expect(deps.store.applyInvoice(lndInvoice(short, 'SETTLED', { amtPaidMsat: 3000n }), 'subscription')).toBe('underpaid');
    expect(deps.store.order('O-08')?.state).toBe('awaiting-payment');
    const replacement = await created(deps, 'O-08');
    expect(replacement).not.toBe(short);
    // Still one live invoice per order.
    const again = await lab.receiver.createInvoice(deps, { orderId: 'O-08', amountMsat: 4000n, hold: false, memo: 'x', expirySeconds: 3600 });
    expect(again).toMatchObject({ kind: 'refused', reason: expect.stringContaining(`already has invoice ${replacement} in state open`) as unknown });
    expect(deps.store.applyInvoice(lndInvoice(replacement, 'SETTLED', { settleIndex: 2n }), 'subscription')).toBe('fulfilled');
    expect(deps.store.order('O-08')?.state).toBe('fulfilled');
    expect(deps.store.journal('O-08').map(entry => entry.event)).toEqual(['underpaid-settlement', 'invoice-settled']);
  });

  it('migrations 6 and 7 on a version-5 database: an underpaid order takes a replacement; a newer database is still refused', async () => {
    const store = receiverStore();
    const path = dir.path(`recv-audit-${files}.db`);
    const deps = receiver(store);
    const short = await created(deps, 'O-08M');
    expect(store.applyInvoice(lndInvoice(short, 'SETTLED', { amtPaidMsat: 3000n }), 'subscription')).toBe('underpaid');
    // Back to version 5: its index counted every settled invoice as live.
    store.db.exec(`DROP INDEX invoices_one_live_per_order;
      CREATE UNIQUE INDEX invoices_one_live_per_order ON invoices (order_id) WHERE state IN ('creating', 'open', 'accepted', 'settled');
      PRAGMA user_version = 5`);
    store.close();
    const upgraded = new lab.ReceiverStore(path);
    opened.push(upgraded);
    expect(upgraded.db.prepare('PRAGMA user_version').all()[0]?.user_version).toBe(7n); // 6 (live-invoice index) and 7 (ledger upgrade) run on a version-5 database
    expect((await lab.receiver.createInvoice(receiver(upgraded), { orderId: 'O-08M', amountMsat: 4000n, hold: false, memo: 'x', expirySeconds: 3600 })).kind)
      .toBe('created');
    upgraded.db.exec('PRAGMA user_version = 8');
    upgraded.close();
    expect(() => new lab.ReceiverStore(path)).toThrow(/schema version 8 is newer than this code supports \(7\)/);
  });
});

describe('payment lab receiver audit: SETTLED with nothing paid', () => {
  it('is not recorded as a settlement, by delivery or by lookup', async () => {
    const deps = receiver();
    const hash = await created(deps, 'O-09');
    expect(deps.store.applyInvoice(lndInvoice(hash, 'SETTLED', { amtPaidMsat: 0n }), 'subscription')).toBe('unchanged');
    expect(deps.store.invoice(hash)?.state).toBe('open');
    expect(deps.store.journal('O-09')).toEqual([]);
    const held = deps.api.invoices.get(hash);
    if (held !== undefined) { held.state = 'SETTLED'; held.settleIndex = 1n; held.amtPaidMsat = 0n; }
    expect(await lab.receiver.reconcileInvoices(deps)).toEqual({ resolved: 0, open: 0, unknown: 1 });
    expect(deps.store.invoice(hash)?.state).toBe('open');
    expect(deps.store.order('O-09')?.state).toBe('awaiting-payment');
  });
});

describe('payment lab analysis audit', () => {
  const hash = preimageFor('recv-audit-05').paymentHash;
  const preimage = preimageFor('recv-audit-05').preimage;
  function lndPayment(paymentHash: string): Payment {
    return { paymentHash, status: 'SUCCEEDED', valueMsat: 1000n, feeMsat: 1n, preimage, paymentRequest: syntheticBolt11(paymentHash),
      failureReason: 'FAILURE_REASON_NONE', creationTimeNs: 1n, paymentIndex: '1', htlcs: [] };
  }
  const bigints = (_key: string, value: unknown): unknown => typeof value === 'bigint' ? value.toString() : value;

  it('payments for a hash carry neither the preimage nor the payment request, only whether LND holds a preimage', async () => {
    const read: ReadStub = {
      listPaymentsPage: () => Promise.resolve({ payments: [lndPayment(hash), lndPayment(preimageFor('recv-audit-05-other').paymentHash)], lastIndexOffset: 2n }),
      forwardingHistory: () => Promise.reject(new Error('not used')),
    };
    const result = await lab.analysis.paymentsForHash(read, hash);
    expect(result).toMatchObject({ scanned: 2, complete: true });
    expect(result.payments).toHaveLength(1);
    expect(result.payments[0]).toMatchObject({ paymentHash: hash, status: 'SUCCEEDED', preimagePresent: true });
    expect(Object.keys(result.payments[0] ?? {})).not.toContain('preimage');
    expect(Object.keys(result.payments[0] ?? {})).not.toContain('paymentRequest');
    const printed = JSON.stringify(result, bigints);
    expect(printed).not.toContain(preimage);
    expect(printed).not.toMatch(/lnbc/i);
  });

  it('a full page whose offset does not advance ends the scan incomplete (payments and forwards); diagnose says so', async () => {
    const full = Array.from({ length: 500 }, (_, index) => lndPayment(preimageFor(`recv-audit-06-${index}`).paymentHash));
    const read: ReadStub = {
      listPaymentsPage: () => Promise.resolve({ payments: full, lastIndexOffset: 0n }),
      forwardingHistory: () => Promise.resolve({ events: Array.from({ length: 1000 }, () => ({ timestampNs: 1n })), lastOffsetIndex: 0 }),
    };
    expect(await lab.analysis.paymentsForHash(read, hash)).toMatchObject({ payments: [], scanned: 500, complete: false });
    expect((await lab.analysis.forwardsSince(read, 0n)).complete).toBe(false);
    // A short page is the end of the list.
    const short: ReadStub = { ...read, listPaymentsPage: () => Promise.resolve({ payments: full.slice(0, 3), lastIndexOffset: 0n }) };
    expect(await lab.analysis.paymentsForHash(short, hash)).toMatchObject({ scanned: 3, complete: true });

    const node = {
      getInfo: () => Promise.resolve({ identityPubkey: `02${'22'.repeat(32)}` }),
      walletBalance: () => Promise.resolve({ confirmedSat: 0n, unconfirmedSat: 0n, lockedSat: 0n, reservedForAnchorsSat: 0n }),
      listChannels: () => Promise.resolve([]),
      pendingOpenChannels: () => Promise.resolve([]),
      queryRoutes: () => Promise.resolve([]),
    };
    const input = { amountMsat: 1000n, destination: `02${'11'.repeat(32)}` };
    const incomplete = await lab.diagnose.diagnose(node, { ...input, paymentScan: { complete: false, scanned: 500 } });
    expect(incomplete.findings.join('\n')).toMatch(/not found in the 500 payment\(s\) read, but the scan .* stopped before their end/);
    const complete = await lab.diagnose.diagnose(node, { ...input, paymentScan: { complete: true, scanned: 3 } });
    expect(complete.findings.join('\n')).not.toMatch(/stopped before their end/);
  });
});
