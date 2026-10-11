import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  loadLab, loadLabModule, preimageFor, tempDirectory,
  type DecodedPayReq, type ExplainDocument, type HtlcAttempt, type FakeInvoiceApi, type FakePayerApi, type Invoice, type Lab, type Payment, type PayerDeps,
  type PayerStore, type ReceiverDeps, type ReceiverStore, type StreamDecision,
} from './helpers/payment-lab-modules.js';

/**
 * The payment lab's command line and explain, after the pre-1.4 audit: arguments are checked before any store is opened,
 * read commands open their database read-only, `payer show` and explain print no preimage, explain stays within its
 * bounds (subject and outcome lists, --refresh lookups and deadline), reconcile caps its concurrent streams, and the
 * receiver's settle cursor moves only contiguously. Real stores on temporary SQLite files, scripted stand-ins for LND.
 */

let lab: Lab;
const dir = tempDirectory();

interface SqliteModule { readOnly<T>(open: () => T): T }
interface ExplainCommand {
  explainCommand(input: unknown, options: { json: boolean; refresh: boolean; out?: (text: string) => void; err?: (text: string) => void;
    refreshDeadlineMs?: number }): Promise<number>;
}
interface Format { scrub(value: string, known: ReadonlySet<string>): string }
/** The receiver store's cursor calls, which the shared declarations leave out. */
interface CursorStore { cursor(): { addIndex: bigint; settleIndex: bigint }; setCursor(settleIndex: bigint, addIndex: bigint): void }

let sqlite: SqliteModule;
let explain: ExplainCommand;
let format: Format;

beforeAll(async () => {
  lab = await loadLab();
  sqlite = await loadLabModule<SqliteModule>('store/sqlite.ts');
  explain = await loadLabModule<ExplainCommand>('explain/command.ts');
  format = await loadLabModule<Format>('explain/format.ts');
});
afterAll(() => dir.remove());

const opened: { close(): void }[] = [];
let stdout: string[];
let stderr: string[];
beforeEach(() => {
  stdout = [];
  stderr = [];
  vi.spyOn(process.stdout, 'write').mockImplementation(chunk => { stdout.push(String(chunk)); return true; });
  vi.spyOn(process.stderr, 'write').mockImplementation(chunk => { stderr.push(String(chunk)); return true; });
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const store of opened.splice(0)) {
    try { store.close(); } catch { /* already closed */ }
  }
});

const DESTINATION = `02${'11'.repeat(32)}`;
const quiet = (): void => undefined;
const events = (): Record<string, unknown>[] => stdout.flatMap(chunk => chunk.split('\n')).filter(line => line.startsWith('{'))
  .map(line => JSON.parse(line) as Record<string, unknown>);

function payerStore(file: string): PayerStore {
  const store = new lab.PayerStore(dir.path(file));
  opened.push(store);
  return store;
}

function decoded(paymentHash: string, amountMsat = 1000n): DecodedPayReq {
  return { destination: DESTINATION, paymentHash, amountMsat, timestamp: BigInt(Math.floor(Date.now() / 1000)), expirySeconds: 3600n,
    description: 'payment-lab-cli-audit' };
}

function lndPayment(label: string, status: 'IN_FLIGHT' | 'FAILED' | 'SUCCEEDED', valueMsat = 1000n): Payment {
  const { preimage, paymentHash } = preimageFor(label);
  return { paymentHash, status, valueMsat, feeMsat: status === 'SUCCEEDED' ? 10n : 0n, preimage: status === 'SUCCEEDED' ? preimage : undefined,
    paymentRequest: '', failureReason: status === 'FAILED' ? 'FAILURE_REASON_NO_ROUTE' : '', creationTimeNs: 1n, paymentIndex: '1', htlcs: [] };
}

const noPayerCalls: FakePayerApi = {
  decodePayReq: () => Promise.reject(new Error('not used')),
  sendPaymentV2: () => Promise.reject(new Error('not used')),
  trackPaymentV2: () => Promise.reject(new Error('not used')),
};
const noInvoiceCalls: FakeInvoiceApi = {
  lookupInvoice: () => Promise.reject(new Error('not used')),
  settleInvoice: () => Promise.reject(new Error('not used')),
  cancelInvoice: () => Promise.reject(new Error('not used')),
  subscribeInvoices: () => Promise.reject(new Error('not used')),
};

/** Services as the lab's own: a store opened read-only (sqlite.ts, readOnly) when main asks for 'read'. */
function labLike(file: string, api: FakePayerApi = noPayerCalls) {
  const accesses: (string | undefined)[] = [];
  return {
    accesses,
    services: {
      payer: (_lab: string | undefined, _profile: string, access?: 'read' | 'write'): PayerDeps => {
        accesses.push(access);
        const open = (): PayerStore => new lab.PayerStore(dir.path(file));
        return { api, store: access === 'read' ? sqlite.readOnly(open) : open(), emit: quiet };
      },
      receiver: (_lab: string | undefined, _profile: string, access?: 'read' | 'write'): ReceiverDeps => {
        accesses.push(access);
        const open = (): ReceiverStore => new lab.ReceiverStore(dir.path(file));
        return { api: noInvoiceCalls, store: access === 'read' ? sqlite.readOnly(open) : open(), emit: quiet };
      },
    },
  };
}

/** Services that fail the test if anything is opened. */
function untouchable() {
  const fail = (what: string) => vi.fn((): never => { throw new Error(`${what} was opened`); });
  return { payer: fail('payer'), receiver: fail('receiver'), ledgerSource: fail('ledgerSource'), outbox: fail('outbox') };
}

describe('a usage error opens nothing (no database created or migrated)', () => {
  const HASH = 'ab'.repeat(32);
  const cases: string[][] = [
    ['payer', 'show', '--as', 'customer-payer'],
    ['payer', 'explain', '--as', 'customer-payer'],
    ['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP', '--payment-hash', HASH],
    ['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP', '--kind', 'payout', '--invoice', 'lnbcrt1x', '--fee-limit-msat', '0x10'],
    ['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP', '--kind', 'payout', '--invoice', 'lnbcrt1x', '--fee-limit-msat', '1',
      '--max-parts', '0'],
    ['payer', 'retry', '--as', 'customer-payer', '--operation', 'bad id'],
    ['payer', 'reconcile', '--as', 'customer-payer', '--payment-hash', 'xyz'],
    ['payer', 'reconcile', '--as', 'customer-payer', '--timeout-s', '0'],
    ['payer', 'budget-set', '--as', 'customer-payer', '--budget', 'B', '--limit-msat', '1.5'],
    ['payer', 'budget-show', '--as', 'customer-payer'],
    ['payer', 'outbox-run', '--as', 'customer-payer', '--interval-s', 'soon'],
    ['payer', 'outbox-status', '--as', 'customer-payer', '--deadline-s', '0'],
    ['receiver', 'create-invoice', '--as', 'merchant', '--order', 'O', '--amount-msat', '0x10'],
    ['receiver', 'create-invoice', '--as', 'merchant', '--order', 'O', '--amount-msat', '10', '--expiry-s', '0'],
    ['receiver', 'settle', '--as', 'merchant'],
    ['receiver', 'reconcile', '--as', 'merchant', '--order', 'bad id'],
    ['receiver', 'listen', '--as', 'merchant', '--reconcile-interval-s', '0'],
    ['receiver', 'cursor-set', '--as', 'merchant'],
    ['receiver', 'explain', '--as', 'merchant'],
    ['receiver', 'outbox-status', '--as', 'merchant', '--deadline-s', 'x'],
  ];

  it.each(cases)('%s %s with a missing or malformed argument: exit 2, nothing opened', async (...argv) => {
    const services = untouchable();
    expect(await lab.main(argv, services)).toBe(2);
    for (const factory of Object.values(services)) expect(factory).not.toHaveBeenCalled();
    expect(stdout).toEqual([]);
  });

  it('analysis checks its arguments before the lab is loaded', async () => {
    const missingLab = dir.path('no-such-lab');
    for (const argv of [['analysis', 'payments', '--node', 'nowhere', '--payment-hash', HASH], ['analysis', 'payments', '--node', 'customer'],
      ['analysis', 'diagnose', '--node', 'customer', '--payer', 'customer-payer'], ['analysis', 'diagnose', '--node', 'customer', '--payer', 'nobody',
        '--operation', 'OP']]) {
      stderr.length = 0;
      expect(await lab.main([...argv, '--lab', missingLab], untouchable()), argv.join(' ')).toBe(2);
      expect(stderr.join(''), argv.join(' ')).not.toContain('lab.json');
    }
  });

  it('--as names a profile only, not an object property (toString, __proto__, constructor)', async () => {
    for (const as of ['toString', '__proto__', 'constructor', 'hasOwnProperty']) {
      for (const argv of [['payer', 'show', '--as', as, '--operation', 'OP'], ['receiver', 'show', '--as', as, '--order', 'O']]) {
        const services = untouchable();
        expect(await lab.main(argv, services), argv.join(' ')).toBe(2);
        for (const factory of Object.values(services)) expect(factory).not.toHaveBeenCalled();
      }
    }
  });

  it('an option given twice, and --fault none, are usage errors', async () => {
    expect(await lab.main(['payer', 'show', '--as', 'customer-payer', '--operation', 'A', '--operation', 'B'], untouchable())).toBe(2);
    expect(stderr.join('')).toContain('--operation is given more than once');
    expect(await lab.main(['payer', 'explain', '--as', 'customer-payer', '--operation', 'A', '--json', '--json'], untouchable())).toBe(2);
    expect(await lab.main(['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP', '--kind', 'payout', '--invoice', 'lnbcrt1x',
      '--fee-limit-msat', '1', '--fault', 'none'], untouchable())).toBe(2);
    expect(stderr.join('')).toContain('--fault must be drop-stream-after-in-flight');
  });

  it('an unknown command or option is printed escaped: no control character reaches stderr', async () => {
    expect(await lab.main(['payer', '\u001b]0;title\u0007\u001b[2J'], untouchable())).toBe(2);
    expect(await lab.main(['payer', 'show', '--\u001b[31mred'], untouchable())).toBe(2);
    expect(await lab.main(['\u001b[2Jcomponent', 'x'], untouchable())).toBe(2);
    const text = stderr.join('');
    expect(text).not.toContain('\u001b');
    expect(text).not.toContain('\u0007');
    expect(text).toContain('\\x1b');
  });
});

describe('read commands open their database read-only', () => {
  it('main asks for read access exactly for the commands that only read', async () => {
    const { accesses, services } = labLike('access.db');
    const run = async (argv: string[]): Promise<string | undefined> => {
      accesses.length = 0;
      await lab.main(argv, services);
      return accesses[0];
    };
    for (const argv of [['payer', 'show', '--as', 'customer-payer', '--operation', 'OP'], ['payer', 'budget-show', '--as', 'customer-payer', '--budget', 'B'],
      ['payer', 'outbox-status', '--as', 'customer-payer'], ['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP'],
      ['receiver', 'show', '--as', 'merchant', '--order', 'O'], ['receiver', 'outbox-status', '--as', 'merchant'],
      ['receiver', 'explain', '--as', 'merchant', '--order', 'O']]) {
      expect(await run(argv), argv.join(' ')).toBe('read');
    }
    expect(await run(['payer', 'budget-set', '--as', 'customer-payer', '--budget', 'B', '--limit-msat', '10'])).toBe('write');
    expect(await run(['receiver', 'cursor-set', '--as', 'merchant', '--settle-index', '1'])).toBe('write');
  });

  it('explain on a database that does not exist exits 3 and leaves no file behind', async () => {
    const { services } = labLike('missing.db');
    expect(await lab.main(['payer', 'explain', '--as', 'customer-payer', '--operation', 'NOPE', '--json'], services)).toBe(3);
    expect(existsSync(dir.path('missing.db'))).toBe(false);
    expect(await lab.main(['payer', 'show', '--as', 'customer-payer', '--operation', 'NOPE'], services)).toBe(0);
    expect(existsSync(dir.path('missing.db'))).toBe(false);
    const { services: receiver } = labLike('missing-receiver.db');
    expect(await lab.main(['receiver', 'explain', '--as', 'merchant', '--order', 'NOPE'], receiver)).toBe(3);
    expect(existsSync(dir.path('missing-receiver.db'))).toBe(false);
  });

  it('a read command refuses a database of an older schema and leaves it unchanged; a write command migrates it', async () => {
    const setup = payerStore('older.db');
    const current = Number((setup.db.prepare('PRAGMA user_version').all()[0] as { user_version: bigint }).user_version);
    setup.db.exec(`PRAGMA user_version = ${String(current - 1)}`);
    setup.close();
    const { services } = labLike('older.db');
    expect(await lab.main(['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP', '--json'], services)).toBe(4);
    expect(stdout.join('')).toContain('older than this code');
    // Still the older version: a read-only open names it (an ordinary open would migrate it).
    const version = sqlite.readOnly(() => {
      try { return new lab.PayerStore(dir.path('older.db')); } catch (error) { return error as Error; }
    });
    expect(version).toBeInstanceOf(Error);
    expect((version as Error).message).toContain(`database schema version ${String(current - 1)} is older`);
  });

  it('a read-only store refuses a write', () => {
    payerStore('ro.db').close();
    const store = sqlite.readOnly(() => new lab.PayerStore(dir.path('ro.db')));
    opened.push(store);
    expect(() => { store.setBudget('B', 10n); }).toThrow(/readonly/);
  });
});

describe('no preimage or payment request is printed', () => {
  it('payer show says whether a preimage is recorded, never what it is', async () => {
    const setup = payerStore('show.db');
    const { preimage, paymentHash } = preimageFor('show');
    setup.recordIntent({ operationId: 'OP-S', kind: 'payout', paymentRequest: 'lnbcrt1show', invoice: decoded(paymentHash), feeLimitMsat: 10n, maxParts: 1 });
    setup.claimForSubmission(paymentHash);
    setup.applyUpdate(lndPayment('show', 'SUCCEEDED'), 'SendPaymentV2', 1);
    setup.close();
    const { services } = labLike('show.db');
    expect(await lab.main(['payer', 'show', '--as', 'customer-payer', '--operation', 'OP-S'], services)).toBe(0);
    expect(stdout.join('')).not.toContain(preimage);
    const record = events().find(item => item.event === 'payment-record');
    expect(record?.payment).toEqual(expect.objectContaining({ paymentHash, preimageRecorded: true }));
    expect(record?.payment).not.toHaveProperty('preimage');
  });
});

describe('payer reconcile', () => {
  it('opens at most 16 TrackPaymentV2 streams at once and reconciles every payment', async () => {
    const setup = payerStore('pool.db');
    const count = 40;
    for (let index = 0; index < count; index += 1) {
      const { paymentHash } = preimageFor(`pool-${String(index)}`);
      setup.recordIntent({ operationId: `OP-${String(index)}`, kind: 'payout', paymentRequest: `lnbcrt1pool${String(index)}`,
        invoice: decoded(paymentHash), feeLimitMsat: 10n, maxParts: 1 });
      setup.claimForSubmission(paymentHash);
      setup.markUncertain(paymentHash, 'connection lost', 1);
    }
    setup.close();
    let open = 0;
    let most = 0;
    let calls = 0;
    const api: FakePayerApi = { ...noPayerCalls, trackPaymentV2: async (paymentHash, onUpdate) => {
      open += 1;
      calls += 1;
      most = Math.max(most, open);
      await new Promise(resolve => { setImmediate(resolve); });
      open -= 1;
      onUpdate({ ...lndPayment('pool', 'FAILED'), paymentHash });
    } };
    const { services } = labLike('pool.db', api);
    expect(await lab.main(['payer', 'reconcile', '--as', 'customer-payer'], services)).toBe(1);
    expect(calls).toBe(count);
    expect(most).toBeGreaterThan(1);
    expect(most).toBeLessThanOrEqual(16);
    expect(events().filter(item => item.event === 'outcome')).toHaveLength(count);
  });

  it('F02: with more unresolved payments than streams, a payment after the first 16 is still read before the deadline', async () => {
    const setup = payerStore('pool-starved.db');
    const count = 17;
    const hashes: string[] = [];
    for (let index = 0; index < count; index += 1) {
      const { paymentHash } = preimageFor(`starved-${String(index)}`);
      setup.recordIntent({ operationId: `OP-S-${String(index)}`, kind: 'payout', paymentRequest: `lnbcrt1starved${String(index)}`,
        invoice: decoded(paymentHash), feeLimitMsat: 10n, maxParts: 1 });
      setup.claimForSubmission(paymentHash);
      hashes.push(paymentHash);
    }
    setup.close();
    const last = hashes[count - 1] as string;
    const queried = new Set<string>();
    let open = 0;
    let most = 0;
    // The first 16 streams stay open without delivering anything until aborted; the 17th payment LND has already failed.
    const api: FakePayerApi = { ...noPayerCalls, trackPaymentV2: (paymentHash, onUpdate, signal) => {
      queried.add(paymentHash);
      if (paymentHash === last) { onUpdate({ ...lndPayment('starved-16', 'FAILED'), paymentHash }); return Promise.resolve(); }
      open += 1;
      most = Math.max(most, open);
      return new Promise((_resolve, reject) => {
        const abort = (): void => { open -= 1; reject(new lab.TransportError('aborted by the caller', 'response')); };
        if (signal === undefined) { abort(); return; }
        if (signal.aborted) { abort(); return; }
        signal.addEventListener('abort', abort, { once: true });
      });
    } };
    const { services } = labLike('pool-starved.db', api);
    expect(await lab.main(['payer', 'reconcile', '--as', 'customer-payer', '--timeout-s', '1'], services)).toBe(75);
    expect(most).toBeLessThanOrEqual(16);
    expect(queried.has(last), 'the 17th payment was read').toBe(true);
    const outcomes = events().filter(item => item.event === 'outcome');
    expect(outcomes).toHaveLength(count);
    expect(outcomes.find(item => item.paymentHash === last)).toMatchObject({ kind: 'failed', reason: 'FAILURE_REASON_NO_ROUTE' });
    expect(outcomes.filter(item => item.kind === 'unresolved')).toHaveLength(count - 1);
    const after = payerStore('pool-starved.db');
    expect(after.payment(last)?.state).toBe('failed');
    expect(hashes.filter(hash => after.payment(hash)?.state === 'submitting')).toHaveLength(count - 1);
  });
});

/** explain run directly, its output collected. */
async function explainDoc(input: unknown, options: { refresh?: boolean; refreshDeadlineMs?: number } = {}):
  Promise<{ code: number; doc: ExplainDocument }> {
  const out: string[] = [];
  const code = await explain.explainCommand(input, { json: true, refresh: options.refresh ?? false, out: text => { out.push(text); },
    err: quiet, ...(options.refreshDeadlineMs === undefined ? {} : { refreshDeadlineMs: options.refreshDeadlineMs }) });
  return { code, doc: JSON.parse(out.join('')) as ExplainDocument };
}

async function explainText(input: unknown): Promise<string> {
  const out: string[] = [];
  await explain.explainCommand(input, { json: false, refresh: false, out: text => { out.push(text); }, err: quiet });
  return out.join('');
}

describe('explain', () => {
  it('a withdrawn payment is not explained as reverted to intent', async () => {
    const store = payerStore('withdrawn.db');
    store.setBudget('B', 100_000n);
    const a = preimageFor('w-a').paymentHash;
    const b = preimageFor('w-b').paymentHash;
    store.recordIntent({ operationId: 'OP-W', kind: 'payout', paymentRequest: 'lnbcrt1wa', invoice: decoded(a), feeLimitMsat: 100n, maxParts: 1, budgetId: 'B' });
    store.claimForSubmission(a);
    store.applyUpdate(lndPayment('w-a', 'FAILED'), 'SendPaymentV2', 1);
    expect(store.recordIntent({ operationId: 'OP-W', kind: 'payout', paymentRequest: 'lnbcrt1wb', invoice: decoded(b), feeLimitMsat: 100n, maxParts: 1,
      budgetId: 'B' }).outcome).toBe('recorded');
    store.claimForSubmission(b);
    store.markUncertain(b, 'connection lost', 1);
    store.applyUpdate(lndPayment('w-a', 'SUCCEEDED'), 'TrackPaymentV2', 1);
    const notFound = new lab.LndError('payment isn\'t initiated', 5, 404);
    const api: FakePayerApi = { ...noPayerCalls, trackPaymentV2: () => Promise.reject(notFound) };
    await lab.reconcile({ api, store, emit: quiet }, b, AbortSignal.timeout(10_000));
    expect(store.events(b).map(item => item.kind)).toContain('not-initiated');
    expect(store.payment(b)?.state).toBe('failed');
    const { doc } = await explainDoc({ component: 'payer', store, api, subject: { paymentHash: b } });
    const fp = doc.result?.subject.payments[1] ?? '';
    const items = doc.result?.timeline.filter(item => item.detail.includes(fp)) ?? [];
    expect(items.map(item => item.kind)).not.toContain('revert');
    expect(items.map(item => item.detail).join('\n')).not.toContain('back to intent');
    expect(items).toContainEqual(expect.objectContaining({ kind: 'not-initiated', rule: 'Unresolved is a state, not an error' }));
  });

  it('budget-actual-principal and budget-overrun have their own kinds and rules', async () => {
    const store = payerStore('overrun.db');
    store.setBudget('B', 1200n);
    const { paymentHash } = preimageFor('overrun');
    store.recordIntent({ operationId: 'OP-O', kind: 'payout', paymentRequest: 'lnbcrt1over', invoice: decoded(paymentHash), feeLimitMsat: 100n,
      maxParts: 1, budgetId: 'B' });
    store.claimForSubmission(paymentHash);
    store.applyUpdate(lndPayment('overrun', 'SUCCEEDED', 1500n), 'SendPaymentV2', 1);
    expect(store.events(paymentHash).map(item => item.kind)).toEqual(expect.arrayContaining(['budget-actual-principal', 'budget-overrun']));
    const { doc } = await explainDoc({ component: 'payer', store, api: noPayerCalls, subject: { operationId: 'OP-O' } });
    const timeline = doc.result?.timeline ?? [];
    expect(timeline.map(item => item.kind)).not.toContain('event');
    expect(timeline).toContainEqual(expect.objectContaining({ kind: 'budget-actual-principal', rule: 'Accounting from LND\'s numbers' }));
    expect(timeline).toContainEqual(expect.objectContaining({ kind: 'budget-overrun', rule: 'Reservations' }));
    expect(doc.result?.reconciliation.map(item => item.decision)).toEqual(expect.arrayContaining(['budget-actual-principal', 'budget-overrun']));
  });

  it('subject and outcome lists, the text header and --refresh stay within their bounds', async () => {
    const store = payerStore('many.db');
    const count = 300;
    for (let index = 0; index < count; index += 1) {
      const label = `many-${String(index)}`;
      const { paymentHash } = preimageFor(label);
      store.recordIntent({ operationId: 'OP-N', kind: 'payout', paymentRequest: `lnbcrt1many${String(index)}`, invoice: decoded(paymentHash),
        feeLimitMsat: 100n, maxParts: 1 });
      store.claimForSubmission(paymentHash);
      store.applyUpdate(lndPayment(label, 'FAILED'), 'SendPaymentV2', 1);
    }
    let calls = 0;
    const api: FakePayerApi = { ...noPayerCalls, trackPaymentV2: async (paymentHash, onUpdate) => {
      calls += 1;
      onUpdate({ ...lndPayment('many', 'FAILED'), paymentHash });
    } };
    const input = { component: 'payer', store, api, subject: { operationId: 'OP-N' } };
    const { code, doc } = await explainDoc(input, { refresh: true });
    expect(code).toBe(0);
    expect(doc.result?.subject.payments.length).toBe(200);
    expect((doc.result?.outcome.payments as unknown[]).length).toBe(200);
    const truncated = (doc.result as unknown as { truncated: Record<string, number> }).truncated;
    expect(truncated.payments).toBe(100);
    expect(truncated.refresh).toBe(100);
    expect(calls).toBe(200);
    expect(doc.result?.timeline.filter(item => item.kind === 'refreshed').map(item => item.detail).join('\n')).toContain('100 payment hash(es) not looked up');
    const text = await explainText(input);
    const header = text.split('\n').findIndex(line => line === '');
    expect(header).toBeLessThanOrEqual(3);
    expect(text.split('\n')[0]).toContain('300 payment hashes');
  });

  it('--refresh stops at its overall deadline with an error (exit 4), the explanation from the records printed', async () => {
    const store = payerStore('deadline.db');
    for (let index = 0; index < 3; index += 1) {
      const label = `deadline-${String(index)}`;
      const { paymentHash } = preimageFor(label);
      store.recordIntent({ operationId: 'OP-D', kind: 'payout', paymentRequest: `lnbcrt1dl${String(index)}`, invoice: decoded(paymentHash),
        feeLimitMsat: 100n, maxParts: 1 });
      store.claimForSubmission(paymentHash);
      store.applyUpdate(lndPayment(label, 'FAILED'), 'SendPaymentV2', 1);
    }
    // A node that never answers: each lookup ends only when its signal aborts.
    const api: FakePayerApi = { ...noPayerCalls, trackPaymentV2: (_hash: string, _onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal) =>
      new Promise<void>((_resolve, reject) => { signal?.addEventListener('abort', () => { reject(new lab.TransportError('aborted', 'response')); }); }) };
    const { code, doc } = await explainDoc({ component: 'payer', store, api, subject: { operationId: 'OP-D' } }, { refresh: true, refreshDeadlineMs: 300 });
    expect(code).toBe(4);
    expect(doc.error).toEqual(expect.objectContaining({ step: 'refresh' }));
    expect(doc.error?.message).toContain('deadline after 0 of 3 lookup(s)');
    expect(doc.result).not.toBeNull();
  });

  it('--json prints one explain document when the records cannot be read', async () => {
    const store = payerStore('damaged.db');
    const { paymentHash } = preimageFor('damaged');
    store.recordIntent({ operationId: 'OP-X', kind: 'payout', paymentRequest: 'lnbcrt1dmg', invoice: decoded(paymentHash), feeLimitMsat: 10n, maxParts: 1 });
    store.db.exec(`UPDATE operations SET amount_msat = 'abc' WHERE operation_id = 'OP-X'`);
    const { code, doc } = await explainDoc({ component: 'payer', store, api: noPayerCalls, subject: { operationId: 'OP-X' } });
    expect(code).toBe(4);
    expect(doc).toEqual(expect.objectContaining({ schema: 1, command: 'explain', ok: false, result: null }));
    expect(doc.error).toEqual(expect.objectContaining({ code: 4, step: 'records' }));
  });

  it('an order canceled and then settled for less is not summarised as canceled before it was paid', async () => {
    const store = new lab.ReceiverStore(dir.path('underpaid.db'));
    opened.push(store);
    const { preimage, paymentHash } = preimageFor('underpaid');
    store.recordInvoiceIntent({ orderId: 'ORD-U', amountMsat: 5000n, kind: 'hold', preimage, paymentHash });
    store.markCreated(paymentHash, 'lnbcrt1underpaid', 1n);
    const invoice = (state: string, paid = 0n, settle = 0n): Invoice => ({ paymentHash, state, memo: '', valueMsat: 5000n, amtPaidMsat: paid,
      addIndex: 1n, settleIndex: settle, paymentRequest: '', htlcs: [] });
    store.applyInvoice(invoice('CANCELED'), 'lookup');
    store.applyInvoice(invoice('SETTLED', 1000n, 1n), 'subscription');
    const { doc } = await explainDoc({ component: 'receiver', store, api: noInvoiceCalls, subject: { orderId: 'ORD-U' } });
    const outcome = doc.result?.outcome as { summary: string; order: { state: string }; invoices: { state: string }[] };
    expect(outcome.invoices[0]?.state).toBe('settled');
    if (outcome.order.state === 'canceled') {
      expect(outcome.summary).toContain('1 settled invoice(s) did not fulfill it');
      expect(outcome.summary).not.toContain('canceled before it was paid');
    } else {
      expect(outcome.summary).toContain('settled invoice(s) did not fulfill it');
    }
  });

  it('a settlement-amount-conflict says which amount stands: the first for a delivery, the fulfilling one for the migration\'s row', async () => {
    const store = new lab.ReceiverStore(dir.path('conflict.db'));
    opened.push(store);
    const { preimage, paymentHash } = preimageFor('conflict');
    store.recordInvoiceIntent({ orderId: 'ORD-C', amountMsat: 1000n, kind: 'standard', preimage, paymentHash });
    store.markCreated(paymentHash, 'lnbcrt1conflict', 1n);
    const insert = store.db.prepare(`INSERT INTO deliveries (payment_hash, source, lnd_state, settle_index, outcome, received_at)
      VALUES (?, ?, 'SETTLED', 1, 'settlement-amount-conflict', ?)`);
    insert.run(paymentHash, 'subscription', '2026-01-01T00:00:01.000Z');
    insert.run(paymentHash, 'migration: record amt_paid_msat 900 msat, fulfilling settlement 1000 msat', '2026-01-01T00:00:02.000Z');
    const { doc } = await explainDoc({ component: 'receiver', store, api: noInvoiceCalls, subject: { orderId: 'ORD-C' } });
    const deliveries = (doc.result?.timeline ?? []).filter(item => item.kind === 'delivery').map(item => item.detail);
    const live = deliveries.find(item => item.includes('via subscription'));
    const migrated = deliveries.find(item => item.includes('via migration:'));
    expect(live).toContain('the first one stands');
    expect(migrated, migrated).toContain('the fulfilling amount, which stands');
    expect(migrated).not.toContain('the first one stands');
  });

  it('scrub removes a 32-byte value written in base64, keeps the subject\'s own ID and hex for the hex rule', () => {
    const { preimage, paymentHash } = preimageFor('base64');
    const bytes = Buffer.from(preimage, 'hex');
    const known = new Set([paymentHash]);
    for (const encoded of [bytes.toString('base64'), bytes.toString('base64').replace(/=$/, '')]) {
      const scrubbed = format.scrub(`LND said: preimage ${encoded}.`, known);
      expect(scrubbed).not.toContain(encoded);
      expect(scrubbed).toContain('[redacted base64]');
    }
    const ownId = 'ORDER0123456789abcdefghijklmnopqrstuvwxyzAB';
    expect(ownId).toHaveLength(43);
    expect(format.scrub(`order ${ownId}`, new Set([ownId.toLowerCase()]))).toBe(`order ${ownId}`);
    expect(format.scrub(`hash ${paymentHash}`, known)).toBe(`hash ${paymentHash.slice(0, 8)}…${paymentHash.slice(-4)}`);
    expect(format.scrub('plain words stay as they are', known)).toBe('plain words stay as they are');
  });
});

describe('receiver settle cursor', () => {
  function invoiceAt(label: string, settleIndex: bigint, addIndex: bigint): Invoice {
    return { paymentHash: preimageFor(label).paymentHash, state: 'SETTLED', memo: '', valueMsat: 1000n, amtPaidMsat: 1000n, addIndex, settleIndex,
      paymentRequest: '', htlcs: [] };
  }

  it('moves only contiguously over the settle indexes the subscription delivered', () => {
    const store = new lab.ReceiverStore(dir.path('cursor.db'));
    opened.push(store);
    const cursor = store as unknown as CursorStore;
    cursor.setCursor(1n, 0n);
    // The add backlog brings an invoice settled at 3 before the settle backlog brings 2.
    store.applyInvoice(invoiceAt('c3', 3n, 3n), 'subscription');
    expect(cursor.cursor()).toEqual({ settleIndex: 1n, addIndex: 3n });
    // A lookup's settlement does not count: only the subscription delivers in settle-index order.
    store.applyInvoice(invoiceAt('c2', 2n, 2n), 'lookup');
    expect(cursor.cursor().settleIndex).toBe(1n);
    store.applyInvoice(invoiceAt('c2', 2n, 2n), 'subscription');
    expect(cursor.cursor()).toEqual({ settleIndex: 3n, addIndex: 3n });
    // A repeat moves nothing back; the next index moves it on.
    store.applyInvoice(invoiceAt('c2', 2n, 2n), 'subscription');
    store.applyInvoice(invoiceAt('c4', 4n, 4n), 'subscription');
    expect(cursor.cursor()).toEqual({ settleIndex: 4n, addIndex: 4n });
  });

  it('a cursor reopened after a stop in the add backlog still lets the settle backlog deliver what it skipped', () => {
    const file = dir.path('cursor-restart.db');
    const first = new lab.ReceiverStore(file);
    opened.push(first);
    first.applyInvoice(invoiceAt('r1', 1n, 1n), 'subscription');
    first.applyInvoice(invoiceAt('r3', 3n, 3n), 'subscription');
    first.close();
    const second = new lab.ReceiverStore(file);
    opened.push(second);
    // The listener resumes from settle index 1: LND replays 2 and 3.
    expect((second as unknown as CursorStore).cursor().settleIndex).toBe(1n);
    second.applyInvoice(invoiceAt('r2', 2n, 2n), 'subscription');
    expect((second as unknown as CursorStore).cursor().settleIndex).toBe(3n);
  });
});

interface CliModule {
  labOutboxTarget(labDir: string | undefined, component: 'payer' | 'receiver', profile: string, db: unknown): { dir: string; key: Buffer };
}

describe('outbox effects are kept per profile', () => {
  let cli: CliModule;
  beforeAll(async () => { cli = await loadLabModule<CliModule>('cli.ts'); });

  /** A lab directory with a minimal lab.json (no node, no credential: only the outbox target reads it). */
  function labDir(name: string): string {
    const path = dir.path(name);
    mkdirSync(path, { recursive: true });
    writeFileSync(join(path, 'lab.json'), JSON.stringify({ schema: 1 }));
    return path;
  }

  /** A receiver database with order `orderId` settled in full: one pending fulfill-order row. */
  function settled(file: string, orderId: string, label: string): void {
    const store = new lab.ReceiverStore(dir.path(file));
    const { preimage, paymentHash } = preimageFor(label);
    store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', preimage, paymentHash });
    store.markCreated(paymentHash, `lnbcrt1${label}`, 1n);
    expect(store.applyInvoice({ paymentHash, state: 'SETTLED', memo: '', valueMsat: 1000n, amtPaidMsat: 1000n, addIndex: 1n, settleIndex: 1n,
      paymentRequest: '', htlcs: [] }, 'subscription')).toBe('fulfilled');
    store.close();
  }

  function services(files: Record<string, string>) {
    return {
      payer: (): never => { throw new Error('not used'); },
      receiver: (_lab: string | undefined, profile: string): ReceiverDeps => ({ api: noInvoiceCalls,
        store: new lab.ReceiverStore(dir.path(files[profile] ?? 'unknown.db')), emit: quiet }),
      outbox: (labPath: string | undefined, component: 'payer' | 'receiver', profile: string, db: unknown) =>
        cli.labOutboxTarget(labPath, component, profile, db),
    };
  }

  const jsonIn = (path: string): string[] => (existsSync(path) ? readdirSync(path).filter(name => name.endsWith('.json')) : []);

  it('the same order ID in two receiver profiles gets two receipts, and outbox-run --once exits 0 for both', async () => {
    const root = labDir('lab-two-profiles');
    settled('two-merchant.db', 'ORD-1', 'two-merchant');
    settled('two-customer.db', 'ORD-1', 'two-customer');
    const run = services({ merchant: 'two-merchant.db', customer: 'two-customer.db' });
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'merchant', '--once', '--lab', root], run)).toBe(0);
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'customer', '--once', '--lab', root], run)).toBe(0);
    expect(jsonIn(join(root, 'receipts', 'merchant'))).toEqual([`${lab.outbox.fileBase('ORD-1')}.json`]);
    expect(jsonIn(join(root, 'receipts', 'customer'))).toEqual([`${lab.outbox.fileBase('ORD-1')}.json`]);
  });

  it('a receipt an earlier version wrote for a profile is adopted into its directory, not written again; another profile\'s is left', async () => {
    const root = labDir('lab-legacy');
    settled('legacy-merchant.db', 'ORD-L', 'legacy-merchant');
    settled('legacy-customer.db', 'ORD-L', 'legacy-customer');
    // The 1.3 layout: the merchant's worker wrote <lab>/receipts/ORD-L.json and was killed before acknowledging it.
    const merchant = new lab.ReceiverStore(dir.path('legacy-merchant.db'));
    const key = cli.labOutboxTarget(root, 'receiver', 'merchant', merchant.db).key;
    expect(lab.outbox.runPass(merchant.db, { dir: join(root, 'receipts'), key }, { emit: quiet })).toMatchObject({ performed: 1 });
    merchant.db.exec(`UPDATE outbox SET state = 'pending', acknowledged_at = NULL, next_attempt_at = '1970-01-01T00:00:00.000Z'`);
    merchant.close();
    expect(jsonIn(join(root, 'receipts'))).toEqual([`${lab.outbox.fileBase('ORD-L')}.json`]);
    const run = services({ merchant: 'legacy-merchant.db', customer: 'legacy-customer.db' });
    // The customer's row for the same order ID does not own that file: it gets its own, and the file stays.
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'customer', '--once', '--lab', root], run)).toBe(0);
    expect(jsonIn(join(root, 'receipts'))).toEqual([`${lab.outbox.fileBase('ORD-L')}.json`]);
    stdout.length = 0;
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'merchant', '--once', '--lab', root], run)).toBe(0);
    expect(events()).toContainEqual(expect.objectContaining({ event: 'outbox-effect-adopted' }));
    expect(events()).toContainEqual(expect.objectContaining({ event: 'outbox-pass', alreadyPresent: 1, performed: 0 }));
    expect(jsonIn(join(root, 'receipts'))).toEqual([]);
    expect(jsonIn(join(root, 'receipts', 'merchant'))).toEqual([`${lab.outbox.fileBase('ORD-L')}.json`]);
    expect(jsonIn(join(root, 'receipts', 'customer'))).toEqual([`${lab.outbox.fileBase('ORD-L')}.json`]);
  });

  it('a missing key is not recreated while a profile directory holds signed effects', async () => {
    const root = labDir('lab-lost-key');
    settled('lost-merchant.db', 'ORD-K', 'lost-merchant');
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'merchant', '--once', '--lab', root], services({ merchant: 'lost-merchant.db' }))).toBe(0);
    const keyFile = join(root, 'outbox.key');
    expect(existsSync(keyFile)).toBe(true);
    rmSync(keyFile);
    settled('lost-customer.db', 'ORD-K2', 'lost-customer');
    stdout.length = 0;
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'customer', '--once', '--lab', root],
      services({ customer: 'lost-customer.db' }))).toBe(4);
    expect(stdout.join('')).toContain('outbox.key is missing');
    expect(existsSync(keyFile)).toBe(false);
  });
});

describe('explain from the evidence at each point', () => {
  it('an HTLC attempt\'s last recorded state is not shown before the disconnect that preceded it', async () => {
    const store = payerStore('attempt-times.db');
    const { paymentHash } = preimageFor('attempt-times');
    store.recordIntent({ operationId: 'OP-T', kind: 'payout', paymentRequest: 'lnbcrt1times', invoice: decoded(paymentHash), feeLimitMsat: 100n,
      maxParts: 1 });
    store.claimForSubmission(paymentHash);
    const htlc = (status: 'IN_FLIGHT' | 'SUCCEEDED'): HtlcAttempt => ({ attemptId: '2', status, route: { totalAmtMsat: 1010n, totalFeesMsat: 10n,
      hops: [{ chanId: '1', pubKey: DESTINATION, amtToForwardMsat: 1000n }] }, principalMsat: 1000n, attemptTimeNs: 1n,
      resolveTimeNs: status === 'SUCCEEDED' ? 2n : 0n, failureCode: undefined, failureSourceIndex: undefined });
    store.applyUpdate({ ...lndPayment('attempt-times', 'IN_FLIGHT'), htlcs: [htlc('IN_FLIGHT')] }, 'SendPaymentV2', 1);
    store.markUncertain(paymentHash, 'connection lost', 1);
    store.applyUpdate({ ...lndPayment('attempt-times', 'SUCCEEDED'), htlcs: [htlc('SUCCEEDED')] }, 'TrackPaymentV2', 1);
    const { doc } = await explainDoc({ component: 'payer', store, api: noPayerCalls, subject: { operationId: 'OP-T' } });
    const timeline = doc.result?.timeline ?? [];
    const attemptAt = timeline.findIndex(item => item.kind === 'htlc-attempt');
    expect(timeline[attemptAt]?.detail).toContain('SUCCEEDED');
    expect(timeline[attemptAt]?.detail).toContain('its last recorded state');
    expect(attemptAt).toBeGreaterThan(timeline.findIndex(item => item.kind === 'uncertain'));
    expect(attemptAt).toBeGreaterThan(timeline.findIndex(item => item.kind === 'lnd-update'));
  });

  it('a later cancellation does not turn an earlier unchanged lookup into a replay after CANCELED', async () => {
    const store = new lab.ReceiverStore(dir.path('cancel-later.db'));
    opened.push(store);
    const { preimage, paymentHash } = preimageFor('cancel-later');
    store.recordInvoiceIntent({ orderId: 'ORD-CL', amountMsat: 1000n, kind: 'hold', preimage, paymentHash });
    store.markCreated(paymentHash, 'lnbcrt1cancellater', 1n);
    const invoice = (state: string): Invoice => ({ paymentHash, state, memo: '', valueMsat: 1000n, amtPaidMsat: 0n, addIndex: 1n, settleIndex: 0n,
      paymentRequest: '', htlcs: [] });
    expect(store.applyInvoice(invoice('OPEN'), 'lookup')).toBe('unchanged');
    store.applyInvoice(invoice('CANCELED'), 'lookup');
    expect(store.applyInvoice(invoice('OPEN'), 'subscription')).toBe('unchanged');
    const { doc } = await explainDoc({ component: 'receiver', store, api: noInvoiceCalls, subject: { orderId: 'ORD-CL' } });
    const deliveries = (doc.result?.timeline ?? []).filter(item => item.kind === 'delivery');
    expect(deliveries[0]?.detail).toContain('LND OPEN');
    expect(deliveries[0]?.detail).not.toContain('after CANCELED');
    expect(deliveries[0]?.rule).not.toBe('Canceled is final');
    const replay = deliveries.at(-1);
    expect(replay?.detail).toContain('a replayed update after CANCELED');
    expect(replay?.rule).toBe('Canceled is final');
  });
});

describe('payer pay keeps the operation\'s recorded kind', () => {
  it('a --kind other than the operation\'s recorded one is a usage error naming both, before anything is decoded or sent', async () => {
    const setup = payerStore('kind.db');
    const { paymentHash } = preimageFor('kind');
    setup.recordIntent({ operationId: 'OP-K', kind: 'payout', paymentRequest: 'lnbcrt1kind', invoice: decoded(paymentHash), feeLimitMsat: 10n, maxParts: 1 });
    setup.close();
    const decode = vi.fn(() => Promise.reject(new Error('decodePayReq called')));
    const { services } = labLike('kind.db', { ...noPayerCalls, decodePayReq: decode });
    expect(await lab.main(['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP-K', '--kind', 'refund', '--invoice', 'lnbcrt1other',
      '--fee-limit-msat', '10'], services)).toBe(2);
    expect(stderr.join('')).toContain('--kind refund differs from operation OP-K\'s recorded kind payout');
    expect(decode).not.toHaveBeenCalled();
  });

  it('F06: two concurrent pay commands for an absent operation with different --kind: the second is refused by the record, not booked as the first\'s kind', async () => {
    const payout = preimageFor('kind-race-payout');
    const refund = preimageFor('kind-race-refund');
    const decodes = new Map<string, { promise: Promise<DecodedPayReq>; resolve: (value: DecodedPayReq) => void }>();
    for (const request of ['lnbcrt1kindpayout', 'lnbcrt1kindrefund']) {
      let resolve!: (value: DecodedPayReq) => void;
      const promise = new Promise<DecodedPayReq>(done => { resolve = done; });
      decodes.set(request, { promise, resolve });
    }
    const sent: string[] = [];
    const api: FakePayerApi = {
      decodePayReq: request => (decodes.get(request) as { promise: Promise<DecodedPayReq> }).promise,
      sendPaymentV2: async (request, onUpdate) => {
        const { paymentRequest } = request as { paymentRequest: string };
        sent.push(paymentRequest);
        onUpdate(paymentRequest === 'lnbcrt1kindpayout' ? lndPayment('kind-race-payout', 'FAILED') : lndPayment('kind-race-refund', 'SUCCEEDED'));
      },
      trackPaymentV2: () => Promise.reject(new Error('not used')),
    };
    // Two processes: each main gets its own store handle on the same file (labLike opens one per call).
    const { services } = labLike('kind-race.db', api);
    const run = (kind: string, invoice: string): Promise<number> => lab.main(['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP-RACE',
      '--kind', kind, '--invoice', invoice, '--fee-limit-msat', '10'], services);
    const first = run('payout', 'lnbcrt1kindpayout');
    const second = run('refund', 'lnbcrt1kindrefund');
    // Both passed the --kind check before the operation existed and await DecodePayReq; the payout's decode completes first and its payment fails.
    for (let turn = 0; turn < 20; turn += 1) await new Promise(resolve => setImmediate(resolve));
    (decodes.get('lnbcrt1kindpayout') as { resolve: (value: DecodedPayReq) => void }).resolve(decoded(payout.paymentHash));
    expect(await first).toBe(1);
    const between = payerStore('kind-race.db');
    expect(between.operation('OP-RACE')).toMatchObject({ kind: 'payout', state: 'failed' });
    between.close();
    opened.pop();
    // The refund's decode completes: its intent names kind refund for an operation recorded as a payout, and is refused inside the record's transaction.
    (decodes.get('lnbcrt1kindrefund') as { resolve: (value: DecodedPayReq) => void }).resolve(decoded(refund.paymentHash));
    expect(await second).toBe(3);
    expect(sent).toEqual(['lnbcrt1kindpayout']);
    expect(events().map(item => item.event)).toEqual(['invoice-decoded', 'outcome', 'invoice-decoded']);
    const after = payerStore('kind-race.db');
    expect(after.operation('OP-RACE')).toMatchObject({ kind: 'payout', state: 'failed' });
    expect(after.payment(refund.paymentHash)).toBeUndefined();
    expect(after.outbox('OP-RACE')).toEqual([]);
    // The record's own refusal, as the command received it (its deps.emit is silent here).
    expect(after.recordIntent({ operationId: 'OP-RACE', kind: 'refund', paymentRequest: 'lnbcrt1kindrefund', invoice: decoded(refund.paymentHash),
      feeLimitMsat: 10n, maxParts: 1 })).toEqual({ outcome: 'refused', reason: '--kind refund differs from operation OP-RACE\'s recorded kind payout' });
    // The same kind for the same hash (a replay of the payout's own invoice) is still answered from the record.
    expect(after.recordIntent({ operationId: 'OP-RACE', kind: 'refund', paymentRequest: 'lnbcrt1kindpayout', invoice: decoded(payout.paymentHash),
      feeLimitMsat: 10n, maxParts: 1 })).toEqual({ outcome: 'refused', reason: '--kind refund differs from operation OP-RACE\'s recorded kind payout' });
    expect(after.recordIntent({ operationId: 'OP-RACE', kind: 'payout', paymentRequest: 'lnbcrt1kindpayout', invoice: decoded(payout.paymentHash),
      feeLimitMsat: 10n, maxParts: 1 })).toMatchObject({ outcome: 'existing', payment: { paymentHash: payout.paymentHash, state: 'failed' } });
  });
});

describe('ledger-verify text output', () => {
  it('lists the per-payment differences from LND, at most 100, with their count and "… N more"', async () => {
    const setup = payerStore('lnd-differences.db');
    const reported: Payment[] = [];
    const count = 51;
    for (let index = 0; index < count; index += 1) {
      const label = `lnd-diff-${String(index)}`;
      const { paymentHash } = preimageFor(label);
      setup.recordIntent({ operationId: `OP-LD-${String(index)}`, kind: 'payout', paymentRequest: `lnbcrt1ld${String(index)}`, invoice: decoded(paymentHash),
        feeLimitMsat: 100n, maxParts: 1 });
      setup.claimForSubmission(paymentHash);
      setup.applyUpdate(lndPayment(label, 'SUCCEEDED'), 'SendPaymentV2', 1);
      // LND reports another fee for every payment.
      reported.push({ ...lndPayment(label, 'SUCCEEDED'), feeMsat: 17n, paymentIndex: String(index + 1) });
    }
    setup.close();
    const { services } = labLike('lnd-differences.db');
    const run = { ...services, ledgerSource: () => ({ listPaymentsPage: async () => ({ payments: reported, lastIndexOffset: BigInt(count) }) }) };
    expect(await lab.main(['payer', 'ledger-verify', '--as', 'customer-payer'], run)).toBe(1);
    const summary = events().find(item => item.event === 'ledger-verify');
    // Two differences per payment: the fee account and the wallet's outgoing total.
    expect(summary?.lndDifferenceCount).toBe(2 * count);
    expect((summary?.lndDifferences as unknown[]).length).toBe(100);
    expect(summary?.lndDifferencesMore).toBe('… 2 more');
    expect(stdout.join('')).not.toContain(preimageFor('lnd-diff-0').preimage);
  });
});
