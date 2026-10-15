import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  loadLab, preimageFor, tempDirectory,
  type DecodedPayReq, type FakePayerApi, type Lab, type LedgerVerification, type Payment, type PayerStore, type StreamDecision,
} from './helpers/payment-lab-modules.js';

/**
 * The payment lab's command line (examples/payment-lab/src/cli.ts): ledger-verify's text output names the
 * malformed entries, payer reconcile skips the outbox pass once it was stopped, and every command refuses a
 * flag that belongs to another command (exit 2, before anything is opened). Real stores on temporary SQLite
 * files, scripted stand-ins for LND; no node, no Docker, no credential.
 */

let lab: Lab;
const dir = tempDirectory();

beforeAll(async () => { lab = await loadLab(); });
afterAll(() => dir.remove());

const opened: { close(): void }[] = [];
afterEach(() => {
  for (const store of opened.splice(0)) {
    try { store.close(); } catch { /* already closed */ }
  }
});

function payerStore(file: string): PayerStore {
  const store = new lab.PayerStore(dir.path(file));
  opened.push(store);
  return store;
}

const DESTINATION = `02${'11'.repeat(32)}`;
const quiet = (): void => undefined;

function decoded(paymentHash: string): DecodedPayReq {
  return { destination: DESTINATION, paymentHash, amountMsat: 1000n, timestamp: BigInt(Math.floor(Date.now() / 1000)), expirySeconds: 3600n,
    description: 'payment-lab-cli' };
}

function lndPayment(label: string, status: 'IN_FLIGHT' | 'SUCCEEDED'): Payment {
  const { preimage, paymentHash } = preimageFor(label);
  return { paymentHash, status, valueMsat: 1000n, feeMsat: status === 'SUCCEEDED' ? 10n : 0n, preimage: status === 'SUCCEEDED' ? preimage : undefined,
    paymentRequest: '', failureReason: '', creationTimeNs: 1n, paymentIndex: '1', htlcs: [] };
}

/** Records a payout of 1000 msat for `operationId` and claims it for submission 1; returns its payment hash. */
function submitted(store: PayerStore, label: string, operationId: string): string {
  const { paymentHash } = preimageFor(label);
  expect(store.recordIntent({ operationId, kind: 'payout', paymentRequest: `lnbcrt1${label}`, invoice: decoded(paymentHash), feeLimitMsat: 100n,
    maxParts: 1 }).outcome).toBe('recorded');
  expect(store.claimForSubmission(paymentHash)).toBe(true);
  return paymentHash;
}

let stdout: string[];
let stderr: string[];
beforeEach(() => {
  stdout = [];
  stderr = [];
  vi.spyOn(process.stdout, 'write').mockImplementation(chunk => { stdout.push(String(chunk)); return true; });
  vi.spyOn(process.stderr, 'write').mockImplementation(chunk => { stderr.push(String(chunk)); return true; });
});
afterEach(() => { vi.restoreAllMocks(); });

const events = (): Record<string, unknown>[] => stdout.flatMap(chunk => chunk.split('\n')).filter(line => line !== '')
  .map(line => JSON.parse(line) as Record<string, unknown>);

const noPayerCalls = {} as FakePayerApi;

describe('payment lab CLI: ledger-verify text output', () => {
  it('the ledger-verify summary lists the malformed entries (entry ID and reason), as --json does', async () => {
    const setup = payerStore('invalid-entry.db');
    submitted(setup, 'invalid-entry', 'OP-IE');
    setup.applyUpdate(lndPayment('invalid-entry', 'SUCCEEDED'), 'SendPaymentV2', 1);
    const [entry] = setup.journal('OP-IE');
    expect(entry?.event).toBe('payment-succeeded');
    const entryId = entry?.entryId ?? 0;
    setup.db.exec(`UPDATE journal_entries SET reference = 'other' WHERE entry_id = ${String(entryId)}`);
    const direct: LedgerVerification = await lab.verifyLedger(setup);
    expect(direct.invalidEntries.map(item => item.entryId)).toEqual([entryId]);
    setup.close();

    const services = { payer: () => ({ api: noPayerCalls, store: payerStore('invalid-entry.db'), emit: quiet }),
      receiver: () => { throw new Error('not used'); } };
    expect(await lab.main(['payer', 'ledger-verify', '--as', 'customer-payer'], services)).toBe(1);
    const summary = events().find(item => item.event === 'ledger-verify');
    expect(summary?.invalidEntries).toEqual([expect.objectContaining({ entryId, event: 'payment-succeeded',
      reason: expect.any(String) as string })]);
  });
});

describe('payment lab CLI: payer reconcile and the outbox pass', () => {
  function inFlight(file: string, label: string): string {
    const setup = payerStore(file);
    const hash = submitted(setup, label, `OP-${label}`);
    setup.applyUpdate(lndPayment(label, 'IN_FLIGHT'), 'SendPaymentV2', 1);
    setup.close();
    return hash;
  }

  function services(file: string, track: (onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal) => Promise<void>) {
    const api: FakePayerApi = {
      decodePayReq: () => Promise.reject(new Error('not used')),
      sendPaymentV2: () => Promise.reject(new Error('not used')),
      trackPaymentV2: (_hash, onUpdate, signal) => track(onUpdate, signal),
    };
    const outbox = vi.fn(() => undefined);
    return { outbox, run: { payer: () => ({ api, store: payerStore(file), emit: quiet }), receiver: () => { throw new Error('not used'); }, outbox } };
  }

  it('stopped by --timeout-s: the payment stays unresolved (75) and no outbox pass runs', async () => {
    inFlight('reconcile-stopped.db', 'rs');
    const { outbox, run } = services('reconcile-stopped.db', (_onUpdate, signal) => new Promise((_resolve, reject) => {
      if (signal === undefined) { reject(new Error('no signal')); return; }
      signal.addEventListener('abort', () => reject(new lab.TransportError('aborted by the caller', 'response')), { once: true });
    }));
    expect(await lab.main(['payer', 'reconcile', '--as', 'customer-payer', '--timeout-s', '1'], run)).toBe(75);
    expect(outbox).not.toHaveBeenCalled();
    expect(events().map(item => item.event)).not.toContain('outbox-pass');
    expect(events()).toContainEqual(expect.objectContaining({ event: 'outbox-pass-skipped' }));
  });

  it('not stopped: the outbox pass runs after the reconciliation', async () => {
    inFlight('reconcile-done.db', 'rd');
    const { outbox, run } = services('reconcile-done.db', async onUpdate => { onUpdate(lndPayment('rd', 'SUCCEEDED')); });
    expect(await lab.main(['payer', 'reconcile', '--as', 'customer-payer', '--timeout-s', '30'], run)).toBe(0);
    expect(outbox).toHaveBeenCalledTimes(1);
  });

  it('each main() call removes the SIGINT and SIGTERM listeners its stop signal added, and only its own (audit 1.3.2)', async () => {
    const count = (): number[] => [process.listenerCount('SIGINT'), process.listenerCount('SIGTERM')];
    const before = count();
    const { run } = services('listeners.db', () => Promise.reject(new Error('nothing is unresolved')));
    for (let index = 0; index < 12; index += 1) expect(await lab.main(['payer', 'reconcile', '--as', 'customer-payer'], run)).toBe(0);
    expect(count()).toEqual(before);
    // A call still running keeps its listeners while another call finishes, and its stop signal still works.
    inFlight('listeners-held.db', 'lh');
    let started: (() => void) | undefined;
    const tracking = new Promise<void>(resolve => { started = resolve; });
    const held = services('listeners-held.db', (_onUpdate, signal) => new Promise((_resolve, reject) => {
      signal?.addEventListener('abort', () => { reject(new lab.TransportError('aborted by the caller', 'response')); }, { once: true });
      started?.();
    }));
    const running = lab.main(['payer', 'reconcile', '--as', 'customer-payer'], held.run);
    await tracking;
    expect(count()).toEqual(before.map(item => item + 1));
    expect(await lab.main(['payer', 'reconcile', '--as', 'customer-payer'], run)).toBe(0);
    expect(count()).toEqual(before.map(item => item + 1));
    const added = process.listeners('SIGINT').at(-1) as () => void;
    added();
    expect(await running).toBe(75);
    expect(count()).toEqual(before);
  });
});

describe('payment lab CLI: each command takes its own flags', () => {
  const HASH = 'ab'.repeat(32);
  const missingLab = (): string => dir.path('no-such-lab');

  // [component, command, the command's required arguments, a flag another command takes]
  const matrix: [string, string, string[], string[]][] = [
    ['payer', 'pay', ['--as', 'customer-payer', '--operation', 'OP-X', '--kind', 'payout', '--invoice', 'lnbcrt1x', '--fee-limit-msat', '10'], ['--refresh']],
    ['payer', 'retry', ['--as', 'customer-payer', '--operation', 'OP-X'], ['--json']],
    ['payer', 'reconcile', ['--as', 'customer-payer'], ['--once']],
    ['payer', 'show', ['--as', 'customer-payer', '--operation', 'OP-X'], ['--interval-s', '5']],
    ['payer', 'budget-set', ['--as', 'customer-payer', '--budget', 'B', '--limit-msat', '10'], ['--deadline-s', '5']],
    ['payer', 'budget-show', ['--as', 'customer-payer', '--budget', 'B'], ['--json']],
    ['payer', 'ledger-verify', ['--as', 'customer-payer'], ['--once']],
    ['payer', 'outbox-run', ['--as', 'customer-payer'], ['--deadline-s', '5']],
    ['payer', 'outbox-status', ['--as', 'customer-payer'], ['--once']],
    ['payer', 'explain', ['--as', 'customer-payer', '--operation', 'OP-X'], ['--timeout-s', '5']],
    ['receiver', 'create-invoice', ['--as', 'merchant', '--order', 'ORD-X', '--amount-msat', '10'], ['--refresh']],
    ['receiver', 'settle', ['--as', 'merchant', '--order', 'ORD-X'], ['--json']],
    ['receiver', 'cancel', ['--as', 'merchant', '--order', 'ORD-X'], ['--once']],
    ['receiver', 'show', ['--as', 'merchant', '--order', 'ORD-X'], ['--interval-s', '5']],
    ['receiver', 'reconcile', ['--as', 'merchant'], ['--payment-hash', HASH]],
    ['receiver', 'listen', ['--as', 'merchant'], ['--once']],
    ['receiver', 'cursor-set', ['--as', 'merchant', '--settle-index', '1'], ['--json']],
    ['receiver', 'ledger-verify', ['--as', 'merchant'], ['--order', 'ORD-X']],
    ['receiver', 'outbox-run', ['--as', 'merchant'], ['--deadline-s', '5']],
    ['receiver', 'outbox-status', ['--as', 'merchant'], ['--once']],
    ['receiver', 'explain', ['--as', 'merchant', '--order', 'ORD-X'], ['--hold']],
    ['analysis', 'payments', ['--node', 'customer', '--payment-hash', HASH], ['--operation', 'OP-X']],
    ['analysis', 'diagnose', ['--node', 'customer', '--payer', 'customer-payer', '--operation', 'OP-X'], ['--payment-hash', HASH]],
  ];

  /** Services that fail the test if anything is opened: no store, no RPC, no outbox target. */
  function untouchable() {
    const fail = (what: string) => vi.fn((): never => { throw new Error(`${what} was opened`); });
    return { payer: fail('payer'), receiver: fail('receiver'), ledgerSource: fail('ledgerSource'), outbox: fail('outbox') };
  }

  it.each(matrix)('%s %s refuses a foreign flag with exit 2 before anything is opened', async (component, command, required, foreign) => {
    const services = untouchable();
    // analysis opens the lab itself: point it at a directory that does not exist, so nothing could be reached.
    const lab_ = component === 'analysis' ? ['--lab', missingLab()] : [];
    expect(await lab.main([component, command, ...required, ...lab_, ...foreign], services)).toBe(2);
    expect(stderr.join('')).toContain(`unknown option ${foreign[0] ?? ''} for ${component} ${command}`);
    for (const factory of Object.values(services)) expect(factory).not.toHaveBeenCalled();
    expect(stdout).toEqual([]);
  });

  it('the first foreign flag is the one named', async () => {
    expect(await lab.main(['payer', 'outbox-status', '--as', 'customer-payer', '--once', '--interval-s', '5'], untouchable())).toBe(2);
    expect(stderr.join('')).toContain('unknown option --once for payer outbox-status');
  });

  it('--as and --lab are accepted by every payer and receiver command; --json only where documented', async () => {
    const store = (): PayerStore => payerStore('flags.db');
    const run = { payer: () => ({ api: noPayerCalls, store: store(), emit: quiet }), receiver: () => { throw new Error('not used'); } };
    expect(await lab.main(['payer', 'show', '--as', 'customer-payer', '--operation', 'OP-F', '--lab', dir.path('lab')], run)).toBe(0);
    expect(await lab.main(['payer', 'budget-show', '--as', 'customer-payer', '--budget', 'B', '--lab', dir.path('lab')], run)).toBe(0);
    expect(await lab.main(['payer', 'outbox-status', '--as', 'customer-payer', '--json', '--deadline-s', '5'], run)).toBe(0);
    expect(await lab.main(['payer', 'show', '--as', 'customer-payer', '--operation', 'OP-F', '--json'], run)).toBe(2);
  });

  it('the usage text lists the 1.3.0 commands with their flags', async () => {
    expect(await lab.main(['payer'], untouchable())).toBe(2);
    const usage = stderr.join('').split('\n');
    for (const [line, flags] of [
      ['ledger-verify --as <profile>', ['--json']],
      ['outbox-run --as <profile>', ['--once', '--interval-s <n>']],
      ['outbox-status --as <profile>', ['--json', '--deadline-s <n>']],
    ] as const) {
      for (const component of ['payer', 'receiver']) {
        const found = usage.find(text => text.trimStart().startsWith(`${component} ${line}`));
        expect(found, `${component} ${line}`).toBeDefined();
        for (const flag of flags) expect(found, `${component} ${line} ${flag}`).toContain(flag);
      }
    }
    for (const [component, id] of [['payer', '--operation <id>'], ['receiver', '--order <id>']] as const) {
      const found = usage.find(text => text.trimStart().startsWith(`${component} explain --as <profile>`));
      for (const flag of [id, '--payment-hash <hex>', '--json', '--refresh']) expect(found, `${component} explain ${flag}`).toContain(flag);
    }
  });

  it('an unknown command is a usage error before anything is opened', async () => {
    const services = untouchable();
    expect(await lab.main(['payer', 'frobnicate', '--as', 'customer-payer'], services)).toBe(2);
    expect(stderr.join('')).toContain('unknown payer command frobnicate');
    for (const factory of Object.values(services)) expect(factory).not.toHaveBeenCalled();
  });
});
