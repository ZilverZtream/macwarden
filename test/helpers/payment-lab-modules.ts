import { mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Loads the payment lab's own modules (examples/payment-lab/src) for the regression
 * tests in test/payment-lab-state.test.ts.
 *
 * The lab is written for Node's type stripping: its imports end in `.ts`. Vitest runs
 * them as they are, but `tsc -p tsconfig.test.json` (part of `npm run build`, so of
 * `pretest`) rejects a static import of such a file with TS5097 because that config
 * does not set `allowImportingTsExtensions`. The modules are therefore imported at run
 * time from a computed specifier, which tsc does not follow, and the few shapes the tests
 * use are declared here structurally. The lab's own `npm run typecheck` checks the
 * real types.
 */

/**
 * A relative specifier, resolved the way the lab's own relative imports are, so every
 * module (lnd/errors.ts above all: the workflows test errors with instanceof) has one
 * instance. The specifier is computed, so tsc does not follow it.
 */
async function load<T>(relative: string): Promise<T> {
  return await import(/* @vite-ignore */ `../../examples/payment-lab/src/${relative}`) as T;
}

export type StreamDecision = 'continue' | 'stop' | 'drop';

/** One HTLC attempt of a payment, as lnd/types.ts parses it. */
export interface HtlcAttempt {
  attemptId: string;
  status: 'IN_FLIGHT' | 'SUCCEEDED' | 'FAILED';
  route: { totalAmtMsat: bigint; totalFeesMsat: bigint; hops: { chanId: string; pubKey: string; amtToForwardMsat: bigint }[] };
  principalMsat: bigint;
  attemptTimeNs: bigint;
  resolveTimeNs: bigint;
  failureCode: string | undefined;
  failureSourceIndex: number | undefined;
}

export interface Payment {
  paymentHash: string;
  status: string;
  valueMsat: bigint;
  feeMsat: bigint;
  preimage: string | undefined;
  paymentRequest: string;
  failureReason: string;
  creationTimeNs: bigint;
  paymentIndex: string;
  htlcs: HtlcAttempt[];
}

export interface Invoice {
  paymentHash: string;
  state: string;
  memo: string;
  valueMsat: bigint;
  amtPaidMsat: bigint;
  addIndex: bigint;
  settleIndex: bigint;
  paymentRequest: string;
  htlcs: unknown[];
}

export interface DecodedPayReq {
  destination: string;
  paymentHash: string;
  amountMsat: bigint;
  timestamp: bigint;
  expirySeconds: bigint;
  description: string;
}

export interface PaymentRecord { paymentHash: string; state: string; submissions: number; failureReason: string | undefined }
export interface BudgetStatus { heldMsat: bigint; consumedMsat: bigint; availableMsat: bigint }
export type IntentResult = { outcome: 'recorded' | 'existing'; payment: PaymentRecord } | { outcome: 'refused'; reason: string };

export interface PayerStore {
  readonly db: { prepare(sql: string): { all(...params: unknown[]): Record<string, unknown>[] }; exec(sql: string): void };
  close(): void;
  payment(paymentHash: string): PaymentRecord | undefined;
  operation(operationId: string): { state: string; budgetId: string | undefined } | undefined;
  setBudget(budgetId: string, limitMsat: bigint): void;
  budgetStatus(budgetId: string): BudgetStatus | undefined;
  refusals(budgetId: string): { operationId: string; requestedMsat: bigint; availableMsat: bigint }[];
  events(paymentHash: string): { kind: string; detail: string }[];
  recordIntent(input: { operationId: string; kind: string; paymentRequest: string; invoice: DecodedPayReq; feeLimitMsat: bigint;
    maxParts: number; budgetId?: string }): IntentResult;
  claimForSubmission(paymentHash: string): boolean;
  applyUpdate(payment: Payment, source: 'SendPaymentV2' | 'TrackPaymentV2', submission?: number): { state: string };
  prepareRetry(operationId: string): IntentResult;
}

export type PayOutcome = { kind: string; paymentHash?: string; reason?: string; state?: string };

export interface FakePayerApi {
  decodePayReq(paymentRequest: string): Promise<DecodedPayReq>;
  sendPaymentV2(request: unknown, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void>;
  trackPaymentV2(paymentHash: string, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void>;
}

export interface PayerDeps { api: FakePayerApi; store: PayerStore; emit: (event: Record<string, unknown>) => void }

export interface ReceiverStore {
  close(): void;
  invoice(paymentHash: string): { state: string; orderId: string; lateLndState: string | undefined; settleIndex: bigint | undefined;
    amtPaidMsat: bigint | undefined } | undefined;
  order(orderId: string): { state: string } | undefined;
  isSuperseded(paymentHash: string): boolean;
  fulfillmentCount(orderId: string): number;
  ledger(orderId: string): { paymentHash: string; amountMsat: bigint }[];
  recordInvoiceIntent(input: { orderId: string; amountMsat: bigint; kind: 'standard' | 'hold'; preimage: string; paymentHash: string }):
    { outcome: string };
  markCreated(paymentHash: string, paymentRequest: string, addIndex: bigint): string | undefined;
  markNotCreated(paymentHash: string, createdBefore?: string): boolean;
  applyInvoice(invoice: Invoice, source: string): string;
}

export interface FakeInvoiceApi {
  /** Only createInvoice calls these; a test that does not create an invoice leaves them out. */
  addInvoice?(request: { preimage: string; valueMsat: bigint; memo: string; expirySeconds: number }):
    Promise<{ paymentHash: string; paymentRequest: string; addIndex: bigint }>;
  addHoldInvoice?(request: { paymentHash: string; valueMsat: bigint; memo: string; expirySeconds: number }):
    Promise<{ paymentRequest: string; addIndex: bigint }>;
  lookupInvoice(paymentHash: string, signal?: AbortSignal): Promise<Invoice>;
  settleInvoice(preimage: string): Promise<void>;
  cancelInvoice(paymentHash: string): Promise<void>;
  subscribeInvoices(from: unknown, onInvoice: (invoice: Invoice) => StreamDecision, signal?: AbortSignal): Promise<void>;
}

export interface ReceiverDeps { api: FakeInvoiceApi; store: ReceiverStore; emit: (event: Record<string, unknown>) => void }

export interface Lab {
  PayerStore: new (path: string) => PayerStore;
  ReceiverStore: new (path: string) => ReceiverStore;
  LndError: new (message: string, grpcCode: number | undefined, httpStatus: number | undefined) => Error & { readonly notFound: boolean };
  TransportError: new (message: string, phase: 'connect' | 'request' | 'response') => Error;
  ProtocolError: new (message: string) => Error;
  definiteRefusal(error: unknown): boolean;
  /** lnd/types.ts: LND's REST JSON for a payment, as the payer reads it. */
  parsePayment(value: unknown): Payment;
  submit(deps: PayerDeps, paymentHash: string, options: { timeoutSeconds: number; fault: 'none'; signal?: AbortSignal }): Promise<PayOutcome>;
  reconcile(deps: PayerDeps, paymentHash: string, signal?: AbortSignal): Promise<PayOutcome>;
  settleHoldInvoice(deps: ReceiverDeps, orderId: string): Promise<{ kind: string; reason?: string; outcome?: string }>;
  createInvoice(deps: ReceiverDeps, input: { orderId: string; amountMsat: bigint; hold: boolean; memo: string; expirySeconds: number }):
    Promise<{ kind: string; paymentHash?: string; reason?: string }>;
  reconcileInvoices(deps: ReceiverDeps, onlyOrder?: string, signal?: AbortSignal): Promise<{ resolved: number; open: number; unknown: number }>;
  listen(deps: ReceiverDeps, options: { reconcileIntervalMs: number; signal: AbortSignal }): Promise<void>;
  main(argv: string[], services: { payer(labDir: string | undefined, profile: string): PayerDeps;
    receiver(labDir: string | undefined, profile: string): ReceiverDeps }): Promise<number>;
}

export async function loadLab(): Promise<Lab> {
  // One after another: concurrent first loads of modules that share imports are not needed here.
  const errors = await load<Pick<Lab, 'LndError' | 'TransportError' | 'ProtocolError' | 'definiteRefusal'>>('lnd/errors.ts');
  const types = await load<Pick<Lab, 'parsePayment'>>('lnd/types.ts');
  const payerStore = await load<Pick<Lab, 'PayerStore'>>('payer/store.ts');
  const receiverStore = await load<Pick<Lab, 'ReceiverStore'>>('receiver/store.ts');
  const payer = await load<Pick<Lab, 'submit' | 'reconcile'>>('payer/payer.ts');
  const receiver = await load<Pick<Lab, 'settleHoldInvoice' | 'listen' | 'createInvoice' | 'reconcileInvoices'>>('receiver/receiver.ts');
  const cli = await load<Pick<Lab, 'main'>>('cli.ts');
  // The workflows classify errors with instanceof: an error made here must be the class they import.
  const shared = await load<{ definiteRefusal(error: unknown): boolean }>('receiver/receiver.ts');
  if (!shared.definiteRefusal(new errors.LndError('probe', 2, 500))) {
    throw new Error('examples/payment-lab/src/lnd/errors.ts was loaded twice; the regression tests would test the wrong classes');
  }
  return { PayerStore: payerStore.PayerStore, ReceiverStore: receiverStore.ReceiverStore, LndError: errors.LndError,
    TransportError: errors.TransportError, ProtocolError: errors.ProtocolError, definiteRefusal: errors.definiteRefusal,
    parsePayment: types.parsePayment, submit: payer.submit, reconcile: payer.reconcile,
    settleHoldInvoice: receiver.settleHoldInvoice, listen: receiver.listen, createInvoice: receiver.createInvoice,
    reconcileInvoices: receiver.reconcileInvoices, main: cli.main };
}

/** A private temporary directory for the tests' SQLite files (the lab's store opens a file path). */
export function tempDirectory(): { path(name: string): string; remove(): void } {
  const dir = mkdtempSync(join(tmpdir(), 'macwarden-payment-lab-'));
  return { path: name => join(dir, name), remove: () => rmSync(dir, { recursive: true, force: true }) };
}

/** A preimage and its payment hash, derived from a label so every run uses the same values. */
export function preimageFor(label: string): { preimage: string; paymentHash: string } {
  const preimage = createHash('sha256').update(`payment-lab-state:${label}`).digest('hex');
  return { preimage, paymentHash: createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex') };
}
