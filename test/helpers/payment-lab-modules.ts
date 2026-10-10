import { mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Loads the payment lab's own modules (examples/payment-lab/src) for the regression
 * tests in test/payment-lab-state.test.ts, test/payment-lab-ledger.test.ts and
 * test/payment-lab-outbox.test.ts.
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

/** The raw database handle the tests use to corrupt or rewind a store (node:sqlite's DatabaseSync, narrowed). */
export interface RawDb {
  prepare(sql: string): { all(...params: unknown[]): Record<string, unknown>[]; run(...params: unknown[]): unknown };
  exec(sql: string): void;
}

/** src/ledger/journal.ts */
export interface JournalEntry {
  entryId: number;
  event: string;
  reference: string;
  operationId: string | undefined;
  paymentHash: string | undefined;
  origin: 'live' | 'migrated';
  postedAt: string;
  lines: { lineNo: number; account: string; direction: 'debit' | 'credit'; amountMsat: bigint; leg: string | undefined }[];
}

/** src/ledger/verify.ts */
export interface Explanation { account: string; entryId?: number; event?: string; reference?: string; paymentHash?: string; reason: string }
export interface AccountReport {
  account: string; computed: bigint; stored: bigint; difference: bigint;
  records?: bigint; recordsDifference?: bigint; lnd?: bigint; lndDifference?: bigint; firstEntry?: Explanation;
}
export interface LedgerVerification {
  book: 'payer' | 'receiver';
  balanced: boolean;
  entries: number;
  unbalancedEntries: { entryId: number; event: string; reference: string; debitsMsat: bigint; creditsMsat: bigint; reason: string }[];
  /** Entries whose amounts may balance but whose shape does not match their posting rule or the records. */
  invalidEntries: { entryId: number; event: string; reference: string; reason: string }[];
  accounts: AccountReport[];
  lnd: 'compared' | 'pending' | 'not-requested' | 'unavailable' | 'incomplete';
  lndDetail?: string;
  firstDifference?: Explanation;
}
export interface LndLedgerSource {
  listPaymentsPage?(indexOffset: bigint, maxPayments: number): Promise<{ payments: Payment[]; lastIndexOffset: bigint }>;
  listInvoicesPage?(indexOffset: bigint, maxInvoices: number): Promise<{ invoices: Invoice[]; lastIndexOffset: bigint }>;
}
/** src/outbox/outbox.ts */
export type PayloadValue = string | number | null;
export interface OutboxRow {
  outboxId: number;
  kind: 'fulfill-order' | 'confirm-operation';
  idempotencyKey: string;
  subject: string;
  payload: Record<string, PayloadValue>;
  state: 'pending' | 'leased' | 'done';
  attempts: number;
  nextAttemptAt: string;
  leaseOwner: string | undefined;
  leaseExpiresAt: string | undefined;
  lastError: string | undefined;
  createdAt: string;
  acknowledgedAt: string | undefined;
}
export interface OutboxStatus {
  pending: number; leased: number; done: number; expiredLeases: number; oldestPendingAgeS: number | null; deadlineS: number;
  overdue: { outboxId: number; idempotencyKey: string; state: string; attempts: number; lastError: string | undefined }[];
  overdueCount: number;
}
/** src/outbox/effects.ts */
export interface EffectTarget { dir: string; key: Buffer }
export type EffectRead = { state: 'absent' } | { state: 'invalid'; reason: string } | { state: 'valid'; fields: Record<string, PayloadValue> };
/** src/outbox/worker.ts */
export interface WorkerHooks {
  afterClaim?(row: OutboxRow): void;
  duringWrite?(tmpPath: string): void;
  afterEffect?(row: OutboxRow): void;
  afterAck?(row: OutboxRow): void;
}
export interface PassResult { performed: number; alreadyPresent: number; failed: number; leaseLost: number; remaining: number }
export interface Outbox {
  runPass(db: RawDb, target: EffectTarget, options: { emit: (event: Record<string, unknown>) => void; owner?: string; leaseMs?: number;
    clock?: () => number; maxRows?: number; hooks?: WorkerHooks }): PassResult;
  claim(db: RawDb, owner: string, nowMs: number, leaseMs: number): OutboxRow | undefined;
  acknowledge(db: RawDb, outboxId: number, owner: string, nowMs: number): boolean;
  retryLater(db: RawDb, outboxId: number, owner: string, error: string, nowMs: number): boolean;
  outboxStatus(db: RawDb, nowMs: number, deadlineS: number): OutboxStatus;
  backoffMs(attempts: number): number;
  labKey(labDir: string): Buffer;
  fileBase(subject: string): string;
  effectPath(target: EffectTarget, subject: string): string;
  readEffect(path: string, key: Buffer): EffectRead;
  MAX_RECEIPT_BYTES: number;
}

export interface BudgetStatus { heldMsat: bigint; consumedMsat: bigint; availableMsat: bigint }
export type IntentResult = { outcome: 'recorded' | 'existing'; payment: PaymentRecord } | { outcome: 'refused'; reason: string };

export interface PayerStore {
  readonly db: RawDb;
  readonly book: 'payer';
  close(): void;
  ledger(operationId: string): { account: string; amountMsat: bigint; postedAt: string }[];
  journal(operationId: string): JournalEntry[];
  outbox(operationId?: string): OutboxRow[];
  payment(paymentHash: string): PaymentRecord | undefined;
  operation(operationId: string): { state: string; budgetId: string | undefined } | undefined;
  setBudget(budgetId: string, limitMsat: bigint): void;
  budgetStatus(budgetId: string): BudgetStatus | undefined;
  refusals(budgetId: string): { operationId: string; requestedMsat: bigint; availableMsat: bigint }[];
  events(paymentHash: string): { kind: string; detail: string }[];
  recordIntent(input: { operationId: string; kind: string; paymentRequest: string; invoice: DecodedPayReq; feeLimitMsat: bigint;
    maxParts: number; budgetId?: string }): IntentResult;
  claimForSubmission(paymentHash: string): boolean;
  markUncertain(paymentHash: string, reason: string, submission?: number): string;
  markNotInitiated(paymentHash: string, evidence: string, submission?: number): string;
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
  readonly db: RawDb;
  readonly book: 'receiver';
  journal(orderId: string): JournalEntry[];
  outbox(orderId?: string): OutboxRow[];
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
  /** Only receiver ledger-verify calls it (ListInvoices). */
  listInvoicesPage?(indexOffset: bigint, maxInvoices: number): Promise<{ invoices: Invoice[]; lastIndexOffset: bigint }>;
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
  /** lnd/types.ts: LND's REST JSON for an invoice and for a decoded payment request. */
  parseInvoice(value: unknown): Invoice;
  parsePayReq(value: unknown): DecodedPayReq;
  submit(deps: PayerDeps, paymentHash: string, options: { timeoutSeconds: number; fault: 'none'; signal?: AbortSignal }): Promise<PayOutcome>;
  reconcile(deps: PayerDeps, paymentHash: string, signal?: AbortSignal): Promise<PayOutcome>;
  settleHoldInvoice(deps: ReceiverDeps, orderId: string): Promise<{ kind: string; reason?: string; outcome?: string }>;
  createInvoice(deps: ReceiverDeps, input: { orderId: string; amountMsat: bigint; hold: boolean; memo: string; expirySeconds: number }):
    Promise<{ kind: string; paymentHash?: string; reason?: string }>;
  reconcileInvoices(deps: ReceiverDeps, onlyOrder?: string, signal?: AbortSignal): Promise<{ resolved: number; open: number; unknown: number }>;
  listen(deps: ReceiverDeps, options: { reconcileIntervalMs: number; signal: AbortSignal; afterReconcile?: () => void }): Promise<void>;
  main(argv: string[], services: { payer(labDir: string | undefined, profile: string): PayerDeps;
    receiver(labDir: string | undefined, profile: string): ReceiverDeps;
    ledgerSource?(labDir: string | undefined, component: 'payer' | 'receiver', profile: string): LndLedgerSource | undefined;
    outbox?(labDir: string | undefined, component: 'payer' | 'receiver'): EffectTarget | undefined }): Promise<number>;
  /** src/ledger/verify.ts */
  verifyLedger(store: PayerStore | ReceiverStore, api?: LndLedgerSource): Promise<LedgerVerification>;
  /** src/outbox/ */
  outbox: Outbox;
}

export async function loadLab(): Promise<Lab> {
  // One after another: concurrent first loads of modules that share imports are not needed here.
  const errors = await load<Pick<Lab, 'LndError' | 'TransportError' | 'ProtocolError' | 'definiteRefusal'>>('lnd/errors.ts');
  const types = await load<Pick<Lab, 'parsePayment' | 'parseInvoice' | 'parsePayReq'>>('lnd/types.ts');
  const payerStore = await load<Pick<Lab, 'PayerStore'>>('payer/store.ts');
  const receiverStore = await load<Pick<Lab, 'ReceiverStore'>>('receiver/store.ts');
  const payer = await load<Pick<Lab, 'submit' | 'reconcile'>>('payer/payer.ts');
  const receiver = await load<Pick<Lab, 'settleHoldInvoice' | 'listen' | 'createInvoice' | 'reconcileInvoices'>>('receiver/receiver.ts');
  const cli = await load<Pick<Lab, 'main'>>('cli.ts');
  const ledger = await load<Pick<Lab, 'verifyLedger'>>('ledger/verify.ts');
  const outbox = {
    ...await load<Pick<Outbox, 'claim' | 'acknowledge' | 'retryLater' | 'outboxStatus' | 'backoffMs'>>('outbox/outbox.ts'),
    ...await load<Pick<Outbox, 'labKey' | 'fileBase' | 'effectPath' | 'readEffect' | 'MAX_RECEIPT_BYTES'>>('outbox/effects.ts'),
    ...await load<Pick<Outbox, 'runPass'>>('outbox/worker.ts'),
  };
  // The workflows classify errors with instanceof: an error made here must be the class they import.
  const shared = await load<{ definiteRefusal(error: unknown): boolean }>('receiver/receiver.ts');
  if (!shared.definiteRefusal(new errors.LndError('probe', 2, 500))) {
    throw new Error('examples/payment-lab/src/lnd/errors.ts was loaded twice; the regression tests would test the wrong classes');
  }
  return { PayerStore: payerStore.PayerStore, ReceiverStore: receiverStore.ReceiverStore, LndError: errors.LndError,
    TransportError: errors.TransportError, ProtocolError: errors.ProtocolError, definiteRefusal: errors.definiteRefusal,
    parsePayment: types.parsePayment, parseInvoice: types.parseInvoice, parsePayReq: types.parsePayReq, submit: payer.submit, reconcile: payer.reconcile,
    settleHoldInvoice: receiver.settleHoldInvoice, listen: receiver.listen, createInvoice: receiver.createInvoice,
    reconcileInvoices: receiver.reconcileInvoices, main: cli.main, verifyLedger: ledger.verifyLedger,
    outbox: { claim: outbox.claim, acknowledge: outbox.acknowledge, retryLater: outbox.retryLater, outboxStatus: outbox.outboxStatus,
      backoffMs: outbox.backoffMs, labKey: outbox.labKey, fileBase: outbox.fileBase, effectPath: outbox.effectPath,
      readEffect: outbox.readEffect, MAX_RECEIPT_BYTES: outbox.MAX_RECEIPT_BYTES, runPass: outbox.runPass } };
}

/** src/explain/: the explanation of one payment (payer explain, receiver explain). */
export interface ExplainTimelineItem { at: string; kind: string; detail: string; rule?: string }
export interface ExplainResult {
  subject: { component: 'payer' | 'receiver'; operationId?: string; orderId?: string; payments: string[] };
  timeline: ExplainTimelineItem[];
  outcome: Record<string, unknown> & { summary: string };
  reservation: Record<string, unknown> | null;
  journal: { entryId: number; event: string; reference: string; payment: string | null; lines: { account: string; direction: string; amountMsat: string }[] }[];
  outbox: { outboxId: number; kind: string; idempotencyKey: string; state: string; effect: string }[];
  reconciliation: { at: string; decision: string; detail: string; rule: string; predicates: readonly string[] }[];
}
export interface ExplainDocument {
  schema: 1; command: 'explain'; ok: boolean; warnings: { code: string; message: string }[]; result: ExplainResult | null;
  error: { code: number; step: string | null; message: string } | null;
}
export interface Explain {
  RULES: Record<string, { name: string; form: 'paragraph' | 'section' | 'sentence'; predicates: readonly string[] }>;
  fingerprint(paymentHash: string): string;
  safeText(value: string): string;
}

export async function loadExplain(): Promise<Explain> {
  const rules = await load<Pick<Explain, 'RULES'>>('explain/rules.ts');
  const format = await load<Pick<Explain, 'fingerprint' | 'safeText'>>('explain/format.ts');
  return { RULES: rules.RULES, fingerprint: format.fingerprint, safeText: format.safeText };
}

/**
 * The state-machine harness's case runner (examples/payment-lab/test/harness/harness.ts, class Run), for a test that
 * reads the records a replay leaves behind before the case directory is removed: runCase and replay remove it.
 */
export interface HarnessRun {
  readonly dir: string;
  step(event: unknown): Promise<boolean>;
  quiesce(): Promise<void>;
  dispose(): Promise<void>;
}
export interface HarnessRunner {
  Run: new (lab: unknown, config: unknown, scratch: string) => HarnessRun;
  loadHarnessLab(): Promise<unknown>;
  PREDICATES: Record<string, string>;
}

export async function loadHarnessRunner(): Promise<HarnessRunner> {
  const harnessDir = '../../examples/payment-lab/test/harness/';
  const harness = await import(/* @vite-ignore */ `${harnessDir}harness.ts`) as Pick<HarnessRunner, 'Run' | 'PREDICATES'>;
  const labModule = await import(/* @vite-ignore */ `${harnessDir}lab.ts`) as { loadLab(): Promise<unknown> };
  return { Run: harness.Run, PREDICATES: harness.PREDICATES, loadHarnessLab: () => labModule.loadLab() };
}

/** The file URL of a lab module, for a child process that imports it (the restart tests). */
export function labModuleUrl(relative: string): string {
  return new URL(`../../examples/payment-lab/src/${relative}`, import.meta.url).href;
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
