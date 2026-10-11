import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/**
 * Loads the payment lab's modules from a source directory: the lab's own `src/` by default, or
 * another copy of it (`--lab-src`, for example the 1.2.0 sources extracted with `git archive`), so
 * the replay corpus can be run against the code it was recorded on. The modules are imported at run
 * time from file URLs; the shapes the harness uses are declared here structurally, so this file
 * type-checks without the lab's types and works against older sources whose signatures took fewer
 * arguments (an extra argument is ignored there).
 */

export const DEFAULT_LAB_SRC = resolve(dirname(fileURLToPath(import.meta.url)), '../../src');

export type StreamDecision = 'continue' | 'stop' | 'drop';

export interface HtlcAttempt {
  attemptId: string;
  status: 'IN_FLIGHT' | 'SUCCEEDED' | 'FAILED';
  route: { totalAmtMsat: bigint; totalFeesMsat: bigint; hops: { chanId: string; pubKey: string; amtToForwardMsat: bigint; feeMsat: bigint }[] };
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

/** A store as the harness sees it: any method, called by name through a recording proxy. */
export interface Store {
  readonly db: unknown;
  close(): void;
  [method: string]: unknown;
}

export interface PayerApi {
  decodePayReq(paymentRequest: string): Promise<DecodedPayReq>;
  sendPaymentV2(request: unknown, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void>;
  trackPaymentV2(paymentHash: string, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void>;
}

export interface InvoiceApi {
  addInvoice(request: { preimage: string; valueMsat: bigint; memo: string; expirySeconds: number }):
    Promise<{ paymentHash: string; paymentRequest: string; addIndex: bigint }>;
  addHoldInvoice(request: { paymentHash: string; valueMsat: bigint; memo: string; expirySeconds: number }):
    Promise<{ paymentRequest: string; addIndex: bigint }>;
  lookupInvoice(paymentHash: string, signal?: AbortSignal): Promise<Invoice>;
  settleInvoice(preimage: string): Promise<void>;
  cancelInvoice(paymentHash: string): Promise<void>;
  subscribeInvoices(from: { addIndex: bigint; settleIndex: bigint }, onInvoice: (invoice: Invoice) => StreamDecision,
    signal?: AbortSignal): Promise<void>;
}

type Emit = (event: Record<string, unknown>) => void;
export interface PayerDeps { api: PayerApi; store: Store; emit: Emit }
export interface ReceiverDeps { api: InvoiceApi; store: Store; emit: Emit }
export type Outcome = { kind: string; [key: string]: unknown };

export interface Lab {
  src: string;
  PayerStore: new (path: string) => Store;
  ReceiverStore: new (path: string) => Store;
  LndError: new (message: string, grpcCode: number | undefined, httpStatus: number | undefined) => Error;
  TransportError: new (message: string, phase: 'connect' | 'request' | 'response') => Error;
  recordIntent(deps: PayerDeps, input: Record<string, unknown>): Outcome & { outcome?: string };
  submit(deps: PayerDeps, paymentHash: string, options: { timeoutSeconds: number; fault: 'none'; signal?: AbortSignal }): Promise<Outcome>;
  reconcile(deps: PayerDeps, paymentHash: string, signal?: AbortSignal): Promise<Outcome>;
  createInvoice(deps: ReceiverDeps, input: { orderId: string; amountMsat: bigint; hold: boolean; memo: string; expirySeconds: number }):
    Promise<Outcome>;
  settleHoldInvoice(deps: ReceiverDeps, orderId: string): Promise<Outcome>;
  cancelHoldInvoice(deps: ReceiverDeps, orderId: string): Promise<Outcome>;
  reconcileInvoices(deps: ReceiverDeps, onlyOrder?: string, signal?: AbortSignal): Promise<{ resolved: number; open: number; unknown: number }>;
  listen(deps: ReceiverDeps, options: { reconcileIntervalMs: number; signal: AbortSignal }): Promise<void>;
  /**
   * cli.ts's main with injected services, when the source exports it. The 1.2.0 cli.ts ran main at import
   * time and took no services, so it is not imported at all (cliMain is undefined) and the exit-code half of
   * the reconcile predicate is not checked there.
   */
  cliMain: ((argv: string[], services: { payer(): PayerDeps; receiver(): ReceiverDeps }) => Promise<number>) | undefined;
  /** `ledger verify` (src/ledger/verify.ts), when the source has the double-entry journal (1.3.0); undefined for older sources. */
  verifyLedger: ((store: { db: unknown; book: 'payer' | 'receiver' }, api?: {
    listPaymentsPage(indexOffset: bigint, maxPayments: number): Promise<{ payments: Payment[]; lastIndexOffset: bigint }>;
    listInvoicesPage(indexOffset: bigint, maxInvoices: number): Promise<{ invoices: Invoice[]; lastIndexOffset: bigint }>;
  }) => Promise<LedgerVerification>) | undefined;
  /** The outbox worker and the effect files (src/outbox/), when the source has them (1.3.0); undefined for older sources. */
  outbox: OutboxModules | undefined;
}

/** The parts of verifyLedger's result the oracle reads. */
export interface LedgerVerification {
  balanced: boolean;
  unbalancedEntries: { entryId: number; reason: string }[];
  invalidEntries: { entryId: number; reason: string }[];
  firstDifference?: { account: string; entryId?: number; reason: string };
}

export interface EffectTarget { dir: string; key: Buffer }
export interface OutboxRowView { outboxId: number; kind: string; idempotencyKey: string; subject: string; payload: Record<string, string | number | null> }

export interface OutboxModules {
  runPass(db: unknown, target: EffectTarget, options: { emit: (event: Record<string, unknown>) => void; owner?: string; leaseMs?: number;
    clock?: () => number; hooks?: { afterClaim?(row: OutboxRowView): void; afterEffect?(row: OutboxRowView): void; afterAck?(row: OutboxRowView): void;
      duringWrite?(tmpPath: string): void } }): { performed: number; alreadyPresent: number; failed: number; leaseLost: number; remaining: number };
  labKey(labDir: string): Buffer;
  effectPath(target: EffectTarget, subject: string): string;
  effectFields(row: { kind: string; idempotencyKey: string; payload: Record<string, string | number | null> }): Record<string, string | number | null>;
  readEffect(path: string, key: Buffer): { state: 'absent' } | { state: 'invalid'; reason: string } | { state: 'valid'; fields: Record<string, string | number | null> };
}

const loaded = new Map<string, Promise<Lab>>();

async function load<T>(src: string, relative: string): Promise<T> {
  return await import(/* @vite-ignore */ pathToFileURL(join(src, relative)).href) as T;
}

/** The lab's modules from `src` (a directory holding payer/, receiver/, lnd/ and cli.ts), loaded once per directory. */
export function loadLab(src: string = DEFAULT_LAB_SRC): Promise<Lab> {
  const root = resolve(src);
  let lab = loaded.get(root);
  if (lab === undefined) {
    lab = loadFrom(root);
    loaded.set(root, lab);
  }
  return lab;
}

async function loadFrom(src: string): Promise<Lab> {
  if (!existsSync(join(src, 'payer', 'store.ts'))) throw new Error(`${src} is not a payment lab source directory (no payer/store.ts)`);
  // One after another, errors first: the workflows classify errors with instanceof, so the classes the
  // harness throws must be the ones they import (same file URL, same module instance).
  const errors = await load<Pick<Lab, 'LndError' | 'TransportError'>>(src, 'lnd/errors.ts');
  const payerStore = await load<{ PayerStore: Lab['PayerStore'] }>(src, 'payer/store.ts');
  const receiverStore = await load<{ ReceiverStore: Lab['ReceiverStore'] }>(src, 'receiver/store.ts');
  const payer = await load<Pick<Lab, 'recordIntent' | 'submit' | 'reconcile'>>(src, 'payer/payer.ts');
  const receiver = await load<Pick<Lab, 'createInvoice' | 'settleHoldInvoice' | 'cancelHoldInvoice' | 'reconcileInvoices' | 'listen'>>(src,
    'receiver/receiver.ts');
  const cliText = readFileSync(join(src, 'cli.ts'), 'utf8');
  const importable = /export async function main\(argv: string\[\], services/.test(cliText) && /if \(isEntryPoint\(\)\)/.test(cliText);
  const cli = importable ? await load<{ main: NonNullable<Lab['cliMain']> }>(src, 'cli.ts') : undefined;
  const ledger = existsSync(join(src, 'ledger', 'verify.ts')) ? await load<{ verifyLedger: NonNullable<Lab['verifyLedger']> }>(src, 'ledger/verify.ts') : undefined;
  let outbox: OutboxModules | undefined;
  if (existsSync(join(src, 'outbox', 'worker.ts')) && existsSync(join(src, 'outbox', 'effects.ts'))) {
    const worker = await load<Pick<OutboxModules, 'runPass'>>(src, 'outbox/worker.ts');
    const effects = await load<Omit<OutboxModules, 'runPass'>>(src, 'outbox/effects.ts');
    outbox = { runPass: worker.runPass, labKey: effects.labKey, effectPath: effects.effectPath, effectFields: effects.effectFields, readEffect: effects.readEffect };
  }
  return { src, PayerStore: payerStore.PayerStore, ReceiverStore: receiverStore.ReceiverStore, LndError: errors.LndError,
    TransportError: errors.TransportError, recordIntent: payer.recordIntent, submit: payer.submit, reconcile: payer.reconcile,
    createInvoice: receiver.createInvoice, settleHoldInvoice: receiver.settleHoldInvoice, cancelHoldInvoice: receiver.cancelHoldInvoice,
    reconcileInvoices: receiver.reconcileInvoices, listen: receiver.listen, cliMain: cli?.main,
    verifyLedger: ledger?.verifyLedger, outbox };
}
