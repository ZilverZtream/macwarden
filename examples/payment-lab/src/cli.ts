import { mkdirSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { diagnose } from './analysis/diagnose.ts';
import { paymentsForHash } from './analysis/payments.ts';
import {
  NODE_NAMES, PAYER_PROFILES, RECEIVER_PROFILES, databasePath, invoiceApi, loadLab, payerApi, readApi,
  type Lab, type NodeName, type PayerProfile, type ReceiverProfile,
} from './config.ts';
import { describeError } from './lnd/errors.ts';
import { decodeInvoice, reconcile, recordIntent, submit, type Fault, type PayOutcome, type PayerDeps } from './payer/payer.ts';
import { PayerStore, type OperationKind } from './payer/store.ts';
import { cancelHoldInvoice, createInvoice, listen, reconcileInvoices, settleHoldInvoice, type ReceiverDeps } from './receiver/receiver.ts';
import { ReceiverStore } from './receiver/store.ts';
import { assertHash } from './util/encoding.ts';
import { parseAmount } from './util/money.ts';

/**
 * Command-line entry for the payment service. Output is one JSON object per
 * line on stdout, so the scenario drivers (and any supervisor) can follow it.
 *
 * Exit codes: 0 done (payment succeeded, invoice settled, command completed);
 * 1 payment definitely failed; 2 usage error; 3 refused (budget, conflicting
 * operation, wrong state); 4 configuration or node error; 75 unresolved: the
 * outcome is not known yet and the record stays open for reconciliation.
 */

const EXIT = { ok: 0, failed: 1, usage: 2, refused: 3, error: 4, unresolved: 75 } as const;

class UsageError extends Error {}

function emit(event: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify({ at: new Date().toISOString(), ...event },
    (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value)}\n`);
}

function required(values: Record<string, unknown>, name: string): string {
  const value = values[name];
  if (typeof value !== 'string' || value === '') throw new UsageError(`--${name} is required`);
  return value;
}

function identifier(value: string, what: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) throw new UsageError(`${what} must be 1-128 letters, digits, '.', '_', ':' or '-'`);
  return value;
}

function payerProfile(value: string): PayerProfile {
  if (!(value in PAYER_PROFILES)) throw new UsageError(`--as must be one of ${Object.keys(PAYER_PROFILES).join(', ')}`);
  return value as PayerProfile;
}

function receiverProfile(value: string): ReceiverProfile {
  if (!(value in RECEIVER_PROFILES)) throw new UsageError(`--as must be one of ${Object.keys(RECEIVER_PROFILES).join(', ')}`);
  return value as ReceiverProfile;
}

function nodeName(value: string): NodeName {
  if (!(NODE_NAMES as readonly string[]).includes(value)) throw new UsageError(`--node must be one of ${NODE_NAMES.join(', ')}`);
  return value as NodeName;
}

function seconds(values: Record<string, unknown>, name: string, fallback: number): number {
  const value = values[name];
  if (value === undefined) return fallback;
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,5}$/.test(value)) throw new UsageError(`--${name} must be a whole number of seconds`);
  return Number(value);
}

/** Aborts on SIGINT or SIGTERM, and after `timeoutSeconds` when given. */
function stopSignal(timeoutSeconds?: number): AbortSignal {
  const controller = new AbortController();
  const stop = (): void => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  return timeoutSeconds === undefined ? controller.signal : AbortSignal.any([controller.signal, AbortSignal.timeout(timeoutSeconds * 1000)]);
}

function openPayer(lab: Lab, profile: PayerProfile): PayerDeps {
  mkdirSync(databasePath(lab, ''), { recursive: true, mode: 0o700 });
  return { api: payerApi(lab, profile), store: new PayerStore(databasePath(lab, PAYER_PROFILES[profile].database)), emit };
}

function openReceiver(lab: Lab, profile: ReceiverProfile): ReceiverDeps {
  mkdirSync(databasePath(lab, ''), { recursive: true, mode: 0o700 });
  return { api: invoiceApi(lab, profile), store: new ReceiverStore(databasePath(lab, RECEIVER_PROFILES[profile].database)), emit };
}

function exitFor(outcome: PayOutcome): number {
  emit({ event: 'outcome', ...outcome });
  switch (outcome.kind) {
    case 'succeeded': return EXIT.ok;
    case 'failed': return EXIT.failed;
    case 'refused': return EXIT.refused;
    case 'not-submitted': return EXIT.unresolved;
    case 'unresolved': return EXIT.unresolved;
  }
}

async function waitForGo(): Promise<void> {
  emit({ event: 'ready' });
  const lines = createInterface({ input: process.stdin });
  try {
    for await (const line of lines) if (line.trim() === 'go') return;
  } finally {
    lines.close();
  }
  throw new UsageError('stdin closed before "go"');
}

function showPayment(deps: PayerDeps, operationId: string): void {
  const operation = deps.store.operation(operationId);
  const payment = deps.store.paymentForOperation(operationId);
  emit({
    event: 'payment-record',
    operation: operation ?? null,
    payment: payment ?? null,
    attempts: payment === undefined ? [] : deps.store.attempts(payment.paymentHash),
    ledger: deps.store.ledger(operationId),
    events: payment === undefined ? [] : deps.store.events(payment.paymentHash),
    budget: operation?.budgetId === undefined ? null : deps.store.budgetStatus(operation.budgetId) ?? null,
  });
}

async function payer(command: string, args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: {
    as: { type: 'string' }, operation: { type: 'string' }, kind: { type: 'string' }, invoice: { type: 'string' },
    'fee-limit-msat': { type: 'string' }, 'max-parts': { type: 'string' }, 'timeout-s': { type: 'string' }, budget: { type: 'string' },
    'limit-msat': { type: 'string' }, 'payment-hash': { type: 'string' }, fault: { type: 'string' }, 'wait-for-go': { type: 'boolean' },
    lab: { type: 'string' },
  }, strict: true });
  const lab = loadLab(values.lab);
  const deps = openPayer(lab, payerProfile(required(values, 'as')));
  try {
    switch (command) {
      case 'pay': {
        const operationId = identifier(required(values, 'operation'), '--operation');
        const kind = required(values, 'kind');
        if (!['order-payment', 'refund', 'payout'].includes(kind)) throw new UsageError('--kind must be order-payment, refund or payout');
        const feeLimitMsat = parseAmount(required(values, 'fee-limit-msat'), '--fee-limit-msat');
        const maxParts = values['max-parts'] === undefined ? 16 : Number(parseAmount(values['max-parts'], '--max-parts'));
        if (maxParts < 1 || maxParts > 128) throw new UsageError('--max-parts must be 1 to 128');
        const fault = (values.fault ?? 'none') as Fault;
        if (fault !== 'none' && fault !== 'drop-stream-after-in-flight') throw new UsageError('--fault must be drop-stream-after-in-flight');
        const budgetId = values.budget === undefined ? undefined : identifier(values.budget, '--budget');
        const paymentRequest = required(values, 'invoice');
        const replayed = await answerFromRecord(deps, operationId, paymentRequest);
        if (replayed !== undefined) return replayed;
        const decoded = await decodeInvoice(deps, paymentRequest);
        if ('error' in decoded) { emit({ event: 'invoice-refused', operationId, reason: decoded.error }); return EXIT.refused; }
        emit({ event: 'invoice-decoded', operationId, paymentHash: decoded.invoice.paymentHash, amountMsat: decoded.invoice.amountMsat,
          destination: decoded.invoice.destination });
        if (values['wait-for-go']) await waitForGo();
        const intent = recordIntent(deps, { operationId, kind: kind as OperationKind, paymentRequest, invoice: decoded.invoice,
          feeLimitMsat, maxParts, budgetId });
        if (intent.outcome === 'refused') return EXIT.refused;
        if (intent.outcome === 'existing' && intent.payment.state !== 'intent') {
          return exitFor(await reconcileOrReport(deps, intent.payment.paymentHash, intent.payment.state));
        }
        const signal = stopSignal();
        return exitFor(await submit(deps, intent.payment.paymentHash, { timeoutSeconds: seconds(values, 'timeout-s', 60), fault, signal }));
      }
      case 'retry': {
        const operationId = identifier(required(values, 'operation'), '--operation');
        const prepared = deps.store.prepareRetry(operationId);
        if (prepared.outcome !== 'recorded') {
          emit({ event: 'retry-refused', operationId, reason: prepared.outcome === 'refused' ? prepared.reason : 'unexpected' });
          return EXIT.refused;
        }
        emit({ event: 'retry-prepared', operationId, paymentHash: prepared.payment.paymentHash });
        return exitFor(await submit(deps, prepared.payment.paymentHash, { timeoutSeconds: seconds(values, 'timeout-s', 60), fault: 'none',
          signal: stopSignal() }));
      }
      case 'reconcile': {
        const signal = stopSignal(values['timeout-s'] === undefined ? undefined : seconds(values, 'timeout-s', 60));
        const targets = values['payment-hash'] === undefined
          ? deps.store.unresolvedPayments().map(item => item.paymentHash)
          : [assertHash(values['payment-hash'])];
        emit({ event: 'reconcile-started', payments: targets.length });
        const outcomes = await Promise.all(targets.map(hash => reconcile(deps, hash, signal)));
        for (const outcome of outcomes) emit({ event: 'outcome', ...outcome });
        if (outcomes.some(item => item.kind === 'unresolved' || item.kind === 'not-submitted')) return EXIT.unresolved;
        if (outcomes.some(item => item.kind === 'refused')) return EXIT.refused;
        return EXIT.ok;
      }
      case 'show':
        showPayment(deps, identifier(required(values, 'operation'), '--operation'));
        return EXIT.ok;
      case 'budget-set': {
        const budgetId = identifier(required(values, 'budget'), '--budget');
        deps.store.setBudget(budgetId, parseAmount(required(values, 'limit-msat'), '--limit-msat'));
        emit({ event: 'budget', ...deps.store.budgetStatus(budgetId) });
        return EXIT.ok;
      }
      case 'budget-show': {
        const budgetId = identifier(required(values, 'budget'), '--budget');
        emit({ event: 'budget', status: deps.store.budgetStatus(budgetId) ?? null, refusals: deps.store.refusals(budgetId) });
        return EXIT.ok;
      }
      default:
        throw new UsageError(`unknown payer command ${command}`);
    }
  } finally {
    deps.store.close();
  }
}

/**
 * A repeated request is answered from the record before the invoice is decoded,
 * so a replay depends neither on the invoice still being valid (it may have
 * expired since it was paid) nor on a fresh DecodePayReq. A completed operation
 * replays its recorded success for any invoice it recorded, and is refused for
 * any other; a payment that was sent is answered from the record or TrackPaymentV2.
 * Only a new invoice, or a recorded intent that was never sent, goes on to be
 * decoded and checked, because it is about to be sent. Returns undefined for those.
 */
async function answerFromRecord(deps: PayerDeps, operationId: string, paymentRequest: string): Promise<number | undefined> {
  const operation = deps.store.operation(operationId);
  if (operation === undefined) return undefined;
  const recorded = deps.store.paymentForRequest(operationId, paymentRequest);
  if (operation.state === 'completed') {
    const paid = deps.store.paymentForOperation(operationId);
    if (paid?.state !== 'succeeded') return undefined;
    if (recorded === undefined) {
      emit({ event: 'intent-refused', operationId, reason: `operation ${operationId} is already completed` });
      return EXIT.refused;
    }
    emit({ event: 'already-recorded', operationId, paymentHash: paid.paymentHash, state: paid.state });
    return exitFor({ kind: 'succeeded', paymentHash: paid.paymentHash, feeMsat: paid.feeMsat ?? 0n });
  }
  if (recorded === undefined || recorded.state === 'intent') return undefined;
  if (recorded.state === 'failed') {
    emit({ event: 'already-recorded', operationId, paymentHash: recorded.paymentHash, state: recorded.state });
    return exitFor({ kind: 'failed', paymentHash: recorded.paymentHash, reason: recorded.failureReason ?? 'unknown' });
  }
  return exitFor(await reconcileOrReport(deps, recorded.paymentHash, recorded.state));
}

/** A repeated request for an operation that was already submitted is answered from LND, never by paying again. */
async function reconcileOrReport(deps: PayerDeps, paymentHash: string, state: string): Promise<PayOutcome> {
  emit({ event: 'already-submitted', paymentHash, state, action: 'reconcile with TrackPaymentV2; SendPaymentV2 is not called again' });
  return reconcile(deps, paymentHash, AbortSignal.timeout(30_000));
}

async function receiver(command: string, args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: {
    as: { type: 'string' }, order: { type: 'string' }, 'amount-msat': { type: 'string' }, hold: { type: 'boolean' },
    memo: { type: 'string' }, 'expiry-s': { type: 'string' }, 'settle-index': { type: 'string' }, 'add-index': { type: 'string' },
    'reconcile-interval-s': { type: 'string' }, lab: { type: 'string' },
  }, strict: true });
  const lab = loadLab(values.lab);
  const deps = openReceiver(lab, receiverProfile(required(values, 'as')));
  try {
    switch (command) {
      case 'create-invoice': {
        const orderId = identifier(required(values, 'order'), '--order');
        const amountMsat = parseAmount(required(values, 'amount-msat'), '--amount-msat');
        if (amountMsat === 0n) throw new UsageError('--amount-msat must be positive');
        const outcome = await createInvoice(deps, { orderId, amountMsat, hold: values.hold === true, memo: values.memo ?? orderId,
          expirySeconds: seconds(values, 'expiry-s', 3600) });
        emit({ event: 'outcome', ...outcome });
        return outcome.kind === 'created' ? EXIT.ok : outcome.kind === 'unresolved' ? EXIT.unresolved : EXIT.refused;
      }
      case 'settle': {
        const outcome = await settleHoldInvoice(deps, identifier(required(values, 'order'), '--order'));
        emit({ event: 'outcome', ...outcome });
        return outcome.kind === 'settled' ? EXIT.ok : outcome.kind === 'unresolved' ? EXIT.unresolved : EXIT.refused;
      }
      case 'cancel': {
        const outcome = await cancelHoldInvoice(deps, identifier(required(values, 'order'), '--order'));
        emit({ event: 'outcome', ...outcome });
        return outcome.kind === 'canceled' ? EXIT.ok : outcome.kind === 'unresolved' ? EXIT.unresolved : EXIT.refused;
      }
      case 'reconcile': {
        const result = await reconcileInvoices(deps, values.order === undefined ? undefined : identifier(values.order, '--order'));
        emit({ event: 'outcome', ...result });
        return result.unknown > 0 ? EXIT.unresolved : EXIT.ok;
      }
      case 'listen': {
        const interval = seconds(values, 'reconcile-interval-s', 10);
        await listen(deps, { reconcileIntervalMs: interval * 1000, signal: stopSignal() });
        emit({ event: 'stopped' });
        return EXIT.ok;
      }
      case 'cursor-set': {
        const settleIndex = parseAmount(required(values, 'settle-index'), '--settle-index');
        const addIndex = values['add-index'] === undefined ? 0n : parseAmount(values['add-index'], '--add-index');
        const before = deps.store.cursor();
        deps.store.setCursor(settleIndex, addIndex);
        emit({ event: 'cursor-set', before, after: deps.store.cursor() });
        return EXIT.ok;
      }
      case 'show': {
        const orderId = identifier(required(values, 'order'), '--order');
        // The preimage is the proof of payment; it is never printed.
        const invoices = deps.store.invoicesForOrder(orderId).map(item => ({ paymentHash: item.paymentHash, kind: item.kind,
          state: item.state, amountMsat: item.amountMsat, amtPaidMsat: item.amtPaidMsat, settleIndex: item.settleIndex,
          paymentRequest: item.paymentRequest }));
        emit({ event: 'order-record', order: deps.store.order(orderId) ?? null, invoices,
          deliveries: invoices.flatMap(item => deps.store.deliveries(item.paymentHash)),
          fulfillments: deps.store.fulfillmentCount(orderId), ledger: deps.store.ledger(orderId), cursor: deps.store.cursor() });
        return EXIT.ok;
      }
      default:
        throw new UsageError(`unknown receiver command ${command}`);
    }
  } finally {
    deps.store.close();
  }
}

async function analysis(command: string, args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: {
    node: { type: 'string' }, 'payment-hash': { type: 'string' }, payer: { type: 'string' }, operation: { type: 'string' },
    lab: { type: 'string' },
  }, strict: true });
  const lab = loadLab(values.lab);
  const read = readApi(lab, nodeName(required(values, 'node')));
  switch (command) {
    case 'payments': {
      const result = await paymentsForHash(read, assertHash(required(values, 'payment-hash')));
      emit({ event: 'payments-for-hash', count: result.payments.length, scanned: result.scanned, complete: result.complete,
        payments: result.payments });
      return EXIT.ok;
    }
    case 'diagnose': {
      const profile = payerProfile(required(values, 'payer'));
      const store = new PayerStore(databasePath(lab, PAYER_PROFILES[profile].database));
      try {
        const operationId = identifier(required(values, 'operation'), '--operation');
        const record = store.paymentForOperation(operationId);
        if (record === undefined) throw new UsageError(`operation ${operationId} has no payment`);
        const lnd = await paymentsForHash(read, record.paymentHash);
        const result = await diagnose(read, { amountMsat: record.amountMsat, destination: record.destination, payment: lnd.payments[0] });
        emit({ event: 'diagnosis', operationId, paymentHash: record.paymentHash, ...result });
        return EXIT.ok;
      } finally {
        store.close();
      }
    }
    default:
      throw new UsageError(`unknown analysis command ${command}`);
  }
}

const USAGE = `usage: node src/cli.ts <component> <command> [options]
  payer pay --as <customer-payer|merchant-refunds> --operation <id> --kind <order-payment|refund|payout>
            --invoice <bolt11> --fee-limit-msat <n> [--max-parts <n>] [--timeout-s <n>] [--budget <id>]
            [--wait-for-go] [--fault drop-stream-after-in-flight]
  payer retry --as <profile> --operation <id>
  payer reconcile --as <profile> [--payment-hash <hex>] [--timeout-s <n>]
  payer show --as <profile> --operation <id>
  payer budget-set --as <profile> --budget <id> --limit-msat <n>
  payer budget-show --as <profile> --budget <id>
  receiver create-invoice --as <merchant|customer> --order <id> --amount-msat <n> [--hold] [--memo <text>] [--expiry-s <n>]
  receiver settle|cancel|show --as <profile> --order <id>
  receiver reconcile --as <profile> [--order <id>]
  receiver listen --as <profile> [--reconcile-interval-s <n>]
  receiver cursor-set --as <profile> --settle-index <n> [--add-index <n>]
  analysis payments --node <customer|router|merchant> --payment-hash <hex>
  analysis diagnose --node <node> --payer <profile> --operation <id>
All commands accept --lab <dir> (default: the run named in runtime/current.json).`;

async function main(argv: string[]): Promise<number> {
  const [component, command, ...rest] = argv;
  try {
    if (component === undefined || command === undefined) throw new UsageError('component and command are required');
    if (component === 'payer') return await payer(command, rest);
    if (component === 'receiver') return await receiver(command, rest);
    if (component === 'analysis') return await analysis(command, rest);
    throw new UsageError(`unknown component ${component}`);
  } catch (error) {
    if (error instanceof UsageError || (error instanceof TypeError && 'code' in error && String(error.code).startsWith('ERR_PARSE_ARGS'))) {
      process.stderr.write(`${error.message}\n${USAGE}\n`);
      return EXIT.usage;
    }
    emit({ event: 'error', error: describeError(error) });
    return EXIT.error;
  }
}

process.exitCode = await main(process.argv.slice(2));
