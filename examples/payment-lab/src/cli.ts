import { mkdirSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import type { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { diagnose } from './analysis/diagnose.ts';
import { paymentsForHash } from './analysis/payments.ts';
import {
  NODE_NAMES, PAYER_PROFILES, RECEIVER_PROFILES, databasePath, invoiceApi, loadLab, payerApi, readApi,
  type Lab, type NodeName, type PayerProfile, type ReceiverProfile,
} from './config.ts';
import { verifyLedger, type LedgerStore, type LndLedgerSource } from './ledger/verify.ts';
import { explainCommand } from './explain/command.ts';
import { describeError } from './lnd/errors.ts';
import { labKey, type EffectTarget } from './outbox/effects.ts';
import { outboxStatus } from './outbox/outbox.ts';
import { runOutbox, runPass } from './outbox/worker.ts';
import { decodeInvoice, reconcile, recordIntent, submit, type Fault, type PayOutcome, type PayerDeps } from './payer/payer.ts';
import { PayerStore, type OperationKind, type PaymentRecord } from './payer/store.ts';
import { cancelHoldInvoice, createInvoice, listen, reconcileInvoices, settleHoldInvoice, type ReceiverDeps } from './receiver/receiver.ts';
import { ReceiverStore } from './receiver/store.ts';
import { bolt11PaymentHash, damagedPaymentRequest } from './util/bolt11.ts';
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
 * A payment's outcome maps to the same code whichever command learned it (pay,
 * retry, reconcile); for several payments (payer reconcile) the first of 75, 3,
 * 1 that applies to any of them, else 0.
 *
 * Arguments are validated before anything is recorded: a usage error never
 * leaves a durable change behind. An option the command does not take (one
 * another command takes included) is a usage error, before anything is opened.
 *
 * payer reconcile runs one outbox pass after its own, unless it was stopped
 * (SIGINT, SIGTERM or --timeout-s): it then reports outbox-pass-skipped.
 *
 * ledger-verify has its own reading of 0, 1 and 75: 0 the books balance and agree with
 * LND; 1 they do not (an unbalanced entry, a stored balance, the records or LND differ);
 * 75 they balance but LND could not be compared (no list call, an error, more pages than
 * the bound, or a payment or settlement the records have not learned yet).
 *
 * outbox-status exits 0, or 75 when a row is not done more than --deadline-s (default 300) after it
 * was enqueued. outbox-run --once exits 0 when every row is done after the pass, else 75 (a row
 * failed and is in backoff, or another worker holds it); without --once it runs until SIGINT or
 * SIGTERM and exits 0.
 *
 * explain (payer and receiver) exits 0 when the subject is in the records, 3 when it is not, and 4 when a
 * --refresh lookup failed (the explanation from the records is printed all the same, with a warning).
 */

const EXIT = { ok: 0, failed: 1, usage: 2, refused: 3, error: 4, unresolved: 75 } as const;

class UsageError extends Error {}

const bigintAsText = (_key: string, value: unknown): unknown => typeof value === 'bigint' ? value.toString() : value;

function emit(event: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify({ at: new Date().toISOString(), ...event }, bigintAsText)}\n`);
}

function required(values: Record<string, unknown>, name: string): string {
  const value = values[name];
  if (typeof value !== 'string' || value === '') throw new UsageError(`--${name} is required`);
  return value;
}

/**
 * An amount or index given on the command line: a malformed one, or one above 2^63 - 1 (more than SQLite
 * stores), is a usage error (exit 2), not an internal one.
 */
function amountArg(text: string, what: string): bigint {
  try { return parseAmount(text, what); } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
}

/** A payment hash given on the command line (see amountArg). */
function hashArg(value: string, what: string): string {
  try { return assertHash(value, what); } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
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

type Component = 'payer' | 'receiver' | 'analysis';

/** Options every command of a component takes: --lab, and --as for payer and receiver. */
const GLOBAL_OPTIONS: Record<Component, readonly string[]> = { payer: ['as', 'lab'], receiver: ['as', 'lab'], analysis: ['lab'] };

/**
 * The options each command takes besides the global ones, as USAGE lists them. A component's parseArgs knows the union of its
 * commands' options (it validates their values, strict); a flag that belongs to another command is refused here, before
 * anything is opened, rather than ignored.
 */
const COMMAND_OPTIONS: Record<Component, Readonly<Record<string, readonly string[]>>> = {
  payer: {
    pay: ['operation', 'kind', 'invoice', 'fee-limit-msat', 'max-parts', 'timeout-s', 'budget', 'wait-for-go', 'fault'],
    retry: ['operation', 'timeout-s'],
    reconcile: ['payment-hash', 'timeout-s'],
    show: ['operation'],
    'budget-set': ['budget', 'limit-msat'],
    'budget-show': ['budget'],
    'ledger-verify': ['json'],
    'outbox-run': ['once', 'interval-s'],
    'outbox-status': ['json', 'deadline-s'],
    explain: ['operation', 'payment-hash', 'json', 'refresh'],
  },
  receiver: {
    'create-invoice': ['order', 'amount-msat', 'hold', 'memo', 'expiry-s'],
    settle: ['order'],
    cancel: ['order'],
    show: ['order'],
    reconcile: ['order'],
    listen: ['reconcile-interval-s'],
    'cursor-set': ['settle-index', 'add-index'],
    'ledger-verify': ['json'],
    'outbox-run': ['once', 'interval-s'],
    'outbox-status': ['json', 'deadline-s'],
    explain: ['order', 'payment-hash', 'json', 'refresh'],
  },
  analysis: {
    payments: ['node', 'payment-hash'],
    diagnose: ['node', 'payer', 'operation'],
  },
};

/** A usage error for an unknown command, or for the first option given that the command does not take. */
function checkOptions(component: Component, command: string, tokens: readonly { kind: string; name?: string }[]): void {
  const table = COMMAND_OPTIONS[component];
  const allowed = Object.hasOwn(table, command) ? table[command] : undefined;
  if (allowed === undefined) throw new UsageError(`unknown ${component} command ${command}`);
  for (const token of tokens) {
    if (token.kind !== 'option' || token.name === undefined) continue;
    if (!GLOBAL_OPTIONS[component].includes(token.name) && !allowed.includes(token.name)) {
      throw new UsageError(`unknown option --${token.name} for ${component} ${command}`);
    }
  }
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

/** How main opens a profile's records and node API; the regression tests pass in-memory stand-ins. */
export interface Services {
  payer(labDir: string | undefined, profile: PayerProfile): PayerDeps;
  receiver(labDir: string | undefined, profile: ReceiverProfile): ReceiverDeps;
  /**
   * What ledger-verify compares with: ListPayments for a payer (its pay-only credential cannot
   * list payments, so the lab reads them with its node's read-only credential), ListInvoices for
   * a receiver (undefined: the profile's own invoice-only API, which has invoices:read).
   */
  ledgerSource?(labDir: string | undefined, component: 'payer' | 'receiver', profile: string): LndLedgerSource | undefined;
  /**
   * Where the outbox worker writes its effects and the HMAC key it signs them with: `<lab>/receipts`
   * (receiver) or `<lab>/confirmations` (payer), and the lab's `outbox.key`. Undefined: no worker runs
   * (`payer reconcile` and `receiver listen` skip it; `outbox-run` is a configuration error).
   */
  outbox?(labDir: string | undefined, component: 'payer' | 'receiver'): EffectTarget | undefined;
}

const LAB_SERVICES: Services = {
  payer: (labDir, profile) => openPayer(loadLab(labDir), profile),
  receiver: (labDir, profile) => openReceiver(loadLab(labDir), profile),
  ledgerSource: (labDir, component, profile) => {
    if (component !== 'payer') return undefined;
    const lab = loadLab(labDir);
    const credential = lab.manifest.credentials[PAYER_PROFILES[profile as PayerProfile].credential];
    if (credential === undefined) throw new Error(`unknown credential for payer profile ${profile}`);
    return readApi(lab, credential.node);
  },
  outbox: (labDir, component) => {
    const lab = loadLab(labDir);
    return { dir: join(lab.dir, component === 'receiver' ? 'receipts' : 'confirmations'), key: labKey(lab.dir) };
  },
};

function outboxTarget(services: Services, labDir: string | undefined, component: 'payer' | 'receiver'): EffectTarget {
  const target = services.outbox?.(labDir, component);
  if (target === undefined) throw new Error(`no outbox target for the ${component}: this service has no lab directory`);
  return target;
}

/** One worker pass after another command's own work (payer reconcile, the listener); a failure is reported, not raised. */
function outboxPassAfter(services: Services, labDir: string | undefined, component: 'payer' | 'receiver', db: DatabaseSync): void {
  try {
    const target = services.outbox?.(labDir, component);
    if (target !== undefined) emit({ event: 'outbox-pass', ...runPass(db, target, { emit }) });
  } catch (error) {
    emit({ event: 'outbox-pass-failed', error: describeError(error) });
  }
}

/** outbox-run: passes over the due rows, once or every --interval-s until stopped (exit codes in the header). */
async function outboxRun(services: Services, values: Record<string, unknown>, component: 'payer' | 'receiver', db: DatabaseSync): Promise<number> {
  const once = values.once === true;
  const intervalMs = seconds(values, 'interval-s', 5) * 1000;
  const target = outboxTarget(services, values.lab as string | undefined, component);
  const result = await runOutbox(db, target, { emit, once, intervalMs, signal: once ? new AbortController().signal : stopSignal() });
  return once && result.remaining > 0 ? EXIT.unresolved : EXIT.ok;
}

/** outbox-status: counts per state and the oldest pending age, as an event or one JSON object with --json. */
function outboxStatusCommand(values: Record<string, unknown>, db: DatabaseSync): number {
  const status = outboxStatus(db, Date.now(), seconds(values, 'deadline-s', 300));
  if (values.json === true) process.stdout.write(`${JSON.stringify(status)}\n`);
  else emit({ event: 'outbox-status', ...status });
  return status.overdueCount > 0 ? EXIT.unresolved : EXIT.ok;
}

/** ledger-verify: the report as events (or one JSON object with --json) and the exit code (see the header). */
async function ledgerVerify(store: LedgerStore, source: LndLedgerSource | undefined, json: boolean): Promise<number> {
  const result = await verifyLedger(store, source);
  if (json) {
    process.stdout.write(`${JSON.stringify(result, bigintAsText)}\n`);
  } else {
    for (const account of result.accounts) emit({ event: 'ledger-account', ...account });
    emit({ event: 'ledger-verify', book: result.book, balanced: result.balanced, entries: result.entries,
      unbalancedEntries: result.unbalancedEntries, invalidEntries: result.invalidEntries, lnd: result.lnd, lndDetail: result.lndDetail,
      firstDifference: result.firstDifference });
  }
  if (!result.balanced) return EXIT.failed;
  return result.lnd === 'compared' ? EXIT.ok : EXIT.unresolved;
}

function codeFor(outcome: PayOutcome): number {
  switch (outcome.kind) {
    case 'succeeded': return EXIT.ok;
    case 'failed': return EXIT.failed;
    case 'refused': return EXIT.refused;
    case 'not-submitted': return EXIT.unresolved;
    case 'unresolved': return EXIT.unresolved;
  }
}

function exitFor(outcome: PayOutcome): number {
  emit({ event: 'outcome', ...outcome });
  return codeFor(outcome);
}

/** Several payments' outcomes (payer reconcile): unresolved before refused before failed before done. */
function exitForAll(outcomes: PayOutcome[]): number {
  for (const outcome of outcomes) emit({ event: 'outcome', ...outcome });
  const codes = new Set(outcomes.map(codeFor));
  return [EXIT.unresolved, EXIT.refused, EXIT.failed].find(code => codes.has(code)) ?? EXIT.ok;
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

/** explain's subject: exactly one of --<idOption> and --payment-hash (a usage error otherwise). */
function explainSubject(values: Record<string, unknown>, idOption: 'operation' | 'order'): { id?: string; paymentHash?: string } {
  const id = values[idOption];
  const hash = values['payment-hash'];
  if ((id === undefined) === (hash === undefined)) throw new UsageError(`explain needs exactly one of --${idOption} and --payment-hash`);
  if (typeof hash === 'string') return { paymentHash: hashArg(hash, '--payment-hash').toLowerCase() };
  return { id: identifier(required(values, idOption), `--${idOption}`) };
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
    journal: deps.store.journal(operationId),
    events: payment === undefined ? [] : deps.store.events(payment.paymentHash),
    budget: operation?.budgetId === undefined ? null : deps.store.budgetStatus(operation.budgetId) ?? null,
    outbox: deps.store.outbox(operationId),
  });
}

async function payer(command: string, args: string[], services: Services): Promise<number> {
  const { values, tokens } = parseArgs({ args, options: {
    as: { type: 'string' }, operation: { type: 'string' }, kind: { type: 'string' }, invoice: { type: 'string' },
    'fee-limit-msat': { type: 'string' }, 'max-parts': { type: 'string' }, 'timeout-s': { type: 'string' }, budget: { type: 'string' },
    'limit-msat': { type: 'string' }, 'payment-hash': { type: 'string' }, fault: { type: 'string' }, 'wait-for-go': { type: 'boolean' },
    lab: { type: 'string' }, json: { type: 'boolean' }, once: { type: 'boolean' }, 'interval-s': { type: 'string' },
    'deadline-s': { type: 'string' }, refresh: { type: 'boolean' },
  }, strict: true, tokens: true });
  checkOptions('payer', command, tokens);
  const profile = payerProfile(required(values, 'as'));
  const deps = services.payer(values.lab, profile);
  try {
    switch (command) {
      case 'pay': {
        const operationId = identifier(required(values, 'operation'), '--operation');
        const kind = required(values, 'kind');
        if (!['order-payment', 'refund', 'payout'].includes(kind)) throw new UsageError('--kind must be order-payment, refund or payout');
        const feeLimitMsat = amountArg(required(values, 'fee-limit-msat'), '--fee-limit-msat');
        const maxParts = values['max-parts'] === undefined ? 16 : Number(amountArg(values['max-parts'], '--max-parts'));
        if (maxParts < 1 || maxParts > 128) throw new UsageError('--max-parts must be 1 to 128');
        const fault = (values.fault ?? 'none') as Fault;
        if (fault !== 'none' && fault !== 'drop-stream-after-in-flight') throw new UsageError('--fault must be drop-stream-after-in-flight');
        const budgetId = values.budget === undefined ? undefined : identifier(values.budget, '--budget');
        const timeoutSeconds = seconds(values, 'timeout-s', 60);
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
        return exitFor(await submit(deps, intent.payment.paymentHash, { timeoutSeconds, fault, signal }));
      }
      case 'retry': {
        const operationId = identifier(required(values, 'operation'), '--operation');
        const timeoutSeconds = seconds(values, 'timeout-s', 60);
        const prepared = deps.store.prepareRetry(operationId);
        if (prepared.outcome !== 'recorded') {
          emit({ event: 'retry-refused', operationId, reason: prepared.outcome === 'refused' ? prepared.reason : 'unexpected' });
          return EXIT.refused;
        }
        emit({ event: 'retry-prepared', operationId, paymentHash: prepared.payment.paymentHash });
        return exitFor(await submit(deps, prepared.payment.paymentHash, { timeoutSeconds, fault: 'none', signal: stopSignal() }));
      }
      case 'reconcile': {
        const timeoutSeconds = values['timeout-s'] === undefined ? undefined : seconds(values, 'timeout-s', 60);
        const targets = values['payment-hash'] === undefined
          ? deps.store.unresolvedPayments().map(item => item.paymentHash)
          : [hashArg(values['payment-hash'], '--payment-hash')];
        const signal = stopSignal(timeoutSeconds);
        emit({ event: 'reconcile-started', payments: targets.length });
        const outcomes = await Promise.all(targets.map(hash => reconcile(deps, hash, signal)));
        // Then the effects of operations completed so far (this pass's and earlier ones'); they do not change the exit code.
        // Not once stopped (SIGINT, SIGTERM, --timeout-s), as the listener does not: stopping means stop.
        if (signal.aborted) emit({ event: 'outbox-pass-skipped', reason: 'reconcile was stopped' });
        else outboxPassAfter(services, values.lab, 'payer', deps.store.db);
        return exitForAll(outcomes);
      }
      case 'show':
        showPayment(deps, identifier(required(values, 'operation'), '--operation'));
        return EXIT.ok;
      case 'budget-set': {
        const budgetId = identifier(required(values, 'budget'), '--budget');
        deps.store.setBudget(budgetId, amountArg(required(values, 'limit-msat'), '--limit-msat'));
        emit({ event: 'budget', ...deps.store.budgetStatus(budgetId) });
        return EXIT.ok;
      }
      case 'budget-show': {
        const budgetId = identifier(required(values, 'budget'), '--budget');
        emit({ event: 'budget', status: deps.store.budgetStatus(budgetId) ?? null, refusals: deps.store.refusals(budgetId) });
        return EXIT.ok;
      }
      case 'ledger-verify':
        return await ledgerVerify(deps.store, services.ledgerSource?.(values.lab, 'payer', profile) ?? {}, values.json === true);
      case 'outbox-run':
        return await outboxRun(services, values, 'payer', deps.store.db);
      case 'outbox-status':
        return outboxStatusCommand(values, deps.store.db);
      case 'explain': {
        const subject = explainSubject(values, 'operation');
        return await explainCommand({ component: 'payer', store: deps.store, api: deps.api,
          subject: { operationId: subject.id, paymentHash: subject.paymentHash } }, { json: values.json === true, refresh: values.refresh === true });
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
 *
 * "An invoice it recorded" is matched by payment hash when the invoice decodes
 * offline (bolt11.ts), else by text compared case-insensitively: BOLT11 is
 * case-insensitive, and QR codes carry invoices in upper case. If a completed
 * operation's stored invoice is damaged, the invoice given cannot be compared
 * with it as text; it is then read with DecodePayReq (a read, nothing is sent)
 * and matched by hash, and a refusal says the record is damaged.
 */
async function answerFromRecord(deps: PayerDeps, operationId: string, paymentRequest: string): Promise<number | undefined> {
  const operation = deps.store.operation(operationId);
  if (operation === undefined) return undefined;
  const recorded = recordedPayment(deps, operationId, paymentRequest);
  if (operation.state === 'completed') {
    const paid = deps.store.paymentForOperation(operationId);
    if (paid?.state !== 'succeeded') return undefined;
    if (recorded === undefined) {
      const damaged = deps.store.paymentsForOperation(operationId).filter(item => damagedPaymentRequest(item.paymentRequest));
      if (damaged.length === 0) {
        emit({ event: 'intent-refused', operationId, reason: `operation ${operationId} is already completed` });
        return EXIT.refused;
      }
      const hash = await paymentHashFromLnd(deps, paymentRequest);
      const match = hash === undefined ? undefined : deps.store.payment(hash);
      if (match?.operationId !== operationId) {
        emit({ event: 'intent-refused', operationId, reason: `operation ${operationId} is completed (payment ${paid.paymentHash}), but the stored `
          + `invoice of payment ${damaged.map(item => item.paymentHash).join(', ')} is damaged, so the invoice given could not be compared with it as text; `
          + (hash === undefined ? 'DecodePayReq could not read the invoice given either'
            : `the invoice given is for payment hash ${hash}, which this operation never recorded`)
          + '; inspect the record with "payer show"' });
        return EXIT.refused;
      }
      emit({ event: 'stored-invoice-damaged', operationId, paymentHashes: damaged.map(item => item.paymentHash),
        matchedBy: 'payment hash from DecodePayReq' });
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

/** The operation's payment for this invoice: by payment hash when it decodes offline, else by case-insensitive text. */
function recordedPayment(deps: PayerDeps, operationId: string, paymentRequest: string): PaymentRecord | undefined {
  const hash = bolt11PaymentHash(paymentRequest);
  const byHash = hash === undefined ? undefined : deps.store.payment(hash);
  if (byHash?.operationId === operationId) return byHash;
  return deps.store.paymentForRequest(operationId, paymentRequest);
}

/** The payment hash LND reads from an invoice, or undefined. DecodePayReq only reads; expiry does not matter here. */
async function paymentHashFromLnd(deps: PayerDeps, paymentRequest: string): Promise<string | undefined> {
  try {
    return (await deps.api.decodePayReq(paymentRequest)).paymentHash;
  } catch {
    return undefined;
  }
}

/** A repeated request for an operation that was already submitted is answered from LND, never by paying again. */
async function reconcileOrReport(deps: PayerDeps, paymentHash: string, state: string): Promise<PayOutcome> {
  emit({ event: 'already-submitted', paymentHash, state, action: 'reconcile with TrackPaymentV2; SendPaymentV2 is not called again' });
  return reconcile(deps, paymentHash, AbortSignal.timeout(30_000));
}

async function receiver(command: string, args: string[], services: Services): Promise<number> {
  const { values, tokens } = parseArgs({ args, options: {
    as: { type: 'string' }, order: { type: 'string' }, 'amount-msat': { type: 'string' }, hold: { type: 'boolean' },
    memo: { type: 'string' }, 'expiry-s': { type: 'string' }, 'settle-index': { type: 'string' }, 'add-index': { type: 'string' },
    'reconcile-interval-s': { type: 'string' }, lab: { type: 'string' }, json: { type: 'boolean' }, once: { type: 'boolean' },
    'interval-s': { type: 'string' }, 'deadline-s': { type: 'string' }, 'payment-hash': { type: 'string' }, refresh: { type: 'boolean' },
  }, strict: true, tokens: true });
  checkOptions('receiver', command, tokens);
  const profile = receiverProfile(required(values, 'as'));
  const deps = services.receiver(values.lab, profile);
  try {
    switch (command) {
      case 'create-invoice': {
        const orderId = identifier(required(values, 'order'), '--order');
        const amountMsat = amountArg(required(values, 'amount-msat'), '--amount-msat');
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
        const result = await reconcileInvoices(deps, values.order === undefined ? undefined : identifier(values.order, '--order'),
          stopSignal());
        emit({ event: 'outcome', ...result });
        return result.unknown > 0 ? EXIT.unresolved : EXIT.ok;
      }
      case 'listen': {
        const interval = seconds(values, 'reconcile-interval-s', 10);
        // The outbox worker runs after every reconciliation pass (and so once at start).
        await listen(deps, { reconcileIntervalMs: interval * 1000, signal: stopSignal(),
          afterReconcile: () => { outboxPassAfter(services, values.lab, 'receiver', deps.store.db); } });
        emit({ event: 'stopped' });
        return EXIT.ok;
      }
      case 'cursor-set': {
        const settleIndex = amountArg(required(values, 'settle-index'), '--settle-index');
        const addIndex = values['add-index'] === undefined ? 0n : amountArg(values['add-index'], '--add-index');
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
          fulfillments: deps.store.fulfillmentCount(orderId), outbox: deps.store.outbox(orderId), ledger: deps.store.ledger(orderId), journal: deps.store.journal(orderId),
          cursor: deps.store.cursor() });
        return EXIT.ok;
      }
      case 'ledger-verify':
        return await ledgerVerify(deps.store, services.ledgerSource?.(values.lab, 'receiver', profile) ?? deps.api, values.json === true);
      case 'outbox-run':
        return await outboxRun(services, values, 'receiver', deps.store.db);
      case 'outbox-status':
        return outboxStatusCommand(values, deps.store.db);
      case 'explain': {
        const subject = explainSubject(values, 'order');
        return await explainCommand({ component: 'receiver', store: deps.store, api: deps.api,
          subject: { orderId: subject.id, paymentHash: subject.paymentHash } }, { json: values.json === true, refresh: values.refresh === true });
      }
      default:
        throw new UsageError(`unknown receiver command ${command}`);
    }
  } finally {
    deps.store.close();
  }
}

async function analysis(command: string, args: string[]): Promise<number> {
  const { values, tokens } = parseArgs({ args, options: {
    node: { type: 'string' }, 'payment-hash': { type: 'string' }, payer: { type: 'string' }, operation: { type: 'string' },
    lab: { type: 'string' },
  }, strict: true, tokens: true });
  checkOptions('analysis', command, tokens);
  const lab = loadLab(values.lab);
  const read = readApi(lab, nodeName(required(values, 'node')));
  switch (command) {
    case 'payments': {
      const result = await paymentsForHash(read, hashArg(required(values, 'payment-hash'), '--payment-hash'));
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
  payer retry --as <profile> --operation <id> [--timeout-s <n>]
  payer reconcile --as <profile> [--payment-hash <hex>] [--timeout-s <n>]
  payer show --as <profile> --operation <id>
  payer budget-set --as <profile> --budget <id> --limit-msat <n>
  payer budget-show --as <profile> --budget <id>
  payer ledger-verify --as <profile> [--json]
  payer outbox-run --as <profile> [--once] [--interval-s <n>]
  payer outbox-status --as <profile> [--json] [--deadline-s <n>]
  payer explain --as <profile> --operation <id> | --payment-hash <hex> [--json] [--refresh]
  receiver create-invoice --as <merchant|customer> --order <id> --amount-msat <n> [--hold] [--memo <text>] [--expiry-s <n>]
  receiver settle|cancel|show --as <profile> --order <id>
  receiver reconcile --as <profile> [--order <id>]
  receiver listen --as <profile> [--reconcile-interval-s <n>]
  receiver cursor-set --as <profile> --settle-index <n> [--add-index <n>]
  receiver ledger-verify --as <profile> [--json]
  receiver outbox-run --as <profile> [--once] [--interval-s <n>]
  receiver outbox-status --as <profile> [--json] [--deadline-s <n>]
  receiver explain --as <profile> --order <id> | --payment-hash <hex> [--json] [--refresh]
  analysis payments --node <customer|router|merchant> --payment-hash <hex>
  analysis diagnose --node <node> --payer <profile> --operation <id>
All commands accept --lab <dir> (default: the run named in runtime/current.json); otherwise a command takes only
the options listed for it, and any other is a usage error.`;

export async function main(argv: string[], services: Services = LAB_SERVICES): Promise<number> {
  const [component, command, ...rest] = argv;
  try {
    if (component === undefined || command === undefined) throw new UsageError('component and command are required');
    if (component === 'payer') return await payer(command, rest, services);
    if (component === 'receiver') return await receiver(command, rest, services);
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

/** True when this file is the program Node was started with (`node src/cli.ts`), not a module a test imports. */
function isEntryPoint(): boolean {
  const script = process.argv[1];
  if (script === undefined) return false;
  try { return pathToFileURL(realpathSync(script)).href === import.meta.url; } catch { return false; }
}

if (isEntryPoint()) process.exitCode = await main(process.argv.slice(2));
