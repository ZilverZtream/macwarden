import type { PayerStore, PaymentRecord } from '../payer/store.ts';
import { int, optionalInt, optionalText, text, type Row } from '../store/sqlite.ts';
import { fingerprint } from './format.ts';
import { decisions, journalLine, journalView, LIMITS, outboxItems, outboxView, Timeline, type Explanation } from './model.ts';
import type { RuleId } from './rules.ts';

/**
 * `payer explain`: one operation's story from the payer's records. The operation, each payment's
 * intent, submissions with LND's updates and HTLC attempts, reverts, stale updates, retries, the
 * outcome, the budget reservations, the journal and the outbox, each decision with the README rule
 * that made it. Nothing here writes, and nothing reads a preimage or a payment request column.
 */

interface AttemptRow {
  attemptId: string; submission: number; status: string; principalMsat: bigint; feeMsat: bigint; hops: number;
  failureCode: string | undefined; failureSourceIndex: bigint | undefined; attemptTimeNs: bigint;
}

function attempts(store: PayerStore, paymentHash: string): AttemptRow[] {
  return store.db.prepare(`SELECT attempt_id, submission, status, principal_msat, fee_msat, hops, failure_code, failure_source_index,
      attempt_time_ns FROM htlc_attempts WHERE payment_hash = ? ORDER BY submission, attempt_time_ns, CAST(attempt_id AS INTEGER)`).all(paymentHash)
    .map((row: Row) => ({ attemptId: text(row, 'attempt_id'), submission: Math.max(1, Number(int(row, 'submission'))), status: text(row, 'status'),
      principalMsat: int(row, 'principal_msat'), feeMsat: int(row, 'fee_msat'), hops: Number(int(row, 'hops')),
      failureCode: optionalText(row, 'failure_code'), failureSourceIndex: optionalInt(row, 'failure_source_index'),
      attemptTimeNs: int(row, 'attempt_time_ns') }));
}

function attemptDetail(item: AttemptRow): string {
  const failure = item.status === 'FAILED'
    ? `; failure ${item.failureCode ?? 'unknown'}${item.failureSourceIndex === undefined ? '' : ` from hop index ${item.failureSourceIndex}`}` : '';
  return `HTLC attempt ${item.attemptId} (submission ${item.submission}): ${item.status}, route of ${item.hops} hop(s), `
    + `${item.principalMsat} msat, fee ${item.feeMsat} msat${failure}`;
}

function parseDetail(detail: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(detail);
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

const str = (value: unknown): string => (value === null || value === undefined ? 'none' : typeof value === 'string' ? value : JSON.stringify(value));

/** Kinds after which the attempts of the submission so far are shown: its end, or the next one's start. */
const ENDS_SUBMISSION = new Set(['submit', 'retry-prepared', 'succeeded', 'failed', 'withdrawn', 'not-initiated', 'uncertain']);

function paymentItems(timeline: Timeline, store: PayerStore, payment: PaymentRecord): void {
  const fp = fingerprint(payment.paymentHash);
  const pending = attempts(store, payment.paymentHash);
  const perSubmission = new Map<number, number>();
  for (const item of pending) perSubmission.set(item.submission, (perSubmission.get(item.submission) ?? 0) + 1);
  let next = 0;
  let current = 0;
  let index = 0;
  let submission = 0;
  let lastAt = payment.createdAt;
  // A submission's attempts, at most LIMITS.attemptsPerSubmission: the first and last halves, and one item counting the rest.
  const flush = (upTo: number): void => {
    const half = LIMITS.attemptsPerSubmission / 2;
    while (next < pending.length && (pending[next] as AttemptRow).submission <= upTo) {
      const item = pending[next] as AttemptRow;
      next += 1;
      if (item.submission !== current) {
        current = item.submission;
        index = 0;
      }
      const total = perSubmission.get(current) ?? 0;
      if (total <= LIMITS.attemptsPerSubmission || index < half || index >= total - half) {
        timeline.add(lastAt, 'htlc-attempt', `${fp} ${attemptDetail(item)}`);
      } else if (index === half) {
        const omitted = total - LIMITS.attemptsPerSubmission;
        timeline.omit('htlcAttempts', omitted);
        timeline.add(lastAt, 'htlc-attempt', `${fp} ${omitted} more HTLC attempt(s) of submission ${current} not shown (the first ${half} and `
          + `the last ${half} are)`);
      }
      index += 1;
    }
  };
  for (const event of store.events(payment.paymentHash)) {
    const detail = parseDetail(event.detail);
    if (ENDS_SUBMISSION.has(event.kind)) flush(submission);
    lastAt = event.at;
    const add = (kind: string, text: string, rule?: RuleId): void => timeline.add(event.at, kind, `${fp} ${text}`, rule);
    switch (event.kind) {
      case 'intent-recorded':
        add('intent', `intent recorded for operation ${str(detail.operationId)}: ${str(detail.amountMsat)} msat, fee limit `
          + `${str(detail.feeLimitMsat)} msat${detail.budgetId === null || detail.budgetId === undefined ? '' : `, budget ${str(detail.budgetId)}`}; `
          + 'committed before anything was sent', 'durableIntent');
        break;
      case 'submit':
        submission += 1;
        add('submission', `submission ${submission}: claimed intent -> submitting, then SendPaymentV2`, 'compareAndSet');
        break;
      case 'in-flight':
        add('lnd-update', `${str(detail.source)}: ${str(detail.status)} with ${str(detail.htlcAttempts)} HTLC attempt(s) -> record in_flight; `
          + 'unresolved: operation open, reservation held', 'unresolved');
        break;
      case 'uncertain':
        add('uncertain', `connection lost before a terminal state (${str(detail.reason)}) -> record uncertain; only TrackPaymentV2 resolves it`,
          'timeout');
        break;
      case 'track-interrupted':
        add('track-interrupted', `TrackPaymentV2 interrupted (${str(detail.error)}); tried again, the record is unchanged`, 'timeout');
        break;
      case 'not-initiated':
        add('revert', `LND has no payment for the hash and this submission has no HTLC attempt (${str(detail.evidence)}) -> back to intent, `
          + 'same payment hash; the submission stays open', 'timeout');
        break;
      case 'not-found-after-attempts':
        add('not-found-after-attempts', `LND answered NotFound although this submission recorded HTLC attempts (${str(detail.evidence)}); `
          + 'the record stays unresolved for an operator', 'timeout');
        break;
      case 'stale-update': {
        const what = detail.kind === 'update' ? `${str(detail.source)} ${str(detail.status)}`
          : `${str(detail.kind)}${detail.reason === undefined ? '' : ` (${str(detail.reason)})`}${detail.evidence === undefined ? '' : ` (${str(detail.evidence)})`}`;
        add('stale-update', `ignored ${what} read for submission ${str(detail.readForSubmission)}: superseded (current submission `
          + `${str(detail.currentSubmission)}, closed up to ${str(detail.closedSubmission)}, record ${str(detail.recordState)}); `
          + 'neither the payment nor its reservation changed', 'compareAndSet');
        break;
      }
      case 'retry-prepared':
        add('retry', `payer retry after ${str(detail.previousFailure)}: submission ${submission} closed, record back to intent, `
          + 'same invoice and payment hash', 'compareAndSet');
        break;
      case 'failed': {
        const reason = str(detail.reason);
        add('failed', reason.startsWith('REJECTED_BEFORE_INITIATION')
          ? `SendPaymentV2 refused definitely and LND has no payment for the hash (${reason}) -> record failed, reservation released`
          : `LND reported the payment failed (${reason}) -> record failed, operation failed, reservation released`,
        reason.startsWith('REJECTED_BEFORE_INITIATION') ? 'timeout' : 'unresolved');
        break;
      }
      case 'succeeded':
        add('succeeded', `${str(detail.source)}: SUCCEEDED, value ${str(detail.valueMsat)} msat, fee ${str(detail.feeMsat)} msat, `
          + `${str(detail.htlcAttempts)} HTLC attempt(s) (${str(detail.succeededAttempts)} succeeded) -> record succeeded, posted from LND's numbers`,
        'accounting');
        break;
      case 'success-after-failure':
        add('success-after-failure', `${str(detail.source)} reported SUCCEEDED for a payment recorded failed: recorded, because the money left`,
          'unresolved');
        break;
      case 'amount-mismatch':
        add('amount-mismatch', `LND's value ${str(detail.lndValueMsat)} msat differs from the recorded ${str(detail.expectedMsat)} msat; `
          + 'LND\'s value is posted', 'accounting');
        break;
      case 'withdrawn':
        add('withdrawn', `withdrawn, never sent: operation paid by ${fingerprint(str(detail.paidBy))}; failed WITHDRAWN, reservation released`,
          'unresolved');
        break;
      case 'possible-double-payment':
      case 'double-payment':
        add(event.kind, `${event.kind === 'double-payment' ? 'both payments succeeded' : 'another payment may have been sent'}: `
          + `${fingerprint(str(detail.succeeded))} succeeded, ${fingerprint(str(detail.other))} was ${str(detail.otherState)}`, 'unresolved');
        break;
      default:
        add('event', `${event.kind}: ${event.detail}`);
    }
  }
  flush(Number.MAX_SAFE_INTEGER);
}

interface ReservationRow {
  reservationId: bigint; budgetId: string; paymentHash: string; principalMsat: bigint; allowanceMsat: bigint; state: string;
  actualFeeMsat: bigint | undefined; createdAt: string; updatedAt: string;
}

function reservations(store: PayerStore, operationId: string): ReservationRow[] {
  return store.db.prepare(`SELECT reservation_id, budget_id, payment_hash, principal_msat, fee_allowance_msat, state, actual_fee_msat,
      created_at, updated_at FROM reservations WHERE operation_id = ? ORDER BY reservation_id`).all(operationId)
    .map((row: Row) => ({ reservationId: int(row, 'reservation_id'), budgetId: text(row, 'budget_id'), paymentHash: text(row, 'payment_hash'),
      principalMsat: int(row, 'principal_msat'), allowanceMsat: int(row, 'fee_allowance_msat'), state: text(row, 'state'),
      actualFeeMsat: optionalInt(row, 'actual_fee_msat'), createdAt: text(row, 'created_at'), updatedAt: text(row, 'updated_at') }));
}

function refusals(store: PayerStore, operationId: string): { budgetId: string; paymentHash: string; requestedMsat: bigint; availableMsat: bigint; at: string }[] {
  return store.db.prepare(`SELECT budget_id, payment_hash, requested_msat, available_msat, at FROM budget_refusals WHERE operation_id = ?
      ORDER BY refusal_id`).all(operationId)
    .map((row: Row) => ({ budgetId: text(row, 'budget_id'), paymentHash: text(row, 'payment_hash'), requestedMsat: int(row, 'requested_msat'),
      availableMsat: int(row, 'available_msat'), at: text(row, 'at') }));
}

/** The operation the subject names, or undefined when the records have no such operation or payment. */
export function resolvePayerSubject(store: PayerStore, subject: { operationId?: string; paymentHash?: string }): string | undefined {
  if (subject.paymentHash !== undefined) return store.payment(subject.paymentHash.toLowerCase())?.operationId;
  return subject.operationId !== undefined && store.operation(subject.operationId) !== undefined ? subject.operationId : undefined;
}

export function explainPayer(store: PayerStore, operationId: string): Explanation {
  const row = store.db.prepare('SELECT kind, amount_msat, state, budget_id, created_at, completed_at FROM operations WHERE operation_id = ?')
    .get(operationId);
  if (row === undefined) throw new Error(`no operation ${operationId}`);
  const operation = { operationId, kind: text(row, 'kind'), amountMsat: int(row, 'amount_msat').toString(), state: text(row, 'state'),
    budgetId: optionalText(row, 'budget_id') ?? null, createdAt: text(row, 'created_at'), completedAt: optionalText(row, 'completed_at') ?? null };
  const payments = store.paymentsForOperation(operationId);
  // The subject's own ID is fingerprinted like its payment hashes when it is 64 hex.
  const known = new Set([...payments.map(item => item.paymentHash.toLowerCase()), operationId.toLowerCase()]);
  const timeline = new Timeline(known);
  timeline.add(operation.createdAt, 'operation', `operation ${operationId} (${operation.kind}) for ${operation.amountMsat} msat recorded`
    + `${operation.budgetId === null ? '' : `, budget ${operation.budgetId}`}`);
  for (const payment of payments) paymentItems(timeline, store, payment);

  const held = reservations(store, operationId);
  const journal = journalView(store.journal(operationId), known);
  // The first entry per (event, reference), indexed once: a lookup per reservation stays constant time.
  const firstPosted = new Map<string, string>();
  for (const entry of journal) {
    const key = JSON.stringify([entry.event, entry.reference]);
    if (!firstPosted.has(key)) firstPosted.set(key, entry.postedAt);
  }
  const postedAt = (event: string, reference: string): string | undefined => firstPosted.get(JSON.stringify([event, reference]));
  for (const item of held) {
    const fp = fingerprint(item.paymentHash);
    const reference = `reservation:${item.reservationId}`;
    timeline.add(item.createdAt, 'reservation-held', `${fp} reservation #${item.reservationId} on budget ${item.budgetId} held: `
      + `principal ${item.principalMsat} + fee allowance ${item.allowanceMsat} = ${item.principalMsat + item.allowanceMsat} msat`, 'reservations');
    const released = postedAt('budget-released', reference);
    if (released !== undefined || item.state === 'released') {
      timeline.add(released ?? item.updatedAt, 'reservation-released', `${fp} reservation #${item.reservationId} released: `
        + `${item.principalMsat + item.allowanceMsat} msat available again`, 'reservations');
    }
    if (item.state === 'consumed') {
      const fee = item.actualFeeMsat ?? 0n;
      timeline.add(postedAt('budget-consumed', reference) ?? item.updatedAt, 'reservation-consumed', `${fp} reservation #${item.reservationId} `
        + `consumed at principal ${item.principalMsat} + actual fee ${fee} = ${item.principalMsat + fee} msat`
        + (released === undefined ? `; ${item.allowanceMsat - fee} msat of the allowance released` : ' (after a recorded failure had released it)'),
      'reservations');
    }
  }
  const refused = refusals(store, operationId);
  for (const item of refused) {
    timeline.add(item.at, 'budget-refused', `${fingerprint(item.paymentHash)} refused by budget ${item.budgetId}: requested ${item.requestedMsat} msat, `
      + `available ${item.availableMsat} msat; nothing recorded or sent`, 'reservations');
  }
  for (const entry of journal) {
    const rule: RuleId = entry.event === 'payment-succeeded' ? 'accounting' : entry.event === 'double-payment' ? 'unresolved' : 'reservations';
    timeline.add(entry.postedAt, 'journal', journalLine(entry), rule);
  }
  const outbox = outboxView(store.outbox(operationId), known);
  outboxItems(timeline, outbox);

  const succeeded = payments.filter(item => item.state === 'succeeded');
  const live = payments.filter(item => ['intent', 'submitting', 'in_flight', 'uncertain'].includes(item.state));
  const last = payments.at(-1);
  const summary = operation.state === 'completed'
    ? `operation completed: ${succeeded.map(item => `${fingerprint(item.paymentHash)} succeeded, value ${item.valueMsat ?? 0n} msat, fee ${item.feeMsat ?? 0n} msat`).join('; ')}`
      + (succeeded.length > 1 ? ' (double payment)' : '')
    : live.length > 0
      ? `operation open: ${live.map(item => `${fingerprint(item.paymentHash)} ${item.state}`).join(', ')}; the outcome is not known yet`
      : `operation ${operation.state}${last === undefined ? '' : `: ${fingerprint(last.paymentHash)} ${last.state}${last.failureReason === undefined ? '' : ` (${last.failureReason})`}`}`;
  // The outcome closes the timeline: its time is the latest recorded one.
  const lastAt = timeline.sorted().at(-1)?.at ?? operation.createdAt;
  timeline.add(lastAt, 'outcome', summary, operation.state === 'completed' ? 'accounting' : operation.state === 'open'
    ? 'unresolved' : undefined);
  const sorted = timeline.sorted();
  const budgetId = operation.budgetId ?? held[0]?.budgetId;
  const status = budgetId === undefined ? undefined : store.budgetStatus(budgetId);
  return {
    subject: { component: 'payer', operationId, payments: payments.map(item => fingerprint(item.paymentHash)) },
    timeline: sorted,
    outcome: { summary: sorted.find(item => item.kind === 'outcome')?.detail ?? summary, operation, payments: payments.map(item => ({
      payment: fingerprint(item.paymentHash), state: item.state, amountMsat: item.amountMsat.toString(), feeLimitMsat: item.feeLimitMsat.toString(),
      submissions: item.submissions, closedSubmission: item.closedSubmission, valueMsat: item.valueMsat?.toString() ?? null,
      feeMsat: item.feeMsat?.toString() ?? null, failureReason: item.failureReason ?? null, uncertainReason: item.uncertainReason ?? null,
      createdAt: item.createdAt, resolvedAt: item.resolvedAt ?? null })) },
    reservation: budgetId === undefined && held.length === 0 && refused.length === 0 ? null : {
      budgetId: budgetId ?? null,
      budget: status === undefined ? null : { limitMsat: status.limitMsat.toString(), heldMsat: status.heldMsat.toString(),
        consumedMsat: status.consumedMsat.toString(), availableMsat: status.availableMsat.toString() },
      reservations: held.map(item => ({ reservationId: Number(item.reservationId), budgetId: item.budgetId, payment: fingerprint(item.paymentHash),
        state: item.state, principalMsat: item.principalMsat.toString(), feeAllowanceMsat: item.allowanceMsat.toString(),
        actualFeeMsat: item.actualFeeMsat?.toString() ?? null, createdAt: item.createdAt, updatedAt: item.updatedAt })),
      refusals: refused.map(item => ({ budgetId: item.budgetId, payment: fingerprint(item.paymentHash), requestedMsat: item.requestedMsat.toString(),
        availableMsat: item.availableMsat.toString(), at: item.at })),
    },
    journal,
    outbox,
    reconciliation: decisions(sorted),
    ...(Object.keys(timeline.truncated).length === 0 ? {} : { truncated: timeline.truncated }),
  };
}
