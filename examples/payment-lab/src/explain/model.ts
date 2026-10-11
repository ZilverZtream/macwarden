import type { JournalEntry } from '../ledger/journal.ts';
import type { OutboxRow } from '../outbox/outbox.ts';
import { fileBase } from '../outbox/effects.ts';
import { RULES, type RuleId } from './rules.ts';
import { fingerprint, scrub } from './format.ts';

/**
 * The explanation of one payer operation or one receiver order, built from the records only (the
 * `--json` result of `payer explain` and `receiver explain`). Amounts are msat as decimal strings;
 * payment hashes are fingerprints; nothing holds a preimage or a payment request.
 *
 * Bounds, so that no record set makes the output unbounded: the timeline keeps at most LIMITS.timeline
 * items (its first and last halves), as does the reconciliation; the journal, the outbox and the
 * reservation's reservations and refusals keep at most LIMITS.list (first and last halves); a
 * submission shows at most LIMITS.attemptsPerSubmission HTLC attempts (first and last halves, with
 * one item counting the rest); the subject's payments and the outcome's payments (payer) or invoices (receiver) keep at
 * most LIMITS.list (first and last halves, counted once as `payments`); any one string is cut at 1,024 characters
 * (format.ts, capString). `--refresh` looks up at most LIMITS.refresh payment hashes (the same first and last halves),
 * within REFRESH_DEADLINE_MS in all (refresh.ts), and counts the others as `refresh`.
 * `truncated` counts what was left out, per list; it is absent when nothing was.
 */

export const LIMITS = { timeline: 2000, list: 200, attemptsPerSubmission: 200, refresh: 200 } as const;

export type TruncatedKey = 'timeline' | 'htlcAttempts' | 'journal' | 'outbox' | 'reservations' | 'refusals' | 'reconciliation' | 'payments'
  | 'refresh';
export type Truncated = Partial<Record<TruncatedKey, number>>;

export interface TimelineItem {
  /** When the record says it happened (an ISO time); a refreshed fact carries the time it was read. */
  at: string;
  kind: string;
  detail: string;
  /** The README rule that made this decision, by name (src/explain/rules.ts). */
  rule?: string;
}

export interface JournalView {
  entryId: number;
  event: string;
  reference: string;
  payment: string | null;
  origin: string;
  postedAt: string;
  lines: { account: string; direction: string; amountMsat: string }[];
}

export interface OutboxView {
  outboxId: number;
  kind: string;
  idempotencyKey: string;
  state: string;
  attempts: number;
  createdAt: string;
  acknowledgedAt: string | null;
  lastError: string | null;
  /** What performing the row does (or did): the file it writes. */
  effect: string;
}

export interface Decision { at: string; decision: string; detail: string; rule: string; predicates: readonly string[] }

export interface Explanation {
  subject: { component: 'payer' | 'receiver'; operationId?: string; orderId?: string; payments: string[] };
  timeline: TimelineItem[];
  outcome: Record<string, unknown> & { summary: string };
  reservation: Record<string, unknown> | null;
  journal: JournalView[];
  outbox: OutboxView[];
  reconciliation: Decision[];
  /** What the bounds (above) left out, per list; absent when nothing was. */
  truncated?: Truncated;
}

/** A list of more than `max` items keeps its first and last `max / 2`; `omitted` is how many it dropped. */
export function keepEnds<T>(items: readonly T[], max: number): { kept: T[]; omitted: number } {
  if (items.length <= max) return { kept: [...items], omitted: 0 };
  const half = Math.floor(max / 2);
  return { kept: [...items.slice(0, half), ...items.slice(items.length - (max - half))], omitted: items.length - max };
}

/** The explanation with every list within its bound and `truncated` saying what was left out. */
export function bound(explanation: Explanation): Explanation {
  const truncated: Truncated = { ...explanation.truncated };
  const cut = <T>(key: TruncatedKey, items: readonly T[], max: number): T[] => {
    const { kept, omitted } = keepEnds(items, max);
    if (omitted > 0) truncated[key] = (truncated[key] ?? 0) + omitted;
    return kept;
  };
  const timeline = cut('timeline', explanation.timeline, LIMITS.timeline);
  const reservation = explanation.reservation === null ? null : {
    ...explanation.reservation,
    reservations: cut('reservations', (explanation.reservation.reservations ?? []) as unknown[], LIMITS.list),
    refusals: cut('refusals', (explanation.reservation.refusals ?? []) as unknown[], LIMITS.list),
  };
  const journal = cut('journal', explanation.journal, LIMITS.list);
  const outbox = cut('outbox', explanation.outbox, LIMITS.list);
  const reconciliation = cut('reconciliation', explanation.reconciliation, LIMITS.timeline);
  // The subject's payments and the outcome's list of them are the same payments: cut alike, counted once.
  const subject = { ...explanation.subject, payments: cut('payments', explanation.subject.payments, LIMITS.list) };
  const outcome = { ...explanation.outcome };
  for (const key of ['payments', 'invoices'] as const) {
    if (Array.isArray(outcome[key])) outcome[key] = keepEnds(outcome[key] as unknown[], LIMITS.list).kept;
  }
  return { subject, timeline, outcome, reservation, journal, outbox, reconciliation,
    ...(Object.keys(truncated).length === 0 ? {} : { truncated }) };
}

/** Collects timeline items in the order they are added; `sorted` orders them by time, keeping that order for equal times. */
export class Timeline {
  readonly #items: TimelineItem[] = [];
  readonly #known: ReadonlySet<string>;
  /** What the builder left out (HTLC attempts beyond the per-submission bound). */
  readonly truncated: Truncated = {};

  constructor(known: ReadonlySet<string>) {
    this.#known = known;
  }

  add(at: string, kind: string, detail: string, rule?: RuleId): void {
    this.#items.push({ at, kind, detail: scrub(detail, this.#known), ...(rule === undefined ? {} : { rule: RULES[rule].name }) });
  }

  omit(key: TruncatedKey, count: number): void {
    this.truncated[key] = (this.truncated[key] ?? 0) + count;
  }

  sorted(): TimelineItem[] {
    return this.#items.map((item, index) => ({ item, index }))
      .sort((a, b) => (a.item.at < b.item.at ? -1 : a.item.at > b.item.at ? 1 : a.index - b.index)).map(entry => entry.item);
  }
}

/** Timeline kinds that are records of something, not decisions; every other item with a rule is a reconciliation decision. */
const NOT_DECISIONS = new Set(['journal', 'outbox-enqueued', 'outbox-done', 'operation', 'order', 'outcome']);

export function decisions(timeline: TimelineItem[]): Decision[] {
  return timeline.filter(item => item.rule !== undefined && !NOT_DECISIONS.has(item.kind)).map(item => ({ at: item.at, decision: item.kind,
    detail: item.detail, rule: item.rule as string, predicates: Object.values(RULES).find(rule => rule.name === item.rule)?.predicates ?? [] }));
}

export function journalView(entries: JournalEntry[], known: ReadonlySet<string>): JournalView[] {
  return entries.map(entry => ({ entryId: entry.entryId, event: entry.event, reference: scrub(entry.reference, known),
    payment: entry.paymentHash === undefined ? null : fingerprint(entry.paymentHash), origin: entry.origin, postedAt: entry.postedAt,
    lines: entry.lines.map(line => ({ account: line.account, direction: line.direction, amountMsat: line.amountMsat.toString() })) }));
}

/** One line per entry: its event and its lines. */
export function journalLine(entry: JournalView): string {
  const lines = entry.lines.map(line => `${line.direction} ${line.account} ${line.amountMsat} msat`).join(', ');
  return `entry #${entry.entryId} ${entry.event}${entry.origin === 'migrated' ? ' (migrated)' : ''}${entry.payment === null ? '' : ` for ${entry.payment}`}: ${lines}`;
}

/** `profile`: the directory under receipts or confirmations the profile's worker writes to (cli.ts, effectDir). */
export function outboxView(rows: OutboxRow[], known: ReadonlySet<string>, profile?: string): OutboxView[] {
  const under = profile === undefined ? '' : `${profile}/`;
  return rows.map(row => ({ outboxId: row.outboxId, kind: row.kind, idempotencyKey: scrub(row.idempotencyKey, known), state: row.state,
    attempts: row.attempts, createdAt: row.createdAt, acknowledgedAt: row.acknowledgedAt ?? null,
    lastError: row.lastError === undefined ? null : scrub(row.lastError, known),
    effect: row.kind === 'fulfill-order' ? `receipt <lab>/receipts/${under}${fileBase(row.subject)}.json`
      : `confirmation <lab>/confirmations/${under}${fileBase(row.subject)}.json` }));
}

/** The outbox rows on the timeline: enqueued with the state change, and acknowledged once performed. */
export function outboxItems(timeline: Timeline, rows: OutboxView[]): void {
  for (const row of rows) {
    timeline.add(row.createdAt, 'outbox-enqueued', `outbox #${row.outboxId} ${row.kind} enqueued with the state change (key `
      + `${row.idempotencyKey}); effect: ${row.effect}`, 'fulfillment');
    if (row.acknowledgedAt !== null) {
      timeline.add(row.acknowledgedAt, 'outbox-done', `outbox #${row.outboxId} performed and acknowledged after ${row.attempts} claim(s)`, 'worker');
    } else if (row.lastError !== null) {
      timeline.add(row.createdAt, 'outbox-pending', `outbox #${row.outboxId} ${row.state} after ${row.attempts} claim(s), due again `
        + `${row.state === 'pending' ? 'after its backoff' : 'when its lease runs out'}; last error: ${row.lastError}`, 'worker');
    }
  }
}
