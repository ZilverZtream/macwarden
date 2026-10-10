import type { JournalEntry } from '../ledger/journal.ts';
import type { OutboxRow } from '../outbox/outbox.ts';
import { fileBase } from '../outbox/effects.ts';
import { RULES, type RuleId } from './rules.ts';
import { fingerprint, scrub } from './format.ts';

/**
 * The explanation of one payer operation or one receiver order, built from the records only (the
 * `--json` result of `payer explain` and `receiver explain`). Amounts are msat as decimal strings;
 * payment hashes are fingerprints; nothing holds a preimage or a payment request.
 */

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
}

/** Collects timeline items in the order they are added; `sorted` orders them by time, keeping that order for equal times. */
export class Timeline {
  readonly #items: TimelineItem[] = [];
  readonly #known: ReadonlySet<string>;

  constructor(known: ReadonlySet<string>) {
    this.#known = known;
  }

  add(at: string, kind: string, detail: string, rule?: RuleId): void {
    this.#items.push({ at, kind, detail: scrub(detail, this.#known), ...(rule === undefined ? {} : { rule: RULES[rule].name }) });
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

export function outboxView(rows: OutboxRow[], known: ReadonlySet<string>): OutboxView[] {
  return rows.map(row => ({ outboxId: row.outboxId, kind: row.kind, idempotencyKey: scrub(row.idempotencyKey, known), state: row.state,
    attempts: row.attempts, createdAt: row.createdAt, acknowledgedAt: row.acknowledgedAt ?? null,
    lastError: row.lastError === undefined ? null : scrub(row.lastError, known),
    effect: row.kind === 'fulfill-order' ? `receipt <lab>/receipts/${fileBase(row.subject)}.json`
      : `confirmation <lab>/confirmations/${fileBase(row.subject)}.json` }));
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
