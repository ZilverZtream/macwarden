import { MAX_LINE, safeText, wrap } from './format.ts';
import { LIMITS, type Explanation, type TruncatedKey } from './model.ts';

/**
 * The two forms of an explanation. `--json`: one document in the shape of macwarden's Output rules,
 * `{schema: 1, command: 'explain', ok, warnings, result, error}`, `ok` false exactly when `error` is
 * set. Text: one block per section, every line at most 120 characters, every value escaped; where a
 * list was cut (model.ts, bound), one line `… N <items> omitted …` stands where the left-out items were.
 */

export interface Warning { code: string; message: string }
export interface ExplainError { code: number; step: string | null; message: string }

export interface ExplainDocument {
  schema: 1;
  command: 'explain';
  ok: boolean;
  warnings: Warning[];
  result: Explanation | null;
  error: ExplainError | null;
}

export function document(result: Explanation | null, warnings: Warning[], error: ExplainError | null): ExplainDocument {
  return { schema: 1, command: 'explain', ok: error === null, warnings, result, error };
}

const KIND_WIDTH = 24;

/** Appends one by one: spreading a long list into push() overflows the stack. */
function append(target: string[], items: readonly string[]): void {
  for (const item of items) target.push(item);
}

function block(out: string[], title: string, lines: readonly string[]): void {
  out.push(title);
  if (lines.length === 0) out.push('  none');
  append(out, lines);
  out.push('');
}

function kv(value: Record<string, unknown>): string {
  return Object.entries(value).filter(([, item]) => item !== null && typeof item !== 'object').map(([key, item]) => `${key} ${String(item)}`).join(', ');
}

/** Each item's lines, with the omission line after the first half when `key` was cut to `max` items. */
function listLines<T>(explanation: Explanation, key: TruncatedKey, max: number, noun: string, items: readonly T[],
  lines: (item: T) => string[]): string[] {
  const omitted = explanation.truncated?.[key] ?? 0;
  const out: string[] = [];
  items.forEach((item, index) => {
    if (omitted > 0 && index === Math.floor(max / 2)) out.push(`  … ${omitted} ${noun} omitted …`);
    append(out, lines(item));
  });
  return out;
}

/** At most this many payment hashes are named in the header; with more, it counts them and names the first and the last. */
const HEADER_HASHES = 3;

function hashesPhrase(explanation: Explanation): string {
  const listed = explanation.subject.payments;
  const total = listed.length + (explanation.truncated?.payments ?? 0);
  if (total === 0) return 'no payment hash';
  if (total <= HEADER_HASHES) return `payment hash${total > 1 ? 'es' : ''} ${listed.join(', ')}`;
  return `${total} payment hashes, the first ${listed[0] ?? ''}, the last ${listed.at(-1) ?? ''}`;
}

export function renderText(explanation: Explanation): string {
  const { subject } = explanation;
  const name = subject.component === 'payer' ? `operation ${subject.operationId ?? ''}` : `order ${subject.orderId ?? ''}`;
  const lines: string[] = [];
  append(lines, wrap('', `${subject.component} explain: ${name} (${hashesPhrase(explanation)})`, '  '));
  lines.push('');
  block(lines, 'outcome', wrap('  ', explanation.outcome.summary, '    '));
  block(lines, 'timeline', listLines(explanation, 'timeline', LIMITS.timeline, 'items', explanation.timeline, item => [
    ...wrap(`  ${item.at}  ${item.kind.padEnd(KIND_WIDTH)} `, item.detail, `  ${' '.repeat(26 + KIND_WIDTH)}`),
    ...(item.rule === undefined ? [] : wrap(`  ${' '.repeat(26 + KIND_WIDTH)}rule: `, item.rule, `  ${' '.repeat(32 + KIND_WIDTH)}`)),
  ]));
  const reservation = explanation.reservation;
  const reservationLines: string[] = [];
  if (reservation !== null) {
    const budget = reservation.budget as Record<string, unknown> | null;
    append(reservationLines, wrap('  ', `budget ${String(reservation.budgetId ?? 'none')}${budget === null ? '' : `: ${kv(budget)}`}`, '    '));
    append(reservationLines, listLines(explanation, 'reservations', LIMITS.list, 'reservations', reservation.reservations as Record<string, unknown>[],
      item => wrap('  ', `reservation ${kv(item)}`, '    ')));
    append(reservationLines, listLines(explanation, 'refusals', LIMITS.list, 'refusals', reservation.refusals as Record<string, unknown>[],
      item => wrap('  ', `refusal ${kv(item)}`, '    ')));
  }
  block(lines, 'reservation', reservationLines);
  block(lines, 'journal', listLines(explanation, 'journal', LIMITS.list, 'entries', explanation.journal, entry => wrap('  ', `#${entry.entryId} `
    + `${entry.postedAt} ${entry.event}${entry.payment === null ? '' : ` ${entry.payment}`}${entry.origin === 'migrated' ? ' (migrated)' : ''}: `
    + entry.lines.map(line => `${line.direction} ${line.account} ${line.amountMsat} msat`).join(', '), '    ')));
  block(lines, 'outbox', listLines(explanation, 'outbox', LIMITS.list, 'rows', explanation.outbox, row => wrap('  ', `#${row.outboxId} ${row.kind} `
    + `${row.state}, ${row.attempts} claim(s), enqueued ${row.createdAt}${row.acknowledgedAt === null ? '' : `, acknowledged ${row.acknowledgedAt}`}; `
    + `effect: ${row.effect}${row.lastError === null ? '' : `; last error: ${row.lastError}`}`, '    ')));
  block(lines, 'reconciliation', listLines(explanation, 'reconciliation', LIMITS.timeline, 'decisions', explanation.reconciliation,
    item => wrap('  ', `${item.at} ${item.decision}: ${item.rule}${item.predicates.length === 0 ? '' : ` (oracle: ${item.predicates.join(', ')})`}`,
      '    ')));
  return lines.map(line => line.slice(0, MAX_LINE)).join('\n');
}

export function renderWarning(warning: Warning): string {
  return `warning: ${safeText(warning.code)}: ${safeText(warning.message)}\n`;
}

export function renderError(error: ExplainError): string {
  return `error: ${safeText(error.step ?? 'explain')}: ${safeText(error.message)}\n`;
}
