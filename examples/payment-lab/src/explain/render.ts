import { MAX_LINE, safeText, wrap } from './format.ts';
import type { Explanation } from './model.ts';

/**
 * The two forms of an explanation. `--json`: one document in the shape of macwarden's Output rules,
 * `{schema: 1, command: 'explain', ok, warnings, result, error}`, `ok` false exactly when `error` is
 * set. Text: one block per section, every line at most 120 characters, every value escaped.
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

function block(title: string, lines: string[]): string[] {
  return [title, ...(lines.length === 0 ? ['  none'] : lines), ''];
}

function kv(value: Record<string, unknown>): string {
  return Object.entries(value).filter(([, item]) => item !== null && typeof item !== 'object').map(([key, item]) => `${key} ${String(item)}`).join(', ');
}

export function renderText(explanation: Explanation): string {
  const { subject } = explanation;
  const name = subject.component === 'payer' ? `operation ${subject.operationId ?? ''}` : `order ${subject.orderId ?? ''}`;
  const lines: string[] = [];
  lines.push(...wrap('', `${subject.component} explain: ${name} (${subject.payments.length === 0 ? 'no payment hash'
    : `payment hash${subject.payments.length > 1 ? 'es' : ''} ${subject.payments.join(', ')}`})`, '  '));
  lines.push('');
  lines.push(...block('outcome', wrap('  ', explanation.outcome.summary, '    ')));
  const timeline = explanation.timeline.flatMap(item => [
    ...wrap(`  ${item.at}  ${item.kind.padEnd(KIND_WIDTH)} `, item.detail, `  ${' '.repeat(26 + KIND_WIDTH)}`),
    ...(item.rule === undefined ? [] : wrap(`  ${' '.repeat(26 + KIND_WIDTH)}rule: `, item.rule, `  ${' '.repeat(32 + KIND_WIDTH)}`)),
  ]);
  lines.push(...block('timeline', timeline));
  const reservation = explanation.reservation;
  const reservationLines: string[] = [];
  if (reservation !== null) {
    const budget = reservation.budget as Record<string, unknown> | null;
    reservationLines.push(...wrap('  ', `budget ${String(reservation.budgetId ?? 'none')}${budget === null ? '' : `: ${kv(budget)}`}`, '    '));
    for (const item of reservation.reservations as Record<string, unknown>[]) reservationLines.push(...wrap('  ', `reservation ${kv(item)}`, '    '));
    for (const item of reservation.refusals as Record<string, unknown>[]) reservationLines.push(...wrap('  ', `refusal ${kv(item)}`, '    '));
  }
  lines.push(...block('reservation', reservationLines));
  lines.push(...block('journal', explanation.journal.flatMap(entry => wrap('  ', `#${entry.entryId} ${entry.postedAt} ${entry.event}`
    + `${entry.payment === null ? '' : ` ${entry.payment}`}${entry.origin === 'migrated' ? ' (migrated)' : ''}: `
    + entry.lines.map(line => `${line.direction} ${line.account} ${line.amountMsat} msat`).join(', '), '    '))));
  lines.push(...block('outbox', explanation.outbox.flatMap(row => wrap('  ', `#${row.outboxId} ${row.kind} ${row.state}, ${row.attempts} claim(s), `
    + `enqueued ${row.createdAt}${row.acknowledgedAt === null ? '' : `, acknowledged ${row.acknowledgedAt}`}; effect: ${row.effect}`
    + `${row.lastError === null ? '' : `; last error: ${row.lastError}`}`, '    '))));
  lines.push(...block('reconciliation', explanation.reconciliation.flatMap(item => wrap('  ', `${item.at} ${item.decision}: ${item.rule}`
    + `${item.predicates.length === 0 ? '' : ` (oracle: ${item.predicates.join(', ')})`}`, '    '))));
  return `${lines.map(line => line.slice(0, MAX_LINE)).join('\n')}`;
}

export function renderWarning(warning: Warning): string {
  return `warning: ${safeText(warning.code)}: ${safeText(warning.message)}\n`;
}

export function renderError(error: ExplainError): string {
  return `error: ${safeText(error.step ?? 'explain')}: ${safeText(error.message)}\n`;
}
