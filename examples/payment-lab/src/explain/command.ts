import type { PayerStore } from '../payer/store.ts';
import type { ReceiverStore } from '../receiver/store.ts';
import { explainPayer, resolvePayerSubject } from './payer.ts';
import { explainReceiver, resolveReceiverSubject } from './receiver.ts';
import { refreshPayer, refreshReceiver, type LookupSource, type TrackSource } from './refresh.ts';
import { capString, fingerprint, scrub } from './format.ts';
import { bound, type Explanation } from './model.ts';
import { document, renderError, renderText, renderWarning, type ExplainError, type Warning } from './render.ts';

/**
 * `payer explain` and `receiver explain` (src/cli.ts parses and checks the arguments). Exit codes:
 * 0 the subject was found and explained; 3 the records have no such subject; 4 a `--refresh` lookup
 * failed: the explanation from the records is printed all the same, with a warning and the error. An internal error (a
 * damaged record, for one) is exit 4 too, in the same document: `--json` always prints one explain document.
 */

/** `profile`: the profile the store belongs to, for the effect files' paths (`<lab>/receipts/<profile>/…`); left out, none is named. */
export type ExplainInput =
  | { component: 'payer'; store: PayerStore; api: TrackSource; subject: { operationId?: string; paymentHash?: string }; profile?: string }
  | { component: 'receiver'; store: ReceiverStore; api: LookupSource; subject: { orderId?: string; paymentHash?: string }; profile?: string };

export interface ExplainOptions {
  json: boolean;
  refresh: boolean;
  out?: (text: string) => void;
  err?: (text: string) => void;
  /** The --refresh deadline (refresh.ts, REFRESH_DEADLINE_MS when not given; the tests shorten it). */
  refreshDeadlineMs?: number;
}

const EXIT = { ok: 0, unknown: 3, nodeError: 4 } as const;

const asText = (_key: string, value: unknown): unknown => (typeof value === 'bigint' ? value.toString() : value);

/**
 * Every string of the explanation scrubbed and then cut to its bound (format.ts), whatever record field it came
 * from: the last guard before output. Scrubbing first, so a cut never leaves part of a secret behind.
 */
function scrubAll<T>(value: T, known: ReadonlySet<string>): T {
  if (typeof value === 'string') return capString(scrub(value, known)) as T;
  if (Array.isArray(value)) return value.map(item => scrubAll(item as unknown, known)) as T;
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, scrubAll(item as unknown, known)])) as T;
  }
  return value;
}

export async function explainCommand(input: ExplainInput, options: ExplainOptions): Promise<number> {
  const out = options.out ?? ((text: string): void => { process.stdout.write(text); });
  const err = options.err ?? ((text: string): void => { process.stderr.write(text); });
  const finish = (doc: ReturnType<typeof document>): number => {
    if (options.json) {
      out(`${JSON.stringify(doc, asText)}\n`);
    } else {
      for (const warning of doc.warnings) err(renderWarning(warning));
      if (doc.result !== null) out(`${renderText(doc.result)}\n`);
      if (doc.error !== null) err(renderError(doc.error));
    }
    return doc.error === null ? EXIT.ok : doc.error.code;
  };
  try {
    return await explainOrFail(input, options, finish);
  } catch (error) {
    // The message names no secret (scrub, with no hash known: any 64-hex run is redacted) and is cut to its bound.
    const message = capString(scrub(error instanceof Error ? error.message : String(error), new Set()));
    return finish(document(null, [], { code: EXIT.nodeError, step: 'records', message: `the records could not be read: ${message}` }));
  }
}

/** The records' part of the explanation, read in one read transaction: one snapshot, whatever another process commits meanwhile. */
function fromRecords(input: ExplainInput): { target: string; explained: Explanation; hashes: string[] } | undefined {
  const db = input.store.db;
  const own = !db.isTransaction;
  if (own) db.exec('BEGIN');
  try {
    const target = input.component === 'payer' ? resolvePayerSubject(input.store, input.subject)
      : resolveReceiverSubject(input.store, input.subject);
    if (target === undefined) return undefined;
    const explained = input.component === 'payer' ? explainPayer(input.store, target, input.profile)
      : explainReceiver(input.store, target, input.profile);
    const hashes = input.component === 'payer' ? input.store.paymentsForOperation(target).map(item => item.paymentHash)
      : input.store.db.prepare('SELECT payment_hash FROM invoices WHERE order_id = ? ORDER BY created_at, rowid').all(target)
        .map(row => String(row.payment_hash));
    return { target, explained, hashes };
  } finally {
    if (own && db.isTransaction) db.exec('COMMIT');
  }
}

async function explainOrFail(input: ExplainInput, options: ExplainOptions, finish: (doc: ReturnType<typeof document>) => number): Promise<number> {
  const read = fromRecords(input);
  if (read === undefined) {
    // The ID as given, a 64-hex one as its fingerprint (scrub, with the ID as the subject's own).
    const id = (input.component === 'payer' ? input.subject.operationId : input.subject.orderId) ?? '';
    const named = input.subject.paymentHash !== undefined ? `payment hash ${fingerprint(input.subject.paymentHash)}`
      : `${input.component === 'payer' ? 'operation' : 'order'} ${capString(scrub(id, new Set([id.toLowerCase()])))}`;
    return finish(document(null, [], { code: EXIT.unknown, step: 'subject', message: `the ${input.component}'s records have no ${named}` }));
  }
  const { target, explained, hashes } = read;
  // The lists are bounded first (model.ts, bound), so scrubbing walks at most what is printed.
  const known = new Set([...hashes.map(hash => hash.toLowerCase()), target.toLowerCase()]);
  const explanation: Explanation = scrubAll(bound(explained), known);
  const warnings: Warning[] = [];
  let error: ExplainError | null = null;
  if (options.refresh) {
    // The subject's own ID goes with the hashes, so the refresh fingerprints it as the records' part does (audit 1.3.2).
    const refreshOptions = options.refreshDeadlineMs === undefined ? { subject: target } : { deadlineMs: options.refreshDeadlineMs, subject: target };
    const refreshed = input.component === 'payer' ? await refreshPayer(explanation, hashes, input.api, refreshOptions)
      : await refreshReceiver(explanation, hashes, input.api, refreshOptions);
    for (const fact of refreshed.facts) explanation.timeline.push(scrubAll(fact, known));
    if (refreshed.skipped > 0) explanation.truncated = { ...explanation.truncated, refresh: refreshed.skipped };
    if (refreshed.error !== undefined) {
      const message = scrubAll(refreshed.error, known);
      warnings.push({ code: 'refresh-failed', message: `${message}; the explanation is from the records only` });
      error = { code: EXIT.nodeError, step: 'refresh', message };
    }
  }
  return finish(document(explanation, warnings, error));
}
