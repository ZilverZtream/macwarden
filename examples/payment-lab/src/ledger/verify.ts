import { DatabaseSync, type SQLInputValue, type SQLOutputValue, type StatementSync } from 'node:sqlite';
import { describeError } from '../lnd/errors.ts';
import type { Invoice, Payment } from '../lnd/types.ts';
import type { Row } from '../store/sqlite.ts';
import { MAX_INT64 } from '../util/money.ts';
import { ACCOUNT, budgetAccount, budgetOf, counterAccountFor, isAccount } from './accounts.ts';
import { ISO_TIME, MAX_CLOCK_STEP_MS, MAX_SAFE_ENTRY_ID, parseBalance, signed, type Direction, type Leg } from './journal.ts';

/**
 * `ledger verify`: the balance theorem, checked.
 *
 * 1. Every entry balances (debits equal credits, every line a readable amount in 0 to 2^63 - 1
 *    on an account in the chart, with a debit and a credit line), and is well formed: an event
 *    this book posts, with the lines its posting rule prescribes (accounts, directions, legs,
 *    line numbers 1..n, each debit/credit pair equal), a reference of the event's shape, an
 *    operation and payment hash that agree with the records, an entry ID a JavaScript number holds
 *    exactly (within ±(2^53 - 1)), an origin `migrated` at or below the migration's watermark
 *    (journal_migration; 0 when there is none) and `live` above it, a readable posted_at that
 *    never decreases from one live entry to the next (migrated entries, which keep their 1.2
 *    times, all come first) and is at most MAX_CLOCK_STEP_MS ahead of this run's clock. `post`
 *    clamps live times so they never decrease, so an entry out of order was moved: of the two
 *    around a decrease, the one its next live entry disagrees with is named (an entry moved
 *    forward, not the healthy entries after it; an entry moved back, not the one before it).
 * 2. Every account's balance recomputed from the entries equals the stored running balance
 *    (the balances table, and each line's balance_after on the way); every balances row is an
 *    account in the chart with a canonical decimal balance, last_entry_id the last entry that
 *    touches the account and updated_at that entry's posted_at.
 * 3. The book agrees with its own records, record by record. Payer: each reservation's budget
 *    entries commit what the reservation holds or consumed (a released one has its budget-held
 *    and budget-released entries, not merely a net of zero), each succeeded payment has its
 *    payment-succeeded entry with the record's value and fee, nothing else posts to the wallet
 *    or fee accounts, and a double-payment entry exists exactly for each succeeded payment of an
 *    operation after its first, for the payment's value. Receiver: one settlement entry per
 *    invoice, exactly for the invoices the record says settled (or, for one recorded
 *    not-created, LND reported SETTLED), for the record's amt_paid_msat, underpaid-settlement
 *    exactly when that is less than the invoice's amount; and a double-payment entry, for the
 *    same amount, exactly for a paid invoice that did not fulfill its order because another did.
 *    A difference here unbalances the result even when the account totals happen to agree.
 * 4. With an LND source, the wallet and fee accounts agree with LND over the same window, the
 *    payment hashes this store knows: settled invoices' amt_paid_msat (ListInvoices) for the
 *    receiver, succeeded payments' value_msat and fee_msat (ListPayments) for the payer. Both
 *    lists are paged and bounded; a list longer than the bound is reported `incomplete`.
 *
 * Every column read is type-checked: a damaged value (an entry_id that is text, a blob leg) is a
 * finding, never a throw and never coerced. Every difference is listed per account with the first
 * entry (lowest entry ID) that explains it; the unbalanced and the malformed entries are listed
 * up to the first LIST_LIMIT each, lowest entry ID first, with their totals.
 *
 * The books are read in entry-ID batches inside one read transaction, on a read-only connection
 * of its own when the store is a file (so the snapshot can stay open while LND is read; on the
 * store's own connection, an in-memory store, LND is read before the transaction begins), and
 * memory is bounded by a batch and the per-account state, not by the size of the books. All sums
 * are bigints computed here; SQLite only reads rows. Run it when the component is quiet: a
 * payment that succeeds in LND between the read of the store and the read of LND is reported, as
 * `pending` (the record is still unresolved), not as a difference.
 */

export interface LedgerStore {
  readonly db: DatabaseSync;
  readonly book: 'payer' | 'receiver';
}

/** The LND reads verifyLedger uses: a ReadApi (payer) or an InvoiceApi (receiver) fits, as does a test fake. */
export interface LndLedgerSource {
  listPaymentsPage?(indexOffset: bigint, maxPayments: number): Promise<{ payments: Payment[]; lastIndexOffset: bigint }>;
  listInvoicesPage?(indexOffset: bigint, maxInvoices: number): Promise<{ invoices: Invoice[]; lastIndexOffset: bigint }>;
}

export interface Explanation {
  account: string;
  entryId?: number;
  event?: string;
  reference?: string;
  paymentHash?: string;
  reason: string;
}

export interface AccountReport {
  account: string;
  /** Net debit recomputed from the entries. */
  computed: bigint;
  /** Net debit in the balances table (0 when the account has no row or its row is unreadable). */
  stored: bigint;
  /** computed - stored. */
  difference: bigint;
  /** What the store's own records say the account should be (payer only: budgets, wallet, fees). */
  records?: bigint;
  recordsDifference?: bigint;
  /** LND's figure over the same window, in the same net-debit convention. */
  lnd?: bigint;
  lndDifference?: bigint;
  firstEntry?: Explanation;
}

export interface UnbalancedEntry {
  entryId: number;
  event: string;
  reference: string;
  debitsMsat: bigint;
  creditsMsat: bigint;
  reason: string;
}

/** An entry whose amounts may balance but whose shape does not match its posting rule or the records. */
export interface InvalidEntry {
  entryId: number;
  event: string;
  reference: string;
  reason: string;
}

/**
 * - compared        LND was read to the end of the window and every difference is listed
 * - pending         as compared, but LND reports a payment or settlement the record has not learned yet
 *                   (it is unresolved; reconcile first): exit 75
 * - not-requested   no LND source was passed
 * - unavailable     the source lacks the list call, or the call failed (lndDetail says why)
 * - incomplete      the list has more items than the bound (MAX_PAGES full pages)
 */
export type LndComparison = 'compared' | 'pending' | 'not-requested' | 'unavailable' | 'incomplete';

export interface LedgerVerification {
  book: 'payer' | 'receiver';
  balanced: boolean;
  entries: number;
  /** The first LIST_LIMIT unbalanced entries (lowest entry ID first); unbalancedEntryCount counts them all. */
  unbalancedEntries: UnbalancedEntry[];
  unbalancedEntryCount: number;
  /** The first LIST_LIMIT malformed entries that are not unbalanced; invalidEntryCount counts them all. */
  invalidEntries: InvalidEntry[];
  invalidEntryCount: number;
  /**
   * The first LIST_LIMIT payment hashes (per account) whose posted amounts differ from LND's, in record
   * order; lndDifferenceCount counts them all. Kept per payment, whatever the account totals: two
   * differences can cancel out in a total.
   */
  lndDifferences: Explanation[];
  lndDifferenceCount: number;
  accounts: AccountReport[];
  lnd: LndComparison;
  lndDetail?: string;
  firstDifference?: Explanation;
}

/** How many entries each list carries (the counts are complete). */
export const LIST_LIMIT = 100;
/** Entries (and records) read per batch. */
const BATCH = 10_000;
/** Problems listed per entry; more are counted. */
const PROBLEM_LIMIT = 10;
/**
 * The lower bound of the first batch of every ID-ordered read (`id > ?`): a REAL below every int64,
 * so the first batch includes an ID of -2^63 (with MIN_INT64 itself, `>` would skip that row).
 */
const BEFORE_ALL = -1e19;
const PAGE_SIZE = 500;
const MAX_PAGES = 200;
const UNRESOLVED_PAYMENT = new Set(['intent', 'submitting', 'in_flight', 'uncertain', 'failed']);
const PAYMENT_HASH = /^[0-9a-f]{64}$/;
const RESERVATION_REFERENCE = /^reservation:([1-9][0-9]*)$/;
const BOOK_EVENTS: Record<'payer' | 'receiver', ReadonlySet<string>> = {
  payer: new Set(['payment-succeeded', 'double-payment', 'budget-held', 'budget-released', 'budget-consumed']),
  receiver: new Set(['invoice-settled', 'underpaid-settlement', 'double-payment']),
};
const SETTLEMENT_EVENTS: ReadonlySet<string> = new Set(['invoice-settled', 'underpaid-settlement']);
const COUNTER_ACCOUNTS: ReadonlySet<string> = new Set([ACCOUNT.customerReceivable, ACCOUNT.refundsPayable, ACCOUNT.payoutsPayable]);

interface EntryInfo {
  /** Exact (a bigint); reports carry it as a number, and an ID outside ±(2^53 - 1) is malformed. */
  entryId: bigint;
  event: string;
  reference: string;
  paymentHash: string | undefined;
  operationId: string | undefined;
  origin: string | undefined;
  postedAt: string | undefined;
}

interface Line { lineNo: number | undefined; account: string; direction: Direction; amountMsat: bigint; leg: string | undefined;
  balanceAfter: bigint | undefined;
  /** Columns that do not hold their type but carry no money (line_no, leg, balance_after). */
  damaged: string[] }

/** One line of a posting rule: the account, the direction and the legacy leg name (or none). */
interface Slot { account: string; direction: Direction; leg?: Leg }

/**
 * Keeps, per account, the explanation with the lowest entry ID; one without an entry only when
 * there is none, and then the first that names a payment hash (it is more specific).
 */
class Explanations {
  readonly #byAccount = new Map<string, Explanation>();
  /** The accounts whose explanation names an unbalanced entry (bounded by the accounts, not the entries). */
  readonly #unbalanced = new Set<string>();

  /** `unbalanced`: the explanation's entry is an unbalanced one. */
  offer(explanation: Explanation, unbalanced = false): void {
    const known = this.#byAccount.get(explanation.account);
    const earlier = explanation.entryId !== undefined && (known?.entryId === undefined || explanation.entryId < known.entryId);
    const moreSpecific = explanation.entryId === undefined && known?.entryId === undefined && known?.paymentHash === undefined
      && explanation.paymentHash !== undefined;
    if (known === undefined || earlier || moreSpecific) {
      this.#byAccount.set(explanation.account, explanation);
      if (unbalanced) this.#unbalanced.add(explanation.account); else this.#unbalanced.delete(explanation.account);
    } else if (unbalanced && explanation.entryId !== undefined && explanation.entryId === known.entryId) {
      this.#unbalanced.add(explanation.account);
    }
  }

  get(account: string): Explanation | undefined {
    return this.#byAccount.get(account);
  }

  namesUnbalanced(account: string): boolean {
    return this.#unbalanced.has(account);
  }
}

/**
 * The entries of one category: every entry counted, the LIST_LIMIT lowest kept, keyed by the exact
 * (bigint) ID. Memory is the kept items, not one ID per entry: the caller adds an entry once (the
 * entry loop knows which list an entry is in, and a live entry's mark carries it; EntryListing)
 * and extends it after that.
 */
class Listed<T extends { entryId: number; reason: string }> {
  count = 0;
  readonly kept: { id: bigint; item: T }[] = [];

  get items(): T[] {
    return this.kept.map(known => known.item);
  }

  add(id: bigint, item: T): void {
    this.count += 1;
    if (this.kept.length >= LIST_LIMIT && id > (this.kept.at(-1) as { id: bigint }).id) return;
    const at = this.kept.findIndex(known => known.id > id);
    if (at === -1) this.kept.push({ id, item }); else this.kept.splice(at, 0, { id, item });
    if (this.kept.length > LIST_LIMIT) this.kept.pop();
  }

  /** Adds a problem to an entry already listed (no change to the count). */
  extend(id: bigint, problem: string): void {
    const known = this.kept.find(item => item.id === id);
    if (known !== undefined) known.item.reason = `${known.item.reason}; ${problem}`;
  }
}

function explain(account: string, entry: EntryInfo | undefined, reason: string, paymentHash?: string): Explanation {
  const hash = entry?.paymentHash ?? paymentHash;
  const named = entry === undefined ? {} : { entryId: Number(entry.entryId), event: entry.event, reference: entry.reference };
  return { account, ...named, ...(hash === undefined ? {} : { paymentHash: hash }), reason };
}

function add(map: Map<string, bigint>, key: string, value: bigint): void {
  map.set(key, (map.get(key) ?? 0n) + value);
}

/** A value for a reason: its storage type, and a short rendering. */
function describeValue(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'number') return `a real (${value})`;
  if (typeof value === 'bigint') return `an integer (${value})`;
  if (typeof value === 'string') return `text ${JSON.stringify(value.length > 40 ? `${value.slice(0, 40)}…` : value)}`;
  return `a blob (${value instanceof Uint8Array ? value.length : '?'} bytes)`;
}

/** Why a column does not hold its type (text, or an integer; NULL only when nullable), or undefined. */
function typeProblem(row: Row, column: string, kind: 'text' | 'integer', nullable = false): string | undefined {
  const value = row[column];
  if (value === null || value === undefined) return nullable ? undefined : `column ${column} is NULL`;
  if (kind === 'text' ? typeof value === 'string' : typeof value === 'bigint') return undefined;
  return `column ${column} holds ${describeValue(value)}, not ${kind === 'text' ? 'text' : 'an integer'}`;
}

/** A text column, or undefined for NULL or any other type (a damaged row is reported, never coerced). */
function textOf(row: Row, column: string): string | undefined {
  const value = row[column];
  return typeof value === 'string' ? value : undefined;
}

/** An integer column (a bigint, as the reader is opened with readBigInts), or undefined. */
function intOf(row: Row, column: string): bigint | undefined {
  const value = row[column];
  return typeof value === 'bigint' ? value : undefined;
}

/** The problems of a record row's columns, `<column> holds ...`, for the columns listed. */
function recordProblems(row: Row, columns: [string, 'text' | 'integer', boolean?][]): string[] {
  return columns.flatMap(([column, kind, nullable]) => typeProblem(row, column, kind, nullable) ?? []);
}

const listed = (problems: string[]): string => problems.length <= PROBLEM_LIMIT ? problems.join('; ')
  : `${problems.slice(0, PROBLEM_LIMIT).join('; ')}; and ${problems.length - PROBLEM_LIMIT} more`;

/** An entry row's fields and the columns that do not hold their type. */
function readEntry(row: Row): { info: EntryInfo; damaged: string[] } {
  const damaged = recordProblems(row, [['event', 'text'], ['reference', 'text'], ['operation_id', 'text', true], ['payment_hash', 'text', true],
    ['origin', 'text'], ['posted_at', 'text']]);
  return { info: { entryId: row.entry_id as bigint, event: textOf(row, 'event') ?? 'unknown', reference: textOf(row, 'reference') ?? 'unknown',
    paymentHash: textOf(row, 'payment_hash'), operationId: textOf(row, 'operation_id'), origin: textOf(row, 'origin'),
    postedAt: textOf(row, 'posted_at') }, damaged };
}

/** A line's fields, or why its money can not be read (a damaged row is reported, never coerced). */
function readLine(row: Row): Line | { problem: string } {
  const money = recordProblems(row, [['account', 'text'], ['direction', 'text'], ['amount_msat', 'integer']]);
  if (money.length > 0) return { problem: money.join('; ') };
  const account = row.account as string;
  const direction = row.direction as string;
  const amountMsat = row.amount_msat as bigint;
  if (direction !== 'debit' && direction !== 'credit') return { problem: `direction ${JSON.stringify(direction)} is neither debit nor credit` };
  if (!isAccount(account)) return { problem: `account ${JSON.stringify(account)} is not in the chart of accounts` };
  if (amountMsat < 0n || amountMsat > MAX_INT64) return { problem: `amount ${amountMsat} msat is outside 0 to 2^63 - 1` };
  const damaged = recordProblems(row, [['line_no', 'integer'], ['leg', 'text', true], ['balance_after', 'text']]);
  let balanceAfter: bigint | undefined;
  try { balanceAfter = parseBalance(textOf(row, 'balance_after') ?? ''); } catch { balanceAfter = undefined; }
  const lineNo = intOf(row, 'line_no');
  return { lineNo: lineNo === undefined ? undefined : Number(lineNo), account, direction, amountMsat, leg: textOf(row, 'leg'), balanceAfter, damaged };
}

const describeSlots = (slots: Slot[]): string => slots.map(slot => `${slot.direction} ${slot.account}${slot.leg === undefined ? '' : ` (${slot.leg})`}`).join(', ');

/** Whether the lines follow one of the rule's line patterns, every debit/credit pair of equal amounts. */
function matchesRule(lines: Line[], alternatives: Slot[][]): boolean {
  return alternatives.some(slots => slots.length === lines.length && slots.every((slot, index) => {
    const line = lines[index] as Line;
    return line.account === slot.account && line.direction === slot.direction && line.leg === slot.leg;
  }) && lines.every((line, index) => index % 2 === 1 || line.amountMsat === lines[index + 1]?.amountMsat));
}

interface PaymentRecordView { operationId: string | undefined; state: string; kind: string | undefined }
type ReservationView = { budgetId: string; operationId: string; paymentHash: string; state: string; principal: bigint; allowance: bigint }
  | { damaged: string };

/** The records the entries of one batch refer to, by payment hash and by reservation ID. */
interface BatchRecords {
  payments: Map<string, PaymentRecordView>;
  invoices: Map<string, { orderId: string | undefined }>;
  reservations: Map<string, ReservationView>;
  hasEntry(event: string, reference: string): boolean;
}

/**
 * The structural problems of one entry against its posting rule and the records. `lines` are the
 * entry's readable lines in line-number order.
 */
function entryProblems(info: EntryInfo, lines: Line[], book: 'payer' | 'receiver', records: BatchRecords): string[] {
  const problems: string[] = [];
  if (!BOOK_EVENTS[book].has(info.event)) {
    problems.push(`event ${JSON.stringify(info.event)} is not one the ${book}'s book posts`);
    return problems;
  }
  if (info.origin !== 'live' && info.origin !== 'migrated') problems.push(`origin ${JSON.stringify(info.origin ?? null)} is neither live nor migrated`);
  if (info.operationId === undefined) problems.push('it has no operation_id');
  const numbers = lines.map(line => line.lineNo);
  if (numbers.some((value, index) => value !== index + 1)) problems.push(`its line numbers are ${numbers.map(String).join(', ')}, not 1 to ${lines.length}`);

  let alternatives: Slot[][] = [];
  if (info.event.startsWith('budget-')) {
    const match = RESERVATION_REFERENCE.exec(info.reference);
    const reservation = match === null ? undefined : records.reservations.get(match[1] as string);
    if (match === null) problems.push(`reference ${JSON.stringify(info.reference)} is not reservation:<id>`);
    else if (reservation === undefined) problems.push(`reservation ${match[1]} does not exist`);
    else if ('damaged' in reservation) problems.push(`reservation ${match[1]}'s record is damaged (${reservation.damaged})`);
    let budget: string | undefined;
    if (reservation !== undefined && !('damaged' in reservation)) {
      budget = budgetOf(`budget:${reservation.budgetId}`) === undefined ? undefined : budgetAccount(reservation.budgetId);
      if (info.operationId !== reservation.operationId) problems.push(`operation_id ${JSON.stringify(info.operationId ?? null)} is not the reservation's ${reservation.operationId}`);
      if (info.paymentHash !== reservation.paymentHash) problems.push(`payment_hash ${JSON.stringify(info.paymentHash ?? null)} is not the reservation's ${reservation.paymentHash}`);
      const allowed = info.event === 'budget-held' ? ['held', 'released', 'consumed'] : info.event === 'budget-released' ? ['released', 'consumed'] : ['consumed'];
      if (!allowed.includes(reservation.state)) problems.push(`the reservation is ${reservation.state}, which posts no ${info.event} entry`);
      const hold = reservation.principal + reservation.allowance;
      if (info.event !== 'budget-consumed' && lines[0] !== undefined && lines[0].amountMsat !== hold) {
        problems.push(`it moves ${lines[0].amountMsat} msat; the reservation holds principal plus allowance, ${hold} msat`);
      }
    } else {
      budget = lines.map(line => line.account).find(account => budgetOf(account) !== undefined);
    }
    if (budget !== undefined) {
      const commit = ACCOUNT.budgetCommitments;
      alternatives = info.event === 'budget-held' ? [[{ account: budget, direction: 'debit' }, { account: commit, direction: 'credit' }]]
        : info.event === 'budget-released' ? [[{ account: commit, direction: 'debit' }, { account: budget, direction: 'credit' }]]
          : [[{ account: commit, direction: 'debit' }, { account: budget, direction: 'credit' }],
            [{ account: budget, direction: 'debit' }, { account: commit, direction: 'credit' }],
            [{ account: budget, direction: 'debit' }, { account: commit, direction: 'credit' }, { account: budget, direction: 'debit' },
              { account: commit, direction: 'credit' }]];
    }
  } else {
    if (info.paymentHash === undefined || !PAYMENT_HASH.test(info.paymentHash)) problems.push(`payment_hash ${JSON.stringify(info.paymentHash ?? null)} is not a payment hash`);
    if (info.reference !== info.paymentHash) problems.push(`reference ${JSON.stringify(info.reference)} is not its payment hash`);
    if (book === 'payer') {
      const record = info.paymentHash === undefined ? undefined : records.payments.get(info.paymentHash);
      let counter: string | undefined;
      if (record === undefined) {
        problems.push(`no payment record has payment hash ${info.paymentHash ?? 'null'}`);
        counter = lines.map(line => line.account).find(account => COUNTER_ACCOUNTS.has(account));
      } else {
        if (record.operationId !== info.operationId) problems.push(`operation_id ${JSON.stringify(info.operationId ?? null)} is not the payment's ${record.operationId ?? 'null'}`);
        if (record.state !== 'succeeded') problems.push(`the payment is ${record.state}, not succeeded`);
        const kind = record.kind;
        if (kind === 'order-payment' || kind === 'refund' || kind === 'payout') counter = counterAccountFor(kind);
        else problems.push(`the payment's operation has no known kind (${JSON.stringify(kind ?? null)})`);
      }
      if (info.event === 'double-payment' && info.paymentHash !== undefined && !records.hasEntry('payment-succeeded', info.paymentHash)) {
        problems.push('the payment has no payment-succeeded entry');
      }
      if (counter !== undefined) {
        alternatives = info.event === 'payment-succeeded'
          ? [[{ account: counter, direction: 'debit', leg: 'principal' }, { account: ACCOUNT.walletOutgoing, direction: 'credit' },
            { account: ACCOUNT.routingFees, direction: 'debit', leg: 'routing-fee' }, { account: ACCOUNT.walletOutgoing, direction: 'credit' }]]
          : [[{ account: ACCOUNT.suspenseDoublePayment, direction: 'debit' }, { account: counter, direction: 'credit' }]];
      }
    } else {
      const record = info.paymentHash === undefined ? undefined : records.invoices.get(info.paymentHash);
      if (record === undefined) problems.push(`no invoice record has payment hash ${info.paymentHash ?? 'null'}`);
      else if (record.orderId !== info.operationId) {
        problems.push(`operation_id ${JSON.stringify(info.operationId ?? null)} is not the invoice's order ${record.orderId ?? 'null'}`);
      }
      alternatives = info.event === 'invoice-settled'
        ? [[{ account: ACCOUNT.walletIncoming, direction: 'debit', leg: 'sale' }, { account: ACCOUNT.customerReceivable, direction: 'credit' }]]
        : info.event === 'underpaid-settlement'
          ? [[{ account: ACCOUNT.walletIncoming, direction: 'debit' }, { account: ACCOUNT.suspenseDoublePayment, direction: 'credit' }]]
          : [[{ account: ACCOUNT.customerReceivable, direction: 'debit' }, { account: ACCOUNT.suspenseDoublePayment, direction: 'credit' }]];
    }
  }
  if (alternatives.length > 0 && !matchesRule(lines, alternatives)) {
    problems.push(`its lines are not the ${info.event} rule's (${alternatives.map(describeSlots).join(' | ')}, each pair of equal amounts)`);
  } else if (alternatives.length === 0 && problems.length === 0) {
    problems.push(`its lines can not be matched to the ${info.event} rule`);
  }
  return problems;
}

/** A live entry the time check has accepted: its time and the accounts its lines touch. */
interface LiveMark { info: EntryInfo; time: number; accounts: string[]; listing: EntryListing }

/** Which list an entry is in so far (an entry is counted in at most one: unbalanced, else invalid). */
interface EntryListing { unbalanced: boolean; invalid: boolean }

/**
 * The read side: a read-only connection of its own when the store is a file (so the snapshot can
 * stay open across the LND read without touching the store's connection), else the store's.
 */
function openReader(db: DatabaseSync): { reader: DatabaseSync; shared: boolean; close(): void } {
  const file = textOf(db.prepare(`SELECT file FROM pragma_database_list WHERE name = 'main'`).get() ?? {}, 'file') ?? '';
  if (file === '') return { reader: db, shared: true, close: () => undefined };
  const reader = new DatabaseSync(file, { readOnly: true, readBigInts: true, timeout: 15_000 });
  // A page cache of 64 MiB (SQLite's own memory, not the JS heap): the records step looks entries and lines up by key.
  reader.exec('PRAGMA cache_size = -65536');
  return { reader, shared: false, close: () => reader.close() };
}

/** Lets other work run between batches (the snapshot holds; the event loop does not stall on a large book). */
const turn = (): Promise<void> => new Promise(resolve => { setImmediate(resolve); });

export async function verifyLedger(store: LedgerStore, api?: LndLedgerSource): Promise<LedgerVerification> {
  const { reader, shared, close } = openReader(store.db);
  try {
    // On the store's own connection (an in-memory store) the read transaction must not stay open while other work runs on
    // that connection: LND is read before it begins, and between batches only already-resolved promises are awaited (no
    // timer or I/O callback runs inside it). A success LND reports after its read and before the store's is then a difference.
    const before = shared && api !== undefined ? await readLnd(api, store.book) : undefined;
    const ownTransaction = !reader.isTransaction;
    if (ownTransaction) reader.exec('BEGIN');
    try {
      return await verifyIn(reader, store.book, before === undefined ? api : before, shared ? () => Promise.resolve() : turn);
    } finally {
      if (ownTransaction && reader.isTransaction) reader.exec('COMMIT');
    }
  } finally {
    close();
  }
}

/** LND's side of step 4: the comparison state, why it is not `compared`, and the amounts read. */
interface LndOutcome { comparison: LndComparison; lndDetail: string | undefined; lndRead: LndRead | undefined }

async function readLnd(api: LndLedgerSource, book: 'payer' | 'receiver'): Promise<LndOutcome> {
  try {
    const lndRead = book === 'payer' ? await settledPayments(api) : await settledInvoices(api);
    return lndRead.kind === 'read' ? { comparison: 'compared', lndDetail: undefined, lndRead }
      : { comparison: lndRead.kind, lndDetail: lndRead.detail, lndRead };
  } catch (error) {
    return { comparison: 'unavailable', lndDetail: describeError(error), lndRead: undefined };
  }
}

/** The watermark of the 1.3 migration (journal_migration), or why there is none. */
function readWatermark(db: DatabaseSync): { through: bigint; missing?: string } {
  let row: Row | undefined;
  try {
    row = db.prepare('SELECT migrated_through FROM journal_migration WHERE singleton = 1').get();
  } catch {
    return { through: 0n, missing: 'the journal has no journal_migration table' };
  }
  if (row === undefined) return { through: 0n, missing: 'journal_migration has no row' };
  const through = intOf(row, 'migrated_through');
  return through === undefined ? { through: 0n, missing: `journal_migration's migrated_through holds ${describeValue(row.migrated_through)}` } : { through };
}

async function verifyIn(db: DatabaseSync, book: 'payer' | 'receiver', lndSource: LndLedgerSource | LndOutcome | undefined,
  pause: Pause): Promise<LedgerVerification> {
  const explanations = new Explanations();
  const unbalanced = new Listed<UnbalancedEntry>();
  const invalid = new Listed<InvalidEntry>();
  /** Accounts with a difference the account totals alone need not show (a line, a row, a record, an entry's shape). */
  const flagged = new Set<string>();
  const flag = (account: string, entry: EntryInfo | undefined, reason: string, paymentHash?: string): void => {
    flagged.add(account);
    explanations.offer(explain(account, entry, reason, paymentHash));
  };
  /** A malformed entry: listed as invalid unless it is unbalanced (then its reason carries the problems), its accounts flagged. */
  const malformed = (info: EntryInfo, problems: string[], accounts: string[], listing: EntryListing): void => {
    const reason = `entry ${info.entryId} (${info.event} ${info.reference}) is malformed: ${listed(problems)}`;
    if (listing.unbalanced) unbalanced.extend(info.entryId, `malformed: ${listed(problems)}`);
    else if (listing.invalid) invalid.extend(info.entryId, reason);
    else {
      invalid.add(info.entryId, { entryId: Number(info.entryId), event: info.event, reference: info.reference, reason });
      listing.invalid = true;
    }
    for (const account of accounts) flag(account, info, reason);
  };
  const computed = new Map<string, bigint>();
  const running = new Map<string, bigint>();
  /** The last entry with a line on each account, for the balances row's last_entry_id. */
  const lastEntryOf = new Map<string, EntryInfo>();
  let entries = 0;

  const ENTRY_COLUMNS = ['entry_id', 'event', 'reference', 'operation_id', 'payment_hash', 'origin', 'posted_at'];
  const LINE_COLUMNS = ['line_rowid', 'entry_id', 'line_no', 'account', 'direction', 'amount_msat', 'leg', 'balance_after'];
  const entryBatch = rowReader(db.prepare(`SELECT ${ENTRY_COLUMNS.join(', ')} FROM journal_entries WHERE entry_id > ? ORDER BY entry_id LIMIT ?`), ENTRY_COLUMNS);
  // Lines of an entry-ID range; reals in the range come too (an entry_id that is not an integer is reported).
  const lineBatch = rowReader(db.prepare(`SELECT rowid AS line_rowid, ${LINE_COLUMNS.slice(1).join(', ')} FROM journal_lines WHERE entry_id > ? AND entry_id <= ?
    ORDER BY entry_id, line_no`), LINE_COLUMNS);
  const entryByKey = db.prepare('SELECT entry_id FROM journal_entries WHERE event = ? AND reference = ?');
  const hasEntry = (event: string, reference: string): boolean => entryByKey.get(event, reference) !== undefined;
  const recordStatements = batchRecordStatements(db, book);
  const watermark = readWatermark(db);
  const notMigrated = watermark.missing === undefined ? '' : ` (${watermark.missing}, so no entry is a migrated one)`;
  /** This run's clock: a live entry later than this was not posted by `post`, which never runs ahead of its clock by more. */
  const latest = Date.now() + MAX_CLOCK_STEP_MS;

  let lastLive: LiveMark | undefined;
  let beforeLive: LiveMark | undefined;
  let anyLive: EntryInfo | undefined;
  /** A decrease (cur earlier than last) waiting for the next live entry to say which of the two was moved. */
  let decrease: { last: LiveMark; cur: LiveMark; before: LiveMark | undefined } | undefined;
  const movedForward = (moved: LiveMark, next: LiveMark): void => {
    malformed(moved.info, [`posted_at ${moved.info.postedAt ?? ''} is later than the next live entry ${next.info.entryId}'s ${next.info.postedAt ?? ''} `
      + '(live times never decrease: the entry was moved)'], moved.accounts, moved.listing);
  };
  const movedBack = (moved: LiveMark, previous: LiveMark): void => {
    malformed(moved.info, [`posted_at ${moved.info.postedAt ?? ''} is earlier than live entry ${previous.info.entryId}'s ${previous.info.postedAt ?? ''} `
      + '(live times never decrease: the entry was moved)'], moved.accounts, moved.listing);
  };
  /**
   * Decides a pending decrease: last ahead of this run's clock was moved forward (post follows the clock once
   * an entry is that far ahead); otherwise `next` agreeing with last means cur was moved back, else last was moved forward.
   */
  const settle = (next: LiveMark | undefined): void => {
    if (decrease === undefined) return;
    const { last, cur, before } = decrease;
    decrease = undefined;
    const curMoved = last.time > latest ? false
      : next === undefined ? before === undefined || before.time > cur.time : next.time >= last.time;
    if (curMoved) {
      movedBack(cur, last);
    } else {
      movedForward(last, cur);
      lastLive = cur;
      beforeLive = before;
    }
  };

  /** A line that belongs to no entry (its entry_id is damaged, or names no entry): its money is in the stored balances. */
  const strayLine = (row: Row, why: string): void => {
    const line = readLine(row);
    const account = 'problem' in line ? textOf(row, 'account') ?? '(unreadable account)' : line.account;
    const money = 'problem' in line ? `(${line.problem})` : `its ${line.amountMsat} msat ${line.direction}`;
    flag(account, undefined, `journal line ${String(row.line_rowid)} ${why}: ${money} is in no entry`);
  };

  let lower: bigint | number = BEFORE_ALL;
  for (;;) {
    const rows = entryBatch(lower, BATCH);
    const full = rows.length === BATCH;
    const upper = full ? rows.at(-1)?.entry_id as bigint : MAX_INT64;
    const linesOf = new Map<bigint, Row[]>();
    for (const row of lineBatch(lower, upper)) {
      const entryId = row.entry_id;
      if (typeof entryId !== 'bigint') { strayLine(row, `has ${typeProblem(row, 'entry_id', 'integer') ?? 'a damaged entry_id'}`); continue; }
      const list = linesOf.get(entryId);
      if (list === undefined) linesOf.set(entryId, [row]); else list.push(row);
    }
    const records = { ...recordStatements.forEntries(lower, upper), hasEntry };

    for (const row of rows) {
      entries += 1;
      const { info, damaged } = readEntry(row);
      const lineRows = linesOf.get(row.entry_id as bigint) ?? [];
      linesOf.delete(row.entry_id as bigint);
      let debits = 0n;
      let credits = 0n;
      const problems: string[] = [];
      const readable: Line[] = [];
      for (const lineRow of lineRows) {
        const line = readLine(lineRow);
        if ('problem' in line) { problems.push(`line ${String(lineRow.line_no)}: ${line.problem}`); continue; }
        readable.push(line);
        if (line.direction === 'debit') debits += line.amountMsat; else credits += line.amountMsat;
      }
      if (!readable.some(line => line.direction === 'debit') || !readable.some(line => line.direction === 'credit')) {
        problems.push('the entry needs a debit and a credit line');
      }
      if (debits !== credits) problems.push(`debits ${debits} msat differ from credits ${credits} msat`);
      const accounts = [...new Set(readable.map(line => line.account))];
      const listing: EntryListing = { unbalanced: problems.length > 0, invalid: false };
      if (problems.length > 0) {
        const reason = `entry ${info.entryId} (${info.event} ${info.reference}) is unbalanced: ${listed(problems)}`;
        unbalanced.add(info.entryId, { entryId: Number(info.entryId), event: info.event, reference: info.reference, debitsMsat: debits,
          creditsMsat: credits, reason });
        for (const account of accounts) explanations.offer(explain(account, info, reason), true);
      }

      // The entry's shape: its columns, its posting rule, its reference and its agreement with the records; its time.
      const shape = [...damaged, ...readable.flatMap(line => line.damaged.map(problem => `line ${line.lineNo ?? '?'}: ${problem}`))];
      if (!(problems.length > 0 && readable.length < lineRows.length)) shape.push(...entryProblems(info, readable, book, records));
      if (info.entryId > MAX_SAFE_ENTRY_ID || info.entryId < -MAX_SAFE_ENTRY_ID) {
        shape.push(`its entry ID ${info.entryId} is outside ±(2^53 - 1): an outbox row or a report can not name it exactly (post never assigns one)`);
      }
      const time = info.postedAt !== undefined && ISO_TIME.test(info.postedAt) ? Date.parse(info.postedAt) : Number.NaN;
      if (Number.isNaN(time)) shape.push(`posted_at ${JSON.stringify(info.postedAt ?? null)} is not an ISO 8601 UTC time`);
      if (info.origin === 'migrated' && info.entryId > watermark.through) {
        shape.push(`it is migrated, but the ledger migration posted entries up to ${watermark.through} only${notMigrated}`);
      } else if (info.origin === 'live' && info.entryId <= watermark.through) {
        shape.push(`it is live, but at or below entry ${watermark.through}, the last the ledger migration posted`);
      }
      if (info.origin === 'live' && time > latest) {
        shape.push(`posted_at ${info.postedAt ?? ''} is more than ${MAX_CLOCK_STEP_MS / 3_600_000} hours after this run's clock `
          + `(${new Date(latest - MAX_CLOCK_STEP_MS).toISOString()}); post never runs that far ahead`);
      }
      if (info.origin === 'migrated' && anyLive !== undefined) {
        shape.push(`it is migrated but follows live entry ${anyLive.entryId} (migrated entries are posted before any live one)`);
      } else if (info.origin === 'live') {
        anyLive = info;
        if (!Number.isNaN(time)) {
          const mark: LiveMark = { info, time, accounts, listing };
          settle(mark);
          if (lastLive === undefined || time >= lastLive.time) {
            beforeLive = lastLive;
            lastLive = mark;
          } else {
            decrease = { last: lastLive, cur: mark, before: beforeLive };
          }
        }
      }
      if (shape.length > 0) malformed(info, shape, accounts, listing);

      for (const line of readable) {
        const value = signed(line.direction, line.amountMsat);
        add(computed, line.account, value);
        lastEntryOf.set(line.account, info);
        const after = (running.get(line.account) ?? 0n) + value;
        running.set(line.account, after);
        if (line.balanceAfter !== after) {
          flag(line.account, info, line.balanceAfter === undefined
            ? `entry ${info.entryId}: the line's recorded running balance is unreadable`
            : `entry ${info.entryId}: recomputed from the entries, ${line.account} is ${after} msat after this line; the line recorded ${line.balanceAfter} msat`);
        }
      }
    }
    // Lines whose entry row is gone: their money is in the stored balances, so they are reported.
    for (const [entryId, lineRows] of linesOf) {
      const orphan: EntryInfo = { entryId, event: 'unknown', reference: 'unknown', paymentHash: undefined, operationId: undefined,
        origin: undefined, postedAt: undefined };
      unbalanced.add(entryId, { entryId: Number(entryId), event: orphan.event, reference: orphan.reference, debitsMsat: 0n, creditsMsat: 0n,
        reason: `${lineRows.length} line(s) belong to entry ${entryId}, which does not exist` });
      for (const lineRow of lineRows) {
        const line = readLine(lineRow);
        if (!('problem' in line)) explanations.offer(explain(line.account, orphan, `entry ${entryId} is missing but has lines`), true);
      }
    }
    if (!full) break;
    lower = upper;
    await pause();
  }
  // A decrease at the last live entry: no next entry to ask, so the one before decides.
  settle(undefined);
  // Lines whose entry_id is NULL, text or a blob (they sort after every number), or a real outside the batches' range: three
  // index searches (an OR of them would scan every line).
  for (const where of ['entry_id IS NULL', 'entry_id > ?', 'entry_id <= ?']) {
    const statement = db.prepare(`SELECT rowid AS line_rowid, * FROM journal_lines WHERE ${where}`);
    const rows = where.endsWith('NULL') ? statement.iterate() : statement.iterate(where.includes('>') ? MAX_INT64 : BEFORE_ALL);
    for (const row of rows) strayLine(row, `has ${typeProblem(row, 'entry_id', 'integer') ?? 'a damaged entry_id'}`);
  }

  // 2. The stored balances.
  const stored = new Map<string, bigint>();
  const entryById = db.prepare('SELECT * FROM journal_entries WHERE entry_id = ?');
  for (const row of db.prepare('SELECT * FROM balances ORDER BY account').iterate()) {
    const account = textOf(row, 'account') ?? describeValue(row.account);
    const raw = textOf(row, 'balance_msat');
    let value = 0n;
    let readableBalance = true;
    try {
      value = parseBalance(raw ?? '');
    } catch {
      readableBalance = false;
      flag(account, undefined, `the balances row of ${account} is corrupt: balance_msat ${raw === undefined ? describeValue(row.balance_msat) : JSON.stringify(raw)} `
        + `is not a canonical decimal ('0' or -?[1-9][0-9]*), so every later posting to ${account} fails`);
    }
    stored.set(account, value);
    if (!isAccount(account)) flag(account, undefined, `the balances row has an account ${account}, which is not in the chart of accounts`);
    const last = lastEntryOf.get(account);
    const lastId = intOf(row, 'last_entry_id');
    if (lastId === undefined) {
      flag(account, last, `the balances row of ${account}: ${typeProblem(row, 'last_entry_id', 'integer') ?? 'last_entry_id is unreadable'}`);
    } else if (last !== undefined && lastId !== last.entryId) {
      flag(account, last, `the balances row of ${account} names entry ${lastId} as the last to move it; the last entry with a line on it is ${last.entryId}`);
    } else if (last === undefined) {
      flag(account, undefined, `the balances row of ${account} names entry ${lastId} as the last to move it; no entry has a line on it`);
    }
    if (last !== undefined && textOf(row, 'updated_at') !== last.postedAt) {
      flag(account, last, `the balances row of ${account} was updated at ${textOf(row, 'updated_at') === undefined ? describeValue(row.updated_at)
        : JSON.stringify(row.updated_at)}; entry ${last.entryId}, the last to move it, was posted at ${last.postedAt ?? 'null'}`);
    }
    if (readableBalance && (computed.get(account) ?? 0n) !== value) {
      // A stored balance no entry explains (the balances row itself was changed), named by the entry that last moved it.
      const movedRow = lastId === undefined ? undefined : entryById.get(lastId);
      const moved = movedRow === undefined ? undefined : readEntry(movedRow).info;
      explanations.offer(explain(account, undefined, `the stored balance ${value} msat differs from the entries' ${computed.get(account) ?? 0n} msat; `
        + `entry ${lastId ?? describeValue(row.last_entry_id)}${moved === undefined ? '' : ` (${moved.event} ${moved.reference})`} last moved it`));
    }
  }
  // post() writes a balances row for every account a line moves, so one missing is a difference even at zero.
  for (const [account, value] of computed) {
    if (!stored.has(account)) flag(account, lastEntryOf.get(account), `the entries move ${account} (to ${value} msat) but it has no balances row`);
  }

  // 4 (read). LND over the same window, read while the snapshot of the store holds.
  // (Already read, before the transaction, when the store's own connection is the reader.)
  const outcome: LndOutcome = lndSource === undefined ? { comparison: 'not-requested', lndDetail: undefined, lndRead: undefined }
    : 'comparison' in lndSource ? lndSource : await readLnd(lndSource, book);
  let comparison = outcome.comparison;
  let lndDetail = outcome.lndDetail;
  const lndRead = outcome.lndRead;
  const lndAmounts = lndRead?.kind === 'read' ? lndRead.amounts : undefined;

  // 3. The records, record by record, and 4. LND hash by hash.
  const records = new Map<string, bigint>();
  const lnd = new Map<string, bigint>();
  const lndAccounts = book === 'payer' ? [ACCOUNT.walletOutgoing, ACCOUNT.routingFees] : [ACCOUNT.walletIncoming];
  if (lndAmounts !== undefined) for (const account of lndAccounts) lnd.set(account, 0n);
  const lndCheck = { pending: 0, different: false };
  const lndDifferences: Explanation[] = [];
  let lndDifferenceCount = 0;
  /** Compares one known payment hash's posted amounts with LND's. */
  const compareLnd: CompareLnd = (hash, posted, entry, state, unresolved) => {
    if (lndAmounts === undefined) return;
    const reported = lndAmounts.get(hash);
    for (const account of lndAccounts) {
      const expected = reported?.get(account) ?? 0n;
      add(lnd, account, expected);
      const actual = posted.get(account) ?? 0n;
      if (actual === expected) continue;
      if (actual === 0n && unresolved) { lndCheck.pending += 1; continue; }
      lndCheck.different = true;
      // Flagged per payment, so a difference is explained even when another payment's cancels it in the account total.
      const difference = explain(account, entry, `LND reports ${expected} msat for ${account} on payment hash ${hash}; `
        + `the entries post ${actual} msat (record ${state})`, hash);
      lndDifferenceCount += 1;
      if (lndDifferences.length < LIST_LIMIT) lndDifferences.push(difference);
      flag(account, entry, difference.reason, hash);
    }
  };
  if (book === 'payer') {
    await payerRecords(db, { records, flag, compareLnd, pause });
  } else {
    await receiverRecords(db, { flag, compareLnd, pause });
  }
  if (lndAmounts !== undefined && lndCheck.pending > 0 && !lndCheck.different) {
    comparison = 'pending';
    lndDetail = `${lndCheck.pending} amount(s) LND reports are not recorded yet: the records are unresolved; reconcile, then verify again`;
  }

  // An account only the records mention, at zero (a budget never used), is left out.
  const names = new Set([...computed.keys(), ...stored.keys(), ...[...records].filter(([, value]) => value !== 0n).map(([key]) => key), ...lnd.keys(),
    ...flagged]);
  const accounts: AccountReport[] = [...names].sort().map(account => {
    const value = computed.get(account) ?? 0n;
    const storedValue = stored.get(account) ?? 0n;
    const report: AccountReport = { account, computed: value, stored: storedValue, difference: value - storedValue };
    const recorded = records.get(account);
    if (recorded !== undefined) { report.records = recorded; report.recordsDifference = value - recorded; }
    const reported = lnd.get(account);
    if (reported !== undefined) { report.lnd = reported; report.lndDifference = value - reported; }
    return report;
  });
  for (const report of accounts) {
    const explanation = explanations.get(report.account);
    const differs = report.difference !== 0n || (report.recordsDifference ?? 0n) !== 0n || flagged.has(report.account)
      || (comparison === 'compared' && (report.lndDifference ?? 0n) !== 0n)
      || (explanation?.entryId !== undefined && explanations.namesUnbalanced(report.account));
    if (differs && explanation !== undefined) report.firstEntry = explanation;
  }
  // The lowest entry ID first; among explanations naming one entry, an account whose balance itself differs first.
  const own = (report: AccountReport): number => report.difference !== 0n || (report.recordsDifference ?? 0n) !== 0n
    || (report.lndDifference ?? 0n) !== 0n ? 0 : 1;
  const ranked = accounts.filter(report => report.firstEntry !== undefined)
    .sort((a, b) => (a.firstEntry?.entryId ?? Infinity) - (b.firstEntry?.entryId ?? Infinity) || own(a) - own(b));
  const differing = ranked.flatMap(report => report.firstEntry === undefined ? [] : [report.firstEntry]);
  const firstBroken = [...unbalanced.kept, ...invalid.kept].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))[0]?.item;
  const firstDifference = differing.find(item => item.entryId !== undefined)
    ?? differing.find(item => item.paymentHash !== undefined)
    ?? differing[0]
    ?? (firstBroken === undefined ? undefined : { account: '', entryId: firstBroken.entryId, event: firstBroken.event,
      reference: firstBroken.reference, reason: firstBroken.reason });
  const balanced = unbalanced.count === 0 && invalid.count === 0 && !lndCheck.different && flagged.size === 0
    && accounts.every(report => report.difference === 0n && (report.recordsDifference ?? 0n) === 0n);
  return { book, balanced, entries, unbalancedEntries: unbalanced.items, unbalancedEntryCount: unbalanced.count,
    invalidEntries: invalid.items, invalidEntryCount: invalid.count, lndDifferences, lndDifferenceCount, accounts, lnd: comparison,
    ...(lndDetail === undefined ? {} : { lndDetail }), ...(firstDifference === undefined ? {} : { firstDifference }) };
}

/** The statements that read the records one batch of entries refers to. */
function batchRecordStatements(db: DatabaseSync, book: 'payer' | 'receiver'): { forEntries(lower: bigint | number, upper: bigint): Omit<BatchRecords, 'hasEntry'> } {
  // From the batch's entries (the rowid range; `+e.event` keeps the planner off the event index) to their records.
  if (book === 'receiver') {
    const invoices = rowReader(db.prepare(`SELECT i.payment_hash AS payment_hash, i.order_id AS order_id FROM journal_entries e
      CROSS JOIN invoices i ON i.payment_hash = e.payment_hash WHERE e.entry_id > ? AND e.entry_id <= ?`), ['payment_hash', 'order_id']);
    return { forEntries: (lower, upper) => {
      const map = new Map<string, { orderId: string | undefined }>();
      for (const row of invoices(lower, upper)) {
        const hash = textOf(row, 'payment_hash');
        if (hash !== undefined) map.set(hash, { orderId: textOf(row, 'order_id') });
      }
      return { payments: new Map(), invoices: map, reservations: new Map() };
    } };
  }
  const payments = rowReader(db.prepare(`SELECT p.payment_hash AS payment_hash, p.operation_id AS operation_id, p.state AS state, o.kind AS kind
    FROM journal_entries e CROSS JOIN payments p ON p.payment_hash = e.payment_hash LEFT JOIN operations o ON o.operation_id = p.operation_id
    WHERE e.entry_id > ? AND e.entry_id <= ? AND +e.event IN ('payment-succeeded', 'double-payment')`), ['payment_hash', 'operation_id', 'state', 'kind']);
  const reservations = rowReader(db.prepare(`SELECT ${RESERVATION_COLUMNS.join(', ')} FROM reservations WHERE reservation_id IN (
    SELECT CAST(substr(reference, 13) AS INTEGER) FROM journal_entries
    WHERE entry_id > ? AND entry_id <= ? AND typeof(reference) = 'text' AND substr(reference, 1, 12) = 'reservation:')`), RESERVATION_COLUMNS);
  return { forEntries: (lower, upper) => {
    const paymentMap = new Map<string, PaymentRecordView>();
    for (const row of payments(lower, upper)) {
      const hash = textOf(row, 'payment_hash');
      if (hash === undefined) continue;
      paymentMap.set(hash, { operationId: textOf(row, 'operation_id'), state: textOf(row, 'state') ?? `unreadable (${describeValue(row.state)})`,
        kind: textOf(row, 'kind') });
    }
    const reservationMap = new Map<string, ReservationView>();
    for (const row of reservations(lower, upper)) reservationMap.set(String(row.reservation_id), reservationView(row));
    return { payments: paymentMap, invoices: new Map(), reservations: reservationMap };
  } };
}

/** The reservation columns verify reads. */
const RESERVATION_COLUMNS = ['reservation_id', 'budget_id', 'operation_id', 'payment_hash', 'state', 'principal_msat', 'fee_allowance_msat', 'actual_fee_msat'];

function reservationView(row: Row): ReservationView {
  const damaged = recordProblems(row, [['budget_id', 'text'], ['operation_id', 'text'], ['payment_hash', 'text'], ['state', 'text'],
    ['principal_msat', 'integer'], ['fee_allowance_msat', 'integer'], ['actual_fee_msat', 'integer', true]]);
  if (damaged.length > 0) return { damaged: damaged.join('; ') };
  return { budgetId: row.budget_id as string, operationId: row.operation_id as string, paymentHash: row.payment_hash as string, state: row.state as string,
    principal: row.principal_msat as bigint, allowance: row.fee_allowance_msat as bigint };
}

type Flag = (account: string, entry: EntryInfo | undefined, reason: string, paymentHash?: string) => void;
/** Compares one known payment hash's posted amounts (per account) with LND's; `unresolved` makes an unposted amount pending. */
type CompareLnd = (hash: string, posted: ReadonlyMap<string, bigint>, entry: EntryInfo | undefined, state: string, unresolved: boolean) => void;
type Pause = () => Promise<void>;

/**
 * A statement's rows as objects of `columns`, read as arrays where node:sqlite can (about twice as
 * fast as its row objects on a large book). The statement names its result columns `columns`, in
 * that order, so both ways give the same rows.
 */
function rowReader(statement: StatementSync, columns: readonly string[]): (...params: SQLInputValue[]) => Row[] {
  const setReturnArrays = (statement as StatementSync & { setReturnArrays?: (enabled: boolean) => void }).setReturnArrays;
  if (setReturnArrays === undefined) return (...params) => statement.all(...params);
  setReturnArrays.call(statement, true);
  return (...params) => (statement.all(...params) as unknown as SQLOutputValue[][]).map(values => {
    const row: Row = {};
    for (let index = 0; index < columns.length; index += 1) row[columns[index] as string] = values[index] as SQLOutputValue;
    return row;
  });
}

/**
 * Runs `work` over a table's rows in batches of BATCH by rowid (`read` takes the lower bound and the
 * limit and selects record_rowid), with the bounds of each batch for the queries that join it.
 */
async function forEachBatch(read: (lower: bigint | number, limit: number) => Row[], pause: Pause,
  work: (rows: Row[], lower: bigint | number, upper: bigint) => void): Promise<void> {
  let lower: bigint | number = BEFORE_ALL;
  for (;;) {
    const rows = read(lower, BATCH);
    const last = rows.at(-1);
    if (last === undefined) return;
    const upper = last.record_rowid as bigint;
    work(rows, lower, upper);
    if (rows.length < BATCH) return;
    lower = upper;
    await pause();
  }
}

/** A minimal EntryInfo for an entry named by its ID and key (enough for an explanation). */
const named = (entryId: bigint, event: string, reference: string, operationId?: string): EntryInfo => ({ entryId, event, reference,
  paymentHash: event.startsWith('budget-') ? undefined : reference, operationId, origin: undefined, postedAt: undefined });

/**
 * Payer, step 3: reservations against their budget entries; succeeded payments against their
 * payment-succeeded entries (value and fee) and their double-payment entries; and step 4 hash by hash.
 * The payment-succeeded entry's value and fee are its lines 1 and 3 (the rule's principal and
 * routing-fee legs; an entry whose lines are not the rule's is reported malformed in step 1).
 */
async function payerRecords(db: DatabaseSync, context: { records: Map<string, bigint>; flag: Flag; compareLnd: CompareLnd; pause: Pause }): Promise<void> {
  const { records, flag, pause } = context;
  for (const row of db.prepare('SELECT budget_id FROM budgets ORDER BY budget_id').iterate()) {
    const id = textOf(row, 'budget_id');
    if (id !== undefined && budgetOf(`budget:${id}`) !== undefined) records.set(budgetAccount(id), 0n);
    else flag(ACCOUNT.budgetCommitments, undefined, `a budgets row is damaged: ${typeProblem(row, 'budget_id', 'text') ?? `budget_id ${JSON.stringify(id)} is not 1 to 128 characters`}`);
  }
  records.set(ACCOUNT.budgetCommitments, 0n);

  const reservationRows = rowReader(db.prepare(`SELECT reservation_id AS record_rowid, ${RESERVATION_COLUMNS.join(', ')} FROM reservations
    WHERE reservation_id > ? ORDER BY reservation_id LIMIT ?`), ['record_rowid', ...RESERVATION_COLUMNS]);
  const budgetLines = rowReader(db.prepare(`SELECT r.reservation_id AS reservation_id, e.entry_id AS entry_id, e.event AS event, l.account AS account,
      l.direction AS direction, l.amount_msat AS amount_msat
    FROM reservations r CROSS JOIN journal_entries e ON e.event IN ('budget-held', 'budget-released', 'budget-consumed')
      AND e.reference = 'reservation:' || r.reservation_id
    CROSS JOIN journal_lines l ON l.entry_id = e.entry_id WHERE r.reservation_id > ? AND r.reservation_id <= ?`),
  ['reservation_id', 'entry_id', 'event', 'account', 'direction', 'amount_msat']);
  await forEachBatch(reservationRows, pause, (rows, lower, upper) => {
    const posted = new Map<string, { amount: bigint; first: bigint; event: string }>();
    /** The budget events each reservation has an entry (with a line) for. */
    const eventsOf = new Map<string, Set<string>>();
    for (const row of budgetLines(lower, upper)) {
      const reservation = String(row.reservation_id);
      eventsOf.set(reservation, (eventsOf.get(reservation) ?? new Set<string>()).add(String(row.event)));
      const account = textOf(row, 'account');
      const direction = textOf(row, 'direction');
      const amount = intOf(row, 'amount_msat');
      if (account === undefined || budgetOf(account) === undefined || (direction !== 'debit' && direction !== 'credit') || amount === undefined) continue;
      const id = String(row.reservation_id);
      const entryId = row.entry_id as bigint;
      const known = posted.get(id);
      if (known === undefined) posted.set(id, { amount: signed(direction, amount), first: entryId, event: String(row.event) });
      else {
        known.amount += signed(direction, amount);
        if (entryId < known.first) { known.first = entryId; known.event = String(row.event); }
      }
    }
    for (const row of rows) {
      const id = String(row.reservation_id);
      const view = reservationView(row);
      const hash = textOf(row, 'payment_hash');
      const entry = posted.get(id);
      const first = entry === undefined ? undefined : named(entry.first, entry.event, `reservation:${id}`);
      if ('damaged' in view) {
        const budgetId = textOf(row, 'budget_id');
        const account = budgetId !== undefined && budgetOf(`budget:${budgetId}`) !== undefined ? budgetAccount(budgetId) : ACCOUNT.budgetCommitments;
        flag(account, first, `reservation ${id}'s record is damaged: ${view.damaged}`, hash);
        continue;
      }
      if (budgetOf(`budget:${view.budgetId}`) === undefined) {
        flag(ACCOUNT.budgetCommitments, first, `reservation ${id} names budget ${JSON.stringify(view.budgetId)}, not 1 to 128 characters`, hash);
        continue;
      }
      const actualFee = intOf(row, 'actual_fee_msat');
      const committed = view.state === 'held' ? view.principal + view.allowance : view.state === 'consumed' ? view.principal + (actualFee ?? 0n) : 0n;
      const account = budgetAccount(view.budgetId);
      add(records, account, committed);
      add(records, ACCOUNT.budgetCommitments, -committed);
      if ((entry?.amount ?? 0n) !== committed) {
        const reason = `reservation ${id} is ${view.state} for ${committed} msat; its entries commit ${entry?.amount ?? 0n} msat`;
        flag(account, first, reason, view.paymentHash);
        flag(ACCOUNT.budgetCommitments, first, reason, view.paymentHash);
      }
      // A release nets to zero, so the amount alone would not miss a released reservation's whole history: both entries must be there.
      const missing = view.state === 'released' ? ['budget-held', 'budget-released'].filter(event => eventsOf.get(id)?.has(event) !== true) : [];
      if (missing.length > 0) {
        const reason = `reservation ${id} is released; it has no ${missing.join(' or ')} entry (a released reservation was held, then released)`;
        flag(account, first, reason, view.paymentHash);
        flag(ACCOUNT.budgetCommitments, first, reason, view.paymentHash);
      }
    }
  });

  records.set(ACCOUNT.walletOutgoing, 0n);
  records.set(ACCOUNT.routingFees, 0n);
  // Per payment: its payment-succeeded entry with the amounts of lines 1 (principal) and 3 (fee); for a succeeded one,
  // how many other succeeded payments of its operation succeeded before it (by that entry, counted from the
  // operation's entries, journal_entries_by_operation), and its double-payment entry with the amount of its line 1.
  const paymentColumns = ['record_rowid', 'payment_hash', 'operation_id', 'state', 'value_msat', 'fee_msat', 'succeeded_entry', 'principal_msat',
    'fee_line_msat', 'earlier', 'double_entry', 'double_msat'] as const;
  const payments = rowReader(db.prepare(`SELECT p.rowid AS record_rowid, p.payment_hash, p.operation_id, p.state, p.value_msat, p.fee_msat,
      ps.entry_id AS succeeded_entry,
      (SELECT amount_msat FROM journal_lines WHERE entry_id = ps.entry_id AND line_no = 1) AS principal_msat,
      (SELECT amount_msat FROM journal_lines WHERE entry_id = ps.entry_id AND line_no = 3) AS fee_line_msat,
      CASE WHEN p.state = 'succeeded' AND ps.entry_id IS NOT NULL THEN
        (SELECT COUNT(*) FROM journal_entries qe INDEXED BY journal_entries_by_operation CROSS JOIN payments q ON q.payment_hash = qe.reference
          WHERE qe.operation_id = p.operation_id AND qe.event = 'payment-succeeded' AND qe.entry_id < ps.entry_id
            AND q.operation_id = p.operation_id AND q.state = 'succeeded' AND q.payment_hash <> p.payment_hash) END AS earlier,
      dp.entry_id AS double_entry,
      (SELECT amount_msat FROM journal_lines WHERE entry_id = dp.entry_id AND line_no = 1) AS double_msat
    FROM payments p LEFT JOIN journal_entries ps ON ps.event = 'payment-succeeded' AND ps.reference = p.payment_hash
    LEFT JOIN journal_entries dp ON dp.event = 'double-payment' AND dp.reference = p.payment_hash
    WHERE p.rowid > ? ORDER BY p.rowid LIMIT ?`), paymentColumns);
  await forEachBatch(payments, pause, rows => {
    for (const row of rows) {
      const hash = textOf(row, 'payment_hash');
      if (hash === undefined) {
        flag(ACCOUNT.walletOutgoing, undefined, `payment record (rowid ${String(row.record_rowid)}) is damaged: ${typeProblem(row, 'payment_hash', 'text') ?? ''}`);
        continue;
      }
      const state = textOf(row, 'state');
      const succeeded = state === 'succeeded';
      const succeededEntry = intOf(row, 'succeeded_entry');
      const entry = succeededEntry === undefined ? undefined : named(succeededEntry, 'payment-succeeded', hash, textOf(row, 'operation_id'));
      const damaged = recordProblems(row, [['state', 'text'], ['operation_id', 'text'], ...(succeeded
        ? [['value_msat', 'integer'], ['fee_msat', 'integer']] as [string, 'integer'][] : [])]);
      if (damaged.length > 0) {
        flag(ACCOUNT.walletOutgoing, entry, `payment ${hash}'s record is damaged: ${damaged.join('; ')}`, hash);
        continue;
      }
      const value = succeeded ? row.value_msat as bigint : 0n;
      const fee = succeeded ? row.fee_msat as bigint : 0n;
      add(records, ACCOUNT.walletOutgoing, -(value + fee));
      add(records, ACCOUNT.routingFees, fee);
      if (succeeded && entry === undefined) {
        flag(ACCOUNT.walletOutgoing, undefined, `payment ${hash} is succeeded in the record but has no payment-succeeded entry`, hash);
      }
      const postedValue = entry === undefined ? 0n : intOf(row, 'principal_msat');
      const postedFee = entry === undefined ? 0n : intOf(row, 'fee_line_msat');
      const posted = new Map<string, bigint>();
      if (postedValue !== undefined && postedFee !== undefined) {
        posted.set(ACCOUNT.walletOutgoing, -(postedValue + postedFee));
        posted.set(ACCOUNT.routingFees, postedFee);
        for (const [account, expected] of [[ACCOUNT.walletOutgoing, -(value + fee)], [ACCOUNT.routingFees, fee]] as const) {
          const actual = posted.get(account) ?? 0n;
          if (actual !== expected) {
            flag(account, entry, `payment ${hash} is ${state ?? ''} with value ${value} msat and fee ${fee} msat in the record; `
              + `its entries post ${actual} msat to ${account}`, hash);
          }
        }
      }
      if (succeeded && entry !== undefined) checkDoublePayment(hash, value, row.operation_id as string, entry, row, flag);
      if (postedValue !== undefined && postedFee !== undefined) context.compareLnd(hash, posted, entry, state ?? '', UNRESOLVED_PAYMENT.has(state ?? ''));
    }
  });
}

/** A succeeded payment's double-payment entry: there exactly when another payment of its operation succeeded first, for its value. */
function checkDoublePayment(hash: string, value: bigint, operationId: string, succeededEntry: EntryInfo, row: Row, flag: Flag): void {
  const earlier = intOf(row, 'earlier') ?? 0n;
  const entryId = intOf(row, 'double_entry');
  const entry = entryId === undefined ? undefined : named(entryId, 'double-payment', hash, operationId);
  if (earlier > 0n && entry === undefined) {
    flag(ACCOUNT.suspenseDoublePayment, succeededEntry, `payment ${hash} succeeded after ${earlier} other payment(s) of operation ${operationId} `
      + 'had; it has no double-payment entry', hash);
  } else if (earlier === 0n && entry !== undefined) {
    flag(ACCOUNT.suspenseDoublePayment, entry, `payment ${hash} is the first succeeded payment of operation ${operationId}; `
      + `double-payment entry ${entry.entryId} posts it as a second one`, hash);
  }
  const amount = intOf(row, 'double_msat');
  if (entry !== undefined && amount !== value) {
    flag(ACCOUNT.suspenseDoublePayment, entry, `double-payment entry ${entry.entryId} moves ${amount ?? 'an unreadable amount of'} msat; `
      + `payment ${hash}'s value_msat ${value} msat`, hash);
  }
}

/**
 * Receiver, step 3: each invoice against its settlement and double-payment entries (amount, event,
 * existence) without LND; and step 4 hash by hash. A settlement's amount is its line 1 (the rule's
 * lnd-wallet-incoming debit).
 */
async function receiverRecords(db: DatabaseSync, context: { flag: Flag; compareLnd: CompareLnd; pause: Pause }): Promise<void> {
  const { flag, pause } = context;
  const invoiceRows = db.prepare(`SELECT i.rowid AS record_rowid, i.payment_hash, i.order_id, i.state, i.amount_msat, i.amt_paid_msat, i.late_lnd_state,
      EXISTS (SELECT 1 FROM fulfillments f WHERE f.payment_hash = i.payment_hash AND f.order_id = i.order_id) AS fulfilled
    FROM invoices i WHERE i.rowid > ? ORDER BY i.rowid LIMIT ?`);
  const keyed = rowReader(db.prepare(`SELECT i.payment_hash AS payment_hash, e.entry_id AS entry_id, e.event AS event, e.operation_id AS operation_id,
      (SELECT amount_msat FROM journal_lines WHERE entry_id = e.entry_id AND line_no = 1) AS amount_msat
    FROM invoices i CROSS JOIN journal_entries e ON e.event IN ('invoice-settled', 'underpaid-settlement', 'double-payment') AND e.reference = i.payment_hash
    WHERE i.rowid > ? AND i.rowid <= ? ORDER BY e.entry_id`), ['payment_hash', 'entry_id', 'event', 'operation_id', 'amount_msat']);
  // The fulfillments of the orders a batch needs (no index on order_id: one scan per batch, not per invoice).
  const fulfillmentsOf = db.prepare('SELECT order_id, payment_hash FROM fulfillments WHERE order_id IN (SELECT value FROM json_each(?))');
  await forEachBatch((lower, limit) => invoiceRows.all(lower, limit), pause, (rows, lower, upper) => {
    const entriesOf = new Map<string, { info: EntryInfo; amount: bigint | undefined }[]>();
    for (const row of keyed(lower, upper)) {
      const hash = row.payment_hash as string;
      const list = entriesOf.get(hash) ?? [];
      list.push({ info: named(row.entry_id as bigint, String(row.event), hash, textOf(row, 'operation_id')), amount: intOf(row, 'amount_msat') });
      entriesOf.set(hash, list);
    }
    const needed = rows.filter(row => row.fulfilled !== 1n && entriesOf.has(row.payment_hash as string)).flatMap(row => textOf(row, 'order_id') ?? []);
    const fulfilledBy = new Map<string, string[]>();
    if (needed.length > 0) {
      for (const row of fulfillmentsOf.iterate(JSON.stringify([...new Set(needed)]))) {
        const orderId = row.order_id as string;
        fulfilledBy.set(orderId, [...(fulfilledBy.get(orderId) ?? []), String(row.payment_hash)]);
      }
    }
    for (const row of rows) {
      const hash = textOf(row, 'payment_hash');
      if (hash === undefined) {
        flag(ACCOUNT.walletIncoming, undefined, `invoice record (rowid ${String(row.record_rowid)}) is damaged: ${typeProblem(row, 'payment_hash', 'text') ?? ''}`);
        continue;
      }
      const entries = entriesOf.get(hash) ?? [];
      const damaged = recordProblems(row, [['order_id', 'text'], ['state', 'text'], ['amount_msat', 'integer'], ['amt_paid_msat', 'integer', true],
        ['late_lnd_state', 'text', true]]);
      if (damaged.length > 0) {
        flag(ACCOUNT.walletIncoming, entries[0]?.info, `invoice ${hash}'s record is damaged: ${damaged.join('; ')}`, hash);
        continue;
      }
      const state = row.state as string;
      const late = textOf(row, 'late_lnd_state');
      const orderId = row.order_id as string;
      checkInvoice({ hash, orderId, state, late, amount: row.amount_msat as bigint, amtPaid: intOf(row, 'amt_paid_msat'), fulfilled: row.fulfilled === 1n,
        otherFulfillments: (fulfilledBy.get(orderId) ?? []).filter(other => other !== hash) }, entries, flag);
      const settlements = entries.filter(item => SETTLEMENT_EVENTS.has(item.info.event));
      if (settlements.every(item => item.amount !== undefined)) {
        const posted = new Map([[ACCOUNT.walletIncoming as string, settlements.reduce((sum, item) => sum + (item.amount ?? 0n), 0n)]]);
        context.compareLnd(hash, posted, settlements[0]?.info, state, state !== 'settled' && late !== 'SETTLED');
      }
    }
  });
}

interface InvoiceFacts { hash: string; orderId: string; state: string; late: string | undefined; amount: bigint; amtPaid: bigint | undefined;
  fulfilled: boolean; otherFulfillments: string[] }

/** One invoice's settlement and double-payment entries against its record. */
function checkInvoice(invoice: InvoiceFacts, entries: { info: EntryInfo; amount: bigint | undefined }[], flag: Flag): void {
  const { hash } = invoice;
  const wallet = ACCOUNT.walletIncoming;
  const settlements = entries.filter(item => SETTLEMENT_EVENTS.has(item.info.event));
  const double = entries.find(item => item.info.event === 'double-payment');
  const settledInRecord = invoice.state === 'settled' || (invoice.state === 'not-created' && invoice.late === 'SETTLED');
  const [settlement, second] = settlements;
  if (second !== undefined) {
    flag(wallet, second.info, `invoice ${hash} has ${settlements.length} settlement entries (${settlements.map(item => item.info.entryId).join(', ')}); `
      + 'one settlement is posted per payment hash', hash);
  }
  if (settlement === undefined) {
    if (settledInRecord) flag(wallet, undefined, `invoice ${hash} is settled in the record but has no settlement entry`, hash);
  } else {
    if (!settledInRecord) {
      flag(wallet, settlement.info, `invoice ${hash} is ${invoice.state} in the record${invoice.late === undefined ? '' : ` (LND ${invoice.late})`}; `
        + `entry ${settlement.info.entryId} posts a settlement for it`, hash);
    }
    // A late invoice recorded not-created keeps no amt_paid_msat; its amount is compared with LND only.
    if (invoice.state === 'settled' && settlement.amount !== invoice.amtPaid) {
      flag(wallet, settlement.info, `entry ${settlement.info.entryId} settles ${settlement.amount ?? 'an unreadable amount of'} msat; `
        + `the invoice record's amt_paid_msat ${invoice.amtPaid ?? 'null'}`, hash);
    }
    const under = settlement.amount !== undefined && settlement.amount < invoice.amount;
    if (under !== (settlement.info.event === 'underpaid-settlement')) {
      flag(wallet, settlement.info, `entry ${settlement.info.entryId} is ${settlement.info.event} for ${settlement.amount ?? 'an unreadable amount of'} msat, `
        + `${under ? 'less than' : 'at least'} the invoice's ${invoice.amount} msat`, hash);
    }
  }
  const settledEntry = settlement?.info.event === 'invoice-settled' ? settlement : undefined;
  const suspense = ACCOUNT.suspenseDoublePayment;
  if (settledEntry !== undefined && !invoice.fulfilled && double === undefined) {
    flag(suspense, settledEntry.info, `invoice ${hash} was paid but did not fulfill order ${invoice.orderId}${invoice.otherFulfillments.length > 0
      ? ` (invoice ${invoice.otherFulfillments[0] ?? ''} did)` : ''}; it has no double-payment entry`, hash);
  }
  if (double !== undefined) {
    if (invoice.fulfilled) {
      flag(suspense, double.info, `double-payment entry ${double.info.entryId} is for invoice ${hash}, which fulfilled the order itself`, hash);
    } else if (settledEntry === undefined) {
      flag(suspense, double.info, `double-payment entry ${double.info.entryId} is for invoice ${hash}, which has no invoice-settled entry`, hash);
    } else if (invoice.otherFulfillments.length === 0) {
      flag(suspense, double.info, `double-payment entry ${double.info.entryId} is for invoice ${hash}, but no other invoice fulfilled order ${invoice.orderId}`, hash);
    }
    if (settlement !== undefined && double.amount !== settlement.amount) {
      flag(suspense, double.info, `double-payment entry ${double.info.entryId} moves ${double.amount ?? 'an unreadable amount of'} msat; `
        + `the invoice's settlement ${settlement.amount ?? 'an unreadable amount'} msat`, hash);
    }
  }
}

type LndRead = { kind: 'read'; amounts: Map<string, Map<string, bigint>> } | { kind: 'unavailable' | 'incomplete'; detail: string };

/**
 * Reads a paged list to its end, at most MAX_PAGES full pages (MAX_PAGES * PAGE_SIZE items). A list
 * that fills every page is probed once more for a single item: only when one is there is it longer
 * than the bound (`false`).
 */
async function readPages<T>(list: (offset: bigint, max: number) => Promise<{ items: T[]; lastIndexOffset: bigint }>,
  take: (item: T) => void): Promise<boolean> {
  let offset = 0n;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const result = await list(offset, PAGE_SIZE);
    for (const item of result.items) take(item);
    if (result.items.length < PAGE_SIZE || result.lastIndexOffset <= offset) return true;
    offset = result.lastIndexOffset;
  }
  const beyond = await list(offset, 1);
  return beyond.items.length === 0 || beyond.lastIndexOffset <= offset;
}

/**
 * The payer's window in ListPayments: succeeded payments as net debits per account (at most the
 * page bound); only the hashes the store knows are compared.
 */
async function settledPayments(api: LndLedgerSource): Promise<LndRead> {
  const listPaymentsPage = api.listPaymentsPage?.bind(api);
  if (listPaymentsPage === undefined) return { kind: 'unavailable', detail: 'the LND source has no ListPayments (the payer\'s pay-only credential cannot list payments)' };
  const amounts = new Map<string, Map<string, bigint>>();
  const complete = await readPages(async (offset, max) => {
    const result = await listPaymentsPage(offset, max);
    return { items: result.payments, lastIndexOffset: result.lastIndexOffset };
  }, (payment: Payment) => {
    if (payment.status !== 'SUCCEEDED') return;
    const accounts = amounts.get(payment.paymentHash) ?? new Map<string, bigint>();
    add(accounts, ACCOUNT.walletOutgoing, -(payment.valueMsat + payment.feeMsat));
    add(accounts, ACCOUNT.routingFees, payment.feeMsat);
    amounts.set(payment.paymentHash, accounts);
  });
  return complete ? { kind: 'read', amounts } : { kind: 'incomplete', detail: `ListPayments has more than ${MAX_PAGES * PAGE_SIZE} payments; not compared` };
}

/** The receiver's window in ListInvoices: settled invoices as net debits of lnd-wallet-incoming; only known hashes are compared. */
async function settledInvoices(api: LndLedgerSource): Promise<LndRead> {
  const listInvoicesPage = api.listInvoicesPage?.bind(api);
  if (listInvoicesPage === undefined) return { kind: 'unavailable', detail: 'the LND source has no ListInvoices' };
  const amounts = new Map<string, Map<string, bigint>>();
  const complete = await readPages(async (offset, max) => {
    const result = await listInvoicesPage(offset, max);
    return { items: result.invoices, lastIndexOffset: result.lastIndexOffset };
  }, (invoice: Invoice) => {
    if (invoice.state !== 'SETTLED') return;
    const accounts = amounts.get(invoice.paymentHash) ?? new Map<string, bigint>();
    add(accounts, ACCOUNT.walletIncoming, invoice.amtPaidMsat);
    amounts.set(invoice.paymentHash, accounts);
  });
  return complete ? { kind: 'read', amounts } : { kind: 'incomplete', detail: `ListInvoices has more than ${MAX_PAGES * PAGE_SIZE} invoices; not compared` };
}
