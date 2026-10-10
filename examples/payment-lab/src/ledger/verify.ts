import type { DatabaseSync } from 'node:sqlite';
import { describeError } from '../lnd/errors.ts';
import type { Invoice, Payment } from '../lnd/types.ts';
import { int, optionalInt, optionalText, text, type Row } from '../store/sqlite.ts';
import { MAX_INT64 } from '../util/money.ts';
import { ACCOUNT, budgetAccount, budgetOf, counterAccountFor, isAccount } from './accounts.ts';
import { parseBalance, signed, type Direction, type Leg } from './journal.ts';

/**
 * `ledger verify`: the balance theorem, checked.
 *
 * 1. Every entry balances (debits equal credits, every line a readable amount in 0 to 2^63 - 1
 *    on an account in the chart, with a debit and a credit line), and is well formed: an event
 *    this book posts, with the lines its posting rule prescribes (accounts, directions, legs,
 *    line numbers 1..n, each debit/credit pair equal), a reference of the event's shape, an
 *    operation and payment hash that agree with the records, an origin `live` or `migrated`, a
 *    readable posted_at that never decreases from one live entry to the next (migrated entries,
 *    which keep their 1.2 times, all come first).
 * 2. Every account's balance recomputed from the entries equals the stored running balance
 *    (the balances table, and each line's balance_after on the way); every balances row is an
 *    account in the chart with a canonical decimal balance, last_entry_id the last entry that
 *    touches the account and updated_at that entry's posted_at.
 * 3. The payer's book agrees with its own records, record by record: each reservation's budget
 *    entries commit what the reservation holds or consumed, each succeeded payment has its
 *    payment-succeeded entry with the record's value and fee, and nothing else posts to the
 *    wallet or fee accounts. A difference here unbalances the result even when the account
 *    totals happen to agree.
 * 4. With an LND source, the wallet and fee accounts agree with LND over the same window, the
 *    payment hashes this store knows: settled invoices' amt_paid_msat (ListInvoices) for the
 *    receiver, succeeded payments' value_msat and fee_msat (ListPayments) for the payer. Both
 *    lists are paged and bounded; a list longer than the bound is reported `incomplete`.
 *
 * Every difference is listed per account with the first entry (lowest entry ID) that explains
 * it. All sums are bigints computed here; SQLite only reads rows. Run it when the component is
 * quiet: a payment that succeeds in LND between the read of the store and the read of LND is
 * reported, as `pending` (the record is still unresolved), not as a difference.
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
  unbalancedEntries: UnbalancedEntry[];
  invalidEntries: InvalidEntry[];
  accounts: AccountReport[];
  lnd: LndComparison;
  lndDetail?: string;
  firstDifference?: Explanation;
}

const PAGE_SIZE = 500;
const MAX_PAGES = 200;
const UNRESOLVED_PAYMENT = new Set(['intent', 'submitting', 'in_flight', 'uncertain', 'failed']);
const PAYMENT_HASH = /^[0-9a-f]{64}$/;
const RESERVATION_REFERENCE = /^reservation:([1-9][0-9]*)$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
const BOOK_EVENTS: Record<'payer' | 'receiver', ReadonlySet<string>> = {
  payer: new Set(['payment-succeeded', 'double-payment', 'budget-held', 'budget-released', 'budget-consumed']),
  receiver: new Set(['invoice-settled', 'underpaid-settlement', 'double-payment']),
};
const COUNTER_ACCOUNTS: ReadonlySet<string> = new Set([ACCOUNT.customerReceivable, ACCOUNT.refundsPayable, ACCOUNT.payoutsPayable]);

interface EntryInfo {
  entryId: number;
  event: string;
  reference: string;
  paymentHash: string | undefined;
  operationId: string | undefined;
  origin: string | undefined;
  postedAt: string | undefined;
}

interface Line { lineNo: number | undefined; account: string; direction: Direction; amountMsat: bigint; leg: string | undefined;
  balanceAfter: bigint | undefined }

/** One line of a posting rule: the account, the direction and the legacy leg name (or none). */
interface Slot { account: string; direction: Direction; leg?: Leg }

/**
 * Keeps, per account, the explanation with the lowest entry ID; one without an entry only when
 * there is none, and then the first that names a payment hash (it is more specific).
 */
class Explanations {
  readonly #byAccount = new Map<string, Explanation>();

  offer(explanation: Explanation): void {
    const known = this.#byAccount.get(explanation.account);
    const earlier = explanation.entryId !== undefined && (known?.entryId === undefined || explanation.entryId < known.entryId);
    const moreSpecific = explanation.entryId === undefined && known?.entryId === undefined && known?.paymentHash === undefined
      && explanation.paymentHash !== undefined;
    if (known === undefined || earlier || moreSpecific) {
      this.#byAccount.set(explanation.account, explanation);
    }
  }

  get(account: string): Explanation | undefined {
    return this.#byAccount.get(account);
  }
}

function explain(account: string, entry: EntryInfo | undefined, reason: string, paymentHash?: string): Explanation {
  const hash = entry?.paymentHash ?? paymentHash;
  const named = entry === undefined ? {} : { entryId: entry.entryId, event: entry.event, reference: entry.reference };
  return { account, ...named, ...(hash === undefined ? {} : { paymentHash: hash }), reason };
}

function add(map: Map<string, bigint>, key: string, value: bigint): void {
  map.set(key, (map.get(key) ?? 0n) + value);
}

/** A text column, or undefined for NULL or any other type (a damaged row is reported, never coerced). */
function textOf(row: Row, column: string): string | undefined {
  const value = row[column];
  return typeof value === 'string' ? value : undefined;
}

/** An integer column, or undefined. */
function intOf(row: Row, column: string): bigint | undefined {
  try { return int(row, column); } catch { return undefined; }
}

/** Reads every entry, line and stored balance in one read transaction (a consistent snapshot under WAL). */
function snapshot(db: DatabaseSync, book: 'payer' | 'receiver'): { entries: Row[]; lines: Row[]; balances: Row[]; budgets: Row[];
  reservations: Row[]; records: Row[] } {
  db.exec('BEGIN');
  try {
    return {
      entries: db.prepare('SELECT * FROM journal_entries ORDER BY entry_id').all(),
      lines: db.prepare('SELECT * FROM journal_lines ORDER BY entry_id, line_no').all(),
      balances: db.prepare('SELECT * FROM balances ORDER BY account').all(),
      budgets: book === 'payer' ? db.prepare('SELECT budget_id FROM budgets ORDER BY budget_id').all() : [],
      reservations: book === 'payer' ? db.prepare('SELECT * FROM reservations ORDER BY reservation_id').all() : [],
      records: book === 'payer'
        ? db.prepare(`SELECT p.payment_hash, p.operation_id, p.state, p.value_msat, p.fee_msat, o.kind FROM payments p
            LEFT JOIN operations o ON o.operation_id = p.operation_id ORDER BY p.rowid`).all()
        : db.prepare('SELECT payment_hash, order_id, state, late_lnd_state FROM invoices ORDER BY rowid').all(),
    };
  } finally {
    db.exec('COMMIT');
  }
}

/** A line's fields, or why it can not be read (a damaged row is reported, never coerced). */
function readLine(row: Row): Line | { problem: string } {
  try {
    const account = text(row, 'account');
    const direction = text(row, 'direction');
    const amountMsat = int(row, 'amount_msat');
    if (direction !== 'debit' && direction !== 'credit') return { problem: `direction ${JSON.stringify(direction)} is neither debit nor credit` };
    if (!isAccount(account)) return { problem: `account ${JSON.stringify(account)} is not in the chart of accounts` };
    if (amountMsat < 0n || amountMsat > MAX_INT64) return { problem: `amount ${amountMsat} msat is outside 0 to 2^63 - 1` };
    let balanceAfter: bigint | undefined;
    try { balanceAfter = parseBalance(text(row, 'balance_after')); } catch { balanceAfter = undefined; }
    const lineNo = intOf(row, 'line_no');
    return { lineNo: lineNo === undefined ? undefined : Number(lineNo), account, direction, amountMsat, leg: textOf(row, 'leg'), balanceAfter };
  } catch (error) {
    return { problem: error instanceof Error ? error.message : String(error) };
  }
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
interface ReservationView { budgetId: string; operationId: string; paymentHash: string; state: string; principal: bigint; allowance: bigint }

/**
 * The structural problems of one entry against its posting rule and the records. `lines` are the
 * entry's readable lines in line-number order.
 */
function entryProblems(info: EntryInfo, lines: Line[], book: 'payer' | 'receiver', payments: Map<string, PaymentRecordView>,
  invoices: Map<string, Row>, reservations: Map<string, ReservationView>, referencesWithEvent: Set<string>): string[] {
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
    const reservation = match === null ? undefined : reservations.get(match[1] as string);
    if (match === null) problems.push(`reference ${JSON.stringify(info.reference)} is not reservation:<id>`);
    else if (reservation === undefined) problems.push(`reservation ${match[1]} does not exist`);
    let budget: string | undefined;
    if (reservation !== undefined) {
      budget = budgetAccount(reservation.budgetId);
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
      const record = info.paymentHash === undefined ? undefined : payments.get(info.paymentHash);
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
      if (info.event === 'double-payment' && info.paymentHash !== undefined && !referencesWithEvent.has(`payment-succeeded ${info.paymentHash}`)) {
        problems.push('the payment has no payment-succeeded entry');
      }
      if (counter !== undefined) {
        alternatives = info.event === 'payment-succeeded'
          ? [[{ account: counter, direction: 'debit', leg: 'principal' }, { account: ACCOUNT.walletOutgoing, direction: 'credit' },
            { account: ACCOUNT.routingFees, direction: 'debit', leg: 'routing-fee' }, { account: ACCOUNT.walletOutgoing, direction: 'credit' }]]
          : [[{ account: ACCOUNT.suspenseDoublePayment, direction: 'debit' }, { account: counter, direction: 'credit' }]];
      }
    } else {
      const record = info.paymentHash === undefined ? undefined : invoices.get(info.paymentHash);
      if (record === undefined) problems.push(`no invoice record has payment hash ${info.paymentHash ?? 'null'}`);
      else if (textOf(record, 'order_id') !== info.operationId) {
        problems.push(`operation_id ${JSON.stringify(info.operationId ?? null)} is not the invoice's order ${textOf(record, 'order_id') ?? 'null'}`);
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

export async function verifyLedger(store: LedgerStore, api?: LndLedgerSource): Promise<LedgerVerification> {
  const data = snapshot(store.db, store.book);
  const explanations = new Explanations();
  const unbalancedEntries: UnbalancedEntry[] = [];
  const invalidEntries: InvalidEntry[] = [];
  /** Accounts with a difference the account totals alone need not show (a line, a row, a record, an entry's shape). */
  const flagged = new Set<string>();
  const flag = (account: string, entry: EntryInfo | undefined, reason: string, paymentHash?: string): void => {
    flagged.add(account);
    explanations.offer(explain(account, entry, reason, paymentHash));
  };
  const computed = new Map<string, bigint>();
  /** Net debit per payment hash and account, for matching the records and LND hash by hash. */
  const byHash = new Map<string, Map<string, bigint>>();
  const byReference = new Map<string, bigint>();
  /** The first entry of a payment hash that touches an account, keyed `<hash> <account>`. */
  const firstEntryOfHash = new Map<string, EntryInfo>();
  const firstEntryOfReference = new Map<string, EntryInfo>();
  /** The last entry with a line on each account, for the balances row's last_entry_id. */
  const lastEntryOf = new Map<string, EntryInfo>();
  const entryInfo = new Map<number, EntryInfo>();
  for (const row of data.entries) {
    const info: EntryInfo = { entryId: Number(int(row, 'entry_id')), event: textOf(row, 'event') ?? 'unknown', reference: textOf(row, 'reference') ?? 'unknown',
      paymentHash: textOf(row, 'payment_hash'), operationId: textOf(row, 'operation_id'), origin: textOf(row, 'origin'), postedAt: textOf(row, 'posted_at') };
    entryInfo.set(info.entryId, info);
  }
  const linesOf = new Map<number, Row[]>();
  for (const row of data.lines) {
    const entryId = Number(int(row, 'entry_id'));
    const list = linesOf.get(entryId) ?? [];
    list.push(row);
    linesOf.set(entryId, list);
  }
  // Lines whose entry row is gone: their money is in the stored balances, so they are reported.
  for (const [entryId, rows] of linesOf) {
    if (entryInfo.has(entryId)) continue;
    const orphan: EntryInfo = { entryId, event: 'unknown', reference: 'unknown', paymentHash: undefined, operationId: undefined, origin: undefined,
      postedAt: undefined };
    unbalancedEntries.push({ entryId, event: orphan.event, reference: orphan.reference, debitsMsat: 0n, creditsMsat: 0n,
      reason: `${rows.length} line(s) belong to entry ${entryId}, which does not exist` });
    for (const row of rows) {
      const line = readLine(row);
      if (!('problem' in line)) explanations.offer(explain(line.account, orphan, `entry ${entryId} is missing but has lines`));
    }
  }

  // The records, by payment hash and by reservation ID, for the entries' structural checks.
  const payments = new Map<string, PaymentRecordView>();
  const invoices = new Map<string, Row>();
  if (store.book === 'payer') {
    for (const row of data.records) {
      payments.set(text(row, 'payment_hash'), { operationId: textOf(row, 'operation_id'), state: text(row, 'state'), kind: textOf(row, 'kind') });
    }
  } else {
    for (const row of data.records) invoices.set(text(row, 'payment_hash'), row);
  }
  const reservations = new Map<string, ReservationView>();
  for (const row of data.reservations) {
    reservations.set(String(row.reservation_id), { budgetId: text(row, 'budget_id'), operationId: text(row, 'operation_id'),
      paymentHash: text(row, 'payment_hash'), state: text(row, 'state'), principal: int(row, 'principal_msat'), allowance: int(row, 'fee_allowance_msat') });
  }
  const referencesWithEvent = new Set([...entryInfo.values()].map(info => `${info.event} ${info.reference}`));

  const running = new Map<string, bigint>();
  let lastLive: EntryInfo | undefined;
  let lastLiveTime = -Infinity;
  for (const info of entryInfo.values()) {
    const rows = linesOf.get(info.entryId) ?? [];
    let debits = 0n;
    let credits = 0n;
    const problems: string[] = [];
    const lines = rows.map(row => ({ row, line: readLine(row) }));
    for (const { row, line } of lines) {
      if ('problem' in line) { problems.push(`line ${String(row.line_no)}: ${line.problem}`); continue; }
      if (line.direction === 'debit') debits += line.amountMsat; else credits += line.amountMsat;
    }
    const readable = lines.flatMap(item => 'problem' in item.line ? [] : [item.line]);
    if (!readable.some(line => line.direction === 'debit') || !readable.some(line => line.direction === 'credit')) {
      problems.push('the entry needs a debit and a credit line');
    }
    if (debits !== credits) problems.push(`debits ${debits} msat differ from credits ${credits} msat`);
    if (problems.length > 0) {
      const reason = `entry ${info.entryId} (${info.event} ${info.reference}) is unbalanced: ${problems.join('; ')}`;
      unbalancedEntries.push({ entryId: info.entryId, event: info.event, reference: info.reference, debitsMsat: debits, creditsMsat: credits, reason });
      for (const line of readable) explanations.offer(explain(line.account, info, reason));
    }

    // The entry's shape: its posting rule, its reference and its agreement with the records; its time.
    const shape = problems.length > 0 && readable.length < rows.length ? []
      : entryProblems(info, readable, store.book, payments, invoices, reservations, referencesWithEvent);
    const time = info.postedAt !== undefined && ISO_TIME.test(info.postedAt) ? Date.parse(info.postedAt) : Number.NaN;
    if (Number.isNaN(time)) shape.push(`posted_at ${JSON.stringify(info.postedAt ?? null)} is not an ISO 8601 UTC time`);
    if (info.origin === 'migrated' && lastLive !== undefined) {
      shape.push(`it is migrated but follows live entry ${lastLive.entryId} (migrated entries are posted before any live one)`);
    } else if (info.origin === 'live' && !Number.isNaN(time)) {
      if (time < lastLiveTime && lastLive !== undefined) shape.push(`posted_at ${info.postedAt ?? ''} is earlier than live entry ${lastLive.entryId}'s ${lastLive.postedAt ?? ''}`);
      lastLive = info;
      lastLiveTime = Math.max(lastLiveTime, time);
    } else if (info.origin === 'live') {
      lastLive = info;
    }
    if (shape.length > 0) {
      const reason = `entry ${info.entryId} (${info.event} ${info.reference}) is malformed: ${shape.join('; ')}`;
      invalidEntries.push({ entryId: info.entryId, event: info.event, reference: info.reference, reason });
      for (const line of readable) flag(line.account, info, reason);
    }

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
      if (info.paymentHash !== undefined) {
        const accounts = byHash.get(info.paymentHash) ?? new Map<string, bigint>();
        add(accounts, line.account, value);
        byHash.set(info.paymentHash, accounts);
        const key = `${info.paymentHash} ${line.account}`;
        if (!firstEntryOfHash.has(key)) firstEntryOfHash.set(key, info);
      }
      if (info.reference.startsWith('reservation:') && line.account.startsWith('budget:')) {
        add(byReference, info.reference, value);
        if (!firstEntryOfReference.has(info.reference)) firstEntryOfReference.set(info.reference, info);
      }
    }
  }

  const stored = new Map<string, bigint>();
  for (const row of data.balances) {
    const account = textOf(row, 'account') ?? String(row.account);
    const raw = textOf(row, 'balance_msat');
    let value = 0n;
    let readableBalance = true;
    try {
      value = parseBalance(raw ?? '');
    } catch {
      readableBalance = false;
      flag(account, undefined, `the balances row of ${account} is corrupt: balance_msat ${JSON.stringify(raw ?? row.balance_msat ?? null)} is not a canonical `
        + `decimal ('0' or -?[1-9][0-9]*), so every later posting to ${account} fails`);
    }
    stored.set(account, value);
    if (!isAccount(account)) flag(account, undefined, `the balances table has a row for ${JSON.stringify(account)}, which is not in the chart of accounts`);
    const last = lastEntryOf.get(account);
    const lastId = intOf(row, 'last_entry_id');
    if (last !== undefined && lastId !== BigInt(last.entryId)) {
      flag(account, last, `the balances row of ${account} names entry ${String(row.last_entry_id)} as the last to move it; the last entry with a line on it is ${last.entryId}`);
    } else if (last === undefined && lastId !== undefined) {
      flag(account, undefined, `the balances row of ${account} names entry ${lastId} as the last to move it; no entry has a line on it`);
    }
    if (last !== undefined && textOf(row, 'updated_at') !== last.postedAt) {
      flag(account, last, `the balances row of ${account} was updated at ${JSON.stringify(row.updated_at ?? null)}; entry ${last.entryId}, the last to move it, `
        + `was posted at ${last.postedAt ?? 'null'}`);
    }
    if (readableBalance && (computed.get(account) ?? 0n) !== value) {
      // A stored balance no entry explains (the balances row itself was changed), named by the entry that last moved it.
      const moved = lastId === undefined ? undefined : entryInfo.get(Number(lastId));
      explanations.offer(explain(account, undefined, `the stored balance ${value} msat differs from the entries' ${computed.get(account) ?? 0n} msat; `
        + `entry ${String(row.last_entry_id)}${moved === undefined ? '' : ` (${moved.event} ${moved.reference})`} last moved it`));
    }
  }
  for (const [account, value] of computed) {
    if (!stored.has(account) && value !== 0n) explanations.offer({ account, reason: `the entries move ${account} but it has no stored balance` });
  }

  // 3. The payer's own records, record by record.
  const records = new Map<string, bigint>();
  if (store.book === 'payer') {
    for (const row of data.budgets) records.set(budgetAccount(text(row, 'budget_id')), 0n);
    records.set(ACCOUNT.budgetCommitments, 0n);
    for (const row of data.reservations) {
      const state = text(row, 'state');
      const committed = state === 'held' ? int(row, 'principal_msat') + int(row, 'fee_allowance_msat')
        : state === 'consumed' ? int(row, 'principal_msat') + (optionalInt(row, 'actual_fee_msat') ?? 0n) : 0n;
      const account = budgetAccount(text(row, 'budget_id'));
      add(records, account, committed);
      add(records, ACCOUNT.budgetCommitments, -committed);
      const reference = `reservation:${String(row.reservation_id)}`;
      const posted = byReference.get(reference) ?? 0n;
      if (posted !== committed) {
        const reason = `reservation ${String(row.reservation_id)} is ${state} for ${committed} msat; its entries commit ${posted} msat`;
        const first = firstEntryOfReference.get(reference);
        flag(account, first, reason, text(row, 'payment_hash'));
        flag(ACCOUNT.budgetCommitments, first, reason, text(row, 'payment_hash'));
      }
    }
    records.set(ACCOUNT.walletOutgoing, 0n);
    records.set(ACCOUNT.routingFees, 0n);
    for (const row of data.records) {
      const hash = text(row, 'payment_hash');
      const state = text(row, 'state');
      const succeeded = state === 'succeeded';
      const value = succeeded ? optionalInt(row, 'value_msat') ?? 0n : 0n;
      const fee = succeeded ? optionalInt(row, 'fee_msat') ?? 0n : 0n;
      add(records, ACCOUNT.walletOutgoing, -(value + fee));
      add(records, ACCOUNT.routingFees, fee);
      if (succeeded && !referencesWithEvent.has(`payment-succeeded ${hash}`)) {
        flag(ACCOUNT.walletOutgoing, undefined, `payment ${hash} is succeeded in the record but has no payment-succeeded entry`, hash);
      }
      const posted = byHash.get(hash);
      for (const [account, expected] of [[ACCOUNT.walletOutgoing, -(value + fee)], [ACCOUNT.routingFees, fee]] as const) {
        const actual = posted?.get(account) ?? 0n;
        if (actual !== expected) {
          flag(account, firstEntryOfHash.get(`${hash} ${account}`), `payment ${hash} is ${state} with value ${value} msat and `
            + `fee ${fee} msat in the record; its entries post ${actual} msat to ${account}`, hash);
        }
      }
    }
  }

  // 4. LND over the same window.
  const lnd = new Map<string, bigint>();
  let comparison: LndComparison = 'not-requested';
  let lndDetail: string | undefined;
  let lndDifferent = false;
  if (api !== undefined) {
    const known = new Map(data.records.map(row => [text(row, 'payment_hash'), row]));
    try {
      const read = store.book === 'payer' ? await settledPayments(api, known) : await settledInvoices(api, known);
      if (read.kind !== 'read') {
        comparison = read.kind;
        lndDetail = read.detail;
      } else {
        comparison = 'compared';
        const accounts = store.book === 'payer' ? [ACCOUNT.walletOutgoing, ACCOUNT.routingFees] : [ACCOUNT.walletIncoming];
        for (const account of accounts) lnd.set(account, 0n);
        const hashes = new Set([...read.amounts.keys(), ...[...byHash.keys()].filter(hash => known.has(hash))]);
        let pending = 0;
        for (const hash of hashes) {
          const reported = read.amounts.get(hash) ?? new Map<string, bigint>();
          for (const account of accounts) {
            const expected = reported.get(account) ?? 0n;
            add(lnd, account, expected);
            const posted = byHash.get(hash)?.get(account) ?? 0n;
            if (posted === expected) continue;
            const row = known.get(hash);
            const state = row === undefined ? 'unknown' : text(row, 'state');
            const unresolved = posted === 0n && (store.book === 'payer' ? UNRESOLVED_PAYMENT.has(state)
              : state !== 'settled' && (row === undefined || optionalText(row, 'late_lnd_state') !== 'SETTLED'));
            if (unresolved) { pending += 1; continue; }
            lndDifferent = true;
            explanations.offer(explain(account, firstEntryOfHash.get(`${hash} ${account}`), `LND reports ${expected} msat for ${account} on payment hash ${hash}; `
              + `the entries post ${posted} msat (record ${state})`, hash));
          }
        }
        if (pending > 0 && !lndDifferent) {
          comparison = 'pending';
          lndDetail = `${pending} amount(s) LND reports are not recorded yet: the records are unresolved; reconcile, then verify again`;
        }
      }
    } catch (error) {
      comparison = 'unavailable';
      lndDetail = describeError(error);
    }
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
  const unbalancedIds = new Set(unbalancedEntries.map(entry => entry.entryId));
  for (const report of accounts) {
    const explanation = explanations.get(report.account);
    const differs = report.difference !== 0n || (report.recordsDifference ?? 0n) !== 0n || flagged.has(report.account)
      || (comparison === 'compared' && (report.lndDifference ?? 0n) !== 0n)
      || (explanation?.entryId !== undefined && unbalancedIds.has(explanation.entryId));
    if (differs && explanation !== undefined) report.firstEntry = explanation;
  }
  // The lowest entry ID first; among explanations naming one entry, an account whose balance itself differs first.
  const own = (report: AccountReport): number => report.difference !== 0n || (report.recordsDifference ?? 0n) !== 0n
    || (report.lndDifference ?? 0n) !== 0n ? 0 : 1;
  const ranked = accounts.filter(report => report.firstEntry !== undefined)
    .sort((a, b) => (a.firstEntry?.entryId ?? Infinity) - (b.firstEntry?.entryId ?? Infinity) || own(a) - own(b));
  const differing = ranked.flatMap(report => report.firstEntry === undefined ? [] : [report.firstEntry]);
  const firstBroken = [...unbalancedEntries, ...invalidEntries].sort((a, b) => a.entryId - b.entryId)[0];
  const firstDifference = differing.find(item => item.entryId !== undefined)
    ?? differing.find(item => item.paymentHash !== undefined)
    ?? differing[0]
    ?? (firstBroken === undefined ? undefined : { account: '', entryId: firstBroken.entryId, event: firstBroken.event,
      reference: firstBroken.reference, reason: firstBroken.reason });
  const balanced = unbalancedEntries.length === 0 && invalidEntries.length === 0 && !lndDifferent && flagged.size === 0
    && accounts.every(report => report.difference === 0n && (report.recordsDifference ?? 0n) === 0n);
  return { book: store.book, balanced, entries: entryInfo.size, unbalancedEntries, invalidEntries, accounts, lnd: comparison,
    ...(lndDetail === undefined ? {} : { lndDetail }), ...(firstDifference === undefined ? {} : { firstDifference }) };
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

/** The payer's window in ListPayments: succeeded payments whose hash the store knows, as net debits per account. */
async function settledPayments(api: LndLedgerSource, known: Map<string, Row>): Promise<LndRead> {
  const listPaymentsPage = api.listPaymentsPage?.bind(api);
  if (listPaymentsPage === undefined) return { kind: 'unavailable', detail: 'the LND source has no ListPayments (the payer\'s pay-only credential cannot list payments)' };
  const amounts = new Map<string, Map<string, bigint>>();
  const complete = await readPages(async (offset, max) => {
    const result = await listPaymentsPage(offset, max);
    return { items: result.payments, lastIndexOffset: result.lastIndexOffset };
  }, (payment: Payment) => {
    if (payment.status !== 'SUCCEEDED' || !known.has(payment.paymentHash)) return;
    const accounts = amounts.get(payment.paymentHash) ?? new Map<string, bigint>();
    add(accounts, ACCOUNT.walletOutgoing, -(payment.valueMsat + payment.feeMsat));
    add(accounts, ACCOUNT.routingFees, payment.feeMsat);
    amounts.set(payment.paymentHash, accounts);
  });
  return complete ? { kind: 'read', amounts } : { kind: 'incomplete', detail: `ListPayments has more than ${MAX_PAGES * PAGE_SIZE} payments; not compared` };
}

/** The receiver's window in ListInvoices: settled invoices whose hash the store knows, as net debits of lnd-wallet-incoming. */
async function settledInvoices(api: LndLedgerSource, known: Map<string, Row>): Promise<LndRead> {
  const listInvoicesPage = api.listInvoicesPage?.bind(api);
  if (listInvoicesPage === undefined) return { kind: 'unavailable', detail: 'the LND source has no ListInvoices' };
  const amounts = new Map<string, Map<string, bigint>>();
  const complete = await readPages(async (offset, max) => {
    const result = await listInvoicesPage(offset, max);
    return { items: result.invoices, lastIndexOffset: result.lastIndexOffset };
  }, (invoice: Invoice) => {
    if (invoice.state !== 'SETTLED' || !known.has(invoice.paymentHash)) return;
    const accounts = amounts.get(invoice.paymentHash) ?? new Map<string, bigint>();
    add(accounts, ACCOUNT.walletIncoming, invoice.amtPaidMsat);
    amounts.set(invoice.paymentHash, accounts);
  });
  return complete ? { kind: 'read', amounts } : { kind: 'incomplete', detail: `ListInvoices has more than ${MAX_PAGES * PAGE_SIZE} invoices; not compared` };
}
