import type { DatabaseSync } from 'node:sqlite';
import { describeError } from '../lnd/errors.ts';
import type { Invoice, Payment } from '../lnd/types.ts';
import { int, optionalInt, optionalText, text, type Row } from '../store/sqlite.ts';
import { MAX_INT64 } from '../util/money.ts';
import { ACCOUNT, budgetAccount, isAccount } from './accounts.ts';
import { parseBalance, signed, type Direction } from './journal.ts';

/**
 * `ledger verify`: the balance theorem, checked.
 *
 * 1. Every entry balances (debits equal credits, every line a readable amount in 0 to 2^63 - 1
 *    on an account in the chart, with a debit and a credit line).
 * 2. Every account's balance recomputed from the entries equals the stored running balance
 *    (the balances table, and each line's balance_after on the way).
 * 3. The payer's book agrees with its own records: each budget account equals that budget's
 *    held plus consumed reservations, and the wallet and fee accounts equal the succeeded
 *    payments' value and fee.
 * 4. With an LND source, the wallet and fee accounts agree with LND over the same window, the
 *    payment hashes this store knows: settled invoices' amt_paid_msat (ListInvoices) for the
 *    receiver, succeeded payments' value_msat and fee_msat (ListPayments) for the payer. Both
 *    lists are paged and bounded; a list not read to its end is reported `incomplete`.
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
  /** Net debit in the balances table (0 when the account has no row). */
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

/**
 * - compared        LND was read to the end of the window and every difference is listed
 * - pending         as compared, but LND reports a payment or settlement the record has not learned yet
 *                   (it is unresolved; reconcile first): exit 75
 * - not-requested   no LND source was passed
 * - unavailable     the source lacks the list call, or the call failed (lndDetail says why)
 * - incomplete      the list had more pages than the bound
 */
export type LndComparison = 'compared' | 'pending' | 'not-requested' | 'unavailable' | 'incomplete';

export interface LedgerVerification {
  book: 'payer' | 'receiver';
  balanced: boolean;
  entries: number;
  unbalancedEntries: UnbalancedEntry[];
  accounts: AccountReport[];
  lnd: LndComparison;
  lndDetail?: string;
  firstDifference?: Explanation;
}

const PAGE_SIZE = 500;
const MAX_PAGES = 200;
const UNRESOLVED_PAYMENT = new Set(['intent', 'submitting', 'in_flight', 'uncertain', 'failed']);

interface EntryInfo { entryId: number; event: string; reference: string; paymentHash: string | undefined }

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
        ? db.prepare('SELECT payment_hash, state, value_msat, fee_msat FROM payments ORDER BY rowid').all()
        : db.prepare('SELECT payment_hash, state, late_lnd_state FROM invoices ORDER BY rowid').all(),
    };
  } finally {
    db.exec('COMMIT');
  }
}

/** A line's fields, or why it can not be read (a damaged row is reported, never coerced). */
function readLine(row: Row): { account: string; direction: Direction; amountMsat: bigint; balanceAfter: bigint | undefined } | { problem: string } {
  try {
    const account = text(row, 'account');
    const direction = text(row, 'direction');
    const amountMsat = int(row, 'amount_msat');
    if (direction !== 'debit' && direction !== 'credit') return { problem: `direction ${JSON.stringify(direction)} is neither debit nor credit` };
    if (!isAccount(account)) return { problem: `account ${JSON.stringify(account)} is not in the chart of accounts` };
    if (amountMsat < 0n || amountMsat > MAX_INT64) return { problem: `amount ${amountMsat} msat is outside 0 to 2^63 - 1` };
    let balanceAfter: bigint | undefined;
    try { balanceAfter = parseBalance(text(row, 'balance_after')); } catch { balanceAfter = undefined; }
    return { account, direction, amountMsat, balanceAfter };
  } catch (error) {
    return { problem: error instanceof Error ? error.message : String(error) };
  }
}

export async function verifyLedger(store: LedgerStore, api?: LndLedgerSource): Promise<LedgerVerification> {
  const data = snapshot(store.db, store.book);
  const explanations = new Explanations();
  const unbalancedEntries: UnbalancedEntry[] = [];
  const computed = new Map<string, bigint>();
  /** Net debit per payment hash and account, for matching the records and LND hash by hash. */
  const byHash = new Map<string, Map<string, bigint>>();
  const byReference = new Map<string, bigint>();
  const firstEntryOfHash = new Map<string, EntryInfo>();
  const firstEntryOfReference = new Map<string, EntryInfo>();
  const entryInfo = new Map<number, EntryInfo>();
  for (const row of data.entries) {
    const info = { entryId: Number(int(row, 'entry_id')), event: text(row, 'event'), reference: text(row, 'reference'),
      paymentHash: optionalText(row, 'payment_hash') };
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
    const orphan = { entryId, event: 'unknown', reference: 'unknown', paymentHash: undefined };
    unbalancedEntries.push({ entryId, event: orphan.event, reference: orphan.reference, debitsMsat: 0n, creditsMsat: 0n,
      reason: `${rows.length} line(s) belong to entry ${entryId}, which does not exist` });
    for (const row of rows) {
      const line = readLine(row);
      if (!('problem' in line)) explanations.offer(explain(line.account, orphan, `entry ${entryId} is missing but has lines`));
    }
  }

  const running = new Map<string, bigint>();
  /** Accounts with a line whose recorded running balance disagrees with the recomputed one. */
  const runningMismatch = new Set<string>();
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
      unbalancedEntries.push({ ...info, debitsMsat: debits, creditsMsat: credits, reason });
      for (const line of readable) explanations.offer(explain(line.account, info, reason));
    }
    for (const line of readable) {
      const value = signed(line.direction, line.amountMsat);
      add(computed, line.account, value);
      const after = (running.get(line.account) ?? 0n) + value;
      running.set(line.account, after);
      if (line.balanceAfter !== after) {
        runningMismatch.add(line.account);
        explanations.offer(explain(line.account, info, line.balanceAfter === undefined
          ? `entry ${info.entryId}: the line's recorded running balance is unreadable`
          : `entry ${info.entryId}: recomputed from the entries, ${line.account} is ${after} msat after this line; the line recorded ${line.balanceAfter} msat`));
      }
      if (info.paymentHash !== undefined) {
        const accounts = byHash.get(info.paymentHash) ?? new Map<string, bigint>();
        add(accounts, line.account, value);
        byHash.set(info.paymentHash, accounts);
        if (!firstEntryOfHash.has(info.paymentHash)) firstEntryOfHash.set(info.paymentHash, info);
      }
      if (info.reference.startsWith('reservation:') && line.account.startsWith('budget:')) {
        add(byReference, info.reference, value);
        if (!firstEntryOfReference.has(info.reference)) firstEntryOfReference.set(info.reference, info);
      }
    }
  }

  const stored = new Map<string, bigint>();
  for (const row of data.balances) {
    const account = text(row, 'account');
    let value = 0n;
    try {
      value = parseBalance(text(row, 'balance_msat'));
    } catch {
      explanations.offer({ account, reason: `the balances row of ${account} is unreadable` });
    }
    stored.set(account, value);
    if ((computed.get(account) ?? 0n) !== value) {
      // A stored balance no entry explains (the balances row itself was changed), named by the entry that last moved it.
      const last = entryInfo.get(Number(int(row, 'last_entry_id')));
      explanations.offer(explain(account, undefined, `the stored balance ${value} msat differs from the entries' ${computed.get(account) ?? 0n} msat; `
        + `entry ${String(row.last_entry_id)}${last === undefined ? '' : ` (${last.event} ${last.reference})`} last moved it`));
    }
  }
  for (const [account, value] of computed) {
    if (!stored.has(account) && value !== 0n) explanations.offer({ account, reason: `the entries move ${account} but it has no stored balance` });
  }

  // 3. The payer's own records.
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
        explanations.offer(explain(account, first, reason, text(row, 'payment_hash')));
        explanations.offer(explain(ACCOUNT.budgetCommitments, first, reason, text(row, 'payment_hash')));
      }
    }
    records.set(ACCOUNT.walletOutgoing, 0n);
    records.set(ACCOUNT.routingFees, 0n);
    for (const row of data.records) {
      const hash = text(row, 'payment_hash');
      const succeeded = text(row, 'state') === 'succeeded';
      const value = succeeded ? optionalInt(row, 'value_msat') ?? 0n : 0n;
      const fee = succeeded ? optionalInt(row, 'fee_msat') ?? 0n : 0n;
      add(records, ACCOUNT.walletOutgoing, -(value + fee));
      add(records, ACCOUNT.routingFees, fee);
      const posted = byHash.get(hash);
      for (const [account, expected] of [[ACCOUNT.walletOutgoing, -(value + fee)], [ACCOUNT.routingFees, fee]] as const) {
        const actual = posted?.get(account) ?? 0n;
        if (actual !== expected) {
          explanations.offer(explain(account, firstEntryOfHash.get(hash), `payment ${hash} is ${text(row, 'state')} with value ${value} msat and `
            + `fee ${fee} msat in the record; its entries post ${actual} msat to ${account}`, hash));
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
            explanations.offer(explain(account, firstEntryOfHash.get(hash), `LND reports ${expected} msat for ${account} on payment hash ${hash}; `
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
  const names = new Set([...computed.keys(), ...stored.keys(), ...[...records].filter(([, value]) => value !== 0n).map(([key]) => key), ...lnd.keys()]);
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
    const differs = report.difference !== 0n || (report.recordsDifference ?? 0n) !== 0n || runningMismatch.has(report.account)
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
  const firstDifference = differing.find(item => item.entryId !== undefined)
    ?? differing.find(item => item.paymentHash !== undefined)
    ?? differing[0]
    ?? (unbalancedEntries[0] === undefined ? undefined : { account: '', entryId: unbalancedEntries[0].entryId, event: unbalancedEntries[0].event,
      reference: unbalancedEntries[0].reference, reason: unbalancedEntries[0].reason });
  const balanced = unbalancedEntries.length === 0 && !lndDifferent && runningMismatch.size === 0
    && accounts.every(report => report.difference === 0n && (report.recordsDifference ?? 0n) === 0n);
  return { book: store.book, balanced, entries: entryInfo.size, unbalancedEntries, accounts, lnd: comparison,
    ...(lndDetail === undefined ? {} : { lndDetail }), ...(firstDifference === undefined ? {} : { firstDifference }) };
}

type LndRead = { kind: 'read'; amounts: Map<string, Map<string, bigint>> } | { kind: 'unavailable' | 'incomplete'; detail: string };

/** The payer's window in ListPayments: succeeded payments whose hash the store knows, as net debits per account. */
async function settledPayments(api: LndLedgerSource, known: Map<string, Row>): Promise<LndRead> {
  if (api.listPaymentsPage === undefined) return { kind: 'unavailable', detail: 'the LND source has no ListPayments (the payer\'s pay-only credential cannot list payments)' };
  const amounts = new Map<string, Map<string, bigint>>();
  let offset = 0n;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const result = await api.listPaymentsPage(offset, PAGE_SIZE);
    for (const payment of result.payments) {
      if (payment.status !== 'SUCCEEDED' || !known.has(payment.paymentHash)) continue;
      const accounts = amounts.get(payment.paymentHash) ?? new Map<string, bigint>();
      add(accounts, ACCOUNT.walletOutgoing, -(payment.valueMsat + payment.feeMsat));
      add(accounts, ACCOUNT.routingFees, payment.feeMsat);
      amounts.set(payment.paymentHash, accounts);
    }
    if (result.payments.length < PAGE_SIZE || result.lastIndexOffset <= offset) return { kind: 'read', amounts };
    offset = result.lastIndexOffset;
  }
  return { kind: 'incomplete', detail: `ListPayments has more than ${MAX_PAGES * PAGE_SIZE} payments; not compared` };
}

/** The receiver's window in ListInvoices: settled invoices whose hash the store knows, as net debits of lnd-wallet-incoming. */
async function settledInvoices(api: LndLedgerSource, known: Map<string, Row>): Promise<LndRead> {
  if (api.listInvoicesPage === undefined) return { kind: 'unavailable', detail: 'the LND source has no ListInvoices' };
  const amounts = new Map<string, Map<string, bigint>>();
  let offset = 0n;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const result = await api.listInvoicesPage(offset, PAGE_SIZE);
    for (const invoice of result.invoices) {
      if (invoice.state !== 'SETTLED' || !known.has(invoice.paymentHash)) continue;
      const accounts = amounts.get(invoice.paymentHash) ?? new Map<string, bigint>();
      add(accounts, ACCOUNT.walletIncoming, invoice.amtPaidMsat);
      amounts.set(invoice.paymentHash, accounts);
    }
    if (result.invoices.length < PAGE_SIZE || result.lastIndexOffset <= offset) return { kind: 'read', amounts };
    offset = result.lastIndexOffset;
  }
  return { kind: 'incomplete', detail: `ListInvoices has more than ${MAX_PAGES * PAGE_SIZE} invoices; not compared` };
}
