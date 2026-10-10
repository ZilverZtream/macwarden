import type { DatabaseSync } from 'node:sqlite';
import { int, nowIso, optionalText, text } from '../store/sqlite.ts';
import { MAX_INT64 } from '../util/money.ts';
import { EVENTS, isAccount, type LedgerEvent } from './accounts.ts';

/**
 * The double-entry journal both stores keep (each in its own database file).
 *
 * - journal_entries  one row per event that moved or committed money, unique on (event, reference):
 *                    posting the same event twice inserts nothing, which is what makes every
 *                    settlement path idempotent
 * - journal_lines    the entry's legs: account, direction, a non-negative msat amount (int64), and
 *                    balance_after, the account's net-debit running balance after this line
 * - balances         each account's net-debit balance after the last line posted to it
 *
 * Running balances are kept as decimal text, not INTEGER: a sum of int64 amounts need not fit
 * in 64 bits, and SQLite's SUM fails and its + turns to floating point past 2^63. Every sum is
 * computed here, in JavaScript bigints. `post` must run inside the caller's BEGIN IMMEDIATE
 * transaction, the one that makes the state change, so the change and its entry commit together
 * or not at all.
 */

const EVENT_LIST = EVENTS.map(event => `'${event}'`).join(', ');

/** The schema step both stores' ledger migrations run first. */
export const JOURNAL_SCHEMA = `
CREATE TABLE IF NOT EXISTS journal_entries (
  entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL CHECK (event IN (${EVENT_LIST})),
  reference TEXT NOT NULL CHECK (length(reference) BETWEEN 1 AND 256),
  operation_id TEXT,
  payment_hash TEXT,
  origin TEXT NOT NULL CHECK (origin IN ('live', 'migrated')),
  posted_at TEXT NOT NULL,
  UNIQUE (event, reference)
);
CREATE INDEX IF NOT EXISTS journal_entries_by_operation ON journal_entries (operation_id);
CREATE INDEX IF NOT EXISTS journal_entries_by_payment ON journal_entries (payment_hash);
CREATE TABLE IF NOT EXISTS journal_lines (
  entry_id INTEGER NOT NULL REFERENCES journal_entries (entry_id),
  line_no INTEGER NOT NULL CHECK (line_no >= 1),
  account TEXT NOT NULL CHECK (length(account) BETWEEN 1 AND 160),
  direction TEXT NOT NULL CHECK (direction IN ('debit', 'credit')),
  amount_msat INTEGER NOT NULL CHECK (amount_msat >= 0),
  leg TEXT CHECK (leg IN ('principal', 'routing-fee', 'sale')),
  balance_after TEXT NOT NULL CHECK (length(balance_after) BETWEEN 1 AND 40 AND balance_after NOT GLOB '*[^0-9-]*'),
  PRIMARY KEY (entry_id, line_no)
);
CREATE INDEX IF NOT EXISTS journal_lines_by_account ON journal_lines (account);
CREATE TABLE IF NOT EXISTS balances (
  account TEXT PRIMARY KEY,
  balance_msat TEXT NOT NULL CHECK (length(balance_msat) BETWEEN 1 AND 40 AND balance_msat NOT GLOB '*[^0-9-]*'),
  last_entry_id INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
`;

export type Direction = 'debit' | 'credit';
/** The legacy view's name for a line (what the 1.2 ledger_entries rows called it), if it has one. */
export type Leg = 'principal' | 'routing-fee' | 'sale';

export interface PostingLine {
  account: string;
  direction: Direction;
  amountMsat: bigint;
  leg?: Leg;
}

export interface Posting {
  event: LedgerEvent;
  /** The idempotency key within the event: a payment hash, or `reservation:<id>`. */
  reference: string;
  operationId?: string;
  paymentHash?: string;
  lines: PostingLine[];
  origin?: 'live' | 'migrated';
  postedAt?: string;
}

/** A signed decimal balance as stored; anything else is a damaged row. */
export function parseBalance(value: string): bigint {
  if (!/^-?(0|[1-9][0-9]{0,38})$/.test(value) || value === '-0') throw new Error(`balance ${JSON.stringify(value)} is not a decimal integer`);
  return BigInt(value);
}

export function signed(direction: Direction, amountMsat: bigint): bigint {
  return direction === 'debit' ? amountMsat : -amountMsat;
}

/**
 * Posts one balanced journal entry and moves the running balances, in the caller's transaction.
 * Returns the entry ID, or undefined when (event, reference) was already posted (nothing changes).
 * Throws, rolling the caller's transaction back with the state change, for an entry that is not
 * balanced, has no debit or no credit line, names an account outside the chart, or carries an
 * amount outside 0 to 2^63 - 1.
 */
export function post(db: DatabaseSync, posting: Posting): number | undefined {
  if (!db.isTransaction) throw new Error('a journal entry is posted only inside the transaction of the state change that causes it');
  let debits = 0n;
  let credits = 0n;
  for (const line of posting.lines) {
    if (!isAccount(line.account)) throw new Error(`account ${JSON.stringify(line.account)} is not in the chart of accounts`);
    if (line.amountMsat < 0n || line.amountMsat > MAX_INT64) throw new Error(`amount ${line.amountMsat} msat is outside 0 to 2^63 - 1`);
    if (line.direction === 'debit') debits += line.amountMsat; else credits += line.amountMsat;
  }
  if (!posting.lines.some(line => line.direction === 'debit') || !posting.lines.some(line => line.direction === 'credit')) {
    throw new Error(`${posting.event} ${posting.reference}: an entry needs a debit and a credit line`);
  }
  if (debits !== credits) throw new Error(`${posting.event} ${posting.reference}: debits ${debits} msat differ from credits ${credits} msat`);
  const now = posting.postedAt ?? nowIso();
  const inserted = db.prepare(`INSERT INTO journal_entries (event, reference, operation_id, payment_hash, origin, posted_at)
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (event, reference) DO NOTHING`)
    .run(posting.event, posting.reference, posting.operationId ?? null, posting.paymentHash ?? null, posting.origin ?? 'live', now);
  if (Number(inserted.changes) !== 1) return undefined;
  const entryId = Number(inserted.lastInsertRowid);
  const running = new Map<string, bigint>();
  const balanceOf = (account: string): bigint => {
    const known = running.get(account);
    if (known !== undefined) return known;
    const row = db.prepare('SELECT balance_msat FROM balances WHERE account = ?').get(account);
    return row === undefined ? 0n : parseBalance(text(row, 'balance_msat'));
  };
  const line = db.prepare(`INSERT INTO journal_lines (entry_id, line_no, account, direction, amount_msat, leg, balance_after)
    VALUES (?, ?, ?, ?, ?, ?, ?)`);
  posting.lines.forEach((item, index) => {
    const after = balanceOf(item.account) + signed(item.direction, item.amountMsat);
    running.set(item.account, after);
    line.run(entryId, index + 1, item.account, item.direction, item.amountMsat, item.leg ?? null, after.toString());
  });
  const balance = db.prepare(`INSERT INTO balances (account, balance_msat, last_entry_id, updated_at) VALUES (?, ?, ?, ?)
    ON CONFLICT (account) DO UPDATE SET balance_msat = excluded.balance_msat, last_entry_id = excluded.last_entry_id,
      updated_at = excluded.updated_at`);
  for (const [account, value] of running) balance.run(account, value.toString(), entryId, now);
  return entryId;
}

export interface JournalLine {
  lineNo: number;
  account: string;
  direction: Direction;
  amountMsat: bigint;
  leg: Leg | undefined;
}

export interface JournalEntry {
  entryId: number;
  event: LedgerEvent;
  reference: string;
  operationId: string | undefined;
  paymentHash: string | undefined;
  origin: 'live' | 'migrated';
  postedAt: string;
  lines: JournalLine[];
}

/** The entries of one operation (payer) or order (receiver), with their lines, in posting order. */
export function entriesFor(db: DatabaseSync, operationId: string): JournalEntry[] {
  const entries = db.prepare('SELECT * FROM journal_entries WHERE operation_id = ? ORDER BY entry_id').all(operationId);
  const lines = db.prepare('SELECT * FROM journal_lines WHERE entry_id = ? ORDER BY line_no');
  return entries.map(row => ({
    entryId: Number(int(row, 'entry_id')),
    event: text(row, 'event') as LedgerEvent,
    reference: text(row, 'reference'),
    operationId: optionalText(row, 'operation_id'),
    paymentHash: optionalText(row, 'payment_hash'),
    origin: text(row, 'origin') as JournalEntry['origin'],
    postedAt: text(row, 'posted_at'),
    lines: lines.all(int(row, 'entry_id')).map(item => ({ lineNo: Number(int(item, 'line_no')), account: text(item, 'account'),
      direction: text(item, 'direction') as Direction, amountMsat: int(item, 'amount_msat'), leg: optionalText(item, 'leg') as Leg | undefined })),
  }));
}

/** The named legs of an operation's or order's entries of `event` (the 1.2 ledger_entries view), in posting order. */
export function legsFor(db: DatabaseSync, operationId: string, event: LedgerEvent):
  { leg: Leg; paymentHash: string; amountMsat: bigint; postedAt: string }[] {
  return db.prepare(`SELECT l.leg, l.amount_msat, e.payment_hash, e.posted_at FROM journal_lines l JOIN journal_entries e ON e.entry_id = l.entry_id
      WHERE e.operation_id = ? AND e.event = ? AND l.leg IS NOT NULL ORDER BY e.entry_id, l.line_no`).all(operationId, event)
    .map(row => ({ leg: text(row, 'leg') as Leg, paymentHash: optionalText(row, 'payment_hash') ?? '', amountMsat: int(row, 'amount_msat'),
      postedAt: text(row, 'posted_at') }));
}
