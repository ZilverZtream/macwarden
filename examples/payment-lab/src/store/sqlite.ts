import { closeSync, openSync } from 'node:fs';
import { DatabaseSync, type SQLOutputValue } from 'node:sqlite';

/**
 * Durable storage on SQLite through Node's built-in `node:sqlite`.
 *
 * - WAL with `synchronous = FULL`: a transaction is on disk (fsync of the WAL)
 *   before COMMIT returns, so "recorded before submission" survives a crash or
 *   power loss, not only a process exit.
 * - Every write runs in `BEGIN IMMEDIATE`, which takes the database write lock
 *   at the start. Two worker processes on one file therefore serialise their
 *   read-check-write sequences (budget reservations rely on this); the loser
 *   waits up to the busy timeout.
 * - Invariants that must hold whatever the code does (one live payment per
 *   operation, one ledger entry per key) are UNIQUE and CHECK constraints.
 */

export type Row = Record<string, SQLOutputValue>;

const BUSY_TIMEOUT_MS = 15_000;

export function openDatabase(path: string, migrations: readonly string[]): DatabaseSync {
  // Create the file owner-only before SQLite does; SQLite gives -wal and -shm the same mode.
  closeSync(openSync(path, 'a', 0o600));
  const db = new DatabaseSync(path, { timeout: BUSY_TIMEOUT_MS, readBigInts: true, enableForeignKeyConstraints: true });
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA synchronous = FULL');
  immediate(db, () => {
    const version = Number(int(db.prepare('PRAGMA user_version').get() ?? {}, 'user_version'));
    for (let index = version; index < migrations.length; index += 1) db.exec(migrations[index] ?? '');
    if (version < migrations.length) db.exec(`PRAGMA user_version = ${migrations.length}`);
  });
  return db;
}

/** Runs `work` in one write transaction; any throw rolls it back. */
export function immediate<T>(db: DatabaseSync, work: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = work();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    if (db.isTransaction) db.exec('ROLLBACK');
    throw error;
  }
}

export function nowIso(): string {
  return new Date().toISOString();
}

/** Typed column readers: a row from this lab's schema with an unexpected type is a bug, not data to coerce. */
export function int(row: Row, column: string): bigint {
  const value = row[column];
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  throw new Error(`column ${column} is not an integer`);
}

export function optionalInt(row: Row, column: string): bigint | undefined {
  return row[column] === null || row[column] === undefined ? undefined : int(row, column);
}

export function text(row: Row, column: string): string {
  const value = row[column];
  if (typeof value !== 'string') throw new Error(`column ${column} is not text`);
  return value;
}

export function optionalText(row: Row, column: string): string | undefined {
  return row[column] === null || row[column] === undefined ? undefined : text(row, column);
}

export function changes(result: { changes: number | bigint }): number {
  return Number(result.changes);
}
