import { closeSync, existsSync, openSync } from 'node:fs';
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
 * - Invariants that must hold whatever the code does (one pending payment per
 *   operation, one ledger entry per key) are UNIQUE and CHECK constraints.
 */

export type Row = Record<string, SQLOutputValue>;

const BUSY_TIMEOUT_MS = 15_000;

/**
 * One schema step: SQL, or a function for a step that must compute in JavaScript (the ledger
 * migration sums amounts as bigints, which SQLite cannot do past 2^63). Both run inside the
 * same BEGIN IMMEDIATE transaction as the user_version update.
 */
export type Migration = string | ((db: DatabaseSync) => void);

/**
 * Opens the store's database and brings its schema to `migrations.length`. A database whose
 * user_version is newer than the migrations this code knows (written by a later version) is
 * refused before anything is written: forward compatibility is not supported. A failure here
 * (a PRAGMA, a migration, the version check) closes the handle before the error propagates,
 * because the caller never gets the handle to close.
 */
export function openDatabase(path: string, migrations: readonly Migration[]): DatabaseSync {
  if (readOnlyOpens > 0) return openReadOnly(path, migrations);
  // Create the file owner-only before SQLite does; SQLite gives -wal and -shm the same mode.
  closeSync(openSync(path, 'a', 0o600));
  const db = new DatabaseSync(path, { timeout: BUSY_TIMEOUT_MS, readBigInts: true, enableForeignKeyConstraints: true });
  try {
    // Read before the journal-mode PRAGMA, which converts the file to WAL: a newer database is left as it was.
    refuseNewer(db, migrations.length);
    db.exec('PRAGMA journal_mode = WAL');
    db.exec('PRAGMA synchronous = FULL');
    immediate(db, () => {
      // Read again under the write lock: another process may have migrated the file meanwhile.
      const version = refuseNewer(db, migrations.length);
      for (let index = version; index < migrations.length; index += 1) {
        const step = migrations[index] ?? '';
        if (typeof step === 'string') db.exec(step); else step(db);
      }
      if (version < migrations.length) db.exec(`PRAGMA user_version = ${migrations.length}`);
    });
  } catch (error) {
    try { db.close(); } catch { /* the original error is the one to report */ }
    throw error;
  }
  return db;
}

/** How many readOnly() calls are running: a store constructed inside one opens its database read-only. */
let readOnlyOpens = 0;

/**
 * Runs `open` (a store's constructor, which calls openDatabase) with every database it opens opened for
 * reading only, for the commands that only read (explain, show, ledger-verify, outbox-status, …):
 *
 * - a database that does not exist is not created: an empty in-memory database with the current schema
 *   stands in for it, so the command reads no records and nothing appears on disk;
 * - an existing database is opened with SQLite's read-only flag (a write through it fails) and must have the
 *   current schema: an older one is refused, not migrated, and a newer one is refused as openDatabase refuses
 *   it; either is left unchanged. A command that records migrates it.
 *
 * Store constructors are synchronous, so the flag holds exactly for the duration of `open`.
 */
export function readOnly<T>(open: () => T): T {
  readOnlyOpens += 1;
  try {
    return open();
  } finally {
    readOnlyOpens -= 1;
  }
}

function openReadOnly(path: string, migrations: readonly Migration[]): DatabaseSync {
  if (!existsSync(path)) {
    const db = new DatabaseSync(':memory:', { readBigInts: true, enableForeignKeyConstraints: true });
    try {
      immediate(db, () => {
        for (const step of migrations) {
          if (typeof step === 'string') db.exec(step); else step(db);
        }
        db.exec(`PRAGMA user_version = ${migrations.length}`);
      });
    } catch (error) {
      try { db.close(); } catch { /* the original error is the one to report */ }
      throw error;
    }
    return db;
  }
  const db = new DatabaseSync(path, { readOnly: true, timeout: BUSY_TIMEOUT_MS, readBigInts: true, enableForeignKeyConstraints: true });
  try {
    const version = refuseNewer(db, migrations.length);
    if (version < migrations.length) {
      throw new Error(`database schema version ${version} is older than this code's (${migrations.length}); a command that only reads does not `
        + 'migrate it, and it is left unchanged: run a command that records (reconcile, for one) to migrate it first');
    }
  } catch (error) {
    try { db.close(); } catch { /* the original error is the one to report */ }
    throw error;
  }
  return db;
}

/** The database's schema version; throws if it is newer than `known`, the number of migrations this code has. */
function refuseNewer(db: DatabaseSync, known: number): number {
  const version = Number(int(db.prepare('PRAGMA user_version').get() ?? {}, 'user_version'));
  if (version > known) {
    throw new Error(`database schema version ${version} is newer than this code supports (${known}); it was written by a later version, and is left unchanged`);
  }
  return version;
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
