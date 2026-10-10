import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  closeSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeSync,
} from 'node:fs';
import { join } from 'node:path';
import type { OutboxKind, PayloadValue } from './outbox.ts';

/**
 * The lab's stand-in for a business effect: a receipt (receiver, fulfill-order) or a confirmation
 * (payer, confirm-operation) written as a JSON file under the lab directory, carrying the outbox
 * row's fields and an HMAC-SHA256 over them with a per-lab key. The HMAC stands in for a signed
 * receipt: it lets the worker recognise a file it wrote itself, so performing an effect twice is
 * detected, not repeated.
 *
 * Publication is exclusive: the content is written to a temporary file (created owner-only with
 * O_EXCL, written, fsynced), then hard-linked to the final name, which fails if the name exists.
 * A reader therefore never sees a partial file, and of two workers that both got this far only one
 * creates the file; the other finds it and checks its HMAC. A worker killed mid-write leaves only a
 * temporary file, which the next attempt for the same subject removes.
 */

export interface EffectTarget {
  /** `<lab>/receipts` (receiver) or `<lab>/confirmations` (payer). */
  dir: string;
  /** The per-lab HMAC key (labKey). */
  key: Buffer;
}

export type ReceiptFields = Record<string, PayloadValue>;

/** Effect files are small; anything larger than this is not one of them and is not parsed. */
export const MAX_RECEIPT_BYTES = 64 * 1024;
const KEY_FILE = 'outbox.key';

/**
 * The per-lab HMAC key: 32 random bytes as hex in `<lab>/outbox.key`, owner-only, created on first
 * use. Creation is exclusive (temporary file, then link), so concurrent first uses agree on one key.
 */
export function labKey(labDir: string): Buffer {
  const path = join(labDir, KEY_FILE);
  const existing = readKey(path);
  if (existing !== undefined) return existing;
  const tmp = join(labDir, `.${KEY_FILE}.${process.pid}-${randomBytes(6).toString('hex')}.tmp`);
  const fd = openSync(tmp, 'wx', 0o600);
  try {
    writeSync(fd, `${randomBytes(32).toString('hex')}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    linkSync(tmp, path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  } finally {
    unlinkSync(tmp);
  }
  const key = readKey(path);
  if (key === undefined) throw new Error(`${path} is not a 64-digit hex key`);
  return key;
}

function readKey(path: string): Buffer | undefined {
  let size: number;
  try { size = statSync(path).size; } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  if (size > 256) throw new Error(`${path} is not a 64-digit hex key`);
  const value = readFileSync(path, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`${path} is not a 64-digit hex key`);
  return Buffer.from(value, 'hex');
}

const RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])$/i;

/**
 * The file name for a subject: letters, digits, '_' and '-' as they are, every other byte
 * percent-encoded ('.', ':', '/', '%' included), so the name is safe on every platform and
 * two subjects never share a name. A Windows device name (CON, NUL, COM1, …) has its first
 * letter encoded; an encoding longer than 200 characters becomes a SHA-256 of the subject.
 */
export function fileBase(subject: string): string {
  let base = [...Buffer.from(subject, 'utf8')]
    .map(byte => /[A-Za-z0-9_-]/.test(String.fromCharCode(byte)) ? String.fromCharCode(byte) : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`)
    .join('');
  if (RESERVED.test(base)) base = `%${base.charCodeAt(0).toString(16).toUpperCase()}${base.slice(1)}`;
  if (base.length > 200) base = `sha256-${createHash('sha256').update(subject, 'utf8').digest('hex')}`;
  return base;
}

export function effectPath(target: EffectTarget, subject: string): string {
  return join(target.dir, `${fileBase(subject)}.json`);
}

/** The signed text: the fields as [name, value] pairs sorted by name, as JSON. */
function canonical(fields: ReceiptFields): string {
  return JSON.stringify(Object.keys(fields).sort().map(name => [name, fields[name] ?? null]));
}

export function sign(key: Buffer, fields: ReceiptFields): string {
  return createHmac('sha256', key).update(canonical(fields)).digest('hex');
}

/** The fields of an effect file: the outbox row's kind and idempotency key, then its payload. */
export function effectFields(row: { kind: OutboxKind; idempotencyKey: string; payload: Record<string, PayloadValue> }): ReceiptFields {
  return { kind: row.kind, idempotencyKey: row.idempotencyKey, ...row.payload };
}

export type ReadResult =
  | { state: 'absent' }
  | { state: 'invalid'; reason: string }
  | { state: 'valid'; fields: ReceiptFields };

/** Reads an effect file and checks its HMAC. Bounded: a file over MAX_RECEIPT_BYTES is invalid, not read. */
export function readEffect(path: string, key: Buffer): ReadResult {
  let size: number;
  try { size = statSync(path).size; } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { state: 'absent' };
    throw error;
  }
  if (size > MAX_RECEIPT_BYTES) return { state: 'invalid', reason: `${size} bytes, more than ${MAX_RECEIPT_BYTES}` };
  let parsed: unknown;
  try { parsed = JSON.parse(readFileSync(path, 'utf8')); } catch { return { state: 'invalid', reason: 'not JSON' }; }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return { state: 'invalid', reason: 'not an object' };
  const { hmacSha256, ...rest } = parsed as Record<string, unknown>;
  if (typeof hmacSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(hmacSha256)) return { state: 'invalid', reason: 'no HMAC' };
  for (const value of Object.values(rest)) {
    if (value !== null && typeof value !== 'string' && typeof value !== 'number') return { state: 'invalid', reason: 'a field is not text or a number' };
  }
  const fields = rest as ReceiptFields;
  if (!timingSafeEqual(Buffer.from(sign(key, fields), 'hex'), Buffer.from(hmacSha256, 'hex'))) return { state: 'invalid', reason: 'HMAC does not match' };
  return { state: 'valid', fields };
}

export class EffectConflict extends Error {}

/** Hooks for the crash-point tests: called synchronously at that point of the effect. */
export interface EffectHooks {
  /** After the first half of the temporary file is written, before the rest. */
  duringWrite?(tmpPath: string): void;
}

/**
 * Performs the effect for `fields` at most once:
 * - `already-present`: the file exists with a valid HMAC over the same fields (an earlier attempt
 *   performed it and died before its acknowledgement); nothing is written;
 * - `written`: the file did not exist and was created exclusively;
 * - `replaced`: a file existed that is not a valid effect file (damaged, or not ours) and was replaced.
 * Throws EffectConflict when a valid effect file for other fields holds the name (another row's
 * receipt for the same subject): nothing is overwritten.
 */
export function publish(target: EffectTarget, subject: string, fields: ReceiptFields, hooks: EffectHooks = {}):
  'written' | 'already-present' | 'replaced' {
  mkdirSync(target.dir, { recursive: true, mode: 0o700 });
  const base = fileBase(subject);
  const path = join(target.dir, `${base}.json`);
  for (const name of readdirSync(target.dir)) {
    if (name.startsWith(`.${base}.json.`) && name.endsWith('.tmp')) {
      try { unlinkSync(join(target.dir, name)); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
  }
  const expected = canonical(fields);
  const check = (): 'absent' | 'same' | 'invalid' => {
    const found = readEffect(path, target.key);
    if (found.state === 'absent') return 'absent';
    if (found.state === 'invalid') return 'invalid';
    if (canonical(found.fields) === expected) return 'same';
    throw new EffectConflict(`${path} holds a valid effect for ${String(found.fields.idempotencyKey)}, not ${String(fields.idempotencyKey)}`);
  };
  const before = check();
  if (before === 'same') return 'already-present';
  const content = `${JSON.stringify({ ...fields, hmacSha256: sign(target.key, fields) }, null, 2)}\n`;
  const tmp = join(target.dir, `.${base}.json.${process.pid}-${randomBytes(6).toString('hex')}.tmp`);
  const fd = openSync(tmp, 'wx', 0o600);
  try {
    const half = Math.floor(content.length / 2);
    writeSync(fd, content.slice(0, half));
    hooks.duringWrite?.(tmp);
    writeSync(fd, content.slice(half));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (before === 'invalid') {
    renameSync(tmp, path);
    syncDir(target.dir);
    return 'replaced';
  }
  try {
    linkSync(tmp, path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') { unlinkSync(tmp); throw error; }
    // Another worker published first (its lease ran out while it still worked): ours is the same or a conflict.
    unlinkSync(tmp);
    const after = check();
    if (after === 'same') return 'already-present';
    throw new Error(`${path} appeared while this worker wrote it, and is not a valid effect file`, { cause: error });
  }
  unlinkSync(tmp);
  syncDir(target.dir);
  return 'written';
}

/** fsync of the directory, so the new name survives power loss; not supported on Windows, where it is skipped. */
function syncDir(dir: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(dir, 'r');
    fsyncSync(fd);
  } catch { /* EISDIR / EPERM on Windows */ } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
