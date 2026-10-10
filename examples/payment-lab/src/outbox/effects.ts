import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  closeSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, statSync, unlinkSync, writeSync,
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
 * creates the file; the other finds it and checks its HMAC. An existing file is never replaced: one
 * that does not verify under the lab's key is reported as damaged and left for the operator.
 *
 * The temporary file's name carries a tag of the lease owner and the time its lease runs out. A
 * worker killed mid-write leaves only that file; the next attempt for the same subject removes the
 * leftovers of its own owner and of leases that have run out, never those of a lease still running.
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
/** The lab's effect directories (receiver receipts, payer confirmations); src/cli.ts names them the same. */
export const EFFECT_DIRS = ['receipts', 'confirmations'] as const;
/** The lease a direct publish (outside the worker) assumes: 60 s, as the worker's default. */
const DIRECT_LEASE_MS = 60_000;

/**
 * The per-lab HMAC key: 32 random bytes as hex in `<lab>/outbox.key`, owner-only, created on first
 * use. Creation is exclusive (temporary file, then link), so concurrent first uses agree on one key.
 * A missing key is created only while no receipt or confirmation exists: a new key would make every
 * file signed with the old one fail verification, so a lost key is an error naming the key file.
 */
export function labKey(labDir: string): Buffer {
  const path = join(labDir, KEY_FILE);
  const existing = readKey(path);
  if (existing !== undefined) return existing;
  const signed = EFFECT_DIRS.flatMap(name => effectFiles(join(labDir, name)));
  if (signed.length > 0) {
    throw new Error(`${path} is missing, but ${signed.length} receipt or confirmation file(s) signed with it exist (${signed[0] ?? ''}); `
      + `restore ${path} from your copy: a new key would make every one of them fail verification. To start the lab over, `
      + `move ${EFFECT_DIRS.map(name => join(labDir, name)).join(' and ')} aside first`);
  }
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

/** The effect files (final names, not temporary ones) in a directory; none when it does not exist. */
function effectFiles(dir: string): string[] {
  try {
    return readdirSync(dir).filter(name => name.endsWith('.json') && !name.startsWith('.')).map(name => join(dir, name));
  } catch (error) {
    if (['ENOENT', 'ENOTDIR'].includes((error as NodeJS.ErrnoException).code ?? '')) return [];
    throw error;
  }
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
const MAX_BASE = 200;
const hexByte = (byte: number): string => `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;

/**
 * The file name for a subject, distinct for distinct subjects on every platform, including file
 * systems that ignore letter case (Windows, macOS):
 * - lower-case letters, digits, '_' and '-' stay as they are; every other byte is percent-encoded
 *   with upper-case hex, upper-case letters included ('Order1' is '%4Frder1', 'order1' stays). A name
 *   therefore holds letters only as lower-case literals or as hex digits after a '%', so two names
 *   that differ only in case cannot both be produced;
 * - a Windows device name (con, nul, com1, ...) has its first letter encoded, which no other
 *   subject produces (a lower-case letter is otherwise never encoded);
 * - an encoding longer than 200 characters becomes '=sha256-' and the SHA-256 of the subject. The
 *   encoding never produces '=', so a hashed name is never the name of another subject (such as
 *   one literally called 'sha256-<hash>'); two hashed names coincide only on a SHA-256 collision.
 */
export function fileBase(subject: string): string {
  let base = [...Buffer.from(subject, 'utf8')]
    .map(byte => /[a-z0-9_-]/.test(String.fromCharCode(byte)) ? String.fromCharCode(byte) : hexByte(byte))
    .join('');
  if (RESERVED.test(base)) base = `${hexByte(base.charCodeAt(0))}${base.slice(1)}`;
  if (base.length > MAX_BASE) base = `=sha256-${createHash('sha256').update(subject, 'utf8').digest('hex')}`;
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

/**
 * Why an effect was not performed, named in the worker's outbox-failed event and the row's last_error:
 * - conflict: a valid effect file for another idempotency key holds the name;
 * - damaged: a file holds the name that does not verify under the lab's key (partial, edited, or
 *   signed with another key); it is never overwritten: the operator inspects it and moves it aside;
 * - ledger-entry-missing / ledger-entry-mismatch: the row's ledger entry is not in the journal, or is
 *   not the entry of its payment (checked by the worker before the effect);
 * - lease-expired: this worker's temporary file was removed after its lease ran out, and the effect
 *   is not there.
 */
export type EffectFailure = 'conflict' | 'damaged' | 'ledger-entry-missing' | 'ledger-entry-mismatch' | 'lease-expired';

export class EffectError extends Error {
  readonly reason: EffectFailure;
  constructor(reason: EffectFailure, message: string, options?: ErrorOptions) {
    super(message, options);
    this.reason = reason;
  }
}

export class EffectConflict extends EffectError {
  constructor(message: string) { super('conflict', message); }
}

/** Hooks for the crash-point tests: called synchronously at that point of the effect. */
export interface EffectHooks {
  /** After the first half of the temporary file is written, before the rest. */
  duringWrite?(tmpPath: string): void;
}

/** The lease the effect is performed under: its owner, when it runs out, and the worker's clock now. */
export interface EffectLease {
  owner: string;
  expiresAtMs: number;
  nowMs: number;
}

const ownerTag = (owner: string): string => createHash('sha256').update(owner, 'utf8').digest('hex').slice(0, 16);
const TMP_SUFFIX = /^([0-9a-f]{16})\.(\d{1,16})\.tmp$/;

/**
 * Removes the temporary files a killed attempt for this name left: those of this lease owner, and
 * those whose lease ran out (by the claiming worker's clock). A lease still running belongs to a
 * worker that may still be writing, and its file is left alone.
 */
function removeLeftovers(dir: string, base: string, lease: EffectLease): void {
  const prefix = `.${base}.json.`;
  const mine = ownerTag(lease.owner);
  for (const name of readdirSync(dir)) {
    if (!name.startsWith(prefix)) continue;
    const match = TMP_SUFFIX.exec(name.slice(prefix.length));
    if (match === null || (match[1] !== mine && Number(match[2]) > lease.nowMs)) continue;
    try { unlinkSync(join(dir, name)); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
}

/**
 * Performs the effect for `fields` at most once:
 * - `already-present`: the file exists with a valid HMAC over the same fields (an earlier attempt,
 *   or another worker that took over an expired lease, performed it); nothing is written;
 * - `written`: the file did not exist and was created exclusively.
 * Nothing is ever overwritten. Throws EffectError: `conflict` when a valid effect file for other
 * fields holds the name (another row's receipt for the same subject), `damaged` when a file holds
 * the name that does not verify under the key, `lease-expired` when this worker's temporary file
 * was removed after its lease ran out and the effect is not there.
 * `lease` defaults, for a direct call outside the worker, to a fresh owner and a 60 s lease.
 */
export function publish(target: EffectTarget, subject: string, fields: ReceiptFields, hooks: EffectHooks = {}, lease?: EffectLease):
  'written' | 'already-present' {
  const nowMs = Date.now();
  const held = lease ?? { owner: `${process.pid}:${randomBytes(6).toString('hex')}`, expiresAtMs: nowMs + DIRECT_LEASE_MS, nowMs };
  mkdirSync(target.dir, { recursive: true, mode: 0o700 });
  const base = fileBase(subject);
  const path = join(target.dir, `${base}.json`);
  removeLeftovers(target.dir, base, held);
  const expected = canonical(fields);
  const check = (): 'absent' | 'same' => {
    const found = readEffect(path, target.key);
    if (found.state === 'absent') return 'absent';
    if (found.state === 'invalid') {
      throw new EffectError('damaged', `${path} exists but is not a valid effect file under this lab's key (${found.reason}); nothing is overwritten: `
        + 'inspect it and move it out of the directory, and the next attempt writes the effect');
    }
    if (canonical(found.fields) === expected) return 'same';
    throw new EffectConflict(`${path} holds a valid effect for ${String(found.fields.idempotencyKey)}, not ${String(fields.idempotencyKey)}`);
  };
  if (check() === 'same') return 'already-present';
  const content = `${JSON.stringify({ ...fields, hmacSha256: sign(target.key, fields) }, null, 2)}\n`;
  const tmp = join(target.dir, `.${base}.json.${ownerTag(held.owner)}.${Math.max(0, Math.trunc(held.expiresAtMs))}.tmp`);
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
  try {
    linkSync(tmp, path);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      // Our temporary file is gone: our lease ran out and the worker that claimed the row next removed it.
      if (check() === 'same') return 'already-present';
      throw new EffectError('lease-expired', `${tmp} was removed after this worker's lease ran out, and ${path} is not there`, { cause: error });
    }
    unlinkSync(tmp);
    if (code !== 'EEXIST') throw error;
    // Another worker published first (its lease ran out while it still worked, or ours did): the same effect, or a failure.
    if (check() === 'same') return 'already-present';
    throw new Error(`${path} appeared while this worker wrote it`, { cause: error });
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
