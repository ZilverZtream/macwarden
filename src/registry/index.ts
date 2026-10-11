import { ownProcessDomain, validDomain, type ProcessDomain } from './process-domain.js';
import * as nodeFs from 'node:fs/promises';
import type { BigIntStats } from 'node:fs';
import { reserveOwnerOnly } from '../private-file.js';

/** Largest registry file read: 64 MiB holds far more entries than one node ever bakes. */
export const REGISTRY_FILE_LIMIT = 64 * 1024 * 1024;
import { homedir as nodeHomedir, hostname as nodeHostname } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { resolveUnprotectedPath } from '../protected-path.js';
import { LOCK_FILE_LIMIT, readBoundedFile, readPlainFile } from '../bounded-file.js';
import { isInstant } from '../instant.js';
import { isRootKeyId } from '../root-key-id.js';

const fields = ['nodePubkey', 'label', 'rootKeyId', 'permissions', 'caveats', 'grade',
  'fingerprint', 'outPath', 'createdAt', 'verified', 'status', 'revokedAt',
  'revokeEvidence', 'replaces', 'replacedBy'] as const;
const grades = new Set(['ADMIN', 'SPEND', 'OPERATE', 'RECEIVE', 'READ', 'UNASSESSED']);
const caveatTypes = new Set(['time-before', 'ipaddr', 'iprange', 'lnd-custom', 'third-party', 'unknown']);

export interface RegistryEntry {
  nodePubkey: string;
  label: string | null;
  rootKeyId: string;
  permissions: string[];
  caveats: { type: string; value: string; requested?: string }[];
  grade: string;
  fingerprint: string | null;
  outPath: string | null;
  createdAt: string;
  verified: boolean;
  status: 'active' | 'revoked';
  revokedAt: string | null;
  revokeEvidence: string | null;
  replaces: string | null;
  replacedBy: string | null;
}

export type RegistryDeps = {
  fs?: typeof nodeFs;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  homedir?: () => string;
  hostname?: () => string;
  pidAlive?: (pid: number) => boolean;
  sleep?: (ms: number) => Promise<void>;
  /** POSIX user ID the registry directory must belong to (default `process.getuid`; none on Windows). */
  getuid?: () => number | undefined;
};

// Another acquirer holds the claim only for a few file operations: a contended claim is retried
// for up to CLAIM_WAIT_ATTEMPTS x CLAIM_WAIT_MS (300 ms) before it is reported.
const CLAIM_WAIT_ATTEMPTS = 15;
const CLAIM_WAIT_MS = 20;
// Windows save: a program reading registry.json without FILE_SHARE_DELETE blocks the rename. Ten
// attempts with delays doubling from 100 ms to at most 1600 ms wait about 9.5 s in total.
const SAVE_RENAME_ATTEMPTS = 10;
const SAVE_RENAME_FIRST_DELAY_MS = 100;
const SAVE_RENAME_MAX_DELAY_MS = 1600;

/** Why the acquisition claim could not be created, for an error other than an existing claim. */
function claimProblem(code: string | undefined): string {
  if (code === 'EACCES' || code === 'EPERM') return 'permission denied in the registry directory';
  if (code === 'EROFS') return 'the file system is read-only';
  if (code === 'ENOSPC' || code === 'EDQUOT') return 'no space left on the device';
  if (code === 'ENOENT' || code === 'ENOTDIR') return 'the registry directory does not exist';
  return `unexpected file system error${code ? ` ${code}` : ''}`;
}

export class RegistryInputError extends Error {
  readonly code = 3;
  readonly step: string;

  constructor(step: string, message: string) {
    super(message);
    this.name = 'RegistryInputError';
    this.step = step;
  }
}

export class RegistryUsageError extends Error {
  readonly code = 2;
  readonly step = 'registry-entry';

  constructor(message: string) {
    super(message);
    this.name = 'RegistryUsageError';
  }
}

function input(step: string, message: string): never {
  throw new RegistryInputError(step, message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactFields(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every(key => expected.includes(key));
}

const decimalId = isRootKeyId;

// A real instant, not only its shape: 30 February or 24:00 would be read as another day.
const timestamp = isInstant;

/** A recorded expiry duration, as `bake --expires` accepts it (RL-03): rotate S11 reuses it. */
function duration(value: unknown): boolean {
  return typeof value === 'string' && /^[1-9][0-9]{0,4}[mhd]$/.test(value);
}

function validEntry(value: unknown): value is RegistryEntry {
  if (!isRecord(value) || !exactFields(value, fields)) return false;
  if (typeof value.nodePubkey !== 'string' || !/^(02|03)[0-9a-fA-F]{64}$/.test(value.nodePubkey)
    || !decimalId(value.rootKeyId)
    || (value.label !== null && (typeof value.label !== 'string'
      || !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(value.label)))) return false;
  if (!Array.isArray(value.permissions) || !value.permissions.every(permission =>
    typeof permission === 'string' && /^(?:[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*|uri:\/[A-Za-z0-9_./]+)$/.test(permission))) return false;
  if (!Array.isArray(value.caveats) || !value.caveats.every(caveat =>
    isRecord(caveat) && Object.keys(caveat).every(key => ['type', 'value', 'requested'].includes(key))
    && Object.hasOwn(caveat, 'type') && Object.hasOwn(caveat, 'value')
    && typeof caveat.type === 'string' && caveatTypes.has(caveat.type)
    && typeof caveat.value === 'string'
    && (caveat.requested === undefined || (caveat.type === 'time-before' && duration(caveat.requested))))) return false;
  return typeof value.grade === 'string' && grades.has(value.grade)
    && ((typeof value.fingerprint === 'string' && /^fp:[0-9a-f]{16}$/.test(value.fingerprint))
      || (value.fingerprint === null && value.verified === false && value.outPath === null))
    && (value.outPath === null || typeof value.outPath === 'string')
    && timestamp(value.createdAt) && typeof value.verified === 'boolean'
    && (value.status === 'active' || value.status === 'revoked')
    && (value.revokedAt === null || timestamp(value.revokedAt))
    && (value.revokeEvidence === null || value.revokeEvidence === 'rejected' || value.revokeEvidence === 'by-id-only')
    && (value.replaces === null || decimalId(value.replaces))
    && (value.replacedBy === null || decimalId(value.replacedBy))
    && (value.status === 'active' ? value.revokedAt === null && value.revokeEvidence === null
      : value.revokedAt !== null);
}

function validate(entries: unknown): asserts entries is RegistryEntry[] {
  if (!Array.isArray(entries) || !entries.every(validEntry)) input('registry-read', 'invalid registry');
  const ids = new Set<string>();
  for (const entry of entries) {
    if (entry.label === null && entry.status !== 'revoked') input('registry-read', 'invalid registry');
    const key = `${entry.nodePubkey.toLowerCase()}/${entry.rootKeyId}`;
    if (ids.has(key)) input('registry-read', 'invalid registry');
    ids.add(key);
  }
  // Active labelled entries are grouped by node (case-insensitive) and exact label;
  // a label may be shared only by an entry and its direct replacement.
  const groups = new Map<string, RegistryEntry[]>();
  for (const entry of entries) {
    if (entry.status !== 'active' || entry.label === null) continue;
    const key = `${entry.nodePubkey.toLowerCase()}\0${entry.label}`;
    const peers = groups.get(key);
    if (peers) peers.push(entry); else groups.set(key, [entry]);
  }
  for (const peers of groups.values()) {
    if (peers.length > 2) input('registry-read', 'invalid registry');
    if (peers.length === 2 && peers[0].replaces !== peers[1].rootKeyId && peers[1].replaces !== peers[0].rootKeyId)
      input('registry-read', 'invalid registry');
    // Exactly one direction: two entries naming each other form a cycle, which would hide
    // both from respond and rotate (each looks like the other's staged replacement).
    if (peers.length === 2 && peers[0].replaces === peers[1].rootKeyId && peers[1].replaces === peers[0].rootKeyId)
      input('registry-read', 'invalid registry');
  }
}

function defaultPath(deps: RegistryDeps): string {
  const platform = deps.platform ?? process.platform;
  const env = deps.env ?? process.env;
  const home = (deps.homedir ?? nodeHomedir)();
  if (platform === 'win32') return join(env.APPDATA || join(home, 'AppData', 'Roaming'), 'macwarden', 'registry.json');
  if (platform === 'darwin') return join(home, 'Library', 'Application Support', 'macwarden', 'registry.json');
  return join(env.XDG_CONFIG_HOME || join(home, '.config'), 'macwarden', 'registry.json');
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code !== 'ESRCH'; }
}

type LockData = { pid: number; hostname: string; startedAt: string; processDomain?: ProcessDomain | null; token?: string };
const LOCK_TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// `token` (from 1.1.1) is a random per-acquisition nonce that binds release to this owner's
// record; records written without it by earlier versions stay valid.
function validLock(value: unknown): value is LockData {
  return isRecord(value) && (exactFields(value, ['pid', 'hostname', 'startedAt'])
    || exactFields(value, ['pid', 'hostname', 'startedAt', 'processDomain'])
    || exactFields(value, ['pid', 'hostname', 'startedAt', 'processDomain', 'token']))
    && (value.token === undefined || (typeof value.token === 'string' && LOCK_TOKEN.test(value.token)))
    && Number.isSafeInteger(value.pid) && (value.pid as number) > 0
    && typeof value.hostname === 'string' && /^[A-Za-z0-9_.-]+$/.test(value.hostname)
    && timestamp(value.startedAt)
    && (value.processDomain === undefined || value.processDomain === null || validDomain(value.processDomain));
}

export class Registry {
  private readonly fs: typeof nodeFs;
  private readonly deps: RegistryDeps;
  private readonly path: string;
  /** The lock this registry holds: its file identity and the exact owner record written. */
  private ownedLock: { dev: bigint; ino: bigint; birth: bigint; record: string } | undefined;
  readonly entries: RegistryEntry[];
  private readonly originalText: string | undefined;
  private readonly originalEntries: string;

  constructor(path: string, entries: RegistryEntry[], deps: RegistryDeps, originalText?: string) {
    this.path = path;
    this.originalText = originalText;
    this.originalEntries = JSON.stringify(entries);
    this.entries = entries;
    this.deps = deps;
    this.fs = deps.fs ?? nodeFs;
  }

  /** The resolved registry file path (sidecar files are kept next to it). */
  get location(): string { return this.path; }

  find(nodePubkey: string, rootKeyId: string): RegistryEntry | undefined {
    return this.entries.find(entry => entry.nodePubkey.toLowerCase() === nodePubkey.toLowerCase() && entry.rootKeyId === rootKeyId);
  }

  add(entry: RegistryEntry): void {
    if (!validEntry(entry)) input('registry-entry', 'invalid registry entry');
    if (entry.label === null && entry.status !== 'revoked') {
      throw new RegistryUsageError('active entry requires a label');
    }
    if (!this.ownedLock) input('registry-lock', 'registry lock required');
    if (this.find(entry.nodePubkey, entry.rootKeyId)) throw new RegistryUsageError('root key ID already recorded');
    this.entries.push(structuredClone(entry));
    try { validate(this.entries); }
    catch (error) {
      this.entries.pop();
      if (error instanceof RegistryInputError) throw new RegistryUsageError('label conflict');
      throw error;
    }
  }

  removePending(nodePubkey: string, rootKeyId: string): void {
    if (!this.ownedLock) input('registry-lock', 'registry lock required');
    const entry = this.find(nodePubkey, rootKeyId);
    if (!entry || entry.verified || entry.fingerprint !== null || entry.outPath !== null) throw new RegistryUsageError('entry is not a pending allocation');
    this.entries.splice(this.entries.indexOf(entry), 1);
  }

  update(entry: RegistryEntry): void {
    if (!this.ownedLock) input('registry-lock', 'registry lock required');
    if (!validEntry(entry)) input('registry-entry', 'invalid registry entry');
    const index = this.entries.findIndex(row => row.nodePubkey.toLowerCase() === entry.nodePubkey.toLowerCase() && row.rootKeyId === entry.rootKeyId);
    if (index < 0) throw new RegistryUsageError('root key ID is not recorded');
    const previous = this.entries[index];
    this.entries[index] = structuredClone(entry);
    try { validate(this.entries); } catch (error) { this.entries[index] = previous; throw error; }
  }

  markRevoked(nodePubkey: string, rootKeyId: string, revokedAt: string, evidence: string): void {
    if (!this.ownedLock) input('registry-lock', 'registry lock required');
    const entry = this.find(nodePubkey, rootKeyId);
    if (!entry || entry.status !== 'active') throw new RegistryUsageError('root key ID is not active');
    if (!timestamp(revokedAt) || typeof evidence !== 'string') {
      input('registry-entry', 'invalid revocation');
    }
    entry.status = 'revoked';
    entry.revokedAt = revokedAt;
    entry.revokeEvidence = evidence;
  }

  reload(entries: RegistryEntry[]): void {
    if (!this.ownedLock) input('registry-lock', 'registry lock required');
    validate(entries);
    // Never spread into splice: a large registry exceeds the engine's argument limit.
    const copy = structuredClone(entries);
    this.entries.length = 0;
    for (const entry of copy) this.entries.push(entry);
  }

  markReplacedBy(nodePubkey: string, rootKeyId: string, replacementId: string): void {
    if (!this.ownedLock) input('registry-lock', 'registry lock required');
    const entry = this.find(nodePubkey, rootKeyId);
    if (!entry || !decimalId(replacementId)) input('registry-entry', 'invalid replacement');
    entry.replacedBy = replacementId;
  }

  private async privateDirectory(): Promise<void> {
    const directory = dirname(this.path);
    try {
      const created = await this.fs.mkdir(directory, { recursive: true, mode: 0o700 });
      if ((this.deps.platform ?? process.platform) !== 'win32') {
        const stat = await this.fs.stat(directory);
        if (!stat.isDirectory() || (stat.mode & 0o022) !== 0) input('registry-lock', 'unsafe registry directory permissions');
        // Owned by this user (or root, which can change any file anyway): an owner who is someone
        // else can replace registry.json or plant the lock files whatever the mode bits say.
        const uid = this.deps.getuid ? this.deps.getuid() : process.getuid?.();
        if (uid !== undefined && stat.uid !== uid && stat.uid !== 0) input('registry-lock', 'unsafe registry directory owner');
        if (created !== undefined) await this.fs.chmod(directory, 0o700);
      }
    } catch (error) {
      if (error instanceof RegistryInputError) throw error;
      input('registry-lock', 'cannot access registry directory');
    }
  }

  async lock(options: { breakLock?: boolean } = {}): Promise<void> {
    if (this.ownedLock) return;
    await this.privateDirectory();
    const processDomain = await ownProcessDomain();
    // Every cooperating acquirer holds this guard while checking or moving the
    // lock. No new writer can enter the quarantine rename's pathname gap.
    const claimPath = `${this.path}.lock.claim`;
    const claim = await this.createClaim(claimPath);
    // File identity as 64-bit values: NTFS file reference numbers exceed 2^53, where a Number
    // loses the low bits and two different files can compare equal (audit 1.4.0).
    let identity: { dev: bigint; ino: bigint } | undefined;
    let primary: { error: unknown } | undefined;
    try {
      // Under the cleanup below (audit N12): a failing stat must still close the descriptor and
      // remove the claim, and is reported as an ordinary lock failure.
      try { identity = await claim.stat({ bigint: true }); }
      catch { input('registry-lock', 'cannot create registry lock'); }
      await claim.writeFile(JSON.stringify({ pid: process.pid,
        hostname: (this.deps.hostname ?? nodeHostname)(), startedAt: new Date().toISOString(), processDomain }));
      await claim.close();
      await this.lockUnderClaim(options, processDomain);
    } catch (error) { primary = { error }; }
    await claim.close().catch(() => {});
    let cleanup: { error: unknown } | undefined;
    try {
      const current = await this.fs.lstat(claimPath, { bigint: true });
      // Without the descriptor's identity, only the empty file this run created (nothing was
      // written to it) is taken as ours; a competitor's claim carries its owner record.
      const ours = identity ? current.dev === identity.dev && current.ino === identity.ino : current.size === 0n;
      if (!current.isFile() || !ours)
        input('registry-lock', 'registry acquisition owner changed; preserved competing claim');
      await this.retryBusy(() => this.fs.unlink(claimPath));
    } catch (error) {
      cleanup = { error: error instanceof RegistryInputError ? error : new RegistryInputError('registry-lock',
        `cannot remove registry acquisition claim ${claimPath}; stop all writers and delete it offline`) };
    }
    // A failed acquisition is never reported as acquired, so the caller would never
    // release it: release an owned lock here instead of leaving a stale lock behind.
    // A claim cleanup failure is reported in preference to the primary error.
    const failure = cleanup ?? primary;
    if (failure) {
      // unlock() retries a busy lock and gives up ownership only when the lock is released, gone
      // or someone else's: a lock it could not release stays owned, so a later unlock() can
      // release it (as on the release path, audit N11), and the error says it is still held.
      if (this.ownedLock) await this.unlock().catch(() => {});
      if (this.ownedLock) {
        const reported = failure.error instanceof RegistryInputError ? failure.error
          : new RegistryInputError('registry-lock', 'cannot create registry lock');
        throw new RegistryInputError(reported.step, `${reported.message}; the registry lock ${this.path}.lock ` +
          'is still held by this process and could not be released');
      }
      throw failure.error;
    }
    await this.removeStaleTemps();
  }

  private sleep(ms: number): Promise<void> {
    return (this.deps.sleep ?? (wait => new Promise<void>(resolve => setTimeout(resolve, wait))))(ms);
  }

  /**
   * Creates the acquisition claim. Another acquirer holds it only briefly, so an existing claim
   * (and, on Windows, a claim being deleted, which reports EPERM, EACCES or EBUSY) is retried for
   * a bounded time before it is reported; other errors name their cause.
   */
  private async createClaim(claimPath: string): Promise<nodeFs.FileHandle> {
    const windows = (this.deps.platform ?? process.platform) === 'win32';
    for (let attempt = 1; ; attempt++) {
      let code: string | undefined;
      try {
        const handle = await this.fs.open(claimPath, 'wx', 0o600);
        await this.refuseLinkedCreate(claimPath, handle);
        return handle;
      } catch (error) {
        if (error instanceof RegistryInputError) throw error;
        code = (error as NodeJS.ErrnoException).code;
      }
      const contended = code === 'EEXIST' || (windows && (code === 'EPERM' || code === 'EACCES' || code === 'EBUSY'));
      if (contended && attempt < CLAIM_WAIT_ATTEMPTS) { await this.sleep(CLAIM_WAIT_MS); continue; }
      if (code === 'EEXIST') input('registry-lock', `registry acquisition in progress or ambiguous: ${claimPath}. ` +
        'Stop all writers, establish that the recorded process is gone in its namespace, then delete this .claim file (and any stale lock) offline before retrying.');
      input('registry-lock', `cannot create registry lock ${claimPath}: ${claimProblem(code)}`);
    }
  }

  /**
   * On Windows an exclusive create follows a dangling symbolic link and creates its target (as
   * for the watch lock, audit 1.2.1): the file just created must be the regular file at the path
   * itself. Otherwise the handle is closed, the empty file it created is removed, and the lock is
   * refused. A handle whose stat fails is left to the caller, which reports that itself.
   */
  private async refuseLinkedCreate(path: string, handle: nodeFs.FileHandle): Promise<void> {
    let made: BigIntStats;
    try { made = await handle.stat({ bigint: true }); } catch { return; }
    const onDisk = await this.fs.lstat(path, { bigint: true }).catch(() => null);
    if (onDisk && onDisk.isFile() && !onDisk.isSymbolicLink() && onDisk.dev === made.dev && onDisk.ino === made.ino) return;
    await handle.close().catch(() => {});
    const target = await this.fs.realpath(path).catch(() => null);
    const created = target === null ? null : await this.fs.lstat(target, { bigint: true }).catch(() => null);
    if (target !== null && created && created.isFile() && created.dev === made.dev && created.ino === made.ino
      && created.size === 0n) await this.fs.unlink(target).catch(() => {});
    input('registry-lock', `registry lock path ${path} is a symbolic link or was replaced; remove it and retry`);
  }

  // Antivirus and indexers briefly hold files open: retry EBUSY, and on Windows also EPERM/EACCES.
  private async retryBusy<T>(operation: () => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      try { return await operation(); }
      catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        const windows = (this.deps.platform ?? process.platform) === 'win32';
        if (!(code === 'EBUSY' || (windows && (code === 'EPERM' || code === 'EACCES'))) || attempt === 10) throw error;
        await this.sleep(100);
      }
    }
  }

  // Temp files from a save interrupted by a crash. Only the lock holder saves, so
  // while this process holds the lock none of them can belong to a live writer.
  private async removeStaleTemps(): Promise<void> {
    if (!this.ownedLock) return;
    const directory = dirname(this.path);
    const prefix = `${basename(this.path)}.`;
    const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$/;
    let names: string[];
    try { names = await this.fs.readdir(directory); }
    catch { return; }
    for (const name of names) {
      if (!name.startsWith(prefix) || !pattern.test(name.slice(prefix.length))) continue;
      const path = join(directory, name);
      try { if ((await this.fs.lstat(path)).isFile()) await this.fs.unlink(path); }
      catch { /* Best effort: a leftover temp file never affects the registry. */ }
    }
  }

  /**
   * Creates the lock file exclusively; undefined when a lock exists. On Windows a lock whose
   * delete is still pending (the previous holder's release, a scanner's handle) reports EPERM,
   * EACCES or EBUSY for a moment: as for the claim, that is waited out for a bounded time.
   */
  private async createLock(lockPath: string): Promise<nodeFs.FileHandle | undefined> {
    const windows = (this.deps.platform ?? process.platform) === 'win32';
    for (let attempt = 1; ; attempt++) {
      let code: string | undefined;
      try { return await this.fs.open(lockPath, 'wx', 0o600); }
      catch (error) { code = (error as NodeJS.ErrnoException).code; }
      if (code === 'EEXIST') return undefined;
      const pending = windows && (code === 'EPERM' || code === 'EACCES' || code === 'EBUSY');
      if (pending && attempt < CLAIM_WAIT_ATTEMPTS) { await this.sleep(CLAIM_WAIT_MS); continue; }
      input('registry-lock', 'cannot create registry lock');
    }
  }

  private async lockUnderClaim(options: { breakLock?: boolean }, processDomain: ProcessDomain | null): Promise<void> {
    const lockPath = `${this.path}.lock`;
    for (let attempt = 0; attempt < 2; attempt++) {
      const handle = await this.createLock(lockPath);
      if (handle) {
        await this.refuseLinkedCreate(lockPath, handle);
        try {
          const record = JSON.stringify({ pid: process.pid, hostname: (this.deps.hostname ?? nodeHostname)(),
            startedAt: new Date().toISOString(), processDomain, token: randomUUID() });
          await handle.writeFile(record);
          const stat = await handle.stat({ bigint: true });
          await handle.close();
          this.ownedLock = { dev: stat.dev, ino: stat.ino, birth: stat.birthtimeNs, record };
        } catch {
          await handle.close().catch(() => {});
          // A lock without its complete owner record blocks every later run, --break-lock included
          // (it cannot be validated): retry a busy delete, and name the file if it stays.
          let removed = true;
          await this.retryBusy(() => this.fs.unlink(lockPath))
            .catch((error: unknown) => { removed = (error as NodeJS.ErrnoException).code === 'ENOENT'; });
          input('registry-lock', removed ? 'cannot create registry lock'
            : `cannot create registry lock; remove the incomplete lock file ${lockPath} offline before retrying`);
        }
        return;
      }
      let text: string;
      try {
        // The lock is ours to read only as a plain file: never through a symlink (SAFE-02),
        // through one descriptor bound to the checked file and at most LOCK_FILE_LIMIT + 1 bytes.
        text = await readPlainFile(lockPath, this.fs, LOCK_FILE_LIMIT);
      } catch { input('registry-lock', 'invalid registry lock'); }
      let lock: unknown;
      try { lock = JSON.parse(text); }
      catch {
        // Empty or cut short: a writer killed between creating the lock and writing its record.
        // No owner to prove dead, so --break-lock cannot take it either (audit 1.4.0).
        input('registry-lock', `registry lock ${lockPath} holds no complete owner record (a writer may have crashed ` +
          'while creating it), so --break-lock cannot verify it; stop all writers and delete it offline before retrying');
      }
      if (!validLock(lock)) input('registry-lock', 'invalid or unverifiable registry lock; stop writers and recover offline');
      const locked = `registry locked by pid ${lock.pid} on ${lock.hostname} since ${lock.startedAt}`;
      if (options.breakLock && (!processDomain || !lock.processDomain
        || JSON.stringify(lock.processDomain) !== JSON.stringify(processDomain)))
        input('registry-lock', `${locked}; stale lock ownership cannot be proven safely; ` +
          'stop every registry writer, verify the recorded process is gone in its namespace, then remove this lock offline');
      if (!options.breakLock || lock.hostname !== (this.deps.hostname ?? nodeHostname)()
        || (this.deps.pidAlive ?? alive)(lock.pid)) input('registry-lock', locked);
      // Claim the stale inode by rename, then verify what was actually moved.
      // Other breakers cannot proceed without retaining the same pathname identity.
      const quarantine = `${lockPath}.${randomUUID()}.stale`;
      let before;
      let quarantined = false;
      let verified = false;
      try {
        before = await this.fs.lstat(lockPath, { bigint: true });
        if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.ino === 0n)
          input('registry-lock', 'stale lock ownership ambiguous; stop writers and recover offline');
        const text = await readPlainFile(lockPath, this.fs, LOCK_FILE_LIMIT);
        if (text !== JSON.stringify(lock)) {
          // Whitespace is allowed, but the owner must still be identical.
          const reread: unknown = JSON.parse(text);
          if (!validLock(reread) || JSON.stringify(reread) !== JSON.stringify(lock))
            input('registry-lock', 'registry lock changed; stop writers and recover offline');
        }
        const current = await this.fs.lstat(lockPath, { bigint: true });
        if (current.dev !== before.dev || current.ino !== before.ino
          || (this.deps.pidAlive ?? alive)(lock.pid))
          input('registry-lock', 'registry lock changed or owner alive; recover offline');
        await this.fs.rename(lockPath, quarantine);
        quarantined = true;
        // A scanner may hold the just-renamed file for a moment: its stat and read are retried
        // like its delete, so a one-off EBUSY/EPERM does not end the recovery (audit 1.4.0).
        const moved = await this.retryBusy(() => this.fs.lstat(quarantine, { bigint: true }));
        const movedOwner: unknown = JSON.parse(await this.retryBusy(() => readPlainFile(quarantine, this.fs, LOCK_FILE_LIMIT)));
        if (moved.dev !== before.dev || moved.ino !== before.ino || !validLock(movedOwner)
          || JSON.stringify(movedOwner) !== JSON.stringify(lock) || (this.deps.pidAlive ?? alive)(lock.pid)) {
          // Never overwrite a replacement writer's pathname. Hard-link restoration
          // is exclusive; if occupied, preserve the moved file for offline recovery.
          input('registry-lock', 'registry lock changed during recovery; preserved lock requires offline recovery');
        }
        verified = true;
        await this.retryBusy(() => this.fs.unlink(quarantine));
        quarantined = false;
      } catch (error) {
        // A verified stale lock is never linked back: that would leave the lock with two names
        // (nlink 2), which every later --break-lock refuses. The lock path is free; only the
        // quarantined copy is left.
        if (quarantined && verified) input('registry-lock', `the stale registry lock was moved to ${quarantine} ` +
          'but could not be deleted; delete that file offline, then retry');
        if (quarantined) {
          // An unverified lock (changed owner, or a stat or read that kept failing) goes back
          // under its one name: the second name alone would make every later --break-lock refuse
          // it as ambiguous. Only when the lock path is occupied by a replacement writer does the
          // moved file keep its quarantine name, for offline recovery.
          const relinked = await this.fs.link(quarantine, lockPath).then(() => true, () => false);
          if (relinked) await this.retryBusy(() => this.fs.unlink(quarantine)).catch(() => {});
        }
        if (error instanceof RegistryInputError) throw error;
        input('registry-lock', 'stale lock ownership cannot be established; stop writers and recover offline');
      }
    }
    input('registry-lock', 'cannot create registry lock');
  }

  async save(): Promise<void> {
    if (!this.ownedLock) input('registry-lock', 'registry lock required');
    validate(this.entries);
    const text = this.originalText !== undefined && JSON.stringify(this.entries) === this.originalEntries
      ? this.originalText : JSON.stringify({ schema: 1, entries: this.entries }, null, 2) + '\n';
    // The reader refuses a registry above REGISTRY_FILE_LIMIT: never write one it could not read back.
    if (Buffer.byteLength(text) > REGISTRY_FILE_LIMIT)
      input('registry-save', `cannot save registry: it would exceed the ${REGISTRY_FILE_LIMIT / 1024 / 1024} MiB a registry may hold; registry unchanged`);
    const tempPath = `${this.path}.${randomUUID()}.tmp`;
    let handle: nodeFs.FileHandle | undefined;
    let held = false;
    try {
      // Owner-only from creation on every platform (1.2.1); the rename keeps that.
      handle = (await reserveOwnerOnly(tempPath, this.fs)).handle;
      await handle.writeFile(text);
      await handle.sync();
      await handle.close();
      handle = undefined;
      for (let attempt = 1, delay = SAVE_RENAME_FIRST_DELAY_MS; ; attempt++, delay = Math.min(delay * 2, SAVE_RENAME_MAX_DELAY_MS)) {
        try {
          await this.fs.rename(tempPath, this.path);
          await this.syncDirectory();
          return;
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if ((this.deps.platform ?? process.platform) !== 'win32' || (code !== 'EPERM' && code !== 'EBUSY')) throw error;
          if (attempt === SAVE_RENAME_ATTEMPTS) { held = true; throw error; }
          await this.sleep(delay);
        }
      }
    } catch {
      input('registry-save', held ? `cannot save registry: ${this.path} is open in another program, which blocks ` +
        'replacing it; close that program and retry; registry unchanged' : 'cannot save registry');
    }
    finally {
      if (handle) await handle.close().catch(() => {});
      await this.fs.unlink(tempPath).catch(() => {});
    }
  }

  // A rename is durable only once its directory entry is; POSIX needs the directory
  // synced. Best effort: some file systems refuse to sync a directory, and Windows
  // has no such call.
  private async syncDirectory(): Promise<void> {
    if ((this.deps.platform ?? process.platform) === 'win32') return;
    let directory: nodeFs.FileHandle | undefined;
    try {
      directory = await this.fs.open(dirname(this.path), 'r');
      await directory.sync();
    } catch { /* EISDIR, EINVAL, EPERM and similar: nothing more can be done. */ }
    finally { await directory?.close().catch(() => {}); }
  }

  async unlock(): Promise<void> {
    const owned = this.ownedLock;
    if (!owned) return;
    // Ownership is given up only when the lock is released, gone or someone else's (audit N11):
    // after a transient failure a second unlock retries, and this process can still re-lock.
    const lost = () => { this.ownedLock = undefined; input('registry-lock', 'registry lock owner changed; preserved competing lock'); };
    try {
      const lockPath = `${this.path}.lock`;
      const stat = await this.fs.lstat(lockPath, { bigint: true });
      // Birth time (0 where the file system has none) tells most recycled inodes apart too.
      if (!stat.isFile() || stat.dev !== owned.dev || stat.ino !== owned.ino || stat.birthtimeNs !== owned.birth) lost();
      // A file system may hand a freed inode number to the next file at once, so identity
      // alone cannot tell a replaced lock apart: the record, with this acquisition's token,
      // must be exactly the one written.
      if (await readPlainFile(lockPath, this.fs, LOCK_FILE_LIMIT) !== owned.record) lost();
      // Antivirus and indexers briefly hold files open: bounded retries, as for the claim.
      await this.retryBusy(() => this.fs.unlink(lockPath));
      this.ownedLock = undefined;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') this.ownedLock = undefined;
      input('registry-lock', 'cannot release registry lock');
    }
  }
}

export async function openRegistry(path?: string, deps: RegistryDeps = {}): Promise<Registry> {
  const fs = deps.fs ?? nodeFs;
  let selected: string;
  try { selected = await resolveUnprotectedPath(path ?? defaultPath(deps), fs); }
  catch { input('registry-read', 'cannot read registry'); }
  let text: string;
  // Bounded like every other sidecar (audit 1.2.1): a regular file of at most REGISTRY_FILE_LIMIT,
  // read through the descriptor of the file that was checked (audit 1.4.0: a size checked by path
  // and a separate unbounded read let a file swapped in between be read whole).
  try {
    text = (await readBoundedFile(selected, fs, REGISTRY_FILE_LIMIT)).toString('utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new Registry(selected, [], deps);
    input('registry-read', 'cannot read registry');
  }
  let data: unknown;
  try { data = JSON.parse(text); }
  catch { input('registry-read', 'invalid registry'); }
  if (!isRecord(data) || !exactFields(data, ['schema', 'entries']) || data.schema !== 1) {
    input('registry-read', 'invalid registry');
  }
  validate(data.entries);
  return new Registry(selected, data.entries, deps, text);
}

/**
 * Why an active entry that names `old` in `replaces` is not a believable staged replacement
 * of it, or null when it is. rotate writes replacements on the same node, with the same label,
 * on a different root key ID, created after the original; anything else in the registry was
 * not written by macwarden and is treated as tampering, never trusted.
 */
export function replacementProblem(old: RegistryEntry, next: RegistryEntry): string | null {
  if (next.nodePubkey.toLowerCase() !== old.nodePubkey.toLowerCase()) return 'it is on a different node';
  if (next.label !== old.label) return 'its label differs';
  if (next.rootKeyId === old.rootKeyId) return 'it has the same root key ID';
  if (Date.parse(next.createdAt) < Date.parse(old.createdAt) && !rotateWrittenShape(old, next))
    return 'it was created before the credential it replaces (if macwarden staged it while this machine\'s clock ' +
      `was behind, abandon it with macwarden revoke ${next.rootKeyId} and stage again)`;
  return null;
}

/**
 * True when a replacement recorded as created before `old` is the link 1.1.0's own stage wrote
 * under a clock behind O's recorded creation time (RL-02): 1.1.0 recorded N.createdAt as the
 * local clock at S10, so an NTP step back, a resumed VM or O baked while the clock ran ahead made
 * macwarden's own link look "created before" O, and finish, respond and inventory then refused
 * it as tampering. Such a link has exactly the shape rotate writes: O's permissions (as a set)
 * and grade, at most one caveat and only `time-before` (S11), no `replacedBy`, `createdAt` as
 * `Date.toISOString()` writes it, and a gap no larger than a clock error (24 hours). The time
 * order is a plausibility check, not a boundary (whoever can edit the registry can edit
 * createdAt too), and a link of this shape grants no more than O; a link that is older, broader
 * or carries anything rotate would not write stays tampering. 1.1.1 records N.createdAt as
 * max(now, O.createdAt), so it no longer writes such links.
 */
const CLOCK_ERROR_MS = 86_400_000;
function rotateWrittenShape(old: RegistryEntry, next: RegistryEntry): boolean {
  const permissions = new Set(old.permissions);
  return next.permissions.length === permissions.size && next.permissions.every(permission => permissions.has(permission))
    && new Set(next.permissions).size === next.permissions.length
    && next.grade === old.grade && next.replacedBy === null
    && next.caveats.length <= 1 && next.caveats.every(caveat => caveat.type === 'time-before')
    && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(next.createdAt)
    && Date.parse(old.createdAt) - Date.parse(next.createdAt) <= CLOCK_ERROR_MS;
}

/**
 * Every active staged-replacement link that macwarden could not have written. A link is an
 * active entry whose `replaces` names an active entry on the same node (a rotation that
 * is staged but not finished). macwarden writes exactly one such link per original, from a
 * newer entry with the same label to an original that is not itself a staged replacement,
 * so a chain, a cycle or two claimants for one original is tampering. A link to a revoked
 * or absent entry is a finished rotation and is not checked here.
 */
export function replacementLinkProblems(entries: RegistryEntry[]): { rootKeyId: string; replaces: string; problem: string }[] {
  const key = (pubkey: string, id: string) => `${pubkey.toLowerCase()}\u0000${id}`;
  const active = new Map(entries.filter(entry => entry.status === 'active')
    .map(entry => [key(entry.nodePubkey, entry.rootKeyId), entry]));
  const isStagedReplacement = (entry: RegistryEntry) => entry.replaces !== null
    && active.has(key(entry.nodePubkey, entry.replaces));
  const claimed = new Map<string, string>();
  const problems: { rootKeyId: string; replaces: string; problem: string }[] = [];
  for (const next of entries) {
    if (next.status !== 'active' || next.replaces === null) continue;
    const target = key(next.nodePubkey, next.replaces);
    const old = active.get(target);
    if (!old) continue;
    const problem = replacementProblem(old, next)
      ?? (isStagedReplacement(old) ? 'the credential it replaces is itself a staged replacement (a chain or a cycle)' : null)
      ?? (claimed.has(target) ? `root key ID ${claimed.get(target)} also claims to replace it` : null);
    claimed.set(target, next.rootKeyId);
    if (problem) problems.push({ rootKeyId: next.rootKeyId, replaces: next.replaces, problem });
  }
  return problems;
}

/**
 * How the credential file found at an entry's recorded `outPath` relates to that entry (RL-01).
 * - `match`: the entry's credential (same root key ID and fingerprint).
 * - `other-credential`: a credential on another root key ID. The path was reused, for example
 *   when the operator baked or staged a replacement where the app reads its file. It says
 *   nothing about this entry, so the entry is handled as having no usable file (proof by ID).
 * - `same-root-key`: the entry's root key ID with another fingerprint (another macaroon on that
 *   root key, such as an attenuated copy, or an edited fingerprint).
 * - `tampered`: the entry's fingerprint on another root key ID. A fingerprint covers the
 *   identifier, which carries the root key ID, so the entry's root key ID or fingerprint was edited.
 */
export function recordedFileRelation(entry: Pick<RegistryEntry, 'rootKeyId' | 'fingerprint'>,
  facts: { rootKeyId: bigint; fingerprint: string }): 'match' | 'other-credential' | 'same-root-key' | 'tampered' {
  const sameId = facts.rootKeyId === BigInt(entry.rootKeyId);
  const sameFingerprint = facts.fingerprint === entry.fingerprint;
  if (sameId) return sameFingerprint ? 'match' : 'same-root-key';
  return sameFingerprint ? 'tampered' : 'other-credential';
}

/**
 * Whether `entry` is a staged (pending) replacement: an active entry whose `replaces` names an
 * active entry on the same node (SPEC 6). One definition for rotate, respond and inventory
 * (RL-07): a `replaces` naming a revoked entry (a finished rotation) or an entry no longer in
 * the registry (pruned) does not make the entry a replacement, so it is an original that can
 * be rotated again.
 */
export function isStagedReplacement(entries: RegistryEntry[], entry: RegistryEntry): boolean {
  const node = entry.nodePubkey.toLowerCase();
  return entry.status === 'active' && entry.replaces !== null && entries.some(old => old.status === 'active'
    && old.nodePubkey.toLowerCase() === node && old.rootKeyId === entry.replaces);
}

/** An lnd-custom caveat (a canary, or any custom caveat) that a rotation cannot reproduce. */
export function hasCustomCaveat(entry: RegistryEntry): boolean {
  return entry.caveats.some(caveat => caveat.type === 'lnd-custom');
}
