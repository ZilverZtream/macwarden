// `macwarden watch`: a read-only LND RPC middleware that attributes every authenticated
// call to a credential (root key ID, fingerprint, registry label), records usage next
// to the registry, and guards canary macaroons. Intercepted macaroon bytes are decoded
// in memory to derive the fingerprint and dropped; payloads and metadata are never read,
// except that with --payment-journal the request payload of a payment-initiating or
// payment-deleting method is decoded for its payment hash, amount and fee limit
// (src/watch/payment-request.ts) and journaled (src/watch/payment-journal.ts).
import { randomUUID } from 'node:crypto';
import * as nodeFs from 'node:fs/promises';
import { hostname as nodeHostname } from 'node:os';
import { resolve as resolvePath } from 'node:path';
import { Cancelled, cancellationSignal } from '../cancellation.js';
import { decodeMacaroon, macaroonId } from '../decode/index.js';
import { unsafeNodeDiagnostics } from '../environment.js';
import { createLndAdapter, registerMiddleware, type LndAdapter, type MiddlewareCall,
  type MiddlewareEnd, type MiddlewareSession } from '../lnd/index.js';
import { credentialText, endpoint, failureDetails, nodeInfo, onlineAdapter, readBoundedFile,
  readOnlineCredential, connectionSettings } from '../online.js';
import { isProtectedPath } from '../protected-path.js';
import { LOCK_FILE_LIMIT, readPlainFile } from '../bounded-file.js';
import { openRegistry, type RegistryEntry } from '../registry/index.js';
import { ownProcessDomain, validDomain, type ProcessDomain } from '../registry/process-domain.js';
import type { Secret } from '../secret.js';
import { isRootKeyId } from '../root-key-id.js';
import { renderWatchEvent, type OutputResult, type WatchEvent } from '../output/index.js';
import { canaryConfigPath, canaryEntries, readCanaryConfig } from '../watch/canary.js';
import { readUsage, usagePath, writeUsage, UsageFileError, UsageStore } from '../watch/usage.js';
import { ALERT_CLEANUP_MS, ALERT_KILL_MS, alertCleanupDone, reapAlertGroups, runAlertCommand } from '../watch/alert.js';
import { createAlertRunner, createAlertThrottle } from '../watch/alert-throttle.js';
import { createOutputQueue, fdWriter } from '../watch/output-queue.js';
import { JournalError, PaymentJournal, type JournalStats, type UnregisterReason } from '../watch/payment-journal.js';
import { JOURNALED_METHODS } from '../watch/payment-request.js';
import { macwardenVersion } from '../version.js';

export type Register = typeof registerMiddleware;

export type Deps = {
  lnd?: LndAdapter;
  createAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => LndAdapter;
  register?: Register;
  fs: typeof nodeFs;
  env: Record<string, string | undefined>;
  clock: () => Date;
  /**
   * A monotonic clock in ms (default performance.now()) for the flush, reload and stable-session
   * timers, which a wall clock stepping back once stalled. When given, observation coverage is
   * measured on it too, with `clock` only placing spans (watch() passes it); a caller that gives
   * only `clock` (a test scripting wall time) gets coverage that follows `clock`.
   */
  monotonic?: () => number;
  /**
   * Receives each rendered event line. It must never block: intercept feedback shares
   * the event loop. Priority lines (canary alerts, status) must not be dropped.
   */
  emit: (line: string, priority?: boolean) => void;
  /** Lines the output dropped because its reader fell behind. */
  dropped?: () => number;
  /** Waits for queued output, at most the given milliseconds. */
  drainOutput?: (ms: number) => Promise<boolean>;
  /** After closeOutput: resolves once the write already in flight has completed (or after `ms`), so nothing interleaves with the summary. */
  settleOutput?: (ms: number) => Promise<boolean>;
  /** Abandons queued output after a final drain timed out (a reader that never reads). */
  closeOutput?: () => void;
  platform?: NodeJS.Platform;
  /** Runs the alert command; aborting the signal cancels it (watch is stopping). */
  alert?: (command: string, event: WatchEvent, signal: AbortSignal) => Promise<void>;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  hostname?: () => string;
  pid?: number;
  /** This process's boot and PID-namespace identity (process-domain.ts); null when unknown. */
  processDomain?: () => Promise<ProcessDomain | null>;
  /** How often canaries are re-read (default CANARY_RELOAD_MS). */
  canaryReloadMs?: number;
};

type WatchOutput = OutputResult & { schema: 1 };
type Request = { host: string; grpcHost: string; grpcPort: number; grpcSource: string; cert: string; own: string; registry?: string;
  name: string; untilMs: number | null; alertCommand?: string; alertsOnly: boolean; json: boolean; paymentJournal?: string };

const valueFlags = new Set(['--lnd-rest', '--lnd-grpc', '--tls-cert', '--macaroon', '--registry',
  '--middleware-name', '--until', '--alert-command', '--payment-journal']);
const switchFlags = new Set(['--json', '--alerts-only']);
const FLUSH_MS = 5_000;
// The usage file is rewritten whole, so flushes are spaced by its size: on average at
// most this many bytes per second reach the disk, however busy the node is.
const FLUSH_BYTES_PER_SECOND = 64 * 1024;
const MAX_BACKOFF_MS = 30_000;
// Canaries baked while watch runs are picked up within this time (and on every reconnect).
export const CANARY_RELOAD_MS = 60_000;
// Distinct credential IDs counted exactly in the summary; a hostile LND could send more.
const CREDENTIAL_COUNT_LIMIT = 10_000;
// Attribution (decoding the caller's macaroon, recording usage, emitting the event) runs
// behind a bounded queue, a batch per event-loop turn, never before the next intercept's
// feedback. When callers outpace it, further work is dropped and counted: the node's RPC
// latency never grows with the call rate. Each item holds at most its macaroon bytes.
const ATTRIBUTION_QUEUE_ITEMS = 20_000;
const ATTRIBUTION_QUEUE_BYTES = 16 * 1024 * 1024;
const ATTRIBUTION_BATCH = 256;
// Attribution may use at most this share of wall time (a token bucket, refilled as time
// passes, at most ATTRIBUTION_BURST_MS banked), so reading and answering intercepts always
// gets most of the CPU; under overload the queue fills and further calls are dropped and
// counted. When the budget is spent, the next batch waits on a short timer, never spins.
const ATTRIBUTION_SHARE = 0.2;
const ATTRIBUTION_BURST_MS = 5;
const ATTRIBUTION_RETRY_MS = 5;
// Registry re-reads on reconnect are debounced; the periodic reload still runs every
// CANARY_RELOAD_MS, so a new canary is picked up within that time regardless.
const RECONNECT_RELOAD_MS = 5_000;
// Connection attempts before the first registration; then watch fails instead of looping.
const INITIAL_ATTEMPTS = 3;
// A session must stay up this long before the reconnect backoff starts again at 1 s.
const STABLE_SESSION_MS = 60_000;
// Request IDs remembered for attribution of responses and stream messages. At the bound the
// least recently seen is forgotten, so a caller opening many calls cannot make a live stream
// count again (an earlier version forgot every ID at once).
const REQUEST_KEY_LIMIT = 50_000;
const DENIAL = 'permission denied';

function fail(code: number, step: string, message: string, warnings: WatchOutput['warnings'] = []): WatchOutput {
  return { schema: 1, command: 'watch', ok: false, warnings, result: null, error: { code, step, message } };
}

function duration(value: string): number | null {
  const match = /^([1-9][0-9]{0,5})(s|m|h|d)$/.exec(value);
  if (!match) return null;
  const unit = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[match[2] as 's' | 'm' | 'h' | 'd'];
  return Number(match[1]) * unit;
}

function hostPort(value: string): { host: string; port: number } | null {
  const url = endpoint(value);
  if (!url) return null;
  const parsed = new URL(url);
  // URL drops the scheme's default port: an explicit :443 came back as an empty string (1.2.1).
  return { host: parsed.hostname.replace(/^\[|\]$/g, ''), port: parsed.port === '' ? 443 : Number(parsed.port) };
}

function parse(args: string[], env: Deps['env']): Request | string {
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flags.has(flag)) return `repeated flag ${flag}`;
    if (switchFlags.has(flag)) flags.set(flag, true);
    else if (valueFlags.has(flag)) {
      const value = args[++i];
      if (value === undefined || value.startsWith('--')) return `missing value for ${flag}`;
      flags.set(flag, value);
    } else return 'unknown flag';
  }
  const get = (flag: string) => { const value = flags.get(flag); return typeof value === 'string' ? value : undefined; };
  const { host, cert, own, grpc: grpcValue, problem: mixedSource } = connectionSettings(get, env, true);
  if (mixedSource) return mixedSource;
  if (!host) return 'missing --lnd-rest (or MACWARDEN_LND_REST)';
  if (!cert) return 'missing --tls-cert (or MACWARDEN_TLS_CERT)';
  if (!own) return 'missing --macaroon (or MACWARDEN_MACAROON)';
  if (own === '-' || credentialText(own)) return 'own macaroon must be a file path';
  const rest = hostPort(host);
  if (!rest) return 'invalid LND REST endpoint';
  const grpcSource = get('--lnd-grpc') !== undefined ? '--lnd-grpc'
    : grpcValue !== undefined ? 'MACWARDEN_LND_GRPC' : 'the default port 10009 on the --lnd-rest host';
  const grpc = grpcValue === undefined ? { host: rest.host, port: 10009 } : hostPort(grpcValue);
  if (!grpc) return 'invalid LND gRPC endpoint';
  const name = get('--middleware-name') ?? 'macwarden-watch';
  if (!/^[A-Za-z0-9._-]{5,48}$/.test(name)) return '--middleware-name must be 5-48 letters, digits, dot, underscore or dash';
  const until = get('--until');
  const untilMs = until === undefined ? null : duration(until);
  if (until !== undefined && untilMs === null) return '--until must be a whole number followed by s, m, h or d';
  const alertCommand = get('--alert-command');
  if (alertCommand !== undefined && !/^(?:\/|[A-Za-z]:[\\/])/.test(alertCommand))
    return '--alert-command must be an absolute path to an executable';
  const paymentJournal = get('--payment-journal');
  if (paymentJournal !== undefined && !paymentJournal.trim()) return '--payment-journal must be a file path';
  return { host: endpoint(host)!, grpcHost: grpc.host, grpcPort: grpc.port, grpcSource, cert, own, registry: get('--registry'),
    name, untilMs, alertCommand, alertsOnly: flags.get('--alerts-only') === true, json: flags.get('--json') === true, paymentJournal };
}

/** The longest delay setTimeout honours (signed 32-bit milliseconds); longer ones fire after 1 ms. */
export const MAX_TIMER_MS = 2 ** 31 - 1;

/**
 * Calls onExpire once `ms` have passed on a monotonic clock. `--until` accepts up to 999999
 * days, far beyond one timer (audit MW102-09: `--until 25d` ended at once), so the wait is
 * split into chunks of at most MAX_TIMER_MS, each re-measured against the one deadline.
 */
export function scheduleDeadline(ms: number, onExpire: () => void, now: () => number = () => performance.now()): { clear: () => void } {
  const deadline = now() + ms;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let cleared = false;
  const arm = (): void => {
    if (cleared) return;
    const left = deadline - now();
    if (left <= 0) { onExpire(); return; }
    timer = setTimeout(arm, Math.min(Math.ceil(left), MAX_TIMER_MS));
  };
  arm();
  return { clear: () => { cleared = true; clearTimeout(timer); } };
}

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    const timer = setTimeout(done, ms);
    function done() { clearTimeout(timer); signal?.removeEventListener('abort', done); resolve(); }
    signal?.addEventListener('abort', done, { once: true });
  });
}

/** One watcher per registry: an exclusive lock file, replaced only when its owner is gone. */
class OwnerlessLock extends Error {
  /** What the operator is told at W6. */
  readonly detail: string;
  constructor(message: string, detail: string) { super(message); this.detail = detail; }
}
const ownerless = (path: string) => new OwnerlessLock('watch lock without owner record',
  `the watch lock ${path} holds no owner record (an earlier watch was interrupted while creating it); `
  + 'if no watch is running for this registry, delete that file and start watch again');

type LockOwner = { pid: number; hostname: string; domain?: unknown };

/**
 * True only when the recorded owner provably no longer runs; anything uncertain keeps the
 * lock (fail closed). Order matters:
 * 1. another host: its processes cannot be checked from here;
 * 2. same host, another boot: every process of that boot is gone;
 * 3. same host, the recorded PID is ours: it names this process, which holds no lock yet,
 *    so the recorded owner is gone (a restarted container running watch as PID 1 again);
 * 4. same boot, another PID namespace or silo: the PID cannot be probed from here;
 * 5. otherwise probe the PID; only ESRCH (no such process) counts as gone.
 * Two containers that share a registry volume must not share a hostname.
 */
export function lockOwnerGone(owner: LockOwner, host: string, pid: number, domain: ProcessDomain | null,
  probe: (pid: number) => void = target => process.kill(target, 0)): boolean {
  if (owner.hostname !== host) return false;
  const recorded = validDomain(owner.domain) ? owner.domain : null;
  if (recorded && domain && recorded.platform === domain.platform && recorded.bootId !== domain.bootId) return true;
  if (owner.pid === pid) return true;
  if (recorded && domain && (recorded.platform !== domain.platform
    || (recorded.platform === 'linux' && domain.platform === 'linux' && recorded.pidNamespace !== domain.pidNamespace)
    || (recorded.platform === 'win32' && domain.platform === 'win32' && recorded.siloId !== domain.siloId))) return false;
  if (owner.pid <= 0) return false;
  try { probe(owner.pid); return false; }
  catch (error) { return (error as NodeJS.ErrnoException).code === 'ESRCH'; }
}

/**
 * Removes a stale lock so that exactly one of several watches starting at once takes over.
 * Unlinking by path would race: B could delete the fresh lock A created after both read the
 * same stale record. Instead the lock is renamed to a unique name, which only one process can
 * do for a given file. If the file moved is not the stale record read earlier (another watch
 * already replaced it), it is put back without overwriting anything (link fails if the path
 * exists) and the lock counts as held.
 */
async function takeOverStaleLock(path: string, stale: string, pid: number, deps: Deps): Promise<void> {
  const quarantine = `${path}.stale-${pid}-${randomUUID()}`;
  try { await deps.fs.rename(path, quarantine); }
  catch (error) {
    // Another watch moved it first: the caller retries the exclusive create and loses or wins there.
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  let moved = '';
  try { moved = await readPlainFile(quarantine, deps.fs, LOCK_FILE_LIMIT); } catch { /* treated as not ours */ }
  if (moved === stale) { await deps.fs.unlink(quarantine).catch(() => undefined); return; }
  // Not the stale record: restore it unless something already took the path, then back off.
  try { await deps.fs.link(quarantine, path); } catch { /* the path is taken; the moved file stays aside */ }
  await deps.fs.unlink(quarantine).catch(() => undefined);
  throw Object.assign(new Error('watch lock held'), { code: 'EEXIST' });
}

/** Locks this process holds now: a second request for one is refused, never taken over as stale. */
const heldLocks = new Set<string>();

export async function acquireLock(path: string, deps: Deps): Promise<() => Promise<void>> {
  // A lock recorded with this PID is stale only when this process does not hold it (a restarted
  // watch whose earlier run died); one this process holds now is held, whatever the record says.
  const key = resolvePath(path);
  if (heldLocks.has(key)) throw Object.assign(new Error('watch lock held'), { code: 'EEXIST' });
  const host = (deps.hostname ?? nodeHostname)();
  const pid = deps.pid ?? process.pid;
  // The process domain (boot ID plus PID namespace or silo) tells a reused PID apart: after a
  // reboot, or in a restarted container, the same number names a different process.
  const domain = await (deps.processDomain ?? ownProcessDomain)().catch(() => null);
  const body = `${JSON.stringify({ pid, hostname: host, ...(domain ? { domain } : {}) })}\n`;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const handle = await deps.fs.open(path, 'wx', 0o600);
      let identity: { dev: bigint; ino: bigint };
      try {
        await handle.writeFile(body, 'utf8');
        identity = await handle.stat({ bigint: true });
      } catch (failure) {
        // A lock without its owner record would block every later watch: remove it.
        await handle.close().catch(() => undefined);
        await deps.fs.unlink(path).catch(() => undefined);
        throw failure;
      }
      await handle.close();
      // On Windows an exclusive create follows a dangling symbolic link and creates its target
      // (audit 1.2.1): the lock must be the regular file at the path itself, or the file it did
      // create is removed and the lock refused.
      const onDisk = await deps.fs.lstat(path, { bigint: true }).catch(() => null);
      if (!onDisk || !onDisk.isFile() || onDisk.isSymbolicLink() || onDisk.dev !== identity.dev || onDisk.ino !== identity.ino) {
        const target = await deps.fs.realpath(path).catch(() => null);
        if (target && resolvePath(target) !== key) await deps.fs.unlink(target).catch(() => undefined);
        throw new OwnerlessLock('watch lock path is a symbolic link', `the watch lock path ${path} is a symbolic link; remove it and start watch again`);
      }
      heldLocks.add(key);
      return async () => {
        heldLocks.delete(key);
        // Remove the lock only while it is still the file this watch created: same device
        // and inode and still our owner record (a file system may reuse a freed inode number
        // at once, so identity alone cannot tell a replaced lock apart).
        try {
          const current = await deps.fs.lstat(path, { bigint: true });
          if (current.dev === identity.dev && current.ino === identity.ino
            && await readPlainFile(path, deps.fs, LOCK_FILE_LIMIT) === body) await deps.fs.unlink(path);
        } catch { /* already gone */ }
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST' || attempt) throw error;
      let owner: { pid?: unknown; hostname?: unknown; domain?: unknown } = {};
      let stale: string;
      try {
        // The owner record is read only as a plain file: never through a symlink (SAFE-02),
        // through one descriptor bound to the checked file and at most LOCK_FILE_LIMIT + 1 bytes.
        stale = await readPlainFile(path, deps.fs, LOCK_FILE_LIMIT); owner = JSON.parse(stale) as typeof owner;
      }
      catch { throw ownerless(path); }
      if (typeof owner.hostname !== 'string' || !Number.isSafeInteger(owner.pid)) throw ownerless(path);
      if (!lockOwnerGone(owner as LockOwner, host, pid, domain)) throw Object.assign(new Error('watch lock held'), { code: 'EEXIST' });
      await takeOverStaleLock(path, stale, pid, deps);
    }
  }
  throw new Error('watch lock unavailable');
}

/** The alert command must be a regular executable file that runs without a shell. */
async function alertCommandProblem(command: string, deps: Deps): Promise<string | null> {
  const platform = deps.platform ?? process.platform;
  if (platform === 'win32' && !/\.(?:exe|com)$/i.test(command))
    return '--alert-command must be an .exe or .com file on Windows (a .cmd, .bat or .ps1 script cannot run without a shell; '
      + 'wrap it, for example with a small compiled launcher)';
  try {
    const stat = await deps.fs.stat(command);
    if (!stat.isFile()) return '--alert-command must be a regular file';
    if (platform !== 'win32') {
      if ((stat.mode & 0o111) === 0) return '--alert-command is not executable';
      await deps.fs.access(command, nodeFs.constants.X_OK);
    }
  } catch { return '--alert-command does not exist or cannot be executed'; }
  return null;
}

const CREDENTIAL_ID = /^id:[0-9a-f]{16}$/;

function labels(entries: RegistryEntry[], pubkey: string): Map<string, RegistryEntry> {
  const byRootKey = new Map<string, RegistryEntry>();
  for (const entry of entries) {
    if (entry.nodePubkey.toLowerCase() !== pubkey || entry.status !== 'active' || entry.rootKeyId === '0') continue;
    byRootKey.set(entry.rootKeyId, entry);
  }
  return byRootKey;
}

async function runSteps(args: string[], deps: Deps): Promise<WatchOutput> {
  const request = parse(args, deps.env);
  if (typeof request === 'string') return fail(2, 'W1', request);
  if (request.alertCommand) {
    const problem = await alertCommandProblem(request.alertCommand, deps);
    if (problem) return fail(2, 'W1', problem);
  }
  if (unsafeNodeDiagnostics(deps.env)) return fail(2, 'W2', 'unsafe Node diagnostic settings');
  let cert: Buffer;
  let own: Secret;
  try {
    if (isProtectedPath(request.cert)) return fail(4, 'W3', 'unreadable TLS certificate');
    const certPath = await deps.fs.realpath(request.cert);
    if (isProtectedPath(certPath)) return fail(4, 'W3', 'unreadable TLS certificate');
    cert = await readBoundedFile(certPath, deps.fs);
  } catch { return fail(4, 'W3', 'unreadable TLS certificate'); }
  try { own = (await readOnlineCredential(request.own, { stdin: process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, 'W3', 'unreadable own macaroon'); }
  let ownFacts;
  try { ownFacts = decodeMacaroon(own); } catch { return fail(4, 'W3', 'undecodable own macaroon'); }
  const held = new Set(ownFacts.permissions);
  if (!held.has('macaroon:write') && !held.has('uri:/lnrpc.Lightning/RegisterRPCMiddleware'))
    return fail(4, 'W3', 'own macaroon missing permission: macaroon:write (RegisterRPCMiddleware)');
  if (!held.has('info:read') && !held.has('uri:/lnrpc.Lightning/GetInfo'))
    return fail(4, 'W3', 'own macaroon missing permission: info:read (GetInfo)');
  const warnings: WatchOutput['warnings'] = ownFacts.rootKeyId === 0n ? ['own-root-key-0'] : [];

  if (request.registry && isProtectedPath(request.registry)) return fail(3, 'W4', 'protected registry path', warnings);
  let registry;
  try { registry = await openRegistry(request.registry, { fs: deps.fs, env: deps.env }); }
  catch { return fail(3, 'W4', 'unreadable or invalid registry', warnings); }
  let canaryConfig: Awaited<ReturnType<typeof readCanaryConfig>>;
  try { canaryConfig = await readCanaryConfig(canaryConfigPath(registry.location), deps.fs); }
  catch { return fail(3, 'W4', 'unreadable or invalid canary configuration', warnings); }

  const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: request.host, tlsCert: cert, macaroon: own });
  if (!adapter) return fail(8, 'internal', 'unexpected failure', warnings);
  let pubkey: string;
  try { pubkey = nodeInfo(await onlineAdapter(adapter).getInfo()).pubkey; }
  catch (error) {
    // Interrupted before anything registered or was locked: nothing changed (exit 6, as SPEC 10).
    if (error instanceof Cancelled) return fail(6, 'cancelled', 'interrupted', warnings);
    const failure = failureDetails(error); return fail(failure.code, 'W5', failure.message, warnings);
  }
  let known = labels(registry.entries, pubkey);
  let canaries = canaryEntries(registry.entries, canaryConfig, pubkey);
  // Re-reads labels and canaries, so a canary baked while watch runs is guarded without a
  // restart. Returns true when the middleware registrations must change (guard needed or
  // its caveat name changed). A registry that cannot be read keeps the current state.
  let guardName: string | null = null;
  const reloadCanaries = async (): Promise<boolean> => {
    try {
      const fresh = await openRegistry(request.registry, { fs: deps.fs, env: deps.env });
      const config = await readCanaryConfig(canaryConfigPath(fresh.location), deps.fs);
      known = labels(fresh.entries, pubkey);
      canaries = canaryEntries(fresh.entries, config, pubkey);
      canaryConfig = config;
    } catch { return false; }
    const wanted = canaries.size && canaryConfig ? canaryConfig.caveatName : null;
    return wanted !== guardName;
  };

  // Interrupted before W6: nothing locked or registered (audit 1.2.1).
  if (cancellationSignal()?.aborted) return fail(6, 'cancelled', 'interrupted', warnings);
  const usageFile = usagePath(registry.location);
  let release: () => Promise<void>;
  try { release = await acquireLock(`${registry.location}.watch.lock`, deps); }
  catch (error) {
    if (error instanceof OwnerlessLock) return fail(3, 'W6', error.detail, warnings);
    return fail(3, 'W6', `another watch is running for this registry (lock ${registry.location}.watch.lock)`, warnings);
  }
  let usage: UsageStore;
  try { usage = await readUsage(usageFile, deps.fs); }
  catch (error) {
    // A corrupt file must not keep the watcher (and so every canary) down: set it aside
    // for inspection and start empty. A file that cannot be read at all still stops here.
    if (!(error instanceof UsageFileError) || error.message !== 'invalid usage file') {
      await release(); return fail(3, 'W6', 'unreadable usage file', warnings);
    }
    const aside = `${usageFile}.corrupt-${deps.clock().toISOString().replace(/[:.]/g, '-')}`;
    try { await deps.fs.rename(usageFile, aside); }
    catch { await release(); return fail(3, 'W6', 'invalid usage file that could not be set aside', warnings); }
    warnings.push({ code: 'usage-file-quarantined', message: `invalid usage file moved to ${aside}; recording starts empty` });
    usage = new UsageStore();
  }
  // The payment journal (opt-in): opened, locked and started with a synced run-start before
  // anything registers, so a journal that cannot be written stops watch here (exit 3).
  let journal: PaymentJournal | null = null;
  const journalStopped: { reason: JournalStats['stopped'] } = { reason: null };
  if (request.paymentJournal !== undefined) {
    try {
      journal = await PaymentJournal.open(request.paymentJournal, pubkey, macwardenVersion(), { fs: deps.fs, clock: deps.clock,
        lock: path => acquireLock(path, deps), platform: deps.platform, onStop: reason => { journalStopped.reason = reason; } });
    } catch (error) {
      await release();
      return fail(3, 'W6', error instanceof JournalError ? error.message : 'cannot open payment journal', warnings);
    }
  }
  if (journal?.aclWarning) warnings.push({ code: 'acl-best-effort',
    message: 'the payment journal lies on a volume that stores no Windows permissions (FAT or exFAT): anyone with access to the volume can read it' });

  const register = deps.register ?? registerMiddleware;
  const sleep = deps.sleep ?? defaultSleep;
  const signal = cancellationSignal();
  const stop = new AbortController();
  const onAbort = () => stop.abort();
  signal?.addEventListener('abort', onAbort, { once: true });
  if (signal?.aborted) stop.abort();
  const monotonic = deps.monotonic ?? (() => performance.now());
  // Coverage follows the monotonic source only when the caller supplied one (see Deps.monotonic).
  const coverageMono = (): number | undefined => deps.monotonic ? monotonic() : undefined;
  let untilExpired = false;
  const untilTimer = request.untilMs === null ? undefined
    : scheduleDeadline(request.untilMs, () => { untilExpired = true; stop.abort(); });
  const counters = { calls: 0, errors: 0, alerts: 0, canaryUses: 0, alertFailures: 0, reconnects: 0, credentials: new Set<string>(),
    attributionDropped: 0 };
  // The bounded attribution queue (see ATTRIBUTION_QUEUE_ITEMS).
  type Work = { run: () => void; bytes: number };
  const work: Work[] = [];
  let workHead = 0;
  let workBytes = 0;
  let workScheduled = false;
  const runWork = (limit: number, budgetMs = Number.POSITIVE_INFINITY): void => {
    let done = 0;
    const until = performance.now() + budgetMs;
    while (workHead < work.length && done < limit && (done % 16 !== 0 || performance.now() < until)) {
      const item = work[workHead];
      work[workHead++] = undefined as unknown as Work;
      workBytes -= item.bytes;
      done += 1;
      try { item.run(); } catch { /* one bad item never stops attribution */ }
    }
    if (workHead === work.length) { work.length = 0; workHead = 0; }
    else if (workHead > 4_096) { work.splice(0, workHead); workHead = 0; }
  };
  let budget = ATTRIBUTION_BURST_MS;
  let budgetAt = performance.now();
  const drainWork = (): void => {
    workScheduled = false;
    const now = performance.now();
    budget = Math.min(ATTRIBUTION_BURST_MS, budget + (now - budgetAt) * ATTRIBUTION_SHARE);
    budgetAt = now;
    if (budget > 0) {
      runWork(ATTRIBUTION_BATCH, budget);
      const spent = performance.now() - now;
      budget -= spent;
      budgetAt = performance.now();
    }
    if (workHead < work.length) {
      workScheduled = true;
      if (budget > 0) setImmediate(drainWork);
      else setTimeout(drainWork, ATTRIBUTION_RETRY_MS).unref();
    }
  };
  // `make` runs only when the call is admitted, so a dropped call costs a counter and no
  // copy of its macaroon (the copy and its fingerprint are most of the per-call cost).
  const enqueue = (bytes: number, make: () => () => void): void => {
    const size = bytes + 256;
    if (work.length - workHead >= ATTRIBUTION_QUEUE_ITEMS || workBytes + size > ATTRIBUTION_QUEUE_BYTES) {
      counters.attributionDropped += 1;
      // Whose call this was is unknown, so the usage data is marked incomplete for everyone.
      usage.noteDroppedAttribution(deps.clock().getTime());
      return;
    }
    work.push({ run: make(), bytes: size });
    workBytes += size;
    if (!workScheduled) { workScheduled = true; setImmediate(drainWork); }
  };
  const startedAt = deps.clock();
  const requestKeys = new Map<string, { credential: string; rootKeyId: string; method: string; stream: boolean }>();
  const emit = (event: WatchEvent) => {
    if (request.alertsOnly && event.event !== 'canary' && event.event !== 'status') return;
    deps.emit(renderWatchEvent(event, request.json ? 'json' : 'text'), event.event === 'canary' || event.event === 'status');
  };
  let journalStopReported = false;
  // A journal that stopped (full, failed write, stalled disk) is reported once, as a status event.
  const reportJournalStop = () => {
    if (journalStopReported || !journalStopped.reason) return;
    journalStopReported = true;
    emit({ event: 'status', time: deps.clock().toISOString(), status: 'payment-journal-stopped', reason: journalStopped.reason });
  };
  let reportedDrops = 0;
  const reportDrops = () => {
    const total = deps.dropped?.() ?? 0;
    if (total > reportedDrops) {
      emit({ event: 'status', time: deps.clock().toISOString(), status: 'output-dropped', dropped: total - reportedDrops });
      // Re-read: once output is closed the notice itself is dropped, and counting it as a new
      // drop would emit another notice every FLUSH_MS for ever.
      reportedDrops = deps.dropped?.() ?? total;
    }
  };
  // Whoever holds a canary controls how often it is used, so alerting is bounded:
  // one alert per canary per window plus a counted summary, and at most one
  // --alert-command process at a time (src/watch/alert-throttle.ts).
  const runner = createAlertRunner(
    (event, cancel) => deps.alert ? deps.alert(request.alertCommand!, event, cancel)
      : runAlertCommand(request.alertCommand!, event, undefined, undefined, cancel),
    event => {
      // A failed alert must be visible: the operator relies on it for paging.
      counters.alertFailures += 1;
      if (!warnings.some(item => (typeof item === 'string' ? item : item.code) === 'alert-failed'))
        warnings.push({ code: 'alert-failed', message: 'the alert command failed for at least one canary alert' });
      emit({ event: 'status', time: deps.clock().toISOString(), status: 'alert-failed', rootKeyId: event.rootKeyId, label: event.label });
    });
  // The throttle's key (a registered canary or the shared bucket) gives each canary its own
  // waiting slot in the runner, so one canary's alert never replaces another's.
  const throttle = createAlertThrottle({ now: () => deps.clock().getTime(), alert: (event, key) => {
    counters.alerts += 1;
    emit(event);
    if (request.alertCommand) runner.submit(event, key);
  } });

  // Observer: always accepts. Attribution and recording happen after the answer is sent.
  // call.macaroon is read here, synchronously: the middleware wipes the intercepted bytes
  // once this returns. Each registration gets its own observer carrying its session number:
  // attribution is deferred, so work queued by a lost session can still run after the next
  // session began, and LND restarts request IDs with a new session. Correlation keys are
  // therefore session number plus request ID; an ID from one session never matches another's.
  let sessionNumber = 0;
  const observe = (session: number) => (call: MiddlewareCall): string => {
    // A payment request is captured for the journal now, while its payload is readable; it is
    // decoded and written later, off this path, and dropped (counted) under overload.
    if (journal && call.kind === 'request' && JOURNALED_METHODS.has(call.method)) journal.capture(call);
    // A response's macaroon is never copied (attribute uses only its request ID), so it is not charged.
    enqueue(call.kind === 'response' ? 0 : call.macaroonBytes ?? 0, () => {
      const macaroon = call.kind === 'response' ? null : call.macaroon;
      const { kind, requestId, method, isError, oversizedMacaroon, streamRpc } = call;
      return () => attribute(session, { kind, requestId, method, isError, oversizedMacaroon, streamRpc }, macaroon);
    });
    return '';
  };
  const attribute = (session: number, call: Pick<MiddlewareCall, 'kind' | 'requestId' | 'method' | 'isError' | 'oversizedMacaroon' | 'streamRpc'>,
    macaroon: Secret | null): void => {
    const at = deps.clock();
    if (call.kind === 'response') {
      const id = `${session}:${call.requestId}`;
      const key = requestKeys.get(id);
      if (!key) return;
      // A key is kept after a successful response: LND numbers calls uniquely within a session,
      // so a later request with this ID is a further message of a stream, never a new call, even
      // when watch first saw that stream mid-way (after a reconnect). Kept until an error or
      // until it is the least recently seen at REQUEST_KEY_LIMIT.
      if (!call.isError) { requestKeys.delete(id); requestKeys.set(id, key); return; }
      requestKeys.delete(id);
      counters.errors += 1;
      if (CREDENTIAL_ID.test(key.credential) && isRootKeyId(key.rootKeyId))
        usage.record(pubkey, key.credential, key.rootKeyId, key.method, at, true);
      emit({ event: 'error', time: at.toISOString(), method: key.method, rootKeyId: key.rootKeyId,
        credential: key.credential, label: labelFor(key.rootKeyId) });
      return;
    }
    let credential = call.oversizedMacaroon ? 'id:undecodable' : 'id:none';
    let rootKeyId = 'none';
    if (macaroon) {
      try { const identity = macaroonId(macaroon); credential = identity.id; rootKeyId = identity.rootKeyId.toString(); }
      catch { credential = 'id:undecodable'; }
    }
    // A stream reports stream_auth and then one request per message: count it once.
    const id = `${session}:${call.requestId}`;
    const seen = requestKeys.get(id);
    if (call.kind === 'request' && seen) { requestKeys.delete(id); requestKeys.set(id, seen); return; }
    if (!seen && requestKeys.size >= REQUEST_KEY_LIMIT) requestKeys.delete(requestKeys.keys().next().value as string);
    requestKeys.delete(id);
    requestKeys.set(id, { credential, rootKeyId, method: call.method, stream: call.kind === 'stream_auth' || call.streamRpc === true });
    // A message of a stream whose opening this session never saw (the stream was open before a
    // reconnect, or its key was evicted): remembered for its final error, but not a new call.
    // Its opening was counted when seen, or counted as a dropped attribution.
    if (call.kind === 'request' && call.streamRpc === true) return;
    counters.calls += 1;
    if (counters.credentials.size < CREDENTIAL_COUNT_LIMIT) counters.credentials.add(credential);
    if (CREDENTIAL_ID.test(credential) && isRootKeyId(rootKeyId)) usage.record(pubkey, credential, rootKeyId, call.method, at);
    emit({ event: 'call', time: at.toISOString(), method: call.method, rootKeyId, credential,
      label: labelFor(rootKeyId) });
  };
  // Root key 0 is shared by LND's default macaroons, so it is never attributed to a label.
  const labelFor = (rootKeyId: string): string | null => known.get(rootKeyId)?.label ?? null;

  // Canary uses never go through the droppable attribution queue: a burst of ordinary calls
  // must not be able to hide one. Each use is denied at once; uses wait here, one slot per
  // canary plus one shared slot for conditions that are not registered canaries, so this
  // map is bounded by the registry, never by the caller. They are handled on the next turn,
  // before attribution work, and alerting stays rate-limited by the throttle.
  const pendingCanaries = new Map<string, { method: string; oversizedMacaroon?: boolean; macaroon: Secret | null;
    entry: RegistryEntry | undefined; count: number }>();
  let canariesScheduled = false;
  const processCanaries = (): void => {
    canariesScheduled = false;
    for (const [key, item] of pendingCanaries) {
      pendingCanaries.delete(key);
      const { method, oversizedMacaroon, macaroon, entry, count } = item;
      let credential = oversizedMacaroon ? 'id:undecodable' : 'id:none';
      let rootKeyId = entry?.rootKeyId ?? 'none';
      if (macaroon) {
        try { const identity = macaroonId(macaroon); credential = identity.id; rootKeyId = identity.rootKeyId.toString(); }
        catch { credential = 'id:undecodable'; }
      }
      // Recorded apart from ordinary usage, so inventory can show the canary as triggered.
      if (entry) usage.recordCanary(pubkey, entry.rootKeyId, count, deps.clock());
      throttle.offer(key, { event: 'canary', time: deps.clock().toISOString(), method, rootKeyId, credential,
        label: entry?.label ?? null, denied: true }, count);
    }
  };
  // Canary guard: registered for the installation's caveat name; denies every use.
  const guard = (call: MiddlewareCall): string => {
    if (call.kind === 'response') return '';
    // Counted at once, so the summary is exact whatever happens to attribution.
    counters.canaryUses += 1;
    const entry = canaries.get(call.customCaveatCondition);
    // The condition string comes from the caller (anyone holding a canary can append custom
    // caveats), so it never chooses a key: every unregistered condition shares one slot.
    const key = entry ? `canary:${entry.rootKeyId}` : 'unknown-condition';
    const pending = pendingCanaries.get(key);
    if (pending) pending.count += 1;
    // The macaroon is taken now: the middleware wipes the intercepted bytes after this returns.
    else pendingCanaries.set(key, { method: call.method, oversizedMacaroon: call.oversizedMacaroon, macaroon: call.macaroon, entry, count: 1 });
    if (!canariesScheduled) { canariesScheduled = true; setImmediate(processCanaries); }
    return DENIAL;
  };

  // Flushes run one at a time, so an older snapshot can never replace a newer one.
  let flushing: Promise<void> = Promise.resolve();
  let nextFlushAt = Number.NEGATIVE_INFINITY;
  const flush = (): Promise<void> => {
    flushing = flushing.then(async () => {
      if (!usage.changed) return;
      const bytes = await writeUsage(usageFile, usage, deps.fs).catch(() => {
        if (!warnings.includes('usage-write-failed')) warnings.push('usage-write-failed');
        return 0;
      });
      nextFlushAt = monotonic() + Math.max(FLUSH_MS, Math.ceil(bytes / FLUSH_BYTES_PER_SECOND * 1_000));
    });
    return flushing;
  };
  const flusher = setInterval(() => {
    reportDrops();
    reportJournalStop();
    if (monotonic() >= nextFlushAt) { usage.extendCoverage(pubkey, deps.clock(), coverageMono()); void flush(); }
  }, FLUSH_MS);
  let refresh = new AbortController();
  const reloader = setInterval(() => { void reloadCanaries().then(changed => { if (changed) refresh.abort(); }); }, deps.canaryReloadMs ?? CANARY_RELOAD_MS);
  let failure: MiddlewareEnd | null = null;
  let everRegisteredRun = false;
  const unreachable = () => `could not register with LND's gRPC endpoint ${request.grpcHost}:${request.grpcPort} `
    + `(from ${request.grpcSource}); check that LND is running and reachable there, or pass --lnd-grpc <host:port>`;
  // A fresh, removable stop listener per wait: racing one long-lived promise that never
  // settles would retain a reaction on it for every reconnect.
  const stopWait = (): { promise: Promise<'stopped'>; off: () => void } => {
    let off = () => {};
    const promise = new Promise<'stopped'>(resolve => {
      if (stop.signal.aborted) { resolve('stopped'); return; }
      const on = () => resolve('stopped');
      stop.signal.addEventListener('abort', on, { once: true });
      off = () => stop.signal.removeEventListener('abort', on);
    });
    return { promise, off };
  };
  let lastReload = Number.NEGATIVE_INFINITY;
  let nodeChanged: string | null = null;
  let journalStats: JournalStats | null = null;
  try {
    let backoff = 1_000;
    let everRegistered = false;
    const markRegistered = () => { everRegistered = true; everRegisteredRun = true; };
    let initialFailures = 0;
    while (!stop.signal.aborted) {
      if (monotonic() - lastReload >= RECONNECT_RELOAD_MS) { lastReload = monotonic(); await reloadCanaries(); }
      // Each pass yields one event-loop turn, so a peer that ends sessions at once can never
      // starve timers (flushes, stop, --until) with a loop of resolved promises.
      else await new Promise(resolve => setImmediate(resolve));
      refresh = new AbortController();
      const sessions: MiddlewareSession[] = [];
      // Request IDs restart when LND restarts: never carry them across sessions. Clearing alone
      // is not enough (deferred attribution of the last session may still add keys), so keys
      // also carry the session number.
      requestKeys.clear();
      sessionNumber += 1;
      const registeredSessions = new Set<number>();
      const expected = canaries.size ? 2 : 1;
      let registeredAt: number | null = null;
      const onRegistered = (index: number) => () => {
        registeredSessions.add(index);
        // Payments are seen by the observer (session 0): its registration starts journal coverage.
        if (index === 0) journal?.registered();
        if (registeredSessions.size === expected) {
          markRegistered();
          registeredAt = monotonic();
          // Observation coverage: recommend reports how long usage was watched.
          usage.beginCoverage(pubkey, deps.clock(), coverageMono());
          emit({ event: 'status', time: deps.clock().toISOString(), status: 'registered',
            canaries: canaries.size, readOnly: true });
        }
      };
      try {
        const target = { host: request.grpcHost, port: request.grpcPort, tlsCert: cert, macaroon: own };
        sessions.push(register(target, { name: request.name, readOnly: true }, observe(sessionNumber), onRegistered(0),
          journal ? { payloadMethods: JOURNALED_METHODS } : {}));
        guardName = canaries.size && canaryConfig ? canaryConfig.caveatName : null;
        if (guardName)
          sessions.push(register(target, { name: `${request.name}-guard`, readOnly: false, caveatName: guardName },
            guard, onRegistered(1)));
      } catch {
        for (const session of sessions) session.close();
        failure = { registered: false, code: 3, stage: 'W7', message: 'invalid middleware registration', disabled: false };
        break;
      }
      const refreshed = new Promise<'refresh'>(resolve => refresh.signal.addEventListener('abort', () => resolve('refresh'), { once: true }));
      const stopping = stopWait();
      const first = await Promise.race([...sessions.map(session => session.ended), stopping.promise, refreshed]);
      stopping.off();
      for (const session of sessions) session.close();
      const ends = await Promise.all(sessions.map(session => session.ended));
      usage.endCoverage(pubkey, deps.clock(), coverageMono());
      const why: UnregisterReason = first === 'stopped' || stop.signal.aborted ? 'stopping' : first === 'refresh' ? 'refresh' : 'stream-lost';
      journal?.unregistered(why);
      reportJournalStop();
      if (first === 'stopped' || stop.signal.aborted) break;
      // The canaries changed (for example one was baked): register again with the new set.
      if (first === 'refresh') continue;
      const end = ends.find(item => item.message !== 'closed') ?? first;
      const wasRegistered = registeredSessions.size === expected;
      // Configuration and authentication problems do not heal by retrying. "Already
      // registered" after an earlier successful session is LND still holding the lost
      // stream (it notices only at its keepalive), so that one is retried with backoff.
      const staleRegistration = end.code === 3 && everRegistered;
      if (end.disabled || (!wasRegistered && !staleRegistration
        && (end.code === 4 && end.message === 'LND authentication failure' || end.code === 3 || end.code === 5))) {
        failure = end; break;
      }
      // Before any session has registered, a failure is a configuration problem (wrong
      // endpoint, firewall, LND down), not a lost stream: give up after a few quick tries.
      if (!everRegistered && ++initialFailures >= INITIAL_ATTEMPTS) {
        failure = { registered: false, code: 4, stage: 'W7', message: unreachable(), disabled: false }; break;
      }
      // A session that stayed up resets the backoff; one that flaps keeps it growing.
      if (registeredAt !== null && monotonic() - registeredAt >= STABLE_SESSION_MS) backoff = 1_000;
      counters.reconnects += 1;
      emit({ event: 'status', time: deps.clock().toISOString(), status: 'reconnecting', canaries: canaries.size, readOnly: true });
      await sleep(backoff, stop.signal);
      backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
      // The node behind the endpoint may have changed while the stream was down (a restore, a
      // re-pointed DNS name or port forward): attribution, labels, canaries and coverage all
      // belong to the node read at W5, so a different node ends the run. A GetInfo that fails
      // (LND still down) is left to the registration attempt and its backoff.
      if (everRegistered && !stop.signal.aborted) {
        const stopping = stopWait();
        const current = await Promise.race([onlineAdapter(adapter).getInfo().then(info => nodeInfo(info).pubkey, () => null),
          stopping.promise]);
        stopping.off();
        if (current !== null && current !== 'stopped' && current !== pubkey) { nodeChanged = current; break; }
      }
    }
  } finally {
    clearInterval(flusher);
    clearInterval(reloader);
    untilTimer?.clear();
    signal?.removeEventListener('abort', onAbort);
    processCanaries();
    runWork(Number.MAX_SAFE_INTEGER);
    throttle.flush();
    // From here on no alert command starts (audit MW102-05): the usage write below may take a
    // while (the Windows owner-only creation runs a helper), and a waiting alert must not start
    // behind a command that ends meanwhile. The running one gets its deadline at runner.stop.
    runner.stopping();
    usage.endCoverage(pubkey, deps.clock(), coverageMono());
    await flush();
    if (journal) {
      journal.unregistered('stopping');
      journalStats = await journal.close();
      reportJournalStop();
      if (journalStats.stopped) warnings.push({ code: 'payment-journal-stopped', message: `the payment journal stopped (${journalStats.stopped}); `
        + 'payments after that were not journaled, and reconcile reports that time as a gap' });
      if (journalStats.dropped) warnings.push({ code: 'payment-journal-dropped', message: `${journalStats.dropped} payment calls were not `
        + 'journaled (overload or a stopped journal); the journal records when, and reconcile reports those times as gaps' });
    }
    await release();
    // One alert deadline for the whole shutdown (audit MW102-05): no alert command starts from
    // here on and an alert still waiting is discarded (reported as alert-failed); the running
    // one may finish within ALERT_KILL_MS, then it is cancelled (group or tree killed), and
    // the process-tree kills get what is left of ALERT_CLEANUP_MS.
    const alertDeadline = monotonic() + ALERT_KILL_MS + ALERT_CLEANUP_MS;
    await runner.stop(ALERT_KILL_MS, ALERT_CLEANUP_MS);
    // Anything an alert command left running is killed now, not left behind (POSIX groups).
    reapAlertGroups();
    await alertCleanupDone(Math.max(0, alertDeadline - monotonic()));
    reportDrops();
    // Queued events go out before the summary; a reader that never reads cannot hold us forever.
    // A reader that never reads must not keep this process alive: after the bounded
    // drain, drop what is left (counted) and stop retrying writes.
    if (await deps.drainOutput?.(5_000) === false) { deps.closeOutput?.(); await deps.settleOutput?.(1_000); }
  }
  // A run that never registered watched nothing: it must not report success. One interrupted
  // before its first registration was interrupted, not refused (audit 1.2.1).
  if (!failure && !everRegisteredRun && signal?.aborted)
    return fail(6, 'cancelled', `interrupted before any session registered with LND's gRPC endpoint ${request.grpcHost}:${request.grpcPort} `
      + `(from ${request.grpcSource})`, warnings);
  if (nodeChanged) return fail(4, 'W5', `the node at ${request.host} changed while watch was reconnecting (${pubkey} at start, now ${nodeChanged}); `
    + 'usage, labels and canaries were read for the first node: start watch again for the node now there', warnings);
  // --until ran out while LND had not yet confirmed the registration: say so instead of
  // blaming the endpoint, which may be fine but slow.
  if (!failure && !everRegisteredRun && untilExpired)
    return fail(4, 'W7', `--until expired before LND confirmed the middleware registration with its gRPC endpoint `
      + `${request.grpcHost}:${request.grpcPort} (from ${request.grpcSource})`, warnings);
  if (!failure && !everRegisteredRun) failure = { registered: false, code: 4, stage: 'W7', message: unreachable(), disabled: false };
  if (failure) {
    if (failure.disabled) return fail(4, 'W7', 'LND RPC middleware is disabled: set rpcmiddleware.enable=true in lnd.conf and restart LND '
      + '(do not set rpcmiddleware.addmandatory: it blocks every RPC while no watcher is connected)', warnings);
    return fail(failure.code, 'W7', failure.message === 'LND authentication failure'
      ? 'LND refused the middleware registration (authentication failure)' : failure.message, warnings);
  }
  const endedAt = deps.clock();
  return { schema: 1, command: 'watch', ok: true, warnings, error: null, result: {
    node: pubkey, startedAt: startedAt.toISOString(), endedAt: endedAt.toISOString(), calls: counters.calls,
    errors: counters.errors, credentials: counters.credentials.size, canaryAlerts: counters.alerts, canaryUses: counters.canaryUses,
    alertFailures: counters.alertFailures, reconnects: counters.reconnects, canaries: canaries.size, usageFile,
    droppedUsageRecords: usage.dropped, evictedUsageRecords: usage.evictions, droppedAttributions: counters.attributionDropped, droppedEvents: deps.dropped?.() ?? 0,
    ...(journalStats ? { paymentJournal: { path: journalStats.path, payments: journalStats.payments, deletions: journalStats.deletions,
      dropped: journalStats.dropped, stopped: journalStats.stopped } } : {}) } };
}

export async function run(args: string[], deps: Deps): Promise<WatchOutput> {
  return runSteps(args, deps);
}

/** Production event output: queued and written off the event loop (see output-queue.ts). */
export function stdoutEvents(): Pick<Deps, 'emit' | 'dropped' | 'drainOutput' | 'closeOutput' | 'settleOutput'> {
  let stopped = false;
  const queue = createOutputQueue(fdWriter(1, undefined, undefined, () => stopped));
  return { emit: (line, priority) => queue.push(line, priority), dropped: queue.dropped, drainOutput: ms => queue.drain(ms), settleOutput: ms => queue.settle(ms),
    closeOutput: () => { stopped = true; queue.close(); } };
}

export async function watch(args: string[]): Promise<OutputResult> {
  return run(args, { createAdapter: createLndAdapter, fs: nodeFs, env: { ...process.env }, clock: () => new Date(),
    monotonic: () => performance.now(), ...stdoutEvents() });
}
