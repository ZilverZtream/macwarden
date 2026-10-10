import { endpoint, connectionProblem, flagProblem, nodeInfo, drift, listIds, failureDetails, readBoundedFile, readOnlineCredential, onlineAdapter, onlineWarnings, connectionSettings } from '../online.js';
import * as nodeFs from 'node:fs/promises';
import { resolve } from 'node:path';
import { isProtectedPath, outputNameProblem, resolveUnprotectedPath } from '../protected-path.js';
import { unsafeNodeDiagnostics } from '../environment.js';
import { decodeMacaroon, parseTimeBefore } from '../decode/index.js';
import { type InputIO } from '../input/index.js';
import { createLndAdapter, type LndAdapter } from '../lnd/index.js';
import { Secret } from '../secret.js';
import { openRegistry, replacementLinkProblems, type RegistryEntry } from '../registry/index.js';
import { inventoryResult, type InventoryResult, type OutputResult } from '../output/index.js';
import { readUsage, usagePath, type UsageStore } from '../watch/usage.js';
import { buildAccessReview, formatAccessReview, REPORT_FORMATS, type ReportFormat } from '../report/access-review.js';
import { macwardenVersion } from '../version.js';
import { namesRegistryFile, registryPath, REGISTRY_OUT_REFUSAL } from './bake/out-registry.js';
import { reserveOut } from './bake/write-out.js';
import { reserveFailure } from './bake/out-errors.js';
import { interruptibleChecks, interruptibleReserve, OUT_CREATION_INTERRUPTED, rethrowCancelled } from './bake/out-interrupt.js';
import { Cancelled } from '../cancellation.js';

type ReadLnd = LndAdapter;
export type Deps = {
  lnd?: ReadLnd;
  createAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => ReadLnd;
  fs: InputIO['fs'];
  env: Record<string, string | undefined>;
  clock: () => Date;
};

type InventoryOutput = OutputResult & { schema: 1 };
const methods = [
  ['/lnrpc.Lightning/GetInfo', 'info:read'],
  ['/lnrpc.Lightning/ListPermissions', 'info:read'],
  ['/lnrpc.Lightning/ListMacaroonIDs', 'macaroon:read'],
] as const;

const DURATION = /^([1-9][0-9]{0,4})([mhd])$/;
const DEFAULT_EXPIRING = '7d';

function durationMs(text: string): number {
  const [, count, unit] = DURATION.exec(text)!;
  return Number(count) * (unit === 'd' ? 86_400_000 : unit === 'h' ? 3_600_000 : 60_000);
}

// Earliest time-before caveat of a registry entry, as milliseconds since the epoch, or null.
// LND enforces every first-party caveat, so the earliest expiry is the effective one.
function earliestExpiry(entry: RegistryEntry): number | null {
  let earliest: bigint | null = null;
  for (const caveat of entry.caveats) {
    if (caveat.type !== 'time-before') continue;
    const instant = parseTimeBefore(caveat.value);
    if (instant !== undefined && (earliest === null || instant < earliest)) earliest = instant;
  }
  return earliest === null ? null : Number(earliest / 1_000_000n);
}

function entryView(entry: RegistryEntry) {
  return { label: entry.label, grade: entry.grade, permissions: entry.permissions,
    caveats: entry.caveats, createdAt: entry.createdAt, status: entry.status,
    fingerprint: entry.fingerprint, outPath: entry.outPath,
    replaces: entry.replaces, replacedBy: entry.replacedBy };
}

function fail(code: number, step: string | null, message: string, warnings: string[] = []): InventoryOutput {
  return { schema: 1, command: 'inventory', ok: false, warnings,
    result: null, error: { code, step, message } };
}

function ownPermission(permissions: string[], verify: boolean): string | null {
  const held = new Set(permissions);
  for (const [method, required] of methods) {
    if (!held.has(required) && !held.has(`uri:${method}`)) return `${method} requires ${required}`;
  }
  if (verify && !held.has('macaroon:read')
    && !held.has('uri:/lnrpc.Lightning/CheckMacaroonPermissions'))
    return '/lnrpc.Lightning/CheckMacaroonPermissions requires macaroon:read';
  return null;
}


function lndFailure(error: unknown, stage: string, warnings: string[]): InventoryOutput {
  const failure = failureDetails(error);
  return fail(failure.code, stage, failure.message, warnings);
}

async function runSteps(args: string[], deps: Deps): Promise<InventoryOutput> {
  const supplied: Record<string, string> = {};
  let pending: string | null = null;
  const valueFlags = ['--lnd-rest', '--tls-cert', '--macaroon', '--registry', '--expiring-within', '--report', '--out'];
  for (const arg of args) {
    if (pending) {
      if (arg.startsWith('--')) return fail(2, null, flagProblem(pending, 'missing'));
      supplied[pending] = arg;
      pending = null;
    } else if (arg === '--json' || arg === '--verify') continue;
    else if (valueFlags.includes(arg)) {
      if (arg in supplied) return fail(2, null, flagProblem(arg, 'repeated'));
      pending = arg;
    }
    else return fail(2, null, `unknown argument; inventory takes only flags: ${valueFlags.join(' ')} --verify --json`);
  }
  if (pending) return fail(2, null, flagProblem(pending, 'missing'));
  const expiringWithin = supplied['--expiring-within'];
  if (expiringWithin !== undefined && !DURATION.test(expiringWithin))
    return fail(2, null, '--expiring-within must be 1 to 99999 followed by m (minutes), h (hours) or d (days), for example 30d');
  const reportFormat = supplied['--report'] as ReportFormat | undefined;
  if (reportFormat !== undefined && !REPORT_FORMATS.includes(reportFormat))
    return fail(2, null, `--report takes one of ${REPORT_FORMATS.join(', ')}`);
  const reportOut = supplied['--out'];
  if (reportOut !== undefined && reportFormat === undefined) return fail(2, null, '--out needs --report <format>');
  if (reportOut !== undefined && isProtectedPath(reportOut)) return fail(3, 'N7', 'protected report path');
  const reportName = reportOut === undefined ? null : outputNameProblem(reportOut);
  if (reportName) return fail(3, 'N7', `report path refused: ${reportName}`);
  if (reportOut !== undefined) {
    // Each check is abandoned on an interrupt (a stalled mount): exit 6, step cancelled.
    const checks = interruptibleChecks(deps.fs);
    let reportPath: string;
    try { reportPath = await resolveUnprotectedPath(reportOut, checks); }
    catch (error) { rethrowCancelled(error); return fail(3, 'N7', 'cannot check report path'); }
    const registryFile = await registryPath(supplied['--registry'], checks, deps.env);
    if (registryFile !== null && namesRegistryFile(reportPath, registryFile))
      return fail(3, 'N7', REGISTRY_OUT_REFUSAL.replace('output path', 'report path'));
  }
  const settings = connectionSettings(flag => supplied[flag], deps.env);
  if (settings.problem) return fail(2, null, settings.problem);
  // connectionProblem below refuses a missing setting before either path is used.
  const host = settings.host, certPath = settings.cert as string, ownPath = settings.own as string;
  const connection = connectionProblem(host, certPath, ownPath);
  if (connection) return fail(2, null, connection);
  const restEndpoint = endpoint(host!)!;
  if (unsafeNodeDiagnostics(deps.env)) return fail(2, 'N2', 'unsafe Node diagnostic settings');

  let cert: Buffer;
  let own: Awaited<ReturnType<typeof readOnlineCredential>>['secret'];
  try {
    if (isProtectedPath(certPath)) return fail(4, 'N2', 'unreadable TLS certificate');
    const resolvedCertPath = await deps.fs.realpath(certPath);
    if (isProtectedPath(resolvedCertPath)) return fail(4, 'N2', 'unreadable TLS certificate');
    cert = await readBoundedFile(resolvedCertPath, deps.fs);
  } catch { return fail(4, 'N2', 'unreadable TLS certificate'); }
  try {
    own = (await readOnlineCredential(ownPath,
      { stdin: process.stdin, fs: deps.fs })).secret;
  } catch { return fail(4, 'N2', 'unreadable own macaroon'); }
  let facts;
  try { facts = decodeMacaroon(own); }
  catch { return fail(4, 'N2', 'undecodable own macaroon'); }
  const missing = ownPermission(facts.permissions, args.includes('--verify'));
  if (missing) return fail(4, 'N2', `own macaroon missing permission: ${missing}`);
  const warnings = facts.rootKeyId === 0n ? ['own-root-key-0'] : [];

  let entries: RegistryEntry[];
  let registryLocation: string;
  try {
    const registry = await openRegistry(supplied['--registry'], {
      fs: deps.fs as typeof nodeFs,
      env: deps.env,
    });
    entries = registry.entries;
    registryLocation = registry.location;
  } catch { return fail(3, 'N3', 'unreadable or invalid registry', warnings); }
  // Usage recorded by `macwarden watch` is optional context: a damaged file is a warning.
  let usage: UsageStore | null = null;
  try { usage = await readUsage(usagePath(registryLocation), deps.fs as typeof nodeFs); }
  catch { warnings.push('usage-unreadable'); }

  const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: restEndpoint, tlsCert: cert, macaroon: own });
  if (!adapter) return fail(8, 'internal', 'unexpected failure', warnings);
  const lnd = onlineAdapter(adapter);

  let info: Awaited<ReturnType<LndAdapter['getInfo']>>;
  try { info = nodeInfo(await lnd.getInfo()); }
  catch (error) { return lndFailure(error, 'N4', warnings); }
  try {
    if (drift(await lnd.listPermissions())) warnings.push('snapshot-drift');
  } catch (error) { return lndFailure(error, 'N4', warnings); }
  let ids: bigint[];
  try {
    ids = await listIds(lnd);
  } catch (error) { return lndFailure(error, 'N4', warnings); }
  const ownEntries = entries.filter(entry => entry.nodePubkey.toLowerCase() === info.pubkey.toLowerCase());
  const byId = new Map(ownEntries.map(entry => [entry.rootKeyId, entry]));
  const inLnd = new Set(ids.map(id => id.toString()));
  const joined = new Set(inLnd);
  for (const entry of ownEntries) {
    if (entry.status === 'active') joined.add(entry.rootKeyId);
  }
  const pendingReplacements = new Set(ownEntries.filter(entry => entry.status === 'active'
    && entry.replaces !== null && byId.get(entry.replaces)?.status === 'active')
    .map(entry => entry.replaces as string));
  // Links macwarden could not have written (chains, cycles, two claimants): flagged, never trusted.
  const invalidLinks = new Set(replacementLinkProblems(ownEntries).map(problem => problem.rootKeyId));
  const now = deps.clock().getTime();
  const window = durationMs(expiringWithin ?? DEFAULT_EXPIRING);
  const rootKeys = [...joined].sort((left, right) => {
    const a = BigInt(left);
    const b = BigInt(right);
    return a < b ? -1 : a > b ? 1 : 0;
  }).map(rootKeyId => {
    const entry = byId.get(rootKeyId);
    const present = inLnd.has(rootKeyId);
    const flags = [
      ...(rootKeyId === '0' ? ['default-root-key'] : []),
      ...(rootKeyId === facts.rootKeyId.toString() ? ['own-credential'] : []),
      // macwarden's own credential is known even when no registry entry records it.
      ...(present && !entry && rootKeyId !== facts.rootKeyId.toString() ? ['unknown'] : []),
      ...(!present && entry?.status === 'active' ? ['missing-in-lnd'] : []),
      ...(present && entry?.status === 'revoked' ? ['revoked-but-present'] : []),
      ...(pendingReplacements.has(rootKeyId) ? ['pending-replacement'] : []),
      ...(entry?.status === 'active' && entry.replaces !== null
        && byId.get(entry.replaces)?.status === 'active' ? ['replacement'] : []),
      ...(invalidLinks.has(rootKeyId) ? ['invalid-replacement'] : []),
    ];
    // Expiry matters only for credentials still in use: active entries LND still holds.
    const expiry = entry?.status === 'active' && present ? earliestExpiry(entry) : null;
    if (expiry !== null && expiry <= now) flags.push('expired');
    else if (expiry !== null && expiry <= now + window) flags.push('expiring');
    const seen = usage?.forCredential(info.pubkey, { rootKeyId }) ?? [];
    const used = seen.length ? { calls: seen.reduce((sum, record) => sum + record.calls, 0),
      errors: seen.reduce((sum, record) => sum + record.errors, 0),
      lastUsed: seen.reduce((last, record) => record.lastSeen > last ? record.lastSeen : last, ''),
      methods: [...new Set(seen.map(record => record.method))].sort() } : undefined;
    // Denied uses the canary guard recorded: someone holds this credential.
    const triggered = usage?.canaryUsesFor(info.pubkey, rootKeyId) ?? null;
    if (triggered) flags.push('canary-triggered');
    return { rootKeyId, inLnd: present, flags, verify: 'not-checked' as 'accepted' | 'rejected' | 'error' | 'canary' | 'not-checked',
      expires: expiry === null ? null : new Date(expiry).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      entry: entry ? entryView(entry) : null, ...(used ? { usage: used } : {}),
      ...(triggered ? { canary: { uses: triggered.uses, firstUse: triggered.firstUse, lastUse: triggered.lastUse } } : {}) };
  });
  if (args.includes('--verify')) {
    for (const row of rootKeys) {
      const entry = byId.get(row.rootKeyId);
      if (entry?.status !== 'active' || !entry.outPath || entry.outPath === '-') continue;
      // A canary's custom caveat makes LND refuse it unless watch's guard is registered, so a
      // check here would always fail: report it as a canary instead of an error.
      if (entry.caveats.some(caveat => caveat.type === 'lnd-custom')) { row.verify = 'canary'; continue; }
      let mac: Secret;
      let decoded: ReturnType<typeof decodeMacaroon>;
      try {
        // SAFE-02: a registry entry is editable metadata; a protected outPath (macaroons.db,
        // wallet.db, a *.key, ...), or one that resolves to it, is never probed: unverified.
        if (isProtectedPath(entry.outPath)) continue;
        const path = await deps.fs.realpath(entry.outPath);
        if (isProtectedPath(path) || !(await deps.fs.stat(path)).isFile()) continue;
        mac = (await readOnlineCredential(path,
          { stdin: process.stdin, fs: deps.fs })).secret;
        decoded = decodeMacaroon(mac);
      } catch { continue; }
      if (decoded.fingerprint !== entry.fingerprint) continue;
      if (decoded.permissions.length === 0 || !lnd.checkMacaroon) {
        row.verify = 'error';
        continue;
      }
      try {
        const result = await lnd.checkMacaroon(mac, decoded.permissions);
        if (result?.valid === true) row.verify = 'accepted';
        else if (result?.valid === false &&
          (result.reason === 'root-key-missing' || result.reason === 'signature-mismatch')) {
          row.verify = 'rejected';
        } else row.verify = 'error';
      } catch { row.verify = 'error';
      }
      if (row.verify === 'rejected') row.flags.push('rejected');
    }
  }
  const output = inventoryResult({ node: info, rootKeys }, warnings, deps.clock());
  if (expiringWithin !== undefined) {
    // Exit 1 (like scan --fail-on) when an active credential is expired or expires within the window.
    const count = rootKeys.filter(row => row.flags.includes('expired') || row.flags.includes('expiring')).length;
    (output.result as InventoryResult).expiring = { within: expiringWithin, count };
    if (count > 0) output.exitCode = 1;
  }
  if (reportFormat === undefined) return onlineWarnings(output);
  // N7: access-review evidence; registry facts and LND IDs only, never credential bytes.
  // Last use comes from the watch usage file next to the registry, when one exists.
  const usageFor = (rootKeyId: string) => {
    const seen = usage?.forCredential(info.pubkey, { rootKeyId }) ?? [];
    return seen.length ? { calls: seen.reduce((sum, record) => sum + record.calls, 0),
      lastUsed: seen.reduce((last, record) => record.lastSeen > last ? record.lastSeen : last, '') } : null;
  };
  const canaryFor = (rootKeyId: string) => usage?.canaryUsesFor(info.pubkey, rootKeyId) ?? null;
  const review = buildAccessReview({ node: info, ids: [...inLnd], entries: ownEntries, usage: usageFor, canary: canaryFor,
    ownRootKeyId: facts.rootKeyId.toString(), now: deps.clock(), version: macwardenVersion() });
  const text = formatAccessReview(review, reportFormat);
  let path: string | null = null;
  if (reportOut !== undefined) {
    try { await interruptibleChecks(deps.fs).lstat(reportOut); return fail(3, 'N7', 'report file already exists', warnings); }
    catch (error) { rethrowCancelled(error); if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return fail(3, 'N7', 'cannot check report path', warnings); }
    try {
      const reserved = await interruptibleReserve(() => reserveOut(reportOut, deps.fs as typeof nodeFs));
      if (reserved.aclWarning) warnings.push('acl-best-effort');
      try { await reserved.reservation.write(new Secret(Buffer.from(text, 'utf8'))); }
      catch (error) { await reserved.reservation.discard().catch(() => undefined); throw error; }
    } catch (error) {
      if (error instanceof Cancelled) return fail(6, 'cancelled', OUT_CREATION_INTERRUPTED.replace('output file', 'report file'), warnings);
      return fail(3, 'N7', reserveFailure(error, 'cannot write report file'), warnings);
    }
    path = resolve(reportOut);
  }
  if (output.ok && output.command === 'inventory') {
    output.result.report = { format: reportFormat, path, review };
    if (path === null) output.display = { ...output.display, report: text };
  }
  return onlineWarnings(output);
}

export async function run(args: string[], deps: Deps): Promise<InventoryOutput> {
  return onlineWarnings(await runSteps(args, deps));
}

export async function inventory(args: string[]): Promise<OutputResult> {
  return run(args, { createAdapter: createLndAdapter, fs: nodeFs,
    env: { ...process.env }, clock: () => new Date() });
}
