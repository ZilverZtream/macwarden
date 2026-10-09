// `macwarden recommend <label | root-key-id | id:…>` or `--target-file <file>`: least
// privilege from observed usage.
// It reads what `macwarden watch` recorded, maps each observed method to the permissions
// LND requires for it (ListPermissions), and prints the narrower credential to bake.
// Recommendation only: nothing is baked, revoked or written.
import * as nodeFs from 'node:fs/promises';
import { decodeMacaroon, macaroonId } from '../decode/index.js';
import { unsafeNodeDiagnostics } from '../environment.js';
import { createLndAdapter, type LndAdapter } from '../lnd/index.js';
import { credentialText, endpoint, failureDetails, nodeInfo, onlineAdapter, readBoundedFile,
  readOnlineCredential, recoveryPath, shellQuote, connectionSettings } from '../online.js';
import { formatDuration, type OutputResult, type RecommendResult } from '../output/index.js';
import { isProtectedPath } from '../protected-path.js';
import { openRegistry, type RegistryEntry } from '../registry/index.js';
import type { Secret } from '../secret.js';
import { isRootKeyId } from '../root-key-id.js';
import { readUsage, usagePath } from '../watch/usage.js';

export type Deps = {
  lnd?: LndAdapter;
  createAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => LndAdapter;
  fs: typeof nodeFs;
  env: Record<string, string | undefined>;
};

type RecommendOutput = OutputResult & { schema: 1 };

function fail(code: number, step: string, message: string, warnings: RecommendOutput['warnings'] = []): RecommendOutput {
  return { schema: 1, command: 'recommend', ok: false, warnings, result: null, error: { code, step, message } };
}

const valueFlags = new Set(['--lnd-rest', '--tls-cert', '--macaroon', '--registry', '--target-file']);

/**
 * Below this much watched time a narrowing command is withheld: methods an app calls
 * rarely (payments, channel opens, weekly jobs) may not have been seen yet. Seven days
 * covers one weekly cycle. --accept-short-observation prints the command anyway.
 */
export const SHORT_OBSERVATION_SECONDS = 7 * 86_400;

function sortUnique(values: Iterable<string>): string[] { return [...new Set(values)].sort(); }

const quote = (value: string): string => shellQuote(value);

async function runSteps(args: string[], deps: Deps): Promise<RecommendOutput> {
  const flags = new Map<string, string>();
  const operands: string[] = [];
  let acceptShort = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--json') continue;
    if (arg === '--accept-short-observation') { if (acceptShort) return fail(2, 'R1', `repeated flag ${arg}`); acceptShort = true; continue; }
    if (valueFlags.has(arg)) {
      const value = args[++i];
      if (flags.has(arg)) return fail(2, 'R1', `repeated flag ${arg}`);
      if (value === undefined || value.startsWith('--')) return fail(2, 'R1', `missing value for ${arg}`);
      flags.set(arg, value);
    } else if (arg.startsWith('--')) return fail(2, 'R1', 'unknown flag');
    else operands.push(arg);
  }
  const targetFile = flags.get('--target-file');
  if (operands.length !== (targetFile === undefined ? 1 : 0))
    return fail(2, 'R1', 'give exactly one label, root key ID or credential ID (id:…), or --target-file <file>');
  const selector = operands[0] ?? '';
  const byCredential = /^id:[0-9a-f]{16}$/.test(selector);
  const byId = isRootKeyId(selector);
  if (targetFile === undefined && !byCredential && !byId && !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(selector))
    return fail(2, 'R1', 'selector must be a label, a root key ID or id:<16 hex>');
  const { host, cert: certPath, own: ownPath, problem: mixedSource } = connectionSettings(flag => flags.get(flag), deps.env);
  if (mixedSource) return fail(2, 'R1', mixedSource);
  if (!host) return fail(2, 'R1', 'missing --lnd-rest (or MACWARDEN_LND_REST)');
  if (!certPath) return fail(2, 'R1', 'missing --tls-cert (or MACWARDEN_TLS_CERT)');
  if (!ownPath) return fail(2, 'R1', 'missing --macaroon (or MACWARDEN_MACAROON)');
  if (ownPath === '-' || credentialText(ownPath)) return fail(2, 'R1', 'own macaroon must be a file path');
  const rest = endpoint(host);
  if (!rest) return fail(2, 'R1', 'invalid LND REST endpoint');
  if (unsafeNodeDiagnostics(deps.env)) return fail(2, 'R2', 'unsafe Node diagnostic settings');

  let cert: Buffer;
  let own: Secret;
  try {
    if (isProtectedPath(certPath)) return fail(4, 'R3', 'unreadable TLS certificate');
    const resolved = await deps.fs.realpath(certPath);
    if (isProtectedPath(resolved)) return fail(4, 'R3', 'unreadable TLS certificate');
    cert = await readBoundedFile(resolved, deps.fs);
  } catch { return fail(4, 'R3', 'unreadable TLS certificate'); }
  try { own = (await readOnlineCredential(ownPath, { stdin: process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, 'R3', 'unreadable own macaroon'); }
  let facts;
  try { facts = decodeMacaroon(own); } catch { return fail(4, 'R3', 'undecodable own macaroon'); }
  if (!facts.permissions.includes('info:read')
    && !['GetInfo', 'ListPermissions'].every(method => facts.permissions.includes(`uri:/lnrpc.Lightning/${method}`)))
    return fail(4, 'R3', 'own macaroon missing permission: info:read (GetInfo, ListPermissions)');
  const warnings: RecommendOutput['warnings'] = facts.rootKeyId === 0n ? ['own-root-key-0'] : [];

  const registryPath = flags.get('--registry');
  if (registryPath && isProtectedPath(registryPath)) return fail(3, 'R4', 'protected registry path', warnings);
  let registry;
  try { registry = await openRegistry(registryPath, { fs: deps.fs, env: deps.env }); }
  catch { return fail(3, 'R4', 'unreadable or invalid registry', warnings); }
  let usage;
  try { usage = await readUsage(usagePath(registry.location), deps.fs); }
  catch { return fail(3, 'R4', 'unreadable or invalid usage file', warnings); }

  const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: rest, tlsCert: cert, macaroon: own });
  if (!adapter) return fail(8, 'internal', 'unexpected failure', warnings);
  const lnd = onlineAdapter(adapter);
  let pubkey: string;
  let methodPermissions: Record<string, string[]>;
  try {
    pubkey = nodeInfo(await lnd.getInfo()).pubkey;
    methodPermissions = await lnd.listPermissions();
  } catch (error) { const failure = failureDetails(error); return fail(failure.code, 'R5', failure.message, warnings); }

  const ownEntries = registry.entries.filter(entry => entry.nodePubkey.toLowerCase() === pubkey);
  // The one active registry entry for a non-zero root key ID, or none when there is none or
  // more than one (the permissions to check against would be ambiguous).
  const activeFor = (rootKeyId: string): RegistryEntry | undefined => {
    if (rootKeyId === '0') return undefined;
    const found = ownEntries.filter(item => item.rootKeyId === rootKeyId && item.status === 'active');
    return found.length === 1 ? found[0] : undefined;
  };
  let entry: RegistryEntry | undefined;
  let select: { rootKeyId?: string; credential?: string };
  let label = selector;
  // Permissions decoded from --target-file: the selected credential's own, so the widening
  // guard also applies to a credential with no registry entry (a default macaroon).
  let filePermissions: string[] | null = null;
  let fileRootKeyId: string | null = null;
  if (targetFile !== undefined) {
    // The credential ID and permissions come from the identifier only; the file's bytes are not kept.
    let identity;
    try {
      if (isProtectedPath(targetFile)) return fail(3, 'R6', 'protected target file', warnings);
      const secret = (await readOnlineCredential(targetFile, { stdin: process.stdin, fs: deps.fs })).secret;
      identity = macaroonId(secret);
      filePermissions = decodeMacaroon(secret).permissions;
    } catch { return fail(3, 'R6', 'unreadable or undecodable target file', warnings); }
    select = { credential: identity.id };
    label = identity.id;
    fileRootKeyId = identity.rootKeyId.toString();
  } else if (byCredential) {
    select = { credential: selector };
  } else if (byId) {
    // Root key 0 is shared by every default macaroon: only a fingerprint can tell them apart.
    if (selector === '0') return fail(2, 'R6', 'root key ID 0 is shared by the default macaroons; select one with --target-file or its credential ID (id:…)', warnings);
    entry = activeFor(selector);
    select = { rootKeyId: selector };
  } else {
    entry = ownEntries.find(item => item.label === selector && item.status === 'active');
    if (!entry) return fail(2, 'R6', 'no active registry entry with this label on this node', warnings);
    if (entry.rootKeyId === '0') return fail(2, 'R6', 'this entry uses root key ID 0; select it with --target-file', warnings);
    select = { rootKeyId: entry.rootKeyId };
  }
  const records = usage.forCredential(pubkey, select);
  // A credential selector resolves to a registry entry through its usage identity: the root
  // key ID recorded with it (and the file's, for --target-file) must be one non-zero value.
  // One credential ID under several root key IDs is inconsistent evidence and resolves to none.
  const identities = new Set(records.map(item => item.rootKeyId));
  if (fileRootKeyId !== null) identities.add(fileRootKeyId);
  const identity = identities.size === 1 ? [...identities][0] : null;
  if (select.credential !== undefined) {
    if (identity !== null) entry = activeFor(identity);
    if (identities.size > 1) filePermissions = null;
  }
  const byMethod = new Map<string, { calls: number; lastUsed: string }>();
  for (const record of records) {
    const current = byMethod.get(record.method);
    byMethod.set(record.method, { calls: (current?.calls ?? 0) + record.calls,
      lastUsed: current && current.lastUsed > record.lastSeen ? current.lastUsed : record.lastSeen });
  }
  const methods = [...byMethod.keys()].sort();
  const unmapped = methods.filter(method => !Object.hasOwn(methodPermissions, method));
  const observed = methods.map(method => ({ method, ...byMethod.get(method)!,
    permissions: sortUnique(methodPermissions[method] ?? []) }));
  const recommended = sortUnique(observed.flatMap(item => item.permissions));
  const recommendedUris = methods.filter(method => !unmapped.includes(method)).map(method => `uri:${method}`);
  const current = entry ? sortUnique(entry.permissions) : null;
  // Entity permissions the credential holds that no observed method needed.
  const unneeded = current ? current.filter(permission => !permission.startsWith('uri:') && !recommended.includes(permission)) : [];
  // A narrowing command is only printed when the evidence is complete and consistent:
  // following one built from partial or poisoned usage would break the app (missing
  // methods) or widen the credential (methods it never held).
  const incomplete = records.length > 0 && usage.maybeIncomplete();
  if (incomplete) warnings.push({ code: 'usage-incomplete', message: 'the usage data may be missing calls (records were evicted, or watch '
    + 'was overloaded and did not attribute some calls), and any credential could be affected; no narrowing command is printed. '
    + 'For a complete observation, stop watch, move the usage file aside and run watch again' });
  // Every permission set the credential is known to hold must already cover each observed
  // method: the registry entry's and, for --target-file, the file's own.
  const held = [current, filePermissions].filter((item): item is string[] => item !== null);
  const covers = (permissions: string[], method: string) => permissions.includes(`uri:${method}`)
    || (methodPermissions[method] ?? []).every(permission => permissions.includes(permission));
  const beyond = methods.filter(method => !unmapped.includes(method) && held.some(permissions => !covers(permissions, method)));
  // Without any known permission set, narrowing cannot be told from widening.
  const unverified = observed.length > 0 && held.length === 0;
  if (unverified) warnings.push({ code: 'recommendation-unverified', message: 'the observed usage could not be matched to the permissions '
    + 'of exactly one active registry entry (or of --target-file), so a narrowing command could widen the credential; none is printed' });
  if (beyond.length) warnings.push({ code: 'recommendation-broader', message: `observed methods this credential's recorded permissions do not cover: `
    + `${beyond.join(', ')}; the usage data or the registry may be wrong, so no narrowing command is printed` });
  // How long watch observed this node after the credential was created: a provable lower
  // bound, never time watch covered before it existed. Its creation is the registry entry's;
  // without one, the credential existed no later than its first recorded use. Two bounds,
  // the larger is taken: the recorded spans after creation (from 1.1.0), and the covered
  // total minus the most that can lie before creation (all time from the first registration
  // to it). Files written before 1.0.1 record no coverage. Every step must be finite: the
  // usage reader refuses impossible or reversed times, and if evidence that cannot be placed
  // on the clock still got this far, the window is invalid rather than silently long.
  const coverage = usage.coverageFor(pubkey);
  let seconds: number | null = null;
  let invalid = false;
  if (coverage) {
    const start = Date.parse(coverage.firstStart), end = Date.parse(coverage.lastEnd);
    const firstUse = records.length ? records.reduce((first, item) => Math.min(first, Date.parse(item.firstSeen)), Infinity) : null;
    const created = entry ? Date.parse(entry.createdAt) : firstUse;
    const since = Math.max(start, created ?? -Infinity);
    const before = Math.ceil((since - start) / 1_000);
    const spanned = usage.coveredSince(pubkey, since);
    const lower = Math.max(coverage.coveredSeconds - before, spanned ?? 0);
    const bounded = Math.min(lower, Math.floor((end - since) / 1_000));
    invalid = ![start, end, since, before, lower, bounded, firstUse ?? 0, spanned ?? 0].every(Number.isFinite) || end < start;
    if (!invalid) seconds = Math.max(0, bounded);
  }
  // An invalid window is never accepted: --accept-short-observation accepts a short window,
  // not one that cannot be computed.
  const short = invalid || seconds === null || seconds < SHORT_OBSERVATION_SECONDS;
  const observation = { seconds, since: coverage?.firstStart ?? null, until: coverage?.lastEnd ?? null,
    sessions: coverage?.sessions ?? 0, short, accepted: short && acceptShort && !invalid };
  if (invalid && observed.length) warnings.push({ code: 'observation-invalid', message: 'the observation window cannot be computed '
    + 'from the coverage record in the usage file (its times are not valid instants in order); no narrowing command is printed, even with '
    + '--accept-short-observation. Stop watch, move the usage file aside and run watch again' });
  else if (short && observed.length) warnings.push({ code: 'short-observation', message: `usage was observed for ${seconds === null
    ? 'an unknown time (this usage file has no watch coverage record)' : formatDuration(seconds)}, less than ${formatDuration(SHORT_OBSERVATION_SECONDS)}; `
    + 'methods the app calls rarely (such as payments) may be missing, and a credential narrowed to this list would fail on them. '
    + (acceptShort ? 'The narrowing command is printed because --accept-short-observation was given'
      : 'Keep watch running longer, or pass --accept-short-observation to print the narrowing command anyway') });
  const commands: string[] = [];
  if (observed.length && !unmapped.length && !incomplete && !unverified && !beyond.length && !invalid
    && (!short || acceptShort)) {
    const label = entry?.label ? narrowLabel(entry.label) : 'narrowed';
    const connection = `--lnd-rest ${quote(host)} --tls-cert ${quote(recoveryPath(certPath))} --macaroon ${quote(recoveryPath(ownPath))}` +
      (registryPath ? ` --registry ${quote(recoveryPath(registryPath))}` : '');
    commands.push(`macwarden bake --label ${label} --uri ${methods.join(',')} --out <file> ${connection}`);
    // Revoking deletes the whole root key ID: only suggested when the selection covered every
    // credential observed on it (a label or root key ID), never from one credential's usage.
    if (entry?.label && select.credential === undefined) commands.push(`after switching the app to the new file: macwarden revoke ${entry.label} ${connection}`);
  }
  const result: RecommendResult = { node: pubkey, selector: label, label: entry?.label ?? null,
    rootKeyId: entry?.rootKeyId ?? (byId ? selector : identity), credentials: sortUnique(records.map(record => record.credential)),
    observed, unmapped, recommended, recommendedUris, current, unneeded, observation, commands };
  return { schema: 1, command: 'recommend', ok: true, warnings, result, error: null };
}

/** The suggested label: the original plus "-narrow", truncated so it still fits bake's 64-character label rule. */
export function narrowLabel(label: string): string {
  const suffix = '-narrow';
  return `${label.slice(0, 64 - suffix.length)}${suffix}`;
}

export async function run(args: string[], deps: Deps): Promise<RecommendOutput> { return runSteps(args, deps); }

export async function recommend(args: string[]): Promise<OutputResult> {
  return run(args, { createAdapter: createLndAdapter, fs: nodeFs, env: { ...process.env } });
}
