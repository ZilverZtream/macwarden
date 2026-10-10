import * as nodeFs from 'node:fs/promises';
import { Cancelled } from '../cancellation.js';
import type { Readable } from 'node:stream';
import { connectionProblem, drift, endpoint, failureDetails, flagProblem, nodeInfo, onlineAdapter, onlineWarnings,
  readBoundedFile, readOnlineCredential, connectionSettings } from '../online.js';
import { unsafeNodeDiagnostics } from '../environment.js';
import { isProtectedPath } from '../protected-path.js';
import { decodeMacaroon, DecodeError, isL402Container, isL402Macaroon, isNwcContainer, type MacaroonFacts } from '../decode/index.js';
import { readCredential, InputError, UsageError, type InputIO } from '../input/index.js';
import { canBake } from '../grade/index.js';
import { createLndAdapter, type LndAdapter } from '../lnd/index.js';
import { openRegistry, type RegistryEntry } from '../registry/index.js';
import type { Secret } from '../secret.js';
import type { OutputResult, OutputWarning, VerifyResult } from '../output/index.js';
import { inspectResult } from './inspect.js';

export type Deps = {
  lnd?: LndAdapter;
  createAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => LndAdapter;
  fs: InputIO['fs'];
  env: Record<string, string | undefined>;
  clock: () => Date;
  stdin?: Readable & { isTTY?: boolean };
};
type VerifyOutput = OutputResult & { schema: 1 };

const valueFlags = ['--registry', '--lnd-rest', '--tls-cert', '--macaroon'];
// GetInfo (node identity for the registry match), ListPermissions (snapshot drift, as on every
// online command) and CheckMacaroonPermissions are required; ListMacaroonIDs is optional.
const required = [
  ['/lnrpc.Lightning/GetInfo', 'info:read'],
  ['/lnrpc.Lightning/ListPermissions', 'info:read'],
  ['/lnrpc.Lightning/CheckMacaroonPermissions', 'macaroon:read'],
] as const;
const listIdsMethod = ['/lnrpc.Lightning/ListMacaroonIDs', 'macaroon:read'] as const;

// Static operator guidance. macwarden never calls changepassword or touches macaroons.db (SAFE-02).
export const ROOT_KEY_0_ACCEPTED = [
  'This credential is on root key ID 0, shared by admin.macaroon, readonly.macaroon, invoice.macaroon and every macaroon baked without --root_key_id. LND refuses to delete root key ID 0, so it cannot be revoked on its own.',
  'Only regenerating every root key invalidates it: lncli changepassword --new_mac_root_key on the node (it needs the wallet password). macwarden never runs it (SAFE-02).',
  "That also invalidates every other macaroon on the node at once: every app's credential, macwarden's own and any replacement staged with macwarden respond. So regenerate first, in a maintenance window, then bake a fresh per-app macaroon for each app (macwarden bake) and re-pair it. Run macwarden inventory beforehand to list the apps that will need one; staging replacements before the regeneration would only see them invalidated too.",
  'Procedure: docs/incident-playbook.md and docs/replacing-default-macaroons.md.',
];
export const CAN_BAKE_ACCEPTED = 'This credential can bake macaroons (macaroon:generate or uri:/lnrpc.Lightning/BakeMacaroon), or macwarden could not assess all of its permissions. If it leaked, its holder may have created credentials on other root key IDs, and revoking this one does not remove them. Replace and revoke every registered credential with macwarden respond, list unknown root key IDs with macwarden inventory, and if this credential may have been used, regenerate all root keys (see docs/incident-playbook.md).';
export const CAN_BAKE_ROOT_KEY_0 = 'It can also bake macaroons (macaroon:generate or uri:/lnrpc.Lightning/BakeMacaroon), or may (not all of its permissions could be assessed): its holder may have created credentials on other root key IDs. The regeneration invalidates those too; afterwards, revoke any root key ID macwarden inventory still shows as unknown that no app of yours uses.';
export const OWN_ROOT_KEY_ACCEPTED = "This credential shares the root key ID of the credential macwarden is running with, and macwarden revoke refuses its own root key ID. Revoke it with another own credential, or delete that root key ID with lncli deletemacaroonid after switching macwarden to a new session macaroon.";
export const REJECTED_INCONCLUSIVE = 'LND rejected this check, but did not report that the root key ID is gone or that the credential expired. A caveat that depends on the caller (an IP lock, or a custom caveat such as a canary\'s) can make LND accept it from another address or while a middleware runs. Treat it as live until its root key ID is revoked.';
export const LOCAL_EXPIRY_UNCONFIRMED = "By this machine's clock a time-before caveat has passed, but LND did not report the expiry: the clocks may differ, or LND refused an earlier caveat first. A local clock is no proof that the credential is dead.";
export const SIGNATURE_MISMATCH_INCONCLUSIVE = 'LND reports a signature mismatch, but the root key ID is still listed (or could not be listed). This copy is not the credential LND issued: either the root keys were regenerated, or this copy was altered (a flipped byte, a mangled paste, a decoy) and the original it came from may still be accepted. Treat the original as live until its root key ID is revoked.';
export const SIGNATURE_MISMATCH_HOW_TO_CONCLUDE = 'For a conclusive answer, check a copy whose bytes are known to be unaltered: macwarden verify answers conclusively for the exact file it recorded in the registry (same fingerprint). Otherwise compare the fingerprint of this file (above) with one recorded before the incident, such as an inventory --report export or a backup: if they are equal, the bytes are unaltered and the mismatch means the root key was regenerated.';
export const SIGNATURE_MISMATCH_ROOT_KEY_0 = 'On root key ID 0 nothing can be revoked on its own: if you have not regenerated every root key (lncli changepassword --new_mac_root_key, which macwarden never runs), assume the original is still live.';
export const OWN_ROOT_KEY_INCONCLUSIVE = "This credential is on the root key ID of the credential macwarden is running with, which macwarden revoke refuses. To invalidate it: bake a new session credential on its own root key ID, switch MACWARDEN_MACAROON (or --macaroon) to it, then revoke this root key ID from the new session with macwarden revoke <id> --unregistered (or lncli deletemacaroonid <id>). That also invalidates the old session credential.";
export const ROOT_KEY_0_INCONCLUSIVE = 'It is on root key ID 0, which LND cannot revoke on its own: if it may be live, only regenerating every root key invalidates it (lncli changepassword --new_mac_root_key, which macwarden never runs; see docs/incident-playbook.md section 5).';
export const CUSTOM_CAVEAT_REJECTED = 'It carries a custom caveat (a canary, or another lnd-custom caveat): LND accepts it only while a middleware for that caveat, such as macwarden watch, is registered.';

function fail(code: number, step: string | null, message: string, warnings: OutputWarning[] = []): VerifyOutput {
  return { schema: 1, command: 'verify', ok: false, warnings, result: null, error: { code, step, message } };
}

function lndFailure(error: unknown, step: string, warnings: OutputWarning[]): VerifyOutput {
  const failure = failureDetails(error);
  return fail(failure.code, step, failure.message, warnings);
}

type Request = { input: string; unsafeArg: boolean; registry?: string; host: string; cert: string; own: string };

// Returns the request, or a message naming the flag and the rule (never the value).
function parse(args: string[], env: Deps['env']): Request | string {
  const supplied = new Map<string, string>();
  const inputs: string[] = [];
  let unsafeArg = false;
  let endOfFlags = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (endOfFlags) { inputs.push(arg); continue; }
    if (arg === '--') { endOfFlags = true; continue; }
    if (arg === '--json') continue;
    if (arg === '--unsafe-arg') {
      if (unsafeArg) return flagProblem(arg, 'repeated');
      unsafeArg = true;
      continue;
    }
    if (valueFlags.includes(arg)) {
      const value = args[++index];
      if (supplied.has(arg)) return flagProblem(arg, 'repeated');
      if (value === undefined || value.startsWith('--')) return flagProblem(arg, 'missing');
      supplied.set(arg, value);
      continue;
    }
    if (arg.startsWith('-') && arg !== '-')
      return `unknown flag; verify takes: <file | -> --unsafe-arg ${valueFlags.join(' ')} --json`;
    inputs.push(arg);
  }
  if (inputs.length !== 1) return 'expected one input: a credential file, or - for stdin';
  const { host, cert, own, problem: mixedSource } = connectionSettings(flag => supplied.get(flag), env);
  if (mixedSource) return mixedSource;
  const connection = connectionProblem(host, cert, own);
  if (connection) return connection;
  return { input: inputs[0], unsafeArg, registry: supplied.get('--registry'),
    host: endpoint(host!)!, cert: cert!, own: own! };
}

function holds(held: Set<string>, [method, permission]: readonly [string, string]): boolean {
  return held.has(permission) || held.has(`uri:${method}`);
}

/** The registry entry for this credential on this node: the same bytes first, else the same root key ID. */
function registryMatch(entries: RegistryEntry[], pubkey: string, facts: MacaroonFacts): VerifyResult['registry'] {
  const local = entries.filter(entry => entry.nodePubkey.toLowerCase() === pubkey);
  const rootKeyId = facts.rootKeyId.toString();
  const byFingerprint = local.filter(entry => entry.fingerprint === facts.fingerprint);
  const sameId = (entry: RegistryEntry) => entry.rootKeyId === rootKeyId;
  // An active entry outranks a revoked record of the same root key ID.
  const pick = (rows: RegistryEntry[]) => rows.find(entry => entry.status === 'active') ?? rows[0];
  const exact = pick(byFingerprint.filter(sameId));
  if (exact) return { label: exact.label, status: exact.status, match: 'fingerprint' };
  const related = pick(local.filter(sameId));
  return related ? { label: related.label, status: related.status, match: 'root-key-id' } : null;
}

function guidance(result: Omit<VerifyResult, 'guidance'>, localExpiry: boolean): string[] {
  const id = result.rootKeyId;
  if (result.status === 'accepted') {
    const lines = ['LND accepts this credential now: whoever holds a copy can use it against this node.'];
    if (id === '0') return [...lines, ...ROOT_KEY_0_ACCEPTED, ...(result.canBake ? [CAN_BAKE_ROOT_KEY_0] : [])];
    if (result.ownCredential) lines.push(OWN_ROOT_KEY_ACCEPTED);
    else {
      const label = result.registry?.status === 'active' ? result.registry.label : null;
      // By root key ID: a label is ambiguous while a rotation is staged (two active entries).
      lines.push(result.registry === null
        ? `Revoke it: macwarden revoke ${id} --unregistered. It is not in this registry, so first make sure no app you rely on uses root key ID ${id}.`
        : `Revoke it: macwarden revoke ${id}${label ? ` (registered as ${label}; if an app still needs access, rotate it instead: macwarden rotate ${label} --out <file>, switch the app, then macwarden rotate ${label} --finish)` : ''}.`);
      lines.push(`Revoking root key ID ${id} also invalidates every other macaroon baked on it.`);
    }
    if (result.canBake) lines.push(CAN_BAKE_ACCEPTED);
    return lines;
  }
  if (!result.conclusive) {
    const lines = [result.rejection === 'signature-mismatch' ? SIGNATURE_MISMATCH_INCONCLUSIVE : REJECTED_INCONCLUSIVE];
    if (result.rejection === 'signature-mismatch') lines.push(SIGNATURE_MISMATCH_HOW_TO_CONCLUDE);
    if (result.rejection === 'signature-mismatch' && id === '0') lines.push(SIGNATURE_MISMATCH_ROOT_KEY_0);
    if (result.caveats.some(caveat => caveat.type === 'lnd-custom')) lines.push(CUSTOM_CAVEAT_REJECTED);
    if (localExpiry) lines.push(LOCAL_EXPIRY_UNCONFIRMED);
    // Never a revoke command macwarden would refuse (RL-06): not for root key ID 0 (SAFE-03),
    // not for macwarden's own root key ID (revoke V4).
    if (id === '0') { if (result.rejection !== 'signature-mismatch') lines.push(ROOT_KEY_0_INCONCLUSIVE); }
    else if (result.ownCredential) lines.push(OWN_ROOT_KEY_INCONCLUSIVE);
    else lines.push(`To make sure: macwarden revoke ${id}${result.registry === null ? ' --unregistered' : ''}.`);
    return lines;
  }
  const why = result.rejection === 'root-key-missing' ? 'its root key ID no longer exists'
    : result.rejection === 'signature-mismatch' ? (result.rootKeyListed === false
      ? 'its signature does not match and its root key ID is no longer listed'
      : `its root key was regenerated: these are the exact bytes macwarden recorded for root key ID ${id}, and LND no longer accepts their signature`)
      : result.rejection === 'expired' ? 'a time-before caveat has passed' : 'its root key ID is no longer listed';
  const lines = [`LND rejects this credential now: ${why}. It can no longer be used against this node.`];
  if (result.rejection === 'expired' && result.rootKeyListed !== false && id !== '0')
    lines.push(`Its root key ID ${id} still exists: other macaroons baked on it, including copies without this expiry, keep working until it is revoked.`);
  return lines;
}

async function runSteps(args: string[], deps: Deps, warnings: OutputWarning[]): Promise<VerifyOutput> {
  // C1 Parse.
  const request = parse(args, deps.env);
  if (typeof request === 'string') return fail(2, null, request);
  // C2 ENV.
  if (unsafeNodeDiagnostics(deps.env)) return fail(2, 'C2', 'unsafe Node diagnostic settings');
  // C3 Read and decode the credential under test, offline, as inspect does.
  let target: Secret;
  let facts: MacaroonFacts;
  try {
    const read = await readCredential(request.input, { stdin: deps.stdin ?? process.stdin, fs: deps.fs },
      { unsafeArg: request.unsafeArg, nwc: true, l402: true });
    if (read.literal) warnings.push('unsafe-arg');
    if (isNwcContainer(read.secret))
      return fail(3, 'input-form', 'a Nostr Wallet Connect URI is not an LND credential; revoke NWC connections in the wallet service', warnings);
    if (isL402Container(read.secret) || isL402Macaroon(read.secret))
      return fail(3, 'input-form', 'an L402 token is not an LND credential: it pays for access to a service, which alone can revoke it', warnings);
    target = read.secret;
    facts = decodeMacaroon(target);
  } catch (error) {
    if (error instanceof UsageError) return fail(2, null, error.message, warnings);
    if (error instanceof InputError || error instanceof DecodeError) return fail(3, error.stage, error.message, warnings);
    throw error;
  }
  // An empty permission list is never sent: LND would report any macaroon valid for it.
  if (facts.permissions.length === 0)
    return fail(3, 'C3', 'the credential holds no permissions, so LND cannot be asked about it (an empty permission list is never sent)', warnings);
  const offline = inspectResult(facts, deps.clock());

  // C4 OWN.
  let cert: Buffer;
  try {
    if (isProtectedPath(request.cert) || isProtectedPath(await deps.fs.realpath(request.cert)))
      return fail(4, 'C4', 'unreadable TLS certificate', warnings);
    cert = await readBoundedFile(request.cert, deps.fs);
  } catch { return fail(4, 'C4', 'unreadable TLS certificate', warnings); }
  let own: Secret;
  try { own = (await readOnlineCredential(request.own, { stdin: deps.stdin ?? process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, 'C4', 'unreadable own macaroon', warnings); }
  let ownFacts: MacaroonFacts;
  try { ownFacts = decodeMacaroon(own); }
  catch { return fail(4, 'C4', 'undecodable own macaroon', warnings); }
  const held = new Set(ownFacts.permissions);
  for (const method of required)
    if (!holds(held, method)) return fail(4, 'C4', `own macaroon missing permission: ${method[0]} requires ${method[1]}`, warnings);
  const canList = holds(held, listIdsMethod);
  if (ownFacts.rootKeyId === 0n) warnings.push('own-root-key-0');

  // C5 Registry, read-only (no lock).
  let entries: RegistryEntry[];
  try {
    if (request.registry && isProtectedPath(request.registry)) return fail(3, 'C5', 'protected registry path', warnings);
    entries = (await openRegistry(request.registry, { fs: deps.fs as typeof nodeFs, env: deps.env })).entries;
  } catch { return fail(3, 'C5', 'unreadable or invalid registry', warnings); }

  // C6 Node identity, snapshot drift, root key IDs.
  const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: request.host, tlsCert: cert, macaroon: own });
  if (!adapter) return fail(8, 'internal', 'unexpected failure', warnings);
  const lnd = onlineAdapter(adapter);
  let info: ReturnType<typeof nodeInfo>;
  try { info = nodeInfo(await lnd.getInfo()); }
  catch (error) { return lndFailure(error, 'C6', warnings); }
  try { if (drift(await lnd.listPermissions())) warnings.push('snapshot-drift'); }
  catch (error) { return lndFailure(error, 'C6', warnings); }
  let rootKeyListed: boolean | null = null;
  if (canList) {
    try { rootKeyListed = (await lnd.listMacaroonIds()).includes(facts.rootKeyId); }
    catch (error) { return lndFailure(error, 'C6', warnings); }
  }

  // C7 Ask LND: CheckMacaroonPermissions with the credential's own decoded permissions.
  let checked: Awaited<ReturnType<LndAdapter['checkMacaroon']>>;
  try { checked = await lnd.checkMacaroon(target, facts.permissions); }
  catch (error) { return lndFailure(error, 'C7', warnings); }
  // Only node-side evidence makes a rejection conclusive: LND's own expiry error naming one of
  // this credential's time-before caveats (judged by the node's clock), or a missing root key ID
  // (reported by LND or absent from ListMacaroonIDs). The local clock never does (MW110-02): it can be skewed, and an earlier
  // caveat that depends on the caller (IP lock, custom caveat) may be what LND refused.
  const nodeExpired = !checked.valid && checked.reason === 'expired'
    && facts.caveats.some(caveat => caveat.type === 'time-before' && caveat.value === checked.caveat);
  const rejection: VerifyResult['rejection'] = checked.valid ? null
    : checked.reason === 'expired' ? (nodeExpired ? 'expired' : 'other') : checked.reason;
  // A rejection holds everywhere when the root key ID is gone or the credential expired; any other
  // rejection may depend on the caller (IP lock, custom caveat) or on the copy itself.
  // A signature mismatch is what LND answers both after a root key regeneration and for any
  // altered copy (RT-01): a regeneration keeps every root key ID listed, so a mismatch alone never
  // proves the original dead. It is conclusive once the root key ID is no longer listed, or when
  // these are the exact bytes macwarden recorded for this root key ID on this node (registry
  // fingerprint match): known-genuine bytes can only mismatch because the root key changed.
  // The own credential is no such evidence: it authenticating proves only that its own bytes are
  // valid, not whether the target's differ by alteration or by a regeneration since it was baked.
  const registry = registryMatch(entries, info.pubkey, facts);
  const recordedBytes = registry?.match === 'fingerprint';
  const conclusive = checked.valid || rejection === 'root-key-missing' || rejection === 'expired'
    || rootKeyListed === false || (rejection === 'signature-mismatch' && recordedBytes);
  const localExpiry = offline.caveats.some(caveat => caveat.type === 'time-before' && caveat.expired === true);
  const partial: Omit<VerifyResult, 'guidance'> = {
    ...offline,
    node: { pubkey: info.pubkey, alias: info.alias, network: info.network },
    status: checked.valid ? 'accepted' : 'rejected',
    rejection, conclusive, rootKeyListed,
    ownCredential: facts.rootKeyId === ownFacts.rootKeyId,
    canBake: canBake(facts.permissions, offline.grade, offline.warnings),
    registry,
  };
  const result: VerifyResult = { ...partial, guidance: guidance(partial, localExpiry) };
  // Exit 1 is a finding, as with scan --fail-on: the credential is live, or may be.
  return { schema: 1, command: 'verify', ok: true, warnings, result, error: null,
    ...(result.status === 'accepted' || !result.conclusive ? { exitCode: 1 } : {}) };
}

export async function run(args: string[], deps: Deps): Promise<VerifyOutput> {
  const warnings: OutputWarning[] = [];
  try { return onlineWarnings(await runSteps(args, deps, warnings)); }
  catch (error) {
    // verify changes nothing, so an interrupt is always before any mutation (exit 6).
    return onlineWarnings(error instanceof Cancelled ? fail(6, 'cancelled', 'interrupted', warnings)
      : fail(8, 'internal', 'unexpected failure', warnings));
  }
}

export async function verify(args: string[]): Promise<OutputResult> {
  return run(args, { createAdapter: createLndAdapter, fs: nodeFs, env: { ...process.env },
    clock: () => new Date(), stdin: process.stdin });
}
