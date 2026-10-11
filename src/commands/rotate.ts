import { Cancelled, checkCancellation, cancellable, cancellationSignal, cleanup, cleanupOutcome } from '../cancellation.js';
import { endpoint, connectionProblem, flagProblem, LABEL_RULE, nodePubkey, drift, samePermissions, listIds, failureDetails, readBoundedFile, readOnlineCredential, onlineAdapter, onlineWarnings, recoveryCommand, inventoryRecoveryCommand, recoveryPath, shellQuote, connectionSettings } from '../online.js';
import * as nodeFs from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { createInterface } from 'node:readline';
import type { Readable } from 'node:stream';
import { createLndAdapter, type LndAdapter } from '../lnd/index.js';
import { addFirstPartyCaveat, decodeMacaroon, encodeMacaroon, parseTimeBefore, timeBeforeCondition,
  type MacaroonFacts } from '../decode/index.js';
import { grade } from '../grade/index.js';
import { isProtectedPath, outputNameProblem, resolveUnprotectedPath } from '../protected-path.js';
import { unsafeNodeDiagnostics } from '../environment.js';
import { markMutationSent } from '../process-error-context.js';
import { openRegistry, RegistryInputError, RegistryUsageError, type RegistryEntry, hasCustomCaveat, isStagedReplacement, recordedFileRelation, replacementLinkProblems } from '../registry/index.js';
import { DecodeError, LndError, LndUncertainError, UsageError } from '../errors.js';
import { Secret } from '../secret.js';
import { rotateConfirmation, rotatePlanResult, unreproducedCaveatTypes, writeRotateFinishPlan, writeRotateStagePlan, writeRotatePrompt,
  type OutputResult, type RotatePlan, type RotateStagedResult, type RotateFinishedResult } from '../output/index.js';
import { namesRegistryFile, REGISTRY_OUT_REFUSAL } from './bake/out-registry.js';
import { reserveOut, type ReservedOut } from './bake/write-out.js';
import { interruptibleChecks, interruptibleReserve, OUT_CREATION_INTERRUPTED, rethrowCancelled } from './bake/out-interrupt.js';
import { reserveFailure } from './bake/out-errors.js';
import { allocateRootKeyId } from './bake/allocate.js';

type RotateLnd = LndAdapter;
export type Deps = {
  lnd?: RotateLnd;
  createAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => RotateLnd;
  fs: typeof nodeFs;
  env: Record<string, string | undefined>;
  clock: () => Date;
  stdin?: Readable & { isTTY?: boolean };
  prompt?: ((question: string) => Promise<string | null>) & { isTTY?: boolean };
  stdout?: { write(text: string): unknown };
};
type RotateOutput = OutputResult & { schema: 1 };
type Request = { label: string; out: string; registry?: string; host: string; cert: string; own: string;
  allowAdmin: boolean; breakLock: boolean; dryRun: boolean; finish: boolean; yes: boolean };
type RunState = { cleanupFailures: string[]; mutationSent: boolean; warnings: OutputResult['warnings']; inspection?: string };
const valueFlags = new Set(['--out', '--registry', '--lnd-rest', '--tls-cert', '--macaroon']);
const switchFlags = new Set(['--allow-admin', '--break-lock', '--dry-run', '--json', '--finish', '--yes']);
const requiredMethods = [
  ['/lnrpc.Lightning/GetInfo', 'info:read'],
  ['/lnrpc.Lightning/ListPermissions', 'info:read'],
  ['/lnrpc.Lightning/BakeMacaroon', 'macaroon:generate'],
  ['/lnrpc.Lightning/ListMacaroonIDs', 'macaroon:read'],
  ['/lnrpc.Lightning/CheckMacaroonPermissions', 'macaroon:read'],
] as const;

function fail(code: number, step: string, message: string, warnings: OutputResult['warnings'] = []): RotateOutput {
  return { schema: 1, command: 'rotate', ok: false, warnings, result: null, error: { code, step, message } };
}

// Returns the request, or a message naming the flag and the rule (never the value).
function parse(args: string[], env: Deps['env']): Request | string {
  let label: string | undefined;
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (switchFlags.has(arg)) {
      if (flags.has(arg)) return flagProblem(arg, 'repeated');
      flags.set(arg, true);
    } else if (valueFlags.has(arg)) {
      const value = args[++i];
      if (flags.has(arg)) return flagProblem(arg, 'repeated');
      if (!value || value.startsWith('--')) return flagProblem(arg, 'missing');
      flags.set(arg, value);
    } else if (arg.startsWith('--')) {
      return `unknown flag; rotate takes: <label> ${[...valueFlags, ...switchFlags].join(' ')}`;
    } else {
      if (label !== undefined) return 'give exactly one label';
      if (!/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(arg)) return `the label ${LABEL_RULE}`;
      label = arg;
    }
  }
  const get = (flag: string): string | undefined => {
    const value = flags.get(flag);
    return typeof value === 'string' ? value : undefined;
  };
  const out = get('--out');
  const finish = flags.has('--finish');
  if (finish && out !== undefined) return '--out is not used with --finish: the replacement file was written by the stage run';
  if (finish && flags.has('--allow-admin')) return '--allow-admin is not used with --finish';
  if (!finish && !out) return '--out is required for the stage run: the path of the replacement macaroon file';
  if (!finish && flags.has('--yes')) return '--yes is only used with --finish; the stage run asks no confirmation it can skip';
  if (!label) return 'give exactly one label';
  const { host, cert, own, problem: mixedSource } = connectionSettings(get, env);
  if (mixedSource) return mixedSource;
  const connection = connectionProblem(host, cert, own);
  if (connection) return connection;
  return { label, out: out ?? '', registry: get('--registry'), host: endpoint(host!)!, cert: cert!, own: own!,
    allowAdmin: flags.has('--allow-admin'), breakLock: flags.has('--break-lock'), dryRun: flags.has('--dry-run'),
    finish, yes: flags.has('--yes') };
}


function lndFailure(error: unknown, step: string, warnings: OutputResult['warnings']): RotateOutput {
  const failure = failureDetails(error);
  return fail(failure.code, step, failure.message, warnings);
}

function pending(entries: RegistryEntry[], old: RegistryEntry): RegistryEntry | undefined {
  return entries.find(entry => entry.status === 'active' && entry.nodePubkey.toLowerCase() === old.nodePubkey.toLowerCase()
    && entry.replaces === old.rootKeyId);
}

/** A registry entry claiming to replace `old` that macwarden could not have written. */
function tampering(entries: RegistryEntry[], old: RegistryEntry): string | null {
  // Root key IDs are per node: only links on this credential's node are checked, all of them,
  // so a chain or cycle elsewhere on the node cannot hide a credential from the rotation.
  const node = old.nodePubkey.toLowerCase();
  const problem = replacementLinkProblems(entries.filter(entry => entry.nodePubkey.toLowerCase() === node))[0];
  return problem ? `registry tampering: root key ID ${problem.rootKeyId} claims to replace ${problem.replaces}, but ${problem.problem}; ` +
    'restore the registry from a trusted copy before rotating' : null;
}

const CUSTOM_CAVEAT_REFUSAL = 'this credential carries a custom caveat (a canary, or another lnd-custom caveat); a rotation ' +
  'would replace it with an ordinary credential. Revoke it with macwarden revoke <label>, then bake a new canary with ' +
  'macwarden bake --canary and restart macwarden watch';

const OLD_FILE_TAMPERED = 'old credential file carries the registry entry\'s fingerprint on another root key ID: ' +
  'the registry entry was edited; restore the registry from a trusted copy';

function unreproducedCaveatRefusal(types: string[], label: string): string {
  return `this credential carries caveats a rotation does not reproduce (${types.join(', ')}): the replacement would be ` +
    'baked without them, so an IP lock or another restriction would be gone. Bake a new credential with macwarden bake, ' +
    `attenuate it with macwarden attenuate, then revoke this one with macwarden revoke ${label}`;
}

/**
 * The caveat types of O that a stage would not carry over to the replacement (1.3.1): every
 * recorded caveat other than the one `time-before` S11 re-applies from its `requested` duration,
 * and, when O's decoded file is at hand, every caveat in it other than that recorded expiry, or
 * caveats the decoder did not keep. The file decides as much as the editable registry list does.
 */
export function rotationDropsCaveats(entry: Pick<RegistryEntry, 'caveats'>, file?: MacaroonFacts): string[] {
  const dropped = new Set(unreproducedCaveatTypes(entry.caveats));
  if (file) {
    const recorded = new Set(entry.caveats.filter(caveat => caveat.type === 'time-before' && caveat.requested !== undefined)
      .map(caveat => caveat.value));
    for (const caveat of file.caveats) if (caveat.type !== 'time-before' || !recorded.has(caveat.value)) dropped.add(caveat.type);
    if (file.warnings.includes('caveats-exceed-bounds')) dropped.add('caveats-exceed-bounds');
  }
  return [...dropped].sort();
}

/** Active entries with this label that are not a staged replacement (SPEC 6 S3; RL-07). */
function originals(entries: RegistryEntry[], label: string): RegistryEntry[] {
  return entries.filter(entry => entry.label === label && entry.status === 'active' && !isStagedReplacement(entries, entry));
}

/**
 * The original for this label (RL-04). One registry may hold several nodes, and bake allows the
 * same label on each, so a label active on several nodes is resolved against the node macwarden
 * is connected to: its own credential and TLS certificate are read and GetInfo (read-only) names
 * the node. Returns the node's candidates, or a failure at `step`.
 */
async function nodeCandidates(candidates: RegistryEntry[], request: Request, deps: Deps, step: string):
  Promise<RegistryEntry[] | RotateOutput> {
  if (new Set(candidates.map(entry => entry.nodePubkey.toLowerCase())).size < 2) return candidates;
  let cert: Buffer;
  let own: Secret;
  try {
    if (isProtectedPath(request.cert) || isProtectedPath(await deps.fs.realpath(request.cert)))
      return fail(4, step, 'unreadable TLS certificate');
    cert = await readBoundedFile(request.cert, deps.fs);
  } catch { return fail(4, step, 'unreadable TLS certificate'); }
  try { own = (await readOnlineCredential(request.own, { stdin: deps.stdin ?? process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, step, 'unreadable own macaroon'); }
  try { decodeMacaroon(own); }
  catch { return fail(4, step, 'undecodable own macaroon'); }
  const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: request.host, tlsCert: cert, macaroon: own });
  if (!adapter) throw new Error('missing LND adapter');
  let pubkey: string;
  try { pubkey = nodePubkey(await onlineAdapter(adapter).getInfo()); }
  catch (error) { return lndFailure(error, step, []); }
  return candidates.filter(entry => entry.nodePubkey.toLowerCase() === pubkey);
}

type Target = { secret: Secret; facts: MacaroonFacts };
async function readTarget(path: string, deps: Deps): Promise<Target> {
  if (isProtectedPath(path) || isProtectedPath(await deps.fs.realpath(path)))
    throw new Error('protected credential path');
  const secret = (await readOnlineCredential(path, { stdin: deps.stdin ?? process.stdin, fs: deps.fs })).secret;
  return { secret, facts: decodeMacaroon(secret) };
}

function usable(target: Target, now: Date): boolean {
  return target.facts.permissions.length > 0 && !target.facts.caveats.some(caveat => {
    if (caveat.type !== 'time-before') return false;
    const expiry = parseTimeBefore(caveat.value);
    return expiry === undefined || BigInt(now.getTime()) * 1_000_000n >= expiry;
  });
}

function shellArgument(value: string): string {
  return shellQuote(value);
}

function finishRecovery(request: Request): string {
  const args = ['macwarden', 'rotate', request.label, '--finish'];
  if (request.registry) args.push('--registry', recoveryPath(request.registry));
  const url = new URL(request.host);
  args.push('--lnd-rest', `${url.hostname}:${url.port || '443'}`, '--tls-cert', recoveryPath(request.cert),
    '--macaroon', recoveryPath(request.own));
  return args.map(shellArgument).join(' ');
}

async function finishSteps(request: Request, deps: Deps, state: RunState): Promise<RotateOutput> {
  const warnings = state.warnings;
  if (unsafeNodeDiagnostics(deps.env))
    return fail(2, 'F2', 'unsafe Node diagnostic settings');
  let registry;
  try {
    if (request.registry && isProtectedPath(request.registry)) return fail(3, 'F3', 'protected registry path');
    registry = await openRegistry(request.registry, { fs: deps.fs, env: deps.env });
  } catch { return fail(3, 'F3', 'unreadable or invalid registry'); }
  const candidates = await nodeCandidates(originals(registry.entries, request.label), request, deps, 'F3');
  if (!Array.isArray(candidates)) return candidates;
  const old = candidates[0];
  const forged = old && tampering(registry.entries, old);
  if (forged) return fail(3, 'F3', forged);
  const next = old && pending(registry.entries, old);
  if (!old || !next) return fail(2, 'F3',
    `nothing staged; run macwarden rotate ${request.label} --out <file> first`);
  const id = BigInt(old.rootKeyId), nextId = BigInt(next.rootKeyId);
  const inspection = `old root key ID ${id}; replacement root key ID ${nextId}; ` +
    `run \`${inventoryRecoveryCommand(request)}\` to inspect the observed state before deciding whether to run ` +
    `\`${finishRecovery(request)}\`; do not retry deletion blindly`;
  state.inspection = inspection;
  if (id === 0n || nextId === 0n) return fail(2, 'F3', 'cannot rotate root key ID 0');
  let cert: Buffer;
  let own: Secret;
  let ownFacts: MacaroonFacts;
  try {
    if (isProtectedPath(request.cert) || isProtectedPath(await deps.fs.realpath(request.cert)))
      return fail(4, 'F4', 'unreadable TLS certificate');
    cert = await readBoundedFile(request.cert, deps.fs);
  } catch { return fail(4, 'F4', 'unreadable TLS certificate'); }
  try { own = (await readOnlineCredential(request.own, { stdin: deps.stdin ?? process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, 'F4', 'unreadable own macaroon'); }
  try { ownFacts = decodeMacaroon(own); }
  catch { return fail(4, 'F4', 'undecodable own macaroon'); }
  const held = new Set(ownFacts.permissions);
  const finishMethods = [...requiredMethods.filter(([method]) => method !== '/lnrpc.Lightning/BakeMacaroon'),
    ['/lnrpc.Lightning/DeleteMacaroonID', 'macaroon:write']];
  for (const [method, permission] of finishMethods) {
    if (!held.has(permission) && !held.has(`uri:${method}`))
      return fail(4, 'F4', `own macaroon missing permission: ${permission}`);
  }
  if (ownFacts.rootKeyId === 0n) warnings.push('own-root-key-0');
  if (id === ownFacts.rootKeyId) return fail(2, 'F4', 'cannot rotate the own macaroon root key ID', warnings);
  const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: request.host, tlsCert: cert, macaroon: own });
  if (!adapter) throw new Error('missing LND adapter');
  const lnd = onlineAdapter(adapter);
  let pubkey: string;
  try {
    pubkey = nodePubkey(await lnd.getInfo());
  } catch (error) { return lndFailure(error, 'F5', warnings); }
  if (pubkey !== old.nodePubkey.toLowerCase()) return fail(2, 'F5', 'old entry belongs to another node', warnings);
  try { if (drift(await lnd.listPermissions())) warnings.push('snapshot-drift'); }
  catch (error) { return lndFailure(error, 'F5', warnings); }
  let ids: bigint[];
  try { ids = await listIds(lnd); }
  catch (error) { return lndFailure(error, 'F6', warnings); }
  if (!ids.includes(nextId)) return fail(5, 'F6',
    `staged replacement is not in LND; clear it with macwarden revoke ${next.rootKeyId}`, warnings);
  let repaired = !ids.includes(id);
  let replacement: Target;
  try {
    if (!next.outPath) return fail(3, 'F7', 'staged replacement file is not recorded', warnings);
    replacement = await readTarget(next.outPath, deps);
    if (replacement.facts.fingerprint !== next.fingerprint || replacement.facts.rootKeyId !== nextId)
      return fail(3, 'F7', 'staged replacement file does not match the registry', warnings);
  } catch { return fail(3, 'F7', 'unreadable or undecodable staged replacement file', warnings); }
  // No permissions, or a time-before caveat already passed: LND cannot accept it.
  if (!usable(replacement, deps.clock()))
    return fail(5, 'F7', 'new credential is not accepted; nothing changed', warnings);
  try {
    if ((await lnd.checkMacaroon(replacement.secret, replacement.facts.permissions)).valid !== true)
      return fail(5, 'F7', 'new credential is not accepted; nothing changed', warnings);
  } catch (error) { return lndFailure(error, 'F7', warnings); }
  let target: Target | undefined;
  let evidence = 'by-id-only' as RotateFinishedResult['evidence'];
  // F7 baseline for a present O; returns a refusal, or null to continue.
  const baseline = async (): Promise<RotateOutput | null> => {
    if (!old.outPath) return null;
    try { target = await readTarget(old.outPath, deps); }
    catch { /* Without a usable old file, ID absence is the proof. */ }
    const relation = target && recordedFileRelation(old, target.facts);
    if (relation === 'tampered') return fail(3, 'F7', OLD_FILE_TAMPERED, warnings);
    // A replacement staged at O's old path, or another macaroon on O's root key ID, is not O's
    // file: the old credential is then proven revoked by ID only, as in revoke (RL-01).
    if (relation !== 'match') target = undefined;
    if (target && usable(target, deps.clock())) {
      try { if ((await lnd.checkMacaroon(target.secret, target.facts.permissions)).valid === true) evidence = 'rejected'; }
      catch (error) { return lndFailure(error, 'F7', warnings); }
    }
    return null;
  };
  if (!repaired) {
    const refused = await baseline();
    if (refused) return refused;
  }
  if (request.dryRun) return rotatePlanResult({ dryRun: true, stage: 'finish', old,
    permissions: [...old.permissions], grade: old.grade }, next, warnings, repaired);
  writeRotateFinishPlan(old, next, repaired, deps.stdout);
  if (!request.yes) {
    if (!(deps.stdin ?? process.stdin).isTTY)
      return fail(6, 'F8', 'confirmation requires a TTY or --yes', warnings);
    const answer = await cancellable(() => (deps.prompt ?? (async () => null))(rotateConfirmation(old, next)));
    if (answer !== request.label) return fail(6, 'F8', 'operator declined or did not type the exact confirmation', warnings);
  }
  let locked = false;
  try {
    try { await registry.lock({ breakLock: request.breakLock }); locked = true; }
    catch (error) { return fail(3, 'F9', error instanceof RegistryInputError
      ? error.message : 'registry locked or unavailable', warnings); }
    try {
      const current = await openRegistry(request.registry, { fs: deps.fs, env: deps.env });
      if (!isDeepStrictEqual(current.find(pubkey, old.rootKeyId), old)
        || !isDeepStrictEqual(current.find(pubkey, next.rootKeyId), next))
        return fail(3, 'F9', 'old or replacement entry changed since F3; nothing sent to LND', warnings);
      registry.reload(current.entries);
    } catch { return fail(3, 'F9', 'unreadable or invalid registry on reread; nothing sent to LND', warnings); }
    // The F7 local check is as old as the prompt as well: the operator just confirmed that the app
    // uses N's file, so N's file must still hold the credential F7 read (same canonical fingerprint,
    // root key ID and decoded facts). A file removed or overwritten meanwhile must not let O be
    // deleted. This is a local read only: it adds no LND call to the finish sequence.
    let reread: Target | undefined;
    try { reread = await readTarget(next.outPath, deps); } catch { /* reported below */ }
    if (!reread || reread.facts.fingerprint !== replacement.facts.fingerprint
      || reread.facts.rootKeyId !== replacement.facts.rootKeyId || !isDeepStrictEqual(reread.facts, replacement.facts))
      return fail(3, 'F7', 'staged replacement file was removed or changed while waiting for confirmation; ' +
        'nothing changed; restore the replacement the app uses and rerun, ' +
        `or abandon it with macwarden revoke ${next.rootKeyId}`, warnings);
    // The F7 proof is as old as the confirmation prompt: a replacement whose time-before caveat
    // passed while the prompt was open must not let O be deleted (or recorded revoked).
    if (!usable(replacement, deps.clock()))
      return fail(5, 'F7', 'new credential is not accepted: it expired while waiting for confirmation; nothing changed; ' +
        `abandon it with macwarden revoke ${next.rootKeyId} and stage a new replacement`, warnings);
    // The F6 absence of O is as old as the prompt too: a node restore (or another operator) may
    // have put O back meanwhile. Observe LND again before recording O revoked by absence; if O is
    // listed again, take the normal F7 baseline and F10 delete instead.
    if (repaired) {
      try { ids = await listIds(lnd); }
      catch (error) { return lndFailure(error, 'F6', warnings); }
      if (!ids.includes(nextId)) return fail(5, 'F6',
        `staged replacement is not in LND; nothing changed; clear it with macwarden revoke ${next.rootKeyId}`, warnings);
      if (ids.includes(id)) {
        repaired = false;
        const refused = await baseline();
        if (refused) return refused;
      }
    }
    // And the F7 acceptance proof: the replacement may have been deleted from LND (directly or
    // through another registry) while the prompt was open, which the registry re-read cannot see.
    try {
      if ((await lnd.checkMacaroon(replacement.secret, replacement.facts.permissions)).valid !== true)
        return fail(5, 'F7', 'new credential is not accepted after confirmation; nothing changed; ' +
          `run \`${inventoryRecoveryCommand(request)}\`, and abandon it with macwarden revoke ${next.rootKeyId} if LND no longer holds it`, warnings);
    } catch (error) { return lndFailure(error, 'F7', warnings); }
    if (!repaired) {
      if (!lnd.deleteMacaroonId) throw new Error('missing LND delete method');
      let deleted = false;
      let uncertain = false;
      checkCancellation();
      state.mutationSent = true;
      markMutationSent();
      try { deleted = (await lnd.deleteMacaroonId(id)).deleted === true; }
      catch (error) {
        if (!(error instanceof LndError || error instanceof Cancelled)) throw error;
        uncertain = error instanceof LndUncertainError;
        /* Reconcile once without retrying the mutation. */
      }
      try { ids = await listIds(lnd); }
      catch { return fail(7, deleted ? 'F11' : 'F10', `LND state unknown; registry unchanged; ${inspection}`, warnings); }
      // A listed ID after an incomplete response may still be deleted later, so the
      // old credential's state is unknown rather than "still valid".
      if (uncertain && ids.includes(id)) return fail(7, 'F10',
        `DeleteMacaroonID outcome unknown (no complete LND response); old root key ID ${old.rootKeyId} still listed but LND may still delete it; ` +
        `registry unchanged; rerun ${finishRecovery(request)} to confirm; ${inspection}`, warnings);
      if (ids.includes(id)) return fail(deleted ? 7 : 5, deleted ? 'F11' : 'F10',
        deleted ? `old root key ID still present after deletion; registry unchanged; ${inspection}`
          : `old root key ID still present; old credential still valid; registry unchanged; run ${finishRecovery(request)}`, warnings);
      if (evidence === 'rejected') {
        try {
          const checked = await lnd.checkMacaroon(target!.secret, target!.facts.permissions);
          if (checked.valid !== false || (checked.reason !== 'root-key-missing' && checked.reason !== 'signature-mismatch'))
            return fail(7, 'F11', `old root key ID absent, but documented target rejection not confirmed; registry unchanged; ${inspection}`, warnings);
        } catch { return fail(7, 'F11', `old root key ID absent, credential rejection unknown; registry unchanged; ${inspection}`, warnings); }
      }
      try {
        if ((await lnd.checkMacaroon(replacement.secret, replacement.facts.permissions)).valid !== true)
          return fail(7, 'F11', `old root key ID absent, new credential not accepted; registry unchanged; ${inspection}`, warnings);
      } catch { return fail(7, 'F11', `old root key ID absent, new credential acceptance unknown; registry unchanged; ${inspection}`, warnings); }
    }
    let revoked: RegistryEntry;
    try {
      registry.markRevoked(pubkey, old.rootKeyId, deps.clock().toISOString(), evidence);
      revoked = registry.find(pubkey, old.rootKeyId)!;
      registry.markReplacedBy(pubkey, old.rootKeyId, next.rootKeyId);
      await registry.save();
    } catch { return fail(7, 'F12', `old root key ID ${old.rootKeyId} absent from LND; new credential accepted; ` +
      `registry update failed; run ${finishRecovery(request)}`, warnings); }
    const result: RotateFinishedResult = { stage: 'finished', old: revoked,
      new: registry.find(pubkey, next.rootKeyId)!, evidence, repaired };
    return { schema: 1, command: 'rotate', ok: true, warnings, result, error: null };
  } finally { if (locked) await cleanup(state, 'registry unlock', () => registry.unlock()); }
}

async function runSteps(args: string[], deps: Deps, state: RunState): Promise<RotateOutput> {
  const request = parse(args, deps.env);
  if (typeof request === 'string') return fail(2, args.includes('--finish') ? 'F1' : 'S1', request);
  if (request.finish) return finishSteps(request, deps, state);
  if (unsafeNodeDiagnostics(deps.env))
    return fail(2, 'S2', 'unsafe Node diagnostic settings');
  let registry;
  try {
    if (request.registry && isProtectedPath(request.registry)) return fail(3, 'S3', 'protected registry path');
    registry = await openRegistry(request.registry, { fs: deps.fs, env: deps.env });
  } catch { return fail(3, 'S3', 'unreadable or invalid registry'); }
  const candidates = await nodeCandidates(originals(registry.entries, request.label), request, deps, 'S3');
  if (!Array.isArray(candidates)) return candidates;
  if (!candidates.length) return fail(2, 'S3', 'no eligible active entry for this label');
  const old = candidates[0];
  const forged = tampering(registry.entries, old);
  if (forged) return fail(3, 'S3', forged);
  if (hasCustomCaveat(old)) return fail(2, 'S3', CUSTOM_CAVEAT_REFUSAL.replace('<label>', request.label));
  const replacement = pending(registry.entries, old);
  if (replacement) return fail(2, 'S3', `old root key ID ${old.rootKeyId} already has pending replacement ` +
    `${replacement.rootKeyId}; finish with macwarden rotate ${request.label} --finish only after confirming ` +
    `the app uses ${replacement.outPath ?? 'the replacement file (not recorded)'}; ` +
    `or abandon with macwarden revoke ${replacement.rootKeyId}`);
  if (BigInt(old.rootKeyId) === 0n) return fail(2, 'S3', 'cannot rotate root key ID 0');

  let permissions = [...old.permissions];
  let oldTarget: Target | undefined;
  if (old.outPath) {
    try {
      if (!isProtectedPath(old.outPath) && !isProtectedPath(await deps.fs.realpath(old.outPath)))
        oldTarget = await readTarget(old.outPath, deps);
    } catch { /* An unusable old file falls back to the recorded permissions. */ }
  }
  const relation = oldTarget && recordedFileRelation(old, oldTarget.facts);
  if (relation === 'tampered') return fail(3, 'S4', OLD_FILE_TAMPERED);
  // Another credential at a reused path proves nothing about O: O's recorded permissions then
  // need the informed approval below, as for a missing file (RL-01).
  if (relation === 'other-credential') oldTarget = undefined;
  const oldFacts = oldTarget?.facts;
  if (relation === 'same-root-key') return fail(3, 'S4', 'old credential fingerprint differs from the registry entry');
  // The registry's caveat list is editable metadata: the credential itself decides whether it is a
  // canary. A custom caveat the registry does not record is tampering, refused before any mutation.
  if (oldFacts?.caveats.some(caveat => caveat.type === 'lnd-custom'))
    return fail(3, 'S4', 'the credential file carries a custom caveat (a canary, or another lnd-custom caveat) that the ' +
      'registry entry does not record; a rotation would replace it with an ordinary credential. Restore the registry from a trusted copy');
  if (grade(old.permissions).grade !== old.grade) return fail(3, 'S4', 'registry grade differs from recorded permissions');
  if (oldFacts?.fingerprint === old.fingerprint) {
    if (!samePermissions(oldFacts.permissions, old.permissions))
      return fail(3, 'S4', 'registry entry does not match the credential');
    if (grade(oldFacts.permissions).grade !== old.grade)
      return fail(3, 'S4', 'registry grade differs from the credential');
    permissions = [...oldFacts.permissions];
  }
  if (oldTarget && !usable(oldTarget, deps.clock())) oldTarget = undefined;
  const assessment = grade(permissions);
  const warnings = state.warnings;
  if (!oldTarget && !request.dryRun) {
    if (!(deps.stdin ?? process.stdin).isTTY)
      return fail(6, 'S4', 'confirmation of unproven recorded permissions requires a TTY', warnings);
    const question = `Old credential cannot prove the recorded authority. Grade ${assessment.grade}; permissions ${permissions.join(' ')}. ` +
      `Stage a replacement using these unproven permissions? Type ${request.label} to continue:`;
    const answer = await cancellable(() => (deps.prompt ?? (async () => null))(question));
    if (answer !== request.label) return fail(6, 'S4', 'operator declined or did not type the exact confirmation', warnings);
  }
  if (assessment.grade === 'UNASSESSED' || assessment.warnings.some(w => w.startsWith('unassessed-')))
    return fail(2, 'S5', `unassessed permissions: ${assessment.unassessed.join(', ')}`);
  if (assessment.grade === 'ADMIN' && !request.allowAdmin)
    return fail(2, 'S5', 'ADMIN permissions require --allow-admin');
  // S11 re-applies one time-before from O's recorded duration and nothing else: any other caveat
  // of O, recorded or in its decoded file (an IP lock above all), would be dropped silently and the
  // registry would record the narrower list as fact. Refused here, before any lock or LND call
  // (1.3.1); --finish is unaffected, its replacement already exists. Re-applying IP locks is planned.
  const dropped = rotationDropsCaveats(old, oldFacts);
  if (dropped.length) return fail(3, 'S5', unreproducedCaveatRefusal(dropped, request.label));
  // S11 reuses O's recorded expiry duration: it is checked here, before any lock or LND call,
  // so a bad value can never leave a baked root key behind (RL-03).
  const expires = old.caveats.find(caveat => caveat.type === 'time-before' && caveat.requested !== undefined)?.requested;
  if (expires !== undefined) {
    try { timeBeforeCondition(expires, deps.clock); }
    catch { return fail(3, 'S5', 'registry entry records an invalid expiry duration; restore the registry from a trusted copy'); }
  }
  if (isProtectedPath(request.out)) return fail(3, 'S5', 'protected output path');
  const outName = outputNameProblem(request.out);
  if (outName) return fail(3, 'S5', `output path refused: ${outName}`);
  // Each check is abandoned on an interrupt (a stalled mount): exit 6, step cancelled.
  const checks = interruptibleChecks(deps.fs);
  let outPath: string;
  try { outPath = await resolveUnprotectedPath(request.out, checks); }
  catch (error) { rethrowCancelled(error); return fail(3, 'S5', 'cannot check output path'); }
  if (namesRegistryFile(outPath, registry.location)) return fail(3, 'S5', REGISTRY_OUT_REFUSAL);
  try { await checks.lstat(request.out); return fail(3, 'S5', 'output file already exists'); }
  catch (error) { rethrowCancelled(error); if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
    return fail(3, 'S5', 'cannot check output path'); }
  request.out = outPath;

  let cert: Buffer;
  let own: Secret;
  let ownFacts: MacaroonFacts;
  try {
    if (isProtectedPath(request.cert) || isProtectedPath(await deps.fs.realpath(request.cert)))
      return fail(4, 'S6', 'unreadable TLS certificate');
    cert = await readBoundedFile(request.cert, deps.fs);
  } catch { return fail(4, 'S6', 'unreadable TLS certificate'); }
  try { own = (await readOnlineCredential(request.own, { stdin: deps.stdin ?? process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, 'S6', 'unreadable own macaroon'); }
  try { ownFacts = decodeMacaroon(own); }
  catch { return fail(4, 'S6', 'undecodable own macaroon'); }
  const held = new Set(ownFacts.permissions);
  for (const [method, required] of requiredMethods) {
    if (!held.has(required) && !held.has(`uri:${method}`))
      return fail(4, 'S6', `own macaroon missing permission: ${required}`);
  }
  if (ownFacts.rootKeyId === 0n) warnings.push('own-root-key-0');
  if (BigInt(old.rootKeyId) === ownFacts.rootKeyId)
    return fail(2, 'S6', 'cannot rotate the own macaroon root key ID', warnings);
  let locked = false;
  let reservation: ReservedOut | undefined;
  try {
    if (!request.dryRun) {
      try { await registry.lock({ breakLock: request.breakLock }); locked = true; }
      catch (error) { return fail(3, 'S7', error instanceof RegistryInputError
        ? error.message : 'registry locked or unavailable', warnings); }
      try {
        const current = await openRegistry(request.registry, { fs: deps.fs, env: deps.env });
        if (!isDeepStrictEqual(current.find(old.nodePubkey, old.rootKeyId), old) || pending(current.entries, old))
          return fail(3, 'S7', 'old entry changed or a pending replacement appeared since S3; nothing sent to LND', warnings);
        // Preserve unrelated entries from the reread while retaining our lock owner.
        registry.reload(current.entries);
      } catch { return fail(3, 'S7', 'unreadable or invalid registry on reread; nothing sent to LND', warnings); }
      try {
        const reserved = await interruptibleReserve(() => reserveOut(request.out, deps.fs));
        reservation = reserved.reservation;
        if (reserved.aclWarning) warnings.push('acl-best-effort');
      } catch (error) {
        if (error instanceof Cancelled) return fail(6, 'cancelled', OUT_CREATION_INTERRUPTED, warnings);
        return fail(3, 'S7', reserveFailure(error), warnings);
      }
    }
    const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: request.host, tlsCert: cert, macaroon: own });
    if (!adapter) throw new Error('missing LND adapter');
  const lnd = onlineAdapter(adapter);
    let pubkey: string;
    try {
      pubkey = nodePubkey(await lnd.getInfo());
    } catch (error) { return lndFailure(error, 'S8', warnings); }
    if (pubkey !== old.nodePubkey.toLowerCase()) return fail(2, 'S8', 'old entry belongs to another node', warnings);
    try { if (drift(await lnd.listPermissions())) warnings.push('snapshot-drift'); }
    catch (error) { return lndFailure(error, 'S8', warnings); }
    let ids: bigint[];
    try { ids = await listIds(lnd); }
    catch (error) { return lndFailure(error, 'S8', warnings); }
    if (!ids.includes(BigInt(old.rootKeyId))) return fail(5, 'S8', 'old root key ID is not in LND', warnings);
    if (oldTarget) {
      try {
        if ((await lnd.checkMacaroon(oldTarget.secret, oldTarget.facts.permissions)).valid !== true)
          return fail(5, 'S8', 'old credential cannot prove the recorded authority; nothing changed', warnings);
      } catch (error) { return lndFailure(error, 'S8', warnings); }
    }
    if (request.dryRun) {
      const result: RotatePlan = { dryRun: true, stage: 'stage', old, permissions, grade: assessment.grade,
        permissionsProven: oldTarget !== undefined };
      return { schema: 1, command: 'rotate', ok: true, warnings, result, error: null };
    }
    writeRotateStagePlan(old, permissions, assessment.grade, deps.stdout);
    let rootKeyId: bigint;
    try { rootKeyId = allocateRootKeyId(ids, registry.entries.map(entry => BigInt(entry.rootKeyId)),
      () => randomBytes(8).readBigUInt64BE() & ((1n << 63n) - 1n)); }
    catch (error) { return lndFailure(error, 'S10', warnings); }
    const id = rootKeyId.toString();
    state.inspection = `new root key ID ${id}; old credential unchanged; ` +
      `run \`${inventoryRecoveryCommand(request)}\` to inspect state; recover with ${recoveryCommand(request, id)}`;
    // Never before O (RL-02): a clock behind O's recorded creation time must not make this
    // link look like tampering to the finish, respond and inventory checks.
    const createdAt = new Date(Math.max(deps.clock().getTime(), Date.parse(old.createdAt))).toISOString();
    const entry: RegistryEntry = { nodePubkey: pubkey, label: request.label, rootKeyId: id,
      permissions: [...permissions], caveats: [], grade: assessment.grade, fingerprint: null,
      outPath: null, createdAt, verified: false, status: 'active', revokedAt: null, revokeEvidence: null,
      replaces: old.rootKeyId, replacedBy: null };
    checkCancellation();
    // The pending record may be on disk once save started (a failure after the rename, or a signal
    // during it), although nothing was sent to LND: it is removed again before reporting, so exit 3
    // and exit 6 keep meaning "nothing changed"; if the registry on disk still holds it, the exit
    // is 7 and the message names it with its recovery (RL-08).
    const unrecord = async (code: number, step: string, message: string): Promise<RotateOutput> => {
      try { registry.removePending(pubkey, id); await registry.save(); return fail(code, step, message, warnings); }
      catch { /* Decide from what is on disk. */ }
      try { if (!(await openRegistry(request.registry, { fs: deps.fs, env: deps.env })).find(pubkey, id)) return fail(code, step, message, warnings); }
      catch { /* Unreadable: the record may remain. */ }
      return fail(7, step, `${message}; nothing sent to LND, but the registry still holds (or may hold) the pending record for root key ${id}` +
        `; run \`${inventoryRecoveryCommand(request)}\` and, if it lists root key ${id}, ${recoveryCommand(request, id)}`, warnings);
    };
    try { registry.add(entry); await registry.save(); }
    catch { return await unrecord(3, 'S10', 'cannot record pending issued ID; nothing sent to LND'); }
    if (cancellationSignal()?.aborted) return await unrecord(6, 'cancelled', 'interrupted');
    let mac: Secret;
    state.mutationSent = true;
    markMutationSent();
    try { mac = await lnd.bakeMacaroon(permissions, rootKeyId); }
    catch (error) {
      if (!(error instanceof LndError || error instanceof Cancelled)) throw error;
      const failure = error instanceof LndError ? lndFailure(error, 'S10', warnings) : fail(7, 'S10', 'mutation response interrupted or unknown', warnings);
      try { ids = await listIds(lnd); }
      catch { return fail(7, 'S10', `LND state unknown; pending root key ${id}; old credential unchanged; run macwarden inventory to inspect state; recover with ${recoveryCommand(request, id)}`, warnings); }
      if (ids.includes(rootKeyId)) return fail(7, 'S10',
        `LND root key ${id} is present; old credential unchanged; run ${recoveryCommand(request, id)}`, warnings);
      // Without a complete LND response absence proves nothing; keep the pending record.
      if (error instanceof LndUncertainError) return fail(7, 'S10',
        `BakeMacaroon outcome unknown (no complete LND response); LND may still create root key ${id}; ` +
        `old credential unchanged; pending registry entry retained; run macwarden inventory to inspect state; ` +
        `recover with ${recoveryCommand(request, id)}`, warnings);
      try { registry.removePending(pubkey, id); await registry.save(); }
      catch { return fail(7, 'S10', `root key ${id} absent; pending registry cleanup failed; run ${recoveryCommand(request, id)}`, warnings); }
      return fail(failure.error!.code, 'S10', 'chosen root key is absent; LND unchanged, nothing changed', warnings);
    }

    const recover = async (step: string, reason: string): Promise<RotateOutput> => {
      let finalized = false;
      try { registry.update(entry); await registry.save(); finalized = true; }
      catch { /* Preserve primary recovery even when registry recording fails. */ }
      return fail(7, step, `${reason}; LND may have issued root key ${id}; old credential unchanged and still valid; ` +
        `${finalized ? 'recorded active verified:false, outPath:null' : 'pending active verified:false, outPath:null retained; final registry update failed'}; ` +
        `run ${recoveryCommand(request, id)}`, warnings);
    };
    let finalFacts: MacaroonFacts;
    try { finalFacts = decodeMacaroon(mac); }
    catch (error) {
      if (!(error instanceof DecodeError)) throw error;
      return await recover('S11', 'bake response cannot be decoded');
    }
    entry.fingerprint = finalFacts.fingerprint;
    if (finalFacts.rootKeyId !== rootKeyId || !samePermissions(finalFacts.permissions, permissions))
      return await recover('S11', 'bake response root key ID or permissions differ from the request');
    if (finalFacts.caveats.length) return await recover('S11', 'bake response carries caveats the request did not ask for');
    entry.permissions = [...finalFacts.permissions];
    entry.caveats = finalFacts.caveats.map(({ type, value }) => ({ type, value }));
    try {
      mac = expires !== undefined ? addFirstPartyCaveat(mac, timeBeforeCondition(expires, deps.clock))
        : encodeMacaroon(finalFacts);
      finalFacts = decodeMacaroon(mac);
    } catch (error) {
      if (!(error instanceof DecodeError || error instanceof UsageError)) throw error;
      return await recover('S11', 'final macaroon attenuation failed');
    }
    entry.fingerprint = finalFacts.fingerprint;
    entry.permissions = [...finalFacts.permissions];
    entry.caveats = finalFacts.caveats.map(({ type, value }, index) => ({ type, value,
      ...(expires !== undefined && index === finalFacts.caveats.length - 1 ? { requested: expires } : {}) }));
    let accepted: boolean;
    try { accepted = (await lnd.checkMacaroon(mac, finalFacts.permissions)).valid === true; }
    catch {
      return await recover('S12', 'final macaroon verification failed or timed out');
    }
    if (!accepted) return await recover('S12', 'LND rejected the final macaroon');
    if (cancellationSignal()?.aborted) return await recover('S12', 'operation interrupted before output writing');
    try { await reservation!.write(mac); }
    catch {
      return await recover('S12', 'cannot write, flush or close the output file');
    }
    entry.verified = true;
    entry.outPath = resolve(request.out);
    try { registry.update(entry); await registry.save(); }
    catch (error) {
      if (!(error instanceof RegistryInputError || error instanceof RegistryUsageError)) throw error;
      return fail(7, 'S13', `LND issued root key ${id}; the written file ${entry.outPath} is valid; registry update failed; ` +
        `recovery entry: ${JSON.stringify(entry)}; run ${recoveryCommand(request, id)}`, warnings);
    }
    if (cancellationSignal()?.aborted) return fail(7, 'S13',
      `operation interrupted; LND issued root key ${id}; completed output file retained; registry recorded active verified:true; run ${recoveryCommand(request, id)}`, warnings);
    const result: RotateStagedResult = { stage: 'staged', old, new: entry };
    return { schema: 1, command: 'rotate', ok: true, warnings, result, error: null };
  } finally {
    try { if (reservation) await cleanup(state, 'unwritten output discard', () => reservation!.discard()); }
    finally { if (locked) await cleanup(state, 'registry unlock', () => registry.unlock()); }
  }
}

export async function run(args: string[], deps: Deps): Promise<RotateOutput> {
  const state: RunState = { cleanupFailures: [], mutationSent: false, warnings: [] };
  try {
    const result = cleanupOutcome(await runSteps(args, deps, state), state);
    if (result.ok && cancellationSignal()?.aborted) {
      // A successful result means the arguments parsed.
      const request = parse(args, deps.env) as Request;
      if (result.command === 'rotate' && 'stage' in result.result && result.result.stage === 'finished')
        return onlineWarnings(fail(7, 'F12',
          `operation interrupted after rotation finished; old root key ID ${result.result.old.rootKeyId} absent from LND; ` +
          `new root key ID ${result.result.new.rootKeyId} remains active and its credential accepted; ` +
          `completed output and registry state retained; run \`${inventoryRecoveryCommand(request!)}\` to inspect state`, state.warnings));
      const id = result.command === 'rotate' && 'new' in result.result ? result.result.new.rootKeyId : undefined;
      if (id && request) return onlineWarnings(fail(7, 'S13',
        `operation interrupted; LND issued root key ${id}; completed output and registry state retained; run ${recoveryCommand(request, id)}`, state.warnings));
      return onlineWarnings(fail(state.mutationSent ? 7 : 6, 'cancelled', 'operation interrupted; run macwarden inventory to inspect state', state.warnings));
    }
    return onlineWarnings(result);
  }
  catch (error) { return onlineWarnings(cleanupOutcome(fail(error instanceof Cancelled ? (state.mutationSent ? 7 : 6) : 8,
    error instanceof Cancelled ? 'cancelled' : 'internal', error instanceof Cancelled ? 'interrupted' : 'unexpected failure' +
    (state.mutationSent ? `; LND may have changed; ${state.inspection ?? 'run macwarden inventory'}` : ''), state.warnings), state)); }
}

export async function rotate(args: string[]): Promise<OutputResult> {
  return run(args, { fs: nodeFs, env: { ...process.env }, clock: () => new Date(), createAdapter: createLndAdapter,
    stdin: process.stdin,
    prompt: async question => {
      writeRotatePrompt(question);
      const input = createInterface({ input: process.stdin, terminal: false });
      const signal = cancellationSignal();
      const close = () => input.close();
      signal?.addEventListener('abort', close, { once: true });
      try { for await (const line of input) return line; return null; }
      finally { signal?.removeEventListener('abort', close); input.close(); }
    } });
}
