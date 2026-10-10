import { LndError, LndUncertainError } from '../errors.js';
import { resolve } from 'node:path';
import { Cancelled, checkCancellation, cancellable, cancellationSignal, cleanup, cleanupOutcome } from '../cancellation.js';
import { endpoint, credentialText, connectionProblem, flagProblem, LABEL_RULE, nodePubkey, drift, listIds, failureDetails, readBoundedFile, readOnlineCredential, onlineAdapter, onlineWarnings, inventoryRecoveryCommand, recoveryPath, shellQuote, connectionSettings } from '../online.js';
import * as nodeFs from 'node:fs/promises';
import { createInterface } from 'node:readline';
import type { Readable } from 'node:stream';
import { isDeepStrictEqual } from 'node:util';
import { createLndAdapter, type LndAdapter } from '../lnd/index.js';
import { decodeMacaroon, parseTimeBefore, type MacaroonFacts } from '../decode/index.js';
import { openRegistry, recordedFileRelation, RegistryInputError, type RegistryEntry } from '../registry/index.js';
import { gradeFacts } from '../grade/index.js';
import { isProtectedPath } from '../protected-path.js';
import { unsafeNodeDiagnostics } from '../environment.js';
import { markMutationSent } from '../process-error-context.js';
import { Secret } from '../secret.js';
import { isRootKeyId } from '../root-key-id.js';
import { revokeConfirmation, revokePlanResult, writeRevokePrompt,
  type OutputResult, type RevokePlan, type RevokeResult } from '../output/index.js';

type RevokeLnd = LndAdapter;
export type Deps = {
  lnd?: RevokeLnd;
  createAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => RevokeLnd;
  fs: typeof nodeFs;
  env: Record<string, string | undefined>;
  clock: () => Date;
  stdin?: Readable & { isTTY?: boolean };
  prompt?: ((question: string) => Promise<string | null>) & { isTTY?: boolean };
};
type RevokeOutput = OutputResult & { schema: 1 };
type Request = { id?: bigint; label?: string; targetFile?: string; registry?: string;
  host: string; cert: string; own: string; unregistered: boolean; yes: boolean; dryRun: boolean; breakLock: boolean };
type Target = { secret: Secret; facts: MacaroonFacts };
type RunState = { cleanupFailures: string[]; mutationSent: boolean; inspection?: string };
const valueFlags = new Set(['--target-file', '--registry', '--lnd-rest', '--tls-cert', '--macaroon']);
const switchFlags = new Set(['--unregistered', '--yes', '--break-lock', '--dry-run', '--json']);
const requiredMethods = [
  ['/lnrpc.Lightning/GetInfo', 'info:read'],
  ['/lnrpc.Lightning/ListPermissions', 'info:read'],
  ['/lnrpc.Lightning/ListMacaroonIDs', 'macaroon:read'],
  ['/lnrpc.Lightning/CheckMacaroonPermissions', 'macaroon:read'],
  ['/lnrpc.Lightning/DeleteMacaroonID', 'macaroon:write'],
] as const;

function fail(code: number, step: string, message: string, warnings: OutputResult['warnings'] = []): RevokeOutput {
  return { schema: 1, command: 'revoke', ok: false, warnings, result: null, error: { code, step, message } };
}

const targetRule = 'give one target: a label (it ' + LABEL_RULE + ') or a root key ID from 1 to 18446744073709551615';

// Returns the request, or a message naming the flag and the rule (never the value).
function parse(args: string[], env: Deps['env']): Request | string {
  let target: string | undefined;
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
      return `unknown flag; revoke takes: <label|id> ${[...valueFlags, ...switchFlags].join(' ')}`;
    } else {
      if (target !== undefined) return targetRule;
      target = arg;
    }
  }
  let id: bigint | undefined;
  if (target && /^[0-9]+$/.test(target)) {
    if (/^0+$/.test(target)) return 'root key ID 0 cannot be revoked: it is shared by the default macaroons (SAFE-03)';
    if (!isRootKeyId(target)) return targetRule;
    id = BigInt(target);
  } else if (!target || !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(target)) return targetRule;
  const get = (name: string): string | undefined => {
    const value = flags.get(name);
    return typeof value === 'string' ? value : undefined;
  };
  const { host, cert, own, problem: mixedSource } = connectionSettings(get, env);
  const targetFile = get('--target-file');
  if (mixedSource) return mixedSource;
  const connection = connectionProblem(host, cert, own);
  if (connection) return connection;
  if (targetFile === '-' || (targetFile !== undefined && credentialText(targetFile)))
    return '--target-file must be a file path; stdin (-) and literal credentials are refused';
  return { id, label: id === undefined ? target : undefined, targetFile,
    registry: get('--registry'), host: endpoint(host!)!, cert: cert!, own: own!,
    unregistered: flags.has('--unregistered'), yes: flags.has('--yes'), dryRun: flags.has('--dry-run'),
    breakLock: flags.has('--break-lock') };
}


function lndFailure(error: unknown, step: string, warnings: OutputResult['warnings']): RevokeOutput {
  const failure = failureDetails(error);
  return fail(failure.code, step, failure.message, warnings);
}

async function readTarget(path: string, deps: Deps): Promise<Target> {
  if (isProtectedPath(path) || isProtectedPath(await deps.fs.realpath(path)))
    throw new Error('protected target file');
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

function rerun(request: Request, id: bigint): string {
  const restUrl = new URL(request.host);
  const args = ['macwarden', 'revoke', request.label ?? id.toString()];
  if (request.unregistered) args.push('--unregistered');
  if (request.registry) args.push('--registry', recoveryPath(request.registry));
  args.push('--lnd-rest', `${restUrl.hostname}:${restUrl.port || '443'}`, '--tls-cert', recoveryPath(request.cert),
    '--macaroon', recoveryPath(request.own));
  return args.map(shellArgument).join(' ');
}

async function runSteps(args: string[], deps: Deps, warnings: OutputResult['warnings'], state: RunState): Promise<RevokeOutput> {
  const request = parse(args, deps.env);
  if (typeof request === 'string') return fail(2, 'V1', request);
  if (unsafeNodeDiagnostics(deps.env))
    return fail(2, 'V2', 'unsafe Node diagnostic settings');
  let target: Target | undefined;
  if (request.targetFile) {
    try { target = await readTarget(request.targetFile, deps); }
    catch { return fail(3, 'V3', 'unreadable or undecodable target file'); }
    if (target.facts.rootKeyId === 0n) return fail(2, 'V3', 'target file uses root key ID 0');
    if (request.id !== undefined && target.facts.rootKeyId !== request.id)
      return fail(2, 'V3', 'target file root key ID differs from the numeric target');
  }
  let cert: Buffer;
  let own: Secret;
  let ownFacts: MacaroonFacts;
  try {
    if (isProtectedPath(request.cert) || isProtectedPath(await deps.fs.realpath(request.cert)))
      return fail(4, 'V4', 'unreadable TLS certificate');
    cert = await readBoundedFile(request.cert, deps.fs);
  } catch { return fail(4, 'V4', 'unreadable TLS certificate'); }
  try { own = (await readOnlineCredential(request.own, { stdin: deps.stdin ?? process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, 'V4', 'unreadable own macaroon'); }
  try { ownFacts = decodeMacaroon(own); }
  catch { return fail(4, 'V4', 'undecodable own macaroon'); }
  const held = new Set(ownFacts.permissions);
  for (const [method, required] of requiredMethods) {
    if (!held.has(required) && !held.has(`uri:${method}`))
      return fail(4, 'V4', `own macaroon missing permission: ${required}`);
  }
  if (ownFacts.rootKeyId === 0n) warnings.push('own-root-key-0');
  if (request.id === ownFacts.rootKeyId) return fail(2, 'V4', 'cannot revoke the own macaroon root key ID', warnings);
  const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: request.host, tlsCert: cert, macaroon: own });
  if (!adapter) return fail(8, 'internal', 'unexpected failure', warnings);
  const lnd = onlineAdapter(adapter);
  let pubkey: string;
  try {
    pubkey = nodePubkey(await lnd.getInfo());
  } catch (error) { return lndFailure(error, 'V5', warnings); }
  try { if (drift(await lnd.listPermissions())) warnings.push('snapshot-drift'); }
  catch (error) { return lndFailure(error, 'V5', warnings); }
  let registry;
  try {
    if (request.registry && isProtectedPath(request.registry)) return fail(3, 'V6', 'protected registry path', warnings);
    registry = await openRegistry(request.registry, { fs: deps.fs, env: deps.env });
  } catch { return fail(3, 'V6', 'unreadable or invalid registry', warnings); }
  const entries = registry.entries;
  const local = entries.filter(entry => entry.nodePubkey.toLowerCase() === pubkey);
  let entry: RegistryEntry | undefined;
  if (request.label !== undefined) {
    const candidates = local.filter(row => row.label === request.label && row.status === 'active');
    if (candidates.length !== 1) return fail(2, 'V6',
      `label must resolve to exactly one active entry; candidates: ${candidates.map(row => row.rootKeyId).join(', ') || 'none'}`, warnings);
    entry = candidates[0];
  } else {
    entry = local.find(row => BigInt(row.rootKeyId) === request.id);
    // Root key IDs are per node (small IDs from lncli bakemacaroon --root_key_id exist on every
    // node), so an entry for another node says nothing about this node's ID: without
    // --unregistered the operator may have meant that node and is told so; with it, this node's
    // ID is revoked and recorded under this node's pubkey (RL-04).
    if (!entry && !request.unregistered) return fail(2, 'V6', entries.some(row => BigInt(row.rootKeyId) === request.id)
      ? 'root key ID is registered only for another node; check --lnd-rest, or pass --unregistered to revoke this node\'s root key ID'
      : 'unregistered root key ID requires --unregistered; other tools and other operators share the same LND store, including Lightning Terminal', warnings);
  }
  const id = entry ? BigInt(entry.rootKeyId) : request.id!;
  const inspection = `root key ID ${id}; run \`${inventoryRecoveryCommand(request)}\` ` +
    `to inspect the observed state before deciding whether to run \`${rerun(request, id)}\`; do not retry deletion blindly`;
  state.inspection = inspection;
  if (id === 0n) return fail(2, 'V6', 'cannot revoke root key ID 0', warnings);
  if (id === ownFacts.rootKeyId) return fail(2, 'V6', 'cannot revoke the own macaroon root key ID', warnings);
  if (target && target.facts.rootKeyId !== id)
    return fail(2, 'V6', 'target file root key ID differs from the resolved target', warnings);
  if (!request.targetFile && entry?.outPath) {
    try { target = await readTarget(entry.outPath, deps); }
    catch { target = undefined; }
    const relation = target && recordedFileRelation(entry, target.facts);
    if (relation === 'tampered') return fail(3, 'V6', 'default target file carries the registry entry\'s fingerprint ' +
      'on another root key ID: the registry entry was edited; restore the registry from a trusted copy', warnings);
    // Another credential at a reused path, or another macaroon on this root key ID, is not
    // the target: the revocation is proven by ID only (RL-01).
    if (relation !== 'match') target = undefined;
  }
  let ids: bigint[];
  try { ids = await listIds(lnd); }
  catch (error) { return lndFailure(error, 'V7', warnings); }
  const repaired = !ids.includes(id);
  if (repaired && entry?.status !== 'active')
    return fail(5, 'V7', 'root key ID is absent; nothing to revoke', warnings);
  let proof: RevokePlan['proof'] = 'by-id-only';
  if (!repaired && target && usable(target, deps.clock())) {
    try { if ((await lnd.checkMacaroon(target.secret, target.facts.permissions)).valid === true) proof = 'rejected'; }
    catch (error) { return lndFailure(error, 'V8', warnings); }
  }
  const plan: RevokePlan = { dryRun: request.dryRun, rootKeyId: id.toString(),
    label: entry?.label ?? null, grade: entry?.grade ?? null, proof };
  if (request.dryRun) return revokePlanResult(plan, warnings, repaired);
  if (!request.dryRun && !request.yes) {
    const stdin = deps.stdin ?? process.stdin;
    if (!stdin.isTTY)
      return fail(6, 'V9', 'confirmation requires a TTY or --yes', warnings);
    const answer = await cancellable(() => (deps.prompt ?? (async () => null))(revokeConfirmation(plan, repaired)));
    if (answer !== (plan.label ?? plan.rootKeyId))
      return fail(6, 'V9', 'operator declined or did not type the exact confirmation', warnings);
  }
  let locked = false;
  try {
    try { await registry.lock({ breakLock: request.breakLock }); locked = true; }
    catch (error) { return fail(3, 'V10', error instanceof RegistryInputError
      ? error.message : 'registry locked or unavailable', warnings); }
    try {
      const current = await openRegistry(request.registry, { fs: deps.fs, env: deps.env });
      const resolved = current.find(pubkey, id.toString());
      // Node-scoped like V6: an entry for this ID on another node is not this target (RL-04).
      if (!isDeepStrictEqual(resolved, entry))
        return fail(3, 'V10', 'resolved registry entry changed since V6; nothing sent to LND', warnings);
      // Retain the lock owner while preserving unrelated entries from the reread.
      registry.reload(current.entries);
    } catch { return fail(3, 'V10', 'unreadable or invalid registry on reread; nothing sent to LND', warnings); }
    if (!repaired) {
      let deleted = false;
      let uncertain = false;
      checkCancellation();
      state.mutationSent = true;
      markMutationSent();
      try { deleted = (await lnd.deleteMacaroonId(id)).deleted === true; }
      catch (error) {
        if (!(error instanceof LndError || error instanceof Cancelled)) throw error;
        uncertain = error instanceof LndUncertainError;
        /* One state reconciliation determines whether deletion completed. */
      }
      if (!deleted) {
        try { ids = await listIds(lnd); }
        catch { return fail(7, 'V11', `LND state unknown; registry unchanged — ${inspection}`, warnings); }
        // After an incomplete response a listed ID may still be deleted later.
        if (uncertain && ids.includes(id)) return fail(7, 'V11',
          `DeleteMacaroonID outcome unknown (no complete LND response); root key ID still listed but LND may still delete it; ` +
          `registry unchanged; rerun ${rerun(request, id)} to confirm — ${inspection}`, warnings);
        if (ids.includes(id)) return fail(5, 'V11', 'root key ID still present; registry unchanged, credential still valid', warnings);
      } else {
        try { ids = await listIds(lnd); }
        catch { return fail(7, 'V12', `LND state unknown; registry unchanged — ${inspection}`, warnings); }
        if (ids.includes(id)) return fail(7, 'V12', `root key ID still present after deletion; registry unchanged; ${inspection}`, warnings);
      }
      if (proof === 'rejected') {
        // A signature mismatch alone is no proof (RT-01: an altered copy gets it too). Here it is
        // corroborating evidence only: both branches above return unless ListMacaroonIDs shows the
        // ID absent, and proof 'rejected' means V8 saw these exact bytes accepted in this run, so a
        // mismatch now can only come from LND's state for this ID, not from altered bytes.
        try {
          const checked = await lnd.checkMacaroon(target!.secret, target!.facts.permissions);
          if (checked.valid !== false || (checked.reason !== 'root-key-missing' && checked.reason !== 'signature-mismatch'))
            return fail(7, 'V12', `root key ID absent, but documented target rejection not confirmed; registry unchanged; ${inspection}`, warnings);
        } catch { return fail(7, 'V12', `root key ID absent, credential rejection unknown; registry unchanged; ${inspection}`, warnings); }
      }
    }
    const revokedAt = deps.clock().toISOString();
    let revokedEntry: RegistryEntry;
    try {
      const existing = registry.find(pubkey, id.toString());
      if (existing) {
        if (existing.status === 'active') registry.markRevoked(pubkey, id.toString(), revokedAt, proof);
        else if (existing.status === 'revoked' && !repaired) {
          // Revoked but present (a node backup restored the root key, 1.2.1): this run deleted it
          // again, so the entry records this run's time and evidence, matching the result; the
          // earlier event is kept in the warning. The registry lock is held (V10).
          warnings.push({ code: 'revoked-but-present', message: `root key ID ${id.toString()} was recorded revoked at ` +
            `${existing.revokedAt ?? 'an unknown time'} (evidence ${existing.revokeEvidence ?? 'unknown'}) but LND held it ` +
            `again; this run deleted it and the entry now records this revocation` });
          existing.revokedAt = revokedAt;
          existing.revokeEvidence = proof;
        }
        revokedEntry = existing;
      } else {
        const facts = target?.facts;
        revokedEntry = { nodePubkey: pubkey, rootKeyId: id.toString(), label: null,
          permissions: facts ? [...facts.permissions] : [],
          caveats: facts?.caveats.map(({ type, value }) => ({ type, value })) ?? [],
          grade: facts ? gradeFacts(facts).grade : 'UNASSESSED',
          fingerprint: facts?.fingerprint ?? null, outPath: facts && request.targetFile ? resolve(request.targetFile) : null,
          createdAt: revokedAt, verified: facts !== undefined && proof === 'rejected', status: 'revoked', revokedAt,
          revokeEvidence: proof, replaces: null, replacedBy: null };
        registry.add(revokedEntry);
      }
      await registry.save();
    } catch {
      // SPEC V7: an absent unregistered ID has nothing to revoke,
      // so a rerun cannot add a record; say so instead of printing a command that exits 5.
      return fail(7, 'V13', entry
        ? `root key ID ${id.toString()} absent from LND; registry update failed; run ${rerun(request, id)}`
        : `root key ID ${id.toString()} deleted from LND; the registry had no entry and the revocation record could not be saved; no further action is needed`, warnings);
    }
    const result: RevokeResult = { rootKeyId: id.toString(), label: revokedEntry.label,
      evidence: proof, repaired, entry: revokedEntry };
    return { schema: 1, command: 'revoke', ok: true, warnings, result, error: null };
  } finally { if (locked) await cleanup(state, 'registry unlock', () => registry.unlock()); }
}

export async function run(args: string[], deps: Deps): Promise<RevokeOutput> {
  const warnings: OutputResult['warnings'] = [];
  const state: RunState = { cleanupFailures: [], mutationSent: false };
  try { return onlineWarnings(cleanupOutcome(await runSteps(args, deps, warnings, state), state)); }
  catch (error) { return onlineWarnings(cleanupOutcome(fail(error instanceof Cancelled ? (state.mutationSent ? 7 : 6) : 8,
    error instanceof Cancelled ? 'cancelled' : 'internal', error instanceof Cancelled ? 'interrupted' : 'unexpected failure' +
    (state.mutationSent ? `; LND may have changed; ${state.inspection ?? 'run macwarden inventory'}` : ''), warnings), state)); }
}

export async function revoke(args: string[]): Promise<OutputResult> {
  return run(args, { fs: nodeFs, env: { ...process.env }, clock: () => new Date(),
    createAdapter: createLndAdapter, stdin: process.stdin,
    prompt: async question => {
      writeRevokePrompt(question);
      const input = createInterface({ input: process.stdin, terminal: false });
      const signal = cancellationSignal();
      const close = () => input.close();
      signal?.addEventListener('abort', close, { once: true });
      try { for await (const line of input) return line; return null; }
      finally { signal?.removeEventListener('abort', close); input.close(); }
    } });
}
