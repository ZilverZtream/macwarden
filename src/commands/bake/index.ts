import { Cancelled, checkCancellation, cancellationSignal, cleanup, cleanupOutcome } from '../../cancellation.js';
import { endpoint, connectionProblem, flagProblem, LABEL_RULE, nodePubkey, drift, samePermissions, listIds, failureDetails, readBoundedFile, readOnlineCredential, onlineAdapter, onlineWarnings, recoveryCommand, connectionSettings } from '../../online.js';
import * as nodeFs from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { createLndAdapter, type LndAdapter } from '../../lnd/index.js';
import { addFirstPartyCaveat, decodeMacaroon, encodeMacaroon, timeBeforeCondition,
  type MacaroonFacts } from '../../decode/index.js';
import { grade } from '../../grade/index.js';
import { isProtectedPath, outputNameProblem, resolveUnprotectedPath } from '../../protected-path.js';
import { unsafeNodeDiagnostics } from '../../environment.js';
import { markMutationSent } from '../../process-error-context.js';
import { openRegistry, RegistryInputError, RegistryUsageError, type RegistryEntry } from '../../registry/index.js';
import { DecodeError, LndError, LndUncertainError, UsageError } from '../../errors.js';
import { Secret } from '../../secret.js';
import type { OutputResult } from '../../output/index.js';
import { namesRegistryFile, registryPath, REGISTRY_OUT_REFUSAL } from './out-registry.js';
import { reserveOut, type ReservedOut } from './write-out.js';
import { reserveFailure } from './out-errors.js';
import { interruptibleChecks, interruptibleReserve, OUT_CREATION_INTERRUPTED, rethrowCancelled } from './out-interrupt.js';
import { allocateRootKeyId } from './allocate.js';
import { canaryCondition, canaryConfigPath, ensureCanaryConfig, newCondition } from '../../watch/canary.js';

type BakeLnd = LndAdapter;
export type Deps = {
  lnd?: BakeLnd;
  createAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => BakeLnd;
  fs: typeof nodeFs;
  env: Record<string, string | undefined>;
  clock: () => Date;
};

type BakeOutput = OutputResult & { schema: 1 };
type Request = { label: string; out: string; registry?: string; host: string;
  cert: string; own: string; permissions: string[]; expires?: string;
  allowAdmin: boolean; breakLock: boolean; dryRun: boolean; canary: boolean };
// A canary looks like an ordinary read-only credential. Its default permissions cover the
// reconnaissance calls a thief makes first (node info, balances, channels, invoices,
// peers, addresses), because LND rejects calls a macaroon is not permitted before any
// middleware sees them: only permitted calls reach the guard and raise an alert.
const canaryPermissions = ['info:read', 'onchain:read', 'offchain:read', 'address:read', 'invoices:read', 'peers:read'];
const presets = new Map<string, string[]>([
  ['read-only', ['info:read', 'onchain:read', 'offchain:read', 'address:read', 'invoices:read', 'peers:read']],
  ['invoice-only', ['info:read', 'invoices:read', 'invoices:write']],
  ['pay-only', ['info:read', 'uri:/routerrpc.Router/SendPaymentV2',
    'uri:/routerrpc.Router/TrackPaymentV2', 'uri:/lnrpc.Lightning/DecodePayReq']],
  // BTCPay Server v2.4.4, pinned LND client revision and call inventory in docs/references.md.
  ['btcpay', ['uri:/invoicesrpc.Invoices/CancelInvoice',
    'uri:/lnrpc.Lightning/AddInvoice', 'uri:/lnrpc.Lightning/ChannelBalance',
    'uri:/lnrpc.Lightning/ConnectPeer', 'uri:/lnrpc.Lightning/GetInfo',
    'uri:/lnrpc.Lightning/ListChannels', 'uri:/lnrpc.Lightning/ListInvoices',
    'uri:/lnrpc.Lightning/ListPayments', 'uri:/lnrpc.Lightning/LookupInvoice',
    'uri:/lnrpc.Lightning/NewAddress', 'uri:/lnrpc.Lightning/OpenChannelSync',
    'uri:/lnrpc.Lightning/PendingChannels', 'uri:/lnrpc.Lightning/SubscribeInvoices',
    'uri:/lnrpc.Lightning/WalletBalance', 'uri:/routerrpc.Router/SendPaymentV2',
    'uri:/routerrpc.Router/TrackPaymentV2']],
]);
const valueFlags = new Set(['--label', '--preset', '--permissions', '--uri', '--expires', '--out',
  '--registry', '--lnd-rest', '--tls-cert', '--macaroon']);
const switchFlags = new Set(['--allow-admin', '--break-lock', '--dry-run', '--json', '--canary']);
const requiredMethods = [
  ['/lnrpc.Lightning/GetInfo', 'info:read'],
  ['/lnrpc.Lightning/ListPermissions', 'info:read'],
  ['/lnrpc.Lightning/BakeMacaroon', 'macaroon:generate'],
  ['/lnrpc.Lightning/ListMacaroonIDs', 'macaroon:read'],
  ['/lnrpc.Lightning/CheckMacaroonPermissions', 'macaroon:read'],
] as const;

function fail(code: number, step: string, message: string, warnings: BakeOutput['warnings'] = []): BakeOutput {
  return { schema: 1, command: 'bake', ok: false, warnings, result: null,
    error: { code, step, message } };
}

const presetList = () => [...presets.keys()].join(', ');

// Returns the request, or a message naming the flag and the rule (never the value).
function parse(args: string[], env: Deps['env']): Request | string {
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (!switchFlags.has(flag) && !valueFlags.has(flag))
      return `unknown argument; bake takes only flags: ${[...valueFlags, ...switchFlags].join(' ')}`;
    if (flags.has(flag)) return flagProblem(flag, 'repeated');
    if (switchFlags.has(flag)) flags.set(flag, true);
    else {
      const value = args[++i];
      if (value === undefined || value.startsWith('--')) return flagProblem(flag, 'missing');
      flags.set(flag, value);
    }
  }
  const get = (flag: string): string | undefined => {
    const value = flags.get(flag);
    return typeof value === 'string' ? value : undefined;
  };
  const label = get('--label');
  const out = get('--out');
  const preset = get('--preset');
  const raw = get('--permissions');
  const uri = get('--uri');
  const expires = get('--expires');
  const { host, cert, own, problem: mixedSource } = connectionSettings(get, env);
  if (!label) return '--label is required';
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(label)) return `--label ${LABEL_RULE}`;
  if (!out) return '--out is required: the path of the new macaroon file';
  if (mixedSource) return mixedSource;
  const connection = connectionProblem(host, cert, own);
  if (connection) return connection;
  if (preset !== undefined && (raw !== undefined || uri !== undefined))
    return '--preset cannot be combined with --permissions or --uri';
  if (preset === undefined && raw === undefined && uri === undefined && flags.get('--canary') !== true)
    return `give --preset (${presetList()}), --permissions or --uri`;
  if (preset !== undefined && !presets.has(preset)) return `unknown --preset; valid presets: ${presetList()}`;
  if (expires !== undefined && !/^(?:[1-9][0-9]{0,4})(?:m|h|d)$/.test(expires))
    return '--expires must be 1 to 99999 followed by m (minutes), h (hours) or d (days), for example 90d';
  const entities = raw === undefined ? [] : raw.split(',');
  const uris = uri === undefined ? [] : uri.split(',').map(method => `uri:${method}`);
  if (entities.some(value => !value) || uris.some(value => value === 'uri:'))
    return '--permissions and --uri take comma-separated values without empty entries';
  // A canary with no explicit permissions gets read-only-looking defaults.
  const permissions = preset !== undefined ? [...presets.get(preset)!]
    : entities.length || uris.length ? [...entities, ...uris] : [...canaryPermissions];
  if (!permissions.length) return 'give at least one permission';
  return { label, out, registry: get('--registry'), host: endpoint(host!)!, cert: cert!, own: own!,
    permissions, expires, allowAdmin: flags.get('--allow-admin') === true,
    breakLock: flags.get('--break-lock') === true, dryRun: flags.get('--dry-run') === true,
    canary: flags.get('--canary') === true };
}


function lndFailure(error: unknown, warnings: BakeOutput['warnings'], step = 'B8'): BakeOutput {
  const failure = failureDetails(error);
  return fail(failure.code, step, failure.message, warnings);
}

function caveats(request: Request, now: Date): Array<{ type: string; value: string }> {
  if (!request.expires) return [];
  const count = Number(request.expires.slice(0, -1));
  const unit = request.expires.at(-1);
  const milliseconds = count * (unit === 'd' ? 86_400_000 : unit === 'h' ? 3_600_000 : 60_000);
  return [{ type: 'time-before', value: new Date(now.getTime() + milliseconds).toISOString().replace(/\.\d{3}Z$/, 'Z') }];
}

type RunState = { cleanupFailures: string[]; inspection?: string; mutationSent: boolean; warnings: BakeOutput['warnings'] };

async function runSteps(args: string[], deps: Deps, state: RunState): Promise<BakeOutput> {
  const request = parse(args, deps.env);
  if (typeof request === 'string') return fail(2, 'B1', request);
  if (unsafeNodeDiagnostics(deps.env)) return fail(2, 'B2', 'unsafe Node diagnostic settings');
  const assessment = grade(request.permissions);
  if (assessment.grade === 'UNASSESSED' || assessment.warnings.some(w => w.startsWith('unassessed-')))
    return fail(2, 'B3', `unassessed permissions: ${assessment.unassessed.join(', ')}`);
  // Only READ or RECEIVE: if the guard disconnects between LND's macaroon check and its
  // middleware loop, LND runs the call with the macaroon's own permissions, so a canary
  // must never be able to spend, operate channels or administer the node.
  if (request.canary && assessment.grade !== 'READ' && assessment.grade !== 'RECEIVE')
    return fail(2, 'B3', `a canary carries only READ or RECEIVE permissions (this set is ${assessment.grade})`);
  if (assessment.grade === 'ADMIN' && !request.allowAdmin)
    return fail(2, 'B3', 'ADMIN permissions require --allow-admin');
  if (isProtectedPath(request.out)) return fail(3, 'B4', 'protected output path');
  const outName = outputNameProblem(request.out);
  if (outName) return fail(3, 'B4', `output path refused: ${outName}`);
  // Each check is abandoned on an interrupt (a stalled mount): exit 6, step cancelled.
  const checks = interruptibleChecks(deps.fs);
  let outPath: string;
  try { outPath = await resolveUnprotectedPath(request.out, checks); }
  catch (error) { rethrowCancelled(error); return fail(3, 'B4', 'cannot check output path'); }
  const registryFile = await registryPath(request.registry, checks, deps.env);
  if (registryFile !== null && namesRegistryFile(outPath, registryFile)) return fail(3, 'B4', REGISTRY_OUT_REFUSAL);
  try { await checks.lstat(request.out); return fail(3, 'B4', 'output file already exists'); }
  catch (error) { rethrowCancelled(error); if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
    return fail(3, 'B4', 'cannot check output path'); }
  request.out = outPath;

  let cert: Buffer;
  let own: Secret;
  try {
    if (isProtectedPath(request.cert)) return fail(4, 'B5', 'unreadable TLS certificate');
    const certPath = await deps.fs.realpath(request.cert);
    if (isProtectedPath(certPath)) return fail(4, 'B5', 'unreadable TLS certificate');
    cert = await readBoundedFile(certPath, deps.fs);
  } catch { return fail(4, 'B5', 'unreadable TLS certificate'); }
  try { own = (await readOnlineCredential(request.own, { stdin: process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, 'B5', 'unreadable own macaroon'); }
  let facts;
  try { facts = decodeMacaroon(own); }
  catch { return fail(4, 'B5', 'undecodable own macaroon'); }
  const held = new Set(facts.permissions);
  for (const [method, permission] of requiredMethods) {
    if (!held.has(permission) && !held.has(`uri:${method}`))
      return fail(4, 'B5', `own macaroon missing permission: ${permission}`);
  }
  const warnings: BakeOutput['warnings'] = facts.rootKeyId === 0n ? ['own-root-key-0'] : [];
  state.warnings = warnings;
  let registry;
  if (request.registry && isProtectedPath(request.registry))
    return fail(3, 'B6', 'protected registry path', warnings);
  try { registry = await openRegistry(request.registry, { fs: deps.fs, env: deps.env }); }
  catch { return fail(3, 'B6', 'unreadable or invalid registry', warnings); }
  let locked = false;
  let canaryName: string | undefined;
  let reservation: ReservedOut | undefined;
  try {
    if (!request.dryRun) {
      try { await registry.lock({ breakLock: request.breakLock }); locked = true; }
      catch (error) { return fail(3, 'B6', error instanceof RegistryInputError
        ? error.message : 'registry locked or unavailable', warnings); }
      try {
        const current = await openRegistry(request.registry, { fs: deps.fs, env: deps.env });
        registry.reload(current.entries);
      } catch { return fail(3, 'B6', 'unreadable or invalid registry on reread; nothing sent to LND', warnings); }
      if (request.canary) {
        try { canaryName = (await ensureCanaryConfig(canaryConfigPath(registry.location), deps.fs)).caveatName; }
        catch { return fail(3, 'B6', 'cannot read or create the canary configuration; nothing sent to LND', warnings); }
      }
      try {
        const reserved = await interruptibleReserve(() => reserveOut(request.out, deps.fs));
        reservation = reserved.reservation;
        if (reserved.aclWarning) warnings.push('acl-best-effort');
      } catch (error) {
        if (error instanceof Cancelled) return fail(6, 'cancelled', OUT_CREATION_INTERRUPTED, warnings);
        return fail(3, 'B7', reserveFailure(error), warnings);
      }
    }
    const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: request.host, tlsCert: cert, macaroon: own });
    if (!adapter) return fail(8, 'internal', 'unexpected failure', warnings);
  const lnd = onlineAdapter(adapter);
    let pubkey: string;
    try { pubkey = nodePubkey(await lnd.getInfo()); }
    catch (error) { return lndFailure(error, warnings); }
    try { if (drift(await lnd.listPermissions())) warnings.push('snapshot-drift'); }
    catch (error) { return lndFailure(error, warnings); }
    if (registry.entries.some(entry => entry.status === 'active'
      && entry.nodePubkey.toLowerCase() === pubkey && entry.label === request.label))
      return fail(2, 'B8', 'active label already exists for this node', warnings);
    if (request.canary) warnings.push('canary-requires-watch');
    if (request.dryRun) return { schema: 1, command: 'bake', ok: true, warnings,
      result: { dryRun: true, label: request.label, permissions: request.permissions,
        grade: assessment.grade, caveats: caveats(request, deps.clock()), ...(request.canary ? { canary: true } : {}) }, error: null };
    let rootKeyId: bigint;
    try {
      rootKeyId = allocateRootKeyId(await listIds(lnd),
        registry.entries.map(entry => BigInt(entry.rootKeyId)),
        () => randomBytes(8).readBigUInt64BE() & ((1n << 63n) - 1n));
    } catch (error) { return lndFailure(error, warnings, 'B10'); }
    const id = rootKeyId.toString();
    state.inspection = `root key ID ${id}; run ${recoveryCommand(request, id)}`;
    const createdAt = deps.clock().toISOString();
    const entry: RegistryEntry = { nodePubkey: pubkey, label: request.label, rootKeyId: id,
      permissions: [...request.permissions], caveats: [], grade: assessment.grade,
      fingerprint: null, outPath: null, createdAt, verified: false, status: 'active',
      revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null };
    checkCancellation();
    // The pending record may be on disk once save started (a failure after the rename, or a signal
    // during it), although nothing was sent to LND: it is removed again before reporting, so exit 3
    // and exit 6 keep meaning "nothing changed"; if the registry on disk still holds it, the exit
    // is 7 and the message names it with its recovery (RL-08).
    const unrecord = async (code: number, step: string, message: string): Promise<BakeOutput> => {
      try { registry.removePending(pubkey, id); await registry.save(); return fail(code, step, message, warnings); }
      catch { /* Decide from what is on disk. */ }
      try { if (!(await openRegistry(request.registry, { fs: deps.fs, env: deps.env })).find(pubkey, id)) return fail(code, step, message, warnings); }
      catch { /* Unreadable: the record may remain. */ }
      return fail(7, step, `${message}; nothing sent to LND, but the registry still holds (or may hold) the pending record for root key ${id}` +
        `, which keeps the label in use; run macwarden inventory and, if it lists root key ${id}, ${recoveryCommand(request, id)}`, warnings);
    };
    try { registry.add(entry); await registry.save(); }
    catch { return await unrecord(3, 'B11', 'cannot record pending issued ID; nothing sent to LND'); }
    if (cancellationSignal()?.aborted) return await unrecord(6, 'cancelled', 'interrupted');
    let mac: Secret;
    state.mutationSent = true;
    markMutationSent();
    try { mac = await lnd.bakeMacaroon(request.permissions, rootKeyId); }
    catch (error) {
      if (!(error instanceof LndError || error instanceof Cancelled)) throw error;
      const failure = error instanceof LndError ? lndFailure(error, warnings, 'B11') : fail(7, 'B11', 'mutation response interrupted or unknown', warnings);
      let ids: bigint[];
      try { ids = await listIds(lnd); }
      catch { return fail(7, 'B11', `B11: LND state unknown; pending root key ${id}; run macwarden inventory to inspect state; recover with ${recoveryCommand(request, id)}`, warnings); }
      if (ids.includes(rootKeyId)) return fail(7, 'B11',
        `B11: LND root key ${id} is present; run ${recoveryCommand(request, id)}`, warnings);
      // Without a complete LND response the request may still be applied after this
      // list, so absence proves nothing: keep the pending record for the recovery command.
      if (error instanceof LndUncertainError) return fail(7, 'B11',
        `B11: BakeMacaroon outcome unknown (no complete LND response); LND may still create root key ${id}; ` +
        `pending registry entry retained; run macwarden inventory to inspect state; recover with ${recoveryCommand(request, id)}`, warnings);
      try { registry.removePending(pubkey, id); await registry.save(); }
      catch { return fail(7, 'B11', `root key ${id} absent; pending registry cleanup failed; run ${recoveryCommand(request, id)}`, warnings); }
      return fail(failure.error!.code, 'B11',
        'B11: chosen root key is absent; LND unchanged, nothing changed', warnings);
    }

    // A failed response still needs a revocable record for the allocated ID.
    const recover = async (step: string, reason: string): Promise<BakeOutput> => {
      let finalized = false;
      try { registry.update(entry); await registry.save(); finalized = true; }
      catch { /* Preserve primary recovery even when registry recording fails. */ }
      const command = recoveryCommand(request, id);
      return fail(7, step, `${step}: ${reason}; LND may have issued root key ${id}; ` +
        `${finalized ? 'recorded active verified:false, outPath:null' : 'pending active verified:false, outPath:null retained; final registry update failed'}; run ${command}`, warnings);
    };
    let finalFacts: MacaroonFacts;
    try { finalFacts = decodeMacaroon(mac); }
    catch (error) {
      if (!(error instanceof DecodeError)) throw error;
      return await recover('B12', 'bake response cannot be decoded');
    }
    entry.fingerprint = finalFacts.fingerprint;
    if (finalFacts.rootKeyId !== rootKeyId || !samePermissions(finalFacts.permissions, request.permissions))
      return await recover('B12', 'bake response root key ID or permissions differ from the request');
    // BakeMacaroon never returns caveats (audit 1.2.1): a response carrying one (a custom caveat would
    // make the new credential depend on a middleware) is not LND's answer to this request.
    if (finalFacts.caveats.length) return await recover('B12', 'bake response carries caveats the request did not ask for');
    entry.permissions = [...finalFacts.permissions];
    entry.caveats = finalFacts.caveats.map(({ type, value }) => ({ type, value }));
    try {
      mac = request.expires ? addFirstPartyCaveat(mac, timeBeforeCondition(request.expires, deps.clock))
        : encodeMacaroon(finalFacts);
      finalFacts = decodeMacaroon(mac);
    } catch (error) {
      if (!(error instanceof DecodeError || error instanceof UsageError)) throw error;
      return await recover('B13', 'final macaroon attenuation failed');
    }
    entry.fingerprint = finalFacts.fingerprint;
    entry.permissions = [...finalFacts.permissions];
    entry.caveats = finalFacts.caveats.map(({ type, value }, index) => ({ type, value,
      ...(request.expires && index === finalFacts.caveats.length - 1 ? { requested: request.expires } : {}) }));
    let accepted: boolean;
    try { accepted = (await lnd.checkMacaroon(mac, finalFacts.permissions)).valid === true; }
    catch {
      return await recover('B14', 'final macaroon verification failed or timed out');
    }
    if (!accepted) return await recover('B14', 'LND rejected the final macaroon');
    if (request.canary) {
      try {
        mac = addFirstPartyCaveat(mac, canaryCondition(canaryName!, newCondition()));
        finalFacts = decodeMacaroon(mac);
      } catch (error) {
        if (!(error instanceof DecodeError || error instanceof UsageError)) throw error;
        return await recover('B14', 'canary caveat could not be added');
      }
      entry.fingerprint = finalFacts.fingerprint;
      entry.caveats = [...entry.caveats, ...finalFacts.caveats.slice(entry.caveats.length).map(({ type, value }) => ({ type, value }))];
    }
    if (cancellationSignal()?.aborted) return await recover('B14', 'operation interrupted before output writing');
    try { await reservation!.write(mac); }
    catch {
      return await recover('B15', 'cannot write, flush or close the output file');
    }
    entry.verified = true;
    entry.outPath = resolve(request.out);
    try { registry.update(entry); await registry.save(); }
    catch (error) {
      if (!(error instanceof RegistryInputError || error instanceof RegistryUsageError)) throw error;
      return fail(7, 'B16', `B16: LND issued root key ${id}; the written file is valid; ` +
        `registry update failed; recovery entry: ${JSON.stringify(entry)}; run ${recoveryCommand(request, id)}`, warnings);
    }
    if (cancellationSignal()?.aborted) return fail(7, 'B16',
      `operation interrupted; LND issued root key ${id}; completed output file retained; registry recorded active verified:true; run ${recoveryCommand(request, id)}`, warnings);
    return { schema: 1, command: 'bake', ok: true, warnings, result: { ...entry }, error: null };
  } finally {
    try { if (reservation) await cleanup(state, 'unwritten output discard', () => reservation!.discard()); }
    finally { if (locked) await cleanup(state, 'registry unlock', () => registry.unlock()); }
  }
}

export async function run(args: string[], deps: Deps): Promise<BakeOutput> {
  const state: RunState = { cleanupFailures: [], mutationSent: false, warnings: [] };
  try {
    const result = cleanupOutcome(await runSteps(args, deps, state), state);
    if (result.ok && cancellationSignal()?.aborted) {
      const id = result.command === 'bake' && 'rootKeyId' in result.result ? result.result.rootKeyId : undefined;
      const request = parse(args, deps.env);
      if (id && typeof request !== 'string') return onlineWarnings(fail(7, 'B16',
        `operation interrupted; LND issued root key ${id}; completed output and registry state retained; run ${recoveryCommand(request, id)}`, state.warnings));
      return onlineWarnings(fail(state.mutationSent ? 7 : 6, 'cancelled', 'operation interrupted; run macwarden inventory to inspect state', state.warnings));
    }
    return onlineWarnings(result);
  }
  catch (error) { return onlineWarnings(cleanupOutcome(fail(error instanceof Cancelled ? (state.mutationSent ? 7 : 6) : 8,
    error instanceof Cancelled ? 'cancelled' : 'internal', error instanceof Cancelled ? 'interrupted' : 'unexpected failure' +
    (state.mutationSent ? `; LND may have changed; ${'run macwarden inventory'}` : ''), state.warnings), state)); }
}

export async function bake(args: string[]): Promise<OutputResult> {
  return run(args, { fs: nodeFs, env: { ...process.env }, clock: () => new Date(), createAdapter: createLndAdapter });
}
