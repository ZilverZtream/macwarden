import * as nodeFs from 'node:fs/promises';
import { resolve } from 'node:path';
import type { Readable } from 'node:stream';
import { checkCancellation, Cancelled, cleanup, cleanupOutcome, type CleanupState } from '../cancellation.js';
import { canonicalCidr, canonicalIp } from '../caveat-address.js';
import { addFirstPartyCaveat, decodeMacaroon, DecodeError, parseTimeBefore, timeBeforeCondition,
  type Caveat, type MacaroonFacts } from '../decode/index.js';
import { unsafeNodeDiagnostics } from '../environment.js';
import { describe, gradeFacts } from '../grade/index.js';
import { InputError, readCredential, UsageError } from '../input/index.js';
import type { AttenuateResult, OutputResult } from '../output/index.js';
import { isProtectedPath, outputNameProblem, resolveUnprotectedPath } from '../protected-path.js';
import type { Secret } from '../secret.js';
import { reserveOut, type ReservedOut } from './bake/write-out.js';
import { reserveFailure } from './bake/out-errors.js';
import { interruptibleChecks, interruptibleReserve, OUT_CREATION_INTERRUPTED, rethrowCancelled } from './bake/out-interrupt.js';
import { namesRegistryFile, registryPath, REGISTRY_OUT_REFUSAL } from './bake/out-registry.js';

export type Deps = {
  stdin: Readable & { isTTY?: boolean };
  fs: typeof nodeFs;
  env: Record<string, string | undefined>;
  clock: () => Date;
};

type AttenuateOutput = OutputResult & { schema: 1 };
type Request = { input: string; out: string; expires?: string; ip?: string; ipRange?: string;
  dryRun: boolean; unsafeArg: boolean };

const valueFlags = new Set(['--out', '--expires', '--ip', '--ip-range']);
const switchFlags = new Set(['--dry-run', '--unsafe-arg', '--json']);

function fail(code: number, step: string, message: string, warnings: AttenuateOutput['warnings'] = []): AttenuateOutput {
  return { schema: 1, command: 'attenuate', ok: false, warnings, result: null, error: { code, step, message } };
}

function parse(args: string[]): Request | string {
  const flags = new Map<string, string | boolean>();
  const inputs: string[] = [];
  let endOfFlags = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!endOfFlags && arg === '--') { endOfFlags = true; continue; }
    if (!endOfFlags && (switchFlags.has(arg) || valueFlags.has(arg))) {
      if (flags.has(arg)) return `${arg} was given more than once`;
      if (switchFlags.has(arg)) { flags.set(arg, true); continue; }
      const value = args[++i];
      if (value === undefined || value.startsWith('--')) return `${arg} needs a value`;
      flags.set(arg, value);
      continue;
    }
    if (!endOfFlags && arg.startsWith('-') && arg !== '-') return `unknown flag; attenuate takes: <file|-> ${[...valueFlags, ...switchFlags].join(' ')}`;
    inputs.push(arg);
  }
  const get = (flag: string) => { const value = flags.get(flag); return typeof value === 'string' ? value : undefined; };
  if (inputs.length !== 1) return 'give exactly one input: a macaroon file path or - (stdin)';
  const out = get('--out');
  if (!out) return '--out is required: the path of the attenuated copy';
  const expires = get('--expires'), ip = get('--ip'), ipRange = get('--ip-range');
  if (expires === undefined && ip === undefined && ipRange === undefined)
    return 'give at least one caveat: --expires, --ip or --ip-range';
  if (ip !== undefined && ipRange !== undefined) return '--ip and --ip-range are mutually exclusive';
  if (expires !== undefined && !/^[1-9][0-9]{0,4}[mhd]$/.test(expires)) return '--expires must be 1 to 99999 followed by m (minutes), h (hours) or d (days), for example 90d';
  return { input: inputs[0], out, expires, ip, ipRange, dryRun: flags.get('--dry-run') === true,
    unsafeArg: flags.get('--unsafe-arg') === true };
}

function dated(caveat: Caveat, now: Date): Caveat {
  if (caveat.type !== 'time-before') return { ...caveat };
  const instant = parseTimeBefore(caveat.value);
  return instant === undefined ? { ...caveat }
    : { ...caveat, expired: BigInt(now.getTime()) * 1_000_000n >= instant };
}

function byteSort(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}

function result(parent: MacaroonFacts, child: MacaroonFacts, added: string[], out: string | null,
  dryRun: boolean, now: Date): AttenuateResult {
  const assessed = gradeFacts(child);
  return {
    dryRun,
    out,
    parentFingerprint: parent.fingerprint,
    fingerprint: child.fingerprint,
    location: child.location,
    rootKeyId: child.rootKeyId.toString(),
    permissions: [...child.permissions],
    caveats: child.caveats.map(caveat => dated(caveat, now)),
    added: [...added],
    grade: assessed.grade,
    reasons: [...assessed.reasons],
    warnings: byteSort([...assessed.warnings, ...describe(child)]),
    unassessed: [...assessed.unassessed],
    snapshot: '0.21.4-beta',
  };
}

const caveatText = (caveats: Caveat[]) => caveats.map(({ type, value }) => `${type} ${value}`);

async function runSteps(args: string[], deps: Deps, state: CleanupState): Promise<AttenuateOutput> {
  // A1: request and caveat values are fully validated before any file is touched.
  const request = parse(args);
  if (typeof request === 'string') return fail(2, 'A1', request);
  if (unsafeNodeDiagnostics(deps.env)) return fail(2, 'A2', 'unsafe Node diagnostic settings');
  const conditions: string[] = [];
  try { if (request.expires) conditions.push(timeBeforeCondition(request.expires, deps.clock)); }
  catch { return fail(2, 'A1', 'invalid expiry duration'); }
  if (request.ip !== undefined) {
    const value = canonicalIp(request.ip);
    if (!value) return fail(2, 'A1', 'invalid --ip address (IPv4 or IPv6, no zone, no IPv4-mapped form)');
    conditions.push(`ipaddr ${value}`);
  }
  if (request.ipRange !== undefined) {
    const value = canonicalCidr(request.ipRange);
    if (!value) return fail(2, 'A1', 'invalid --ip-range CIDR');
    conditions.push(`iprange ${value}`);
  }

  // A3: the output must be a new, unprotected path that is not the (default) registry or one of
  // its files, as in bake B4. Each check is abandoned on an interrupt: exit 6, step cancelled.
  if (isProtectedPath(request.out)) return fail(3, 'A3', 'protected output path');
  const outName = outputNameProblem(request.out);
  if (outName) return fail(3, 'A3', `output path refused: ${outName}`);
  const checks = interruptibleChecks(deps.fs);
  let outPath: string;
  try { outPath = await resolveUnprotectedPath(request.out, checks); }
  catch (error) { rethrowCancelled(error); return fail(3, 'A3', 'cannot check output path'); }
  const registryFile = await registryPath(undefined, checks, deps.env);
  if (registryFile !== null && namesRegistryFile(outPath, registryFile)) return fail(3, 'A3', REGISTRY_OUT_REFUSAL);
  try { await checks.lstat(request.out); return fail(3, 'A3', 'output file already exists'); }
  catch (error) { rethrowCancelled(error); if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return fail(3, 'A3', 'cannot check output path'); }

  // A4: read and fully decode the input; nothing is attenuated otherwise.
  const warnings: AttenuateOutput['warnings'] = [];
  let parent: MacaroonFacts;
  let parentSecret: Secret;
  try {
    const read = await readCredential(request.input, deps, { unsafeArg: request.unsafeArg });
    if (read.literal) warnings.push('unsafe-arg');
    parentSecret = read.secret;
    parent = decodeMacaroon(parentSecret);
  } catch (error) {
    if (error instanceof UsageError) return fail(2, 'A4', error.message, warnings);
    if (error instanceof InputError || error instanceof DecodeError) return fail(3, error.stage, error.message, warnings);
    throw error;
  }

  // A5: append first-party caveats (HMAC chain) and prove the child is the input plus exactly those caveats.
  let child: Secret = parentSecret;
  for (const condition of conditions) child = addFirstPartyCaveat(child, condition);
  const childFacts = decodeMacaroon(child);
  if (childFacts.rootKeyId !== parent.rootKeyId || childFacts.location !== parent.location
    || JSON.stringify(childFacts.permissions) !== JSON.stringify(parent.permissions)
    || JSON.stringify(caveatText(childFacts.caveats)) !== JSON.stringify([...caveatText(parent.caveats), ...conditions]))
    return fail(8, 'internal', 'attenuated macaroon does not equal the input plus the requested caveats', warnings);

  // LND tracks only the root key ID, so the copy and its input are one revocation unit.
  warnings.push({ code: 'shared-root-key', message: `the attenuated copy shares root key ID ${parent.rootKeyId.toString()}; ` +
    'revoking that ID revokes both, and the registry does not track the copy separately' });
  if (request.ip !== undefined || request.ipRange !== undefined)
    warnings.push({ code: 'ip-caveat-rest-proxy', message: 'LND checks the peer address it sees: REST clients appear as the REST proxy, Tor clients as the local Tor daemon, and clients behind Lightning Terminal, LNC or a reverse proxy as that proxy, so IP caveats can reject them' });
  if (request.expires)
    warnings.push({ code: 'expiry-clock', message: "the expiry is computed from this machine's clock and checked against the node's clock; clock skew between them shortens or lengthens the validity" });
  if (request.expires) {
    const added = parseTimeBefore(conditions[0].slice('time-before '.length))!;
    if (parent.caveats.some(caveat => caveat.type === 'time-before'
      && (parseTimeBefore(caveat.value) ?? added) < added))
      warnings.push({ code: 'earlier-expiry-kept', message: 'the input already expires earlier; caveats only narrow, so the earlier expiry still applies' });
  }
  if ((request.ip !== undefined || request.ipRange !== undefined)
    && parent.caveats.some(caveat => caveat.type === 'ipaddr' || caveat.type === 'iprange'))
    warnings.push({ code: 'existing-ip-caveat', message: 'the input already has an IP caveat; LND requires every IP caveat to match' });

  const now = deps.clock();
  if (request.dryRun) return { schema: 1, command: 'attenuate', ok: true, warnings,
    result: result(parent, childFacts, conditions, null, true, now), error: null };

  // A6: exclusive owner-only create, shared with bake and rotate; never overwrites.
  let reservation: ReservedOut | undefined;
  try {
    try {
      const reserved = await interruptibleReserve(() => reserveOut(outPath, deps.fs));
      reservation = reserved.reservation;
      if (reserved.aclWarning) warnings.push('acl-best-effort');
    } catch (error) {
      if (error instanceof Cancelled) return fail(6, 'cancelled', OUT_CREATION_INTERRUPTED, warnings);
      return fail(3, 'A6', reserveFailure(error, 'cannot create output file'), warnings);
    }
    checkCancellation();
    try { await reservation.write(child); }
    catch { return fail(3, 'A6', 'cannot write, flush or close the output file', warnings); }
    return { schema: 1, command: 'attenuate', ok: true, warnings,
      result: result(parent, childFacts, conditions, resolve(outPath), false, now), error: null };
  } finally {
    if (reservation) await cleanup(state, 'unwritten output discard', () => reservation!.discard());
  }
}

export async function run(args: string[], deps: Deps): Promise<AttenuateOutput> {
  const state: CleanupState = { cleanupFailures: [], mutationSent: false };
  try { return cleanupOutcome(await runSteps(args, deps, state), state); }
  catch (error) {
    return cleanupOutcome(error instanceof Cancelled ? fail(6, 'cancelled', 'interrupted; no output file was written')
      : fail(8, 'internal', 'unexpected failure'), state);
  }
}

export async function attenuate(args: string[]): Promise<OutputResult> {
  return run(args, { stdin: process.stdin, fs: nodeFs, env: { ...process.env }, clock: () => new Date() });
}
