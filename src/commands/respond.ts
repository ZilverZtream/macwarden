import * as nodeFs from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { join, resolve } from 'node:path';
import { cancellable, cancellationSignal } from '../cancellation.js';
import { endpoint, credentialText, drift, nodeInfo, listIds, failureDetails, readBoundedFile, readOnlineCredential,
  onlineAdapter, onlineWarnings, recoveryCommand, inventoryRecoveryCommand, connectionSettings } from '../online.js';
import { createLndAdapter, type LndAdapter } from '../lnd/index.js';
import { decodeMacaroon, type MacaroonFacts } from '../decode/index.js';
import { isProtectedPath, outputNameProblem } from '../protected-path.js';
import { unsafeNodeDiagnostics } from '../environment.js';
import { canBake as mayBake, grade } from '../grade/index.js';
import { hasCustomCaveat, openRegistry, replacementLinkProblems, type RegistryEntry } from '../registry/index.js';
import type { Secret } from '../secret.js';
import { writeRotatePrompt, type OutputResult } from '../output/index.js';
import type { RespondItem, RespondProof, RespondResult } from '../command-result.js';
import { rotationDropsCaveats, run as rotate, type Deps as RotateDeps } from './rotate.js';

export type Deps = RotateDeps;
type RespondOutput = OutputResult & { schema: 1 };
type Request = { registry?: string; host: string; hostArg: string; cert: string; own: string; outDir?: string;
  finish: boolean; dryRun: boolean; yes: boolean; allowAdmin: boolean; breakLock: boolean };

const valueFlags = new Set(['--registry', '--lnd-rest', '--tls-cert', '--macaroon', '--out-dir']);
const switchFlags = new Set(['--finish', '--dry-run', '--yes', '--allow-admin', '--break-lock', '--json']);
const methods = [
  ['/lnrpc.Lightning/GetInfo', 'info:read'],
  // Snapshot drift, as on every online command, checked by respond itself (MW110-09): nested
  // rotations cannot supply it when nothing is rotated (a dry run, an empty batch).
  ['/lnrpc.Lightning/ListPermissions', 'info:read'],
  ['/lnrpc.Lightning/ListMacaroonIDs', 'macaroon:read'],
  ['/lnrpc.Lightning/CheckMacaroonPermissions', 'macaroon:read'],
] as const;

// Static operator guidance. macwarden never calls changepassword (SAFE-02).
export const ROOT_KEY_0_GUIDANCE = [
  'Root key ID 0 holds LND\'s default admin.macaroon, readonly.macaroon and invoice.macaroon, and every macaroon baked without --root_key_id. LND refuses to delete it on its own, so these credentials cannot be revoked individually.',
  "Invalidating root key ID 0 needs lncli changepassword --new_mac_root_key on the node (it needs the wallet password). It regenerates EVERY root key, not only ID 0 (LND v0.21.4 macaroons/store.go, GenerateNewRootKey). macwarden never runs it (SAFE-02).",
  "Effect: every macaroon on the node stops working at once: the default macaroons, every per-app macaroon, macwarden's own credential and any replacement respond has staged. If credentials on root key ID 0 may have leaked, regenerate the root keys first, in a maintenance window, then bake fresh per-app macaroons (docs/replacing-default-macaroons.md). Do not stage replacements with respond --out-dir before it: the regeneration would invalidate them.",
  'LND writes new default macaroon files after the change unless it runs with --stateless_init; consider --stateless_init so admin.macaroon is never stored on disk again.',
];
export const OWN_ON_ROOT_KEY_0 = 'macwarden\'s own credential is on root key ID 0: after the change it stops working too. Bake a new own macaroon from the regenerated admin.macaroon before running macwarden again.';
export const REVOKED_BUT_PRESENT_GUIDANCE = 'The registry records these root key IDs as revoked, but LND still holds them. Either an earlier revoke did not complete, or someone holding a credential that can bake (macaroon:generate) created credentials on them again. Treat them as live and revoke each: macwarden revoke <id>.';
export const BAKING_RISK_GUIDANCE = [
  'These credentials can bake new macaroons (macaroon:generate or uri:/lnrpc.Lightning/BakeMacaroon), or hold permissions macwarden could not assess. If one leaked, its holder can create credentials on any root key ID, including the replacements respond stages and macwarden\'s own ID. Revoking the old root key IDs does not remove credentials baked that way.',
  'respond --finish revokes these first; keep the time between staging and finishing short. If a credential that can bake may have leaked, regenerate all root keys instead (see the root key ID 0 guidance): only that invalidates everything an attacker could have baked.',
  'Each PROVEN result covers that credential only: its old root key ID is gone and its replacement is accepted. It does not prove that no other credential exists.',
];
export const CUSTOM_CAVEAT_NOTE = 'carries a custom caveat (a canary, or another lnd-custom caveat): not rotated, because a replacement would be an ordinary credential. If a thief may know it, revoke it (macwarden revoke <label>), bake a new canary (macwarden bake --canary) and restart macwarden watch.';
export const UNREPRODUCED_CAVEAT_NOTE = 'carries caveats a rotation does not reproduce (<types>): not rotated, because the replacement would be baked without them. Bake a new credential with macwarden bake, attenuate it with macwarden attenuate, then revoke this one (macwarden revoke <label>).';
export const UNKNOWN_GUIDANCE = 'Not in this registry. Lightning Terminal, Loop, Pool, Faraday or another operator may own these root key IDs, so macwarden never revokes them automatically. If one may have leaked, find its owner, then run macwarden revoke <id> --unregistered.';

function fail(code: number, step: string, message: string, warnings: OutputResult['warnings'] = []): RespondOutput {
  return { schema: 1, command: 'respond', ok: false, warnings, result: null, error: { code, step, message } };
}

function parse(args: string[], env: Deps['env']): Request | string {
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (switchFlags.has(arg)) {
      if (flags.has(arg)) return `repeated flag ${arg}`;
      flags.set(arg, true);
    } else if (valueFlags.has(arg)) {
      const value = args[++i];
      if (flags.has(arg)) return `repeated flag ${arg}`;
      if (!value || value.startsWith('--')) return `missing value for ${arg}`;
      flags.set(arg, value);
    } else return 'unknown argument';
  }
  const get = (flag: string) => { const value = flags.get(flag); return typeof value === 'string' ? value : undefined; };
  const finish = flags.has('--finish');
  if (finish && (flags.has('--out-dir') || flags.has('--allow-admin'))) return '--finish takes neither --out-dir nor --allow-admin';
  const { host: hostArg, cert, own, problem: mixedSource } = connectionSettings(get, env);
  if (mixedSource) return mixedSource;
  if (!hostArg) return 'missing --lnd-rest (or MACWARDEN_LND_REST)';
  if (!cert) return 'missing --tls-cert (or MACWARDEN_TLS_CERT)';
  if (!own) return 'missing --macaroon (or MACWARDEN_MACAROON)';
  if (own === '-' || credentialText(own)) return 'own macaroon must be a file path';
  const host = endpoint(hostArg);
  if (!host) return 'invalid LND REST endpoint';
  const dryRun = flags.has('--dry-run');
  const outDir = get('--out-dir');
  if (!finish && !dryRun && !outDir) return 'staging replacements needs --out-dir <directory> (or use --dry-run or --finish)';
  return { registry: get('--registry'), host, hostArg, cert, own, outDir, finish, dryRun, yes: flags.has('--yes'),
    allowAdmin: flags.has('--allow-admin'), breakLock: flags.has('--break-lock') };
}

const byId = (left: string, right: string) => { const a = BigInt(left), b = BigInt(right); return a < b ? -1 : a > b ? 1 : 0; };

/** The first entry per root key ID, as Array.find would return it; built once per registry snapshot. */
function firstById(entries: RegistryEntry[]): Map<string, RegistryEntry> {
  const byRootKeyId = new Map<string, RegistryEntry>();
  for (const entry of entries) if (!byRootKeyId.has(entry.rootKeyId)) byRootKeyId.set(entry.rootKeyId, entry);
  return byRootKeyId;
}

/**
 * Replacement relationships among one node's entries, indexed once per snapshot (as
 * replacementLinkProblems does) so classification stays linear in a mature registry (1.2.1).
 * `originals` are the active entries that are not themselves a staged replacement of another
 * active entry (isStagedReplacement, as rotate S3; RL-07); `staged` maps an original's root key
 * ID to the first active entry that replaces it; `activeLabels` counts active entries per label.
 */
function replacementIndex(mine: RegistryEntry[]) {
  const activeIds = new Set<string>();
  const staged = new Map<string, RegistryEntry>();
  const activeLabels = new Map<string, number>();
  for (const entry of mine) {
    if (entry.status !== 'active') continue;
    activeIds.add(entry.rootKeyId);
    if (entry.replaces !== null && !staged.has(entry.replaces)) staged.set(entry.replaces, entry);
    if (entry.label !== null) activeLabels.set(entry.label, (activeLabels.get(entry.label) ?? 0) + 1);
  }
  const originals = mine.filter(entry => entry.status === 'active' && !(entry.replaces !== null && activeIds.has(entry.replaces)));
  return { originals, staged, activeLabels };
}

/**
 * Generated replacement file names that differ only in case (labels Alice and alice, both valid
 * on one node) name the same file on a case-insensitive file system (Windows, default macOS),
 * where the second stage would fail on the first one's file and a rerun would fail again.
 * Labels are ASCII ([A-Za-z][A-Za-z0-9._-]*), so ASCII lower case is the file systems' folding.
 */
function caseCollision(labels: string[]): [string, string] | null {
  const seen = new Map<string, string>();
  for (const label of labels) {
    const folded = label.toLowerCase();
    const earlier = seen.get(folded);
    if (earlier !== undefined && earlier !== label) return [earlier, label];
    seen.set(folded, label);
  }
  return null;
}

function connection(request: Request): string[] {
  return [...(request.registry ? ['--registry', request.registry] : []), '--lnd-rest', request.hostArg,
    '--tls-cert', request.cert, '--macaroon', request.own, ...(request.breakLock ? ['--break-lock'] : [])];
}

const severity = [7, 8, 4, 5, 3, 6, 2];
/** One exit code for a batch: a possible LND change (7) outranks everything else. */
export function aggregateExit(codes: number[]): number {
  const failing = codes.filter(code => code !== 0);
  if (!failing.length) return 0;
  return severity.find(code => failing.includes(code)) ?? failing[0];
}

type Credential = { secret: Secret; facts: MacaroonFacts };
async function readCredential(path: string | null, deps: Deps): Promise<Credential | null> {
  if (!path || path === '-' || isProtectedPath(path)) return null;
  try {
    if (isProtectedPath(await deps.fs.realpath(path)) || !(await deps.fs.stat(path)).isFile()) return null;
    const secret = (await readOnlineCredential(path, { stdin: deps.stdin ?? process.stdin, fs: deps.fs })).secret;
    return { secret, facts: decodeMacaroon(secret) };
  } catch { return null; }
}

async function verdict(lnd: LndAdapter, credential: Credential | null, fingerprint: string | null):
  Promise<'accepted' | 'rejected' | 'error' | 'not-tested'> {
  if (!credential || credential.facts.fingerprint !== fingerprint || !credential.facts.permissions.length) return 'not-tested';
  try {
    const checked = await lnd.checkMacaroon(credential.secret, credential.facts.permissions);
    if (checked.valid === true) return 'accepted';
    return checked.reason === 'root-key-missing' || checked.reason === 'signature-mismatch' ? 'rejected' : 'error';
  } catch { return 'error'; }
}

async function runSteps(args: string[], deps: Deps): Promise<RespondOutput> {
  const request = parse(args, deps.env);
  if (typeof request === 'string') return fail(2, 'P1', request);
  if (unsafeNodeDiagnostics(deps.env)) return fail(2, 'P2', 'unsafe Node diagnostic settings');
  let cert: Buffer;
  let own: Secret;
  let ownFacts: MacaroonFacts;
  try {
    if (isProtectedPath(request.cert)) return fail(4, 'P2', 'unreadable TLS certificate');
    // The checked resolved path is the one read: the link cannot be changed between the two.
    const resolvedCert = await deps.fs.realpath(request.cert);
    if (isProtectedPath(resolvedCert)) return fail(4, 'P2', 'unreadable TLS certificate');
    cert = await readBoundedFile(resolvedCert, deps.fs);
  } catch { return fail(4, 'P2', 'unreadable TLS certificate'); }
  try { own = (await readOnlineCredential(request.own, { stdin: deps.stdin ?? process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, 'P2', 'unreadable own macaroon'); }
  try { ownFacts = decodeMacaroon(own); }
  catch { return fail(4, 'P2', 'undecodable own macaroon'); }
  const held = new Set(ownFacts.permissions);
  for (const [method, permission] of methods)
    if (!held.has(permission) && !held.has(`uri:${method}`)) return fail(4, 'P2', `own macaroon missing permission: ${permission}`);
  const warnings: OutputResult['warnings'] = ownFacts.rootKeyId === 0n ? ['own-root-key-0'] : [];

  let entries: RegistryEntry[];
  try {
    if (request.registry && isProtectedPath(request.registry)) return fail(3, 'P3', 'protected registry path');
    entries = (await openRegistry(request.registry, { fs: deps.fs, env: deps.env })).entries;
  } catch { return fail(3, 'P3', 'unreadable or invalid registry', warnings); }

  const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: request.host, tlsCert: cert, macaroon: own });
  if (!adapter) return fail(8, 'internal', 'unexpected failure', warnings);
  const lnd = onlineAdapter(adapter);
  let node: ReturnType<typeof nodeInfo>;
  let ids: bigint[];
  try {
    node = nodeInfo(await lnd.getInfo());
    if (drift(await lnd.listPermissions())) warnings.push('snapshot-drift');
    ids = await listIds(lnd);
  }
  catch (error) { const failure = failureDetails(error); return fail(failure.code, 'P4', failure.message, warnings); }

  // P5: classify every credential the registry and LND know about for this node.
  const pubkey = node.pubkey.toLowerCase();
  const mine = entries.filter(entry => entry.nodePubkey.toLowerCase() === pubkey);
  const inLnd = new Set(ids.map(id => id.toString()));
  const ownId = ownFacts.rootKeyId.toString();
  // A staged replacement is believable only if macwarden could have written it; anything else
  // is tampering and is reported instead of trusted (it could hide a credential from the batch).
  // A chain or cycle of links would otherwise make originals() drop live credentials.
  const tampered = replacementLinkProblems(mine)[0];
  const index = replacementIndex(mine);
  if (tampered) return fail(3, 'P5', `registry tampering: root key ID ${tampered.rootKeyId} claims to replace ${tampered.replaces}, but ${tampered.problem}; restore the registry from a trusted copy`, warnings);
  // Whether a credential is a canary is decided by its file, not by the editable registry caveat list:
  // a custom caveat the registry does not record would let the batch rotate a canary into an
  // ordinary credential. Refused before any mutation, like a forged replacement link.
  // An entry whose caveats a stage would not reproduce (an IP lock, recorded or in the file;
  // rotate S5, 1.3.1) is skipped with a note that names them, never failing the batch for it.
  const dropped = new Map<string, string[]>();
  for (const entry of index.originals) {
    if (hasCustomCaveat(entry)) continue;
    const file = await readCredential(entry.outPath, deps);
    const facts = file && file.facts.fingerprint === entry.fingerprint ? file.facts : undefined;
    if (facts?.caveats.some(caveat => caveat.type === 'lnd-custom'))
      return fail(3, 'P5', `registry tampering: root key ID ${entry.rootKeyId}: its credential file carries a custom caveat ` +
        '(a canary, or another lnd-custom caveat) that the registry does not record; restore the registry from a trusted copy', warnings);
    const types = rotationDropsCaveats(entry, facts);
    if (types.length) dropped.set(entry.rootKeyId, types);
  }
  // Only active entries cover an ID LND holds; a revoked entry for a present ID needs action.
  const active = new Set(mine.filter(entry => entry.status === 'active').map(entry => entry.rootKeyId));
  const revokedIds = new Set(mine.filter(entry => entry.status === 'revoked').map(entry => entry.rootKeyId));
  // Baking authority, not the ADMIN grade (MW110-06): macaroon:generate or the BakeMacaroon URI. The
  // recorded grade is editable, so the permissions are also assessed here; anything unassessed may bake.
  const canBake = (entry: RegistryEntry) => {
    const assessed = grade(entry.permissions);
    return mayBake(entry.permissions, entry.grade === 'UNASSESSED' ? 'UNASSESSED' : assessed.grade, assessed.warnings);
  };
  // revoke resolves a label among this node's active entries; where that is ambiguous, advice names the ID.
  const target = (entry: RegistryEntry) => entry.label !== null
    && index.activeLabels.get(entry.label) === 1 ? entry.label : entry.rootKeyId;
  const items: RespondItem[] = [];
  for (const entry of [...index.originals].sort((a, b) => byId(a.rootKeyId, b.rootKeyId))) {
    const staged = index.staged.get(entry.rootKeyId);
    const base = { label: entry.label, rootKeyId: entry.rootKeyId, grade: entry.grade,
      replacementRootKeyId: staged?.rootKeyId ?? null, replacementFingerprint: staged?.fingerprint ?? null,
      outPath: staged?.outPath ?? null, error: null, proof: null };
    if (entry.rootKeyId === '0' || entry.rootKeyId === ownId || entry.label === null)
      items.push({ ...base, action: 'manual', status: 'manual', note: entry.rootKeyId === ownId
        ? 'macwarden\'s own credential: bake a new own macaroon, switch MACWARDEN_MACAROON to it, then revoke this ID'
        : entry.rootKeyId === '0' ? 'root key ID 0: see the root key ID 0 guidance' : 'no label: revoke it by root key ID, then bake a replacement' });
    else if (hasCustomCaveat(entry))
      items.push({ ...base, action: 'manual', status: 'manual', note: CUSTOM_CAVEAT_NOTE.replace('<label>', target(entry)) });
    // A replacement an earlier stage allocated but never verified or wrote (an uncertain bake, a failed
    // verification or write, a failed registry update) is unresolved work, not a usable stage. It is
    // never retried: LND may hold, or still create, its root key ID.
    else if (staged && (!staged.verified || !staged.outPath || !staged.fingerprint)) {
      const listed = inLnd.has(staged.rootKeyId);
      items.push({ ...base, outPath: null, action: 'repair', status: 'failed',
        note: `replacement root key ID ${staged.rootKeyId} is incomplete: abandon it with macwarden revoke ${staged.rootKeyId}, then rerun macwarden respond --out-dir <directory>`,
        error: { code: 7, step: 'P5', message: `replacement root key ID ${staged.rootKeyId} for root key ID ${entry.rootKeyId} was allocated ` +
          'by an earlier stage that did not complete (no verified replacement file); ' +
          (listed ? 'LND lists it' : 'LND does not list it, but may still create it') + '; it is not retried automatically. ' +
          `Inspect with ${inventoryRecoveryCommand(request)}, abandon it with ${recoveryCommand(request, staged.rootKeyId)}, ` +
          'then rerun macwarden respond --out-dir <directory> to stage a new replacement; the old credential is unchanged' } });
    }
    // A staged replacement comes first even when the old ID is already absent: an earlier finish
    // deleted it and was stopped before saving the registry, and rotate F6 repairs exactly that,
    // after proving the replacement accepted.
    else if (staged) items.push({ ...base, action: 'finish', status: 'planned', note: null });
    else if (!inLnd.has(entry.rootKeyId))
      items.push({ ...base, action: 'repair', status: 'manual',
        note: `absent from LND while the registry says active: run macwarden revoke ${target(entry)} to record it` });
    // After the staged branches: a replacement staged before 1.3.1 is still finished.
    else if (dropped.has(entry.rootKeyId))
      items.push({ ...base, action: 'manual', status: 'manual',
        note: UNREPRODUCED_CAVEAT_NOTE.replace('<types>', dropped.get(entry.rootKeyId)!.join(', ')).replace('<label>', target(entry)) });
    else items.push({ ...base, action: 'stage', status: 'planned', note: null });
  }
  // Each root key ID once, even if LND lists one twice.
  const uncovered = [...inLnd].filter(id => id !== '0' && id !== ownId && !active.has(id));
  const unknown = uncovered.filter(id => !revokedIds.has(id)).sort(byId);
  const revokedButPresent = uncovered.filter(id => revokedIds.has(id)).sort(byId);
  if (revokedButPresent.length) warnings.push({ code: 'revoked-but-present',
    message: `LND still holds root key IDs the registry records as revoked: ${revokedButPresent.join(' ')}` });
  const baking = mine.filter(entry => entry.status === 'active' && entry.rootKeyId !== ownId && canBake(entry))
    .map(entry => entry.rootKeyId).sort(byId);
  if (baking.length) warnings.push({ code: 'baking-credential-in-scope',
    message: 'credentials that can bake are in scope: each proof covers its own credential only' });
  const result: RespondResult = {
    mode: request.finish ? 'finish' : 'stage', dryRun: request.dryRun,
    node: { pubkey: node.pubkey, alias: node.alias, network: node.network },
    rootKey0: { present: inLnd.has('0'), ownOnRootKey0: ownFacts.rootKeyId === 0n,
      guidance: [...ROOT_KEY_0_GUIDANCE, ...(ownFacts.rootKeyId === 0n ? [OWN_ON_ROOT_KEY_0] : [])] },
    own: { rootKeyId: ownId }, unknown: { rootKeyIds: unknown, guidance: UNKNOWN_GUIDANCE },
    revokedButPresent: { rootKeyIds: revokedButPresent, guidance: REVOKED_BUT_PRESENT_GUIDANCE },
    bakingRisk: { rootKeyIds: baking, guidance: baking.length ? BAKING_RISK_GUIDANCE : [] },
    outDir: request.outDir ? resolve(request.outDir) : null, items, unproven: [],
  };
  const incomplete = items.filter(item => item.status === 'failed');
  for (const item of incomplete) result.unproven.push({ label: item.label, rootKeyId: item.rootKeyId,
    reason: `replacement root key ID ${item.replacementRootKeyId} incomplete: revoke it by ID, then stage again` });
  const bakingIds = new Set(baking);
  const bakingFirst = (item: RespondItem) => bakingIds.has(item.rootKeyId) ? 0 : 1;
  const mineById = firstById(mine);
  const selected = items.filter(item => item.action === (request.finish ? 'finish' : 'stage'))
    .sort((a, b) => bakingFirst(a) - bakingFirst(b) || byId(a.rootKeyId, b.rootKeyId));
  for (const item of items) {
    if (!request.finish && item.action === 'finish') {
      item.status = 'staged-earlier';
      item.note = inLnd.has(item.rootKeyId) ? 'replacement staged earlier: switch the app, then run macwarden respond --finish'
        : `replacement staged earlier; old root key ID ${item.rootKeyId} is already absent from LND (an earlier finish was interrupted): run macwarden respond --finish to prove the replacement and record the revocation`;
    }
    if (request.finish && item.action === 'stage') {
      // A credential that already replaced a now-revoked one (an earlier finish, or a past
      // rotation) has nothing to finish; telling the operator to stage it would invite a
      // needless second rotation.
      const entry = mineById.get(item.rootKeyId);
      const replacedRevoked = entry?.replaces != null && revokedIds.has(entry.replaces);
      if (replacedRevoked) { item.status = 'finished-earlier'; item.note = `replaces root key ID ${entry!.replaces}, already revoked: nothing to finish`; }
      else { item.status = 'not-staged'; item.note = 'no replacement staged: run macwarden respond --out-dir <directory> first'; }
    }
  }
  const done = (exitCode: number): RespondOutput => ({ schema: 1, command: 'respond', ok: true, warnings, result,
    error: null, ...(exitCode ? { exitCode } : {}) });
  if (request.dryRun) return done(0);
  if (!selected.length) return done(incomplete.length ? 7 : 0);

  // P6: the output directory exists and is a directory; created owner-only when missing.
  if (!request.finish) {
    const outDir = resolve(request.outDir!);
    if (isProtectedPath(outDir)) return fail(3, 'P6', 'protected output directory', warnings);
    // Every replacement path is checked before anything is created, so no label can fail
    // after earlier replacements were written (a label such as CON maps to a Windows device).
    const outName = outputNameProblem(outDir)
      ?? selected.map(item => outputNameProblem(join(outDir, `${item.label}.macaroon`))).find(problem => problem !== null) ?? null;
    if (outName) return fail(3, 'P6', `output path refused: ${outName}`, warnings);
    const collision = caseCollision(selected.map(item => item.label!));
    if (collision) return fail(3, 'P6', `output path refused: labels ${collision[0]} and ${collision[1]} map to the same file ` +
      `name on a case-insensitive file system (${collision[0]}.macaroon, ${collision[1]}.macaroon); nothing was staged. ` +
      `Stage one of them on its own with macwarden rotate <label> --out <path>, then rerun this command`, warnings);
    try { await deps.fs.mkdir(outDir, { mode: 0o700 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') return fail(3, 'P6', 'cannot create output directory', warnings); }
    try { if (!(await deps.fs.stat(outDir)).isDirectory()) return fail(3, 'P6', 'output path is not a directory', warnings); }
    catch { return fail(3, 'P6', 'cannot check output directory', warnings); }
  }

  // P7: one typed confirmation for the batch (SAFE-05), unless --yes.
  if (!request.yes) {
    if (!(deps.stdin ?? process.stdin).isTTY) return fail(6, 'P7', 'confirmation requires a TTY or --yes', warnings);
    const phrase = `${request.finish ? 'finish' : 'stage'} ${selected.length}`;
    const question = `${request.finish ? 'Revoke' : 'Stage replacements for'} ${selected.length} credential(s): ` +
      `${selected.map(item => `${item.label} (root key ID ${item.rootKeyId})`).join(', ')}. Type "${phrase}" to confirm: `;
    const answer = await cancellable(() => (deps.prompt ?? (async () => null))(question));
    if (answer !== phrase) return fail(6, 'P7', 'operator declined or did not type the exact confirmation', warnings);
  }

  // P8: each credential through the rotate path, which keeps its own safety checks and lock.
  const codes: number[] = [];
  const warningCode = (warning: OutputResult['warnings'][number]) => typeof warning === 'string' ? warning : warning.code;
  for (const item of selected) {
    if (cancellationSignal()?.aborted) break;
    const args = request.finish ? [item.label!, '--finish', '--yes', ...connection(request)]
      : [item.label!, '--out', join(result.outDir!, `${item.label}.macaroon`), ...(request.allowAdmin ? ['--allow-admin'] : []), ...connection(request)];
    const outcome = await rotate(args, deps);
    // Rotate's own invocation warnings (acl-best-effort) reach the batch result once (audit 1.3.2).
    for (const warning of outcome.warnings) if (!warnings.some(seen => warningCode(seen) === warningCode(warning))) warnings.push(warning);
    if (!outcome.ok) {
      item.status = 'failed';
      item.error = { code: outcome.error.code, step: outcome.error.step, message: outcome.error.message };
      codes.push(outcome.error.code);
      if (outcome.error.step === 'cancelled') break;
      continue;
    }
    const rotated = outcome.result as { stage: string; new: RegistryEntry; evidence?: 'rejected' | 'by-id-only'; repaired?: boolean };
    item.status = request.finish ? 'finished' : 'staged';
    if (rotated.repaired) item.note = `old root key ID ${item.rootKeyId} was already absent from LND: registry repaired, no second deletion sent`;
    item.replacementRootKeyId = rotated.new.rootKeyId;
    item.replacementFingerprint = rotated.new.fingerprint;
    item.outPath = rotated.new.outPath;
    if (rotated.evidence) item.proof = { evidence: rotated.evidence } as RespondProof;
    codes.push(0);
  }
  const interrupted = cancellationSignal()?.aborted === true;
  if (interrupted) warnings.push({ code: 'interrupted', message: 'interrupted: credentials marked not-run were not changed; rerun the same command to continue' });
  for (const item of selected) if (item.status === 'planned') { item.status = 'not-run'; item.note = 'interrupted before this credential: rerun the same command to continue'; }

  // P9: independent proof after every finish: the old ID is gone and the replacement is accepted.
  if (request.finish && !interrupted) {
    const after = await listIds(lnd).then(list => new Set(list.map(id => id.toString())), () => null);
    const current = await openRegistry(request.registry, { fs: deps.fs, env: deps.env }).then(view => view.entries).catch(() => mine);
    const currentById = firstById(current.filter(entry => entry.nodePubkey.toLowerCase() === pubkey));
    for (const item of selected.filter(entry => entry.status === 'finished')) {
      const old = currentById.get(item.rootKeyId);
      const next = item.replacementRootKeyId === null ? undefined : currentById.get(item.replacementRootKeyId);
      const oldCredential = await verdict(lnd, await readCredential(old?.outPath ?? null, deps), old?.fingerprint ?? null);
      const newCredential = await verdict(lnd, await readCredential(next?.outPath ?? null, deps), next?.fingerprint ?? null);
      const oldAbsent = after === null ? null : !after.has(item.rootKeyId);
      const proof: RespondProof = { evidence: item.proof?.evidence ?? 'by-id-only', oldRootKeyIdAbsent: oldAbsent,
        oldCredential, newCredential,
        proven: oldAbsent === true && newCredential === 'accepted' && oldCredential !== 'accepted' && oldCredential !== 'error',
        strength: oldCredential === 'rejected' ? 'credential-rejected' : 'root-key-id-absent', scope: 'this-credential' };
      item.proof = proof;
      if (!proof.proven) result.unproven.push({ label: item.label, rootKeyId: item.rootKeyId,
        reason: oldAbsent !== true ? 'old root key ID still listed or LND unreachable'
          : newCredential !== 'accepted' ? `replacement credential ${newCredential}` : `old credential ${oldCredential}` });
    }
  }
  for (const item of selected) if (item.status === 'failed') result.unproven.push({ label: item.label, rootKeyId: item.rootKeyId,
    reason: `failed at ${item.error!.step ?? 'usage'} (exit ${item.error!.code})` });
  // A finished credential whose result could not be proven (old ID still listed, LND
  // unreadable after the deletions, replacement not accepted) is a possible LND change
  // that was not confirmed: exit 7, like any mutation whose outcome is unknown.
  const unprovenFinish = selected.some(item => item.status === 'finished' && item.proof !== null && item.proof.proven === false);
  // An interrupt after any staged or finished credential means LND changed (7); before any, nothing changed (6).
  const code = interrupted ? (codes.some(value => value === 0 || value === 7) || incomplete.length ? 7 : 6)
    : aggregateExit([...codes, ...(unprovenFinish || incomplete.length ? [7] : [])]);
  return done(code);
}

export async function run(args: string[], deps: Deps): Promise<RespondOutput> {
  return onlineWarnings(await runSteps(args, deps));
}

export async function respond(args: string[]): Promise<OutputResult> {
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
