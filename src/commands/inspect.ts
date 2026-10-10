import * as fs from 'node:fs/promises';
import { unsafeNodeDiagnostics } from '../environment.js';
import type { Readable } from 'node:stream';
import { decodeL402, decodeMacaroon, decodeNwc, decodeRune, isL402Container, isL402Macaroon, isNwcContainer, isRuneContainer,
  DecodeError, parseTimeBefore, type Caveat, type L402Facts, type MacaroonFacts } from '../decode/index.js';
import { assessL402 } from '../l402.js';
import { unixSeconds } from '../grade/rune.js';
import { runeReport } from '../rune-report.js';
import type { Secret } from '../secret.js';
import { gradeFacts, describe } from '../grade/index.js';
import { readCredential, InputError, UsageError, type InputIO } from '../input/index.js';
import type { InspectResult, L402InspectResult, NwcInspectResult, OutputResult, RuneInspectResult } from '../output/index.js';

export type Deps = { stdin: Readable & { isTTY?: boolean }; fs: InputIO['fs']; clock: () => Date; env?: Record<string, string | undefined> };

function fail(code: number, step: string | null, message: string, warnings: string[] = []): OutputResult {
  return { command: 'inspect', ok: false, warnings, result: null, error: { code, step, message } };
}

function byteSort(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}

function expiration(value: string, now: Date): boolean | undefined {
  const instant = parseTimeBefore(value);
  if (instant === undefined) return undefined;
  return BigInt(now.getTime()) * 1_000_000n >= instant;
}

function datedCaveat(caveat: Caveat, now: Date): Caveat {
  if (caveat.type !== 'time-before') return caveat;
  const expired = expiration(caveat.value, now);
  return expired === undefined ? caveat : { ...caveat, expired };
}

/** The offline facts inspect reports for one macaroon; verify reports the same. */
export function inspectResult(facts: MacaroonFacts, now: Date): InspectResult {
  const assessed = gradeFacts(facts);
  return {
    fingerprint: facts.fingerprint,
    location: facts.location,
    rootKeyId: facts.rootKeyId.toString(),
    permissions: facts.permissions,
    caveats: facts.caveats.map(caveat => datedCaveat(caveat, now)),
    grade: assessed.grade,
    reasons: assessed.reasons,
    warnings: byteSort([...assessed.warnings, ...describe(facts)]),
    unassessed: assessed.unassessed,
    snapshot: '0.21.4-beta',
  };
}

/** The offline facts inspect reports for one L402 credential; scan reports the same per finding. */
export function l402InspectResult(facts: L402Facts, now: Date): L402InspectResult {
  return { kind: 'l402', fingerprint: facts.fingerprint, ...assessL402(facts, now) };
}

function macaroonResult(secret: Secret, now: Date): InspectResult | L402InspectResult {
  if (isL402Container(secret) || isL402Macaroon(secret)) {
    const decoded = decodeL402(secret);
    if ('l402' in decoded) return l402InspectResult(decoded.l402, now);
    return inspectResult(decodeMacaroon(decoded.lnd), now);
  }
  return inspectResult(decodeMacaroon(secret), now);
}

export async function run(args: string[], deps: Deps): Promise<OutputResult> {
  // ENV check (1.2.1): a heap snapshot or profile taken through NODE_OPTIONS would hold every credential decoded here.
  if (deps.env && unsafeNodeDiagnostics(deps.env)) return fail(2, null, 'unsafe Node diagnostic settings');
  let unsafeArg = false;
  let endOfFlags = false;
  const inputs: string[] = [];
  for (const arg of args) {
    if (!endOfFlags && arg === '--json') continue;
    if (!endOfFlags && arg === '--') { endOfFlags = true; continue; }
    if (!endOfFlags && arg === '--unsafe-arg') { unsafeArg = true; continue; }
    if (!endOfFlags && arg.startsWith('-') && arg !== '-') return fail(2, null, 'unknown flag');
    inputs.push(arg);
  }
  if (inputs.length !== 1) return fail(2, null, 'expected one input');

  const warnings: string[] = [];
  try {
    const { secret, literal } = await readCredential(inputs[0], deps, { unsafeArg, nwc: true, l402: true, rune: true });
    if (literal) warnings.push('unsafe-arg');
    if (isNwcContainer(secret)) {
      const nwc = decodeNwc(secret);
      const result: NwcInspectResult = {
        kind: 'nwc',
        fingerprint: nwc.fingerprint,
        walletPubkey: nwc.walletPubkey,
        clientPubkey: nwc.clientPubkey,
        relays: nwc.relays,
        lud16: nwc.lud16,
        grade: 'SPEND',
        reasons: ['nwc-wallet-side-limits'],
        warnings: nwc.relayDetailsRemoved ? ['relay-details-removed'] : [],
      };
      return { command: 'inspect', ok: true, warnings, result, error: null };
    }
    // The containers readCredential produces are disjoint (docs/spec.md, inspect input
    // precedence): rune text never holds the ':' or blank of NWC and L402 text, and a binary
    // macaroon or token store file is never rune text.
    if (isRuneContainer(secret)) {
      // Recognition, assessment and verification are separate: nothing here says a node accepts it.
      const facts = decodeRune(secret);
      const assessed = runeReport(facts, unixSeconds(deps.clock()));
      const result: RuneInspectResult = { kind: 'rune', fingerprint: facts.fingerprint, grade: assessed.grade,
        reasons: assessed.reasons, unassessed: assessed.unassessed, rune: assessed.report };
      return { command: 'inspect', ok: true, warnings, result, error: null };
    }
    const result = macaroonResult(secret, deps.clock());
    return { command: 'inspect', ok: true, warnings, result, error: null };
  } catch (error) {
    if (error instanceof UsageError) return fail(2, null, error.message, warnings);
    if (error instanceof InputError) return fail(3, error.stage, error.message, warnings);
    if (error instanceof DecodeError) return fail(3, error.stage, error.message, warnings);
    return fail(8, 'internal', 'unexpected failure', warnings);
  }
}

export async function inspect(args: string[]): Promise<OutputResult> {
  return run(args, { stdin: process.stdin, fs, clock: () => new Date() });
}
