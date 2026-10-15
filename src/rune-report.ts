// The sanitised facts macwarden reports for a Core Lightning rune (1.2.0), shared by inspect and
// scan. They never include the authenticator or Core Lightning's decoded string (which starts
// with it). Restriction text comes from the credential and may hold secrets (an invoice, a
// preimage, another credential), so every reported field and value is shown as UTF-8 (invalid
// bytes as \xNN), has long opaque tokens and recognised credentials replaced by [redacted],
// and is cut to a bounded length; only so many alternatives are listed.
import type { RuneCondition, RuneFacts, RuneInvalidReason } from './decode/rune.js';
import type { Grade } from './grade/index.js';
import { assessRune, RUNE_METHOD_TABLE, type RuneConditionKind, type RuneExpiry, type RuneWarning } from './grade/rune.js';
import { redactDecoded } from './scan/redact.js';

/** Code points of a field or value shown; the rest is replaced by "…[+N]". */
export const RUNE_SHOWN_LENGTH = 128;
/** Alternatives listed per rune; the rest are counted in omittedAlternatives. */
export const RUNE_SHOWN_ALTERNATIVES = 64;
/** Unreviewed method names listed per rune. */
export const RUNE_SHOWN_METHODS = 32;

export type RuneReport = {
  recognition: 'rune-syntax';
  /** The method table the assessment used: the Core Lightning release it is pinned to. */
  methodTable: string;
  uniqueId: string | null;
  version: string | null;
  restrictions: { field: string; condition: RuneCondition; value: string }[][];
  omittedAlternatives: number;
  methods: 'listed' | 'broad' | 'none';
  allowedMethods: string[];
  capabilities: Grade[];
  sensitiveMethods: string[];
  conditions: RuneConditionKind[];
  expiry: RuneExpiry;
  /** Authenticity, issuing node, blacklist and rate-limit state are never checked offline. */
  verification: 'unchecked';
  warnings: (RuneWarning | 'possibly-truncated')[];
};
/** Why a value in rune context is not reported as a rune: the decoder's reason, or (scan) a parsed rune that
 * checkrune refuses because it has no numeric unique ID. */
export type RuneInvalidReportReason = RuneInvalidReason | 'no-unique-id' | 'unique-id-not-numeric';
export type RuneInvalidReport = { recognition: 'invalid'; reason: RuneInvalidReportReason; verification: 'unchecked' };
export type RuneAssessed = { grade: Grade; reasons: string[]; unassessed: string[]; report: RuneReport };

const fatal = new TextDecoder('utf-8', { fatal: true });
// Long runs of base64, base64url or hex characters are opaque tokens, also when '.', ':' or '~'
// split them into shorter runs (a JWT, or a credential cut into pieces that would otherwise be
// shown one by one): a token is redacted when its runs hold 40 or more characters together. A
// compressed public key (a node ID) is shown, since `id` restrictions name one and it is public.
const TOKEN = /[A-Za-z0-9+/_=-]+(?:[.:~][A-Za-z0-9+/_=-]+)*/g;
const TOKEN_LENGTH = 40;
const NODE_ID = /^0[23][0-9a-fA-F]{64}$/;

/** A byte string from the credential, made safe and bounded for output. */
export function shownRuneText(bytes: string): string {
  const raw = Buffer.from(bytes, 'latin1');
  let text: string;
  try { text = fatal.decode(raw); }
  catch { text = [...raw].map(byte => byte < 0x80 ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, '0')}`).join(''); }
  // Recognised credentials first: replacing long tokens first would cut an encoded macaroon
  // (hex groups, wrapped base64) into pieces no longer recognised, and its short tail would
  // be shown (audit 1.3.2).
  text = redactDecoded(text).replace(TOKEN, token => NODE_ID.test(token) || token.replace(/[.:~]/g, '').length < TOKEN_LENGTH ? token : '[redacted]');
  const points = Array.from(text);
  return points.length <= RUNE_SHOWN_LENGTH ? text
    : `${points.slice(0, RUNE_SHOWN_LENGTH).join('')}…[+${points.length - RUNE_SHOWN_LENGTH}]`;
}

/**
 * Assessment and report for decoded facts. `possiblyTruncated` (a scan candidate whose value may
 * continue past what was read) keeps the grade at UNASSESSED unless it is ADMIN: a cut rune has
 * lost restrictions, so its policy can only look wider, but a cut value can name another method.
 */
export function runeReport(facts: RuneFacts, now: bigint, possiblyTruncated = false): RuneAssessed {
  const assessment = assessRune(facts, now);
  let shown = 0;
  let omitted = 0;
  const restrictions: RuneReport['restrictions'] = [];
  for (const restriction of facts.restrictions) {
    const kept: RuneReport['restrictions'][number] = [];
    for (const alternative of restriction) {
      if (shown >= RUNE_SHOWN_ALTERNATIVES) { omitted++; continue; }
      shown++;
      kept.push({ field: shownRuneText(alternative.field), condition: alternative.condition, value: shownRuneText(alternative.value) });
    }
    if (kept.length) restrictions.push(kept);
  }
  const warnings: RuneReport['warnings'] = [...assessment.warnings];
  let { grade, reasons } = assessment;
  if (possiblyTruncated) {
    warnings.push('possibly-truncated');
    warnings.sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
    if (grade !== 'ADMIN') { grade = 'UNASSESSED'; reasons = []; }
  }
  const unassessed = [...new Set(assessment.unreviewedMethods.slice(0, RUNE_SHOWN_METHODS).map(shownRuneText))];
  return { grade, reasons, unassessed, report: {
    recognition: 'rune-syntax', methodTable: RUNE_METHOD_TABLE,
    uniqueId: facts.uniqueId === null ? null : shownRuneText(facts.uniqueId),
    version: facts.version === null ? null : shownRuneText(facts.version),
    restrictions, omittedAlternatives: omitted,
    methods: assessment.methods, allowedMethods: assessment.allowedMethods, capabilities: assessment.capabilities,
    sensitiveMethods: assessment.sensitiveMethods, conditions: assessment.conditions, expiry: assessment.expiry,
    verification: 'unchecked', warnings,
  } };
}
