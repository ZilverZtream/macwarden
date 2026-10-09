import { describe, expect, it } from 'vitest';
import { decodeRuneText, RUNE_ALTERNATIVE_LIMIT, RUNE_RESTRICTION_LIMIT, RUNE_TEXT_LIMIT } from '../src/decode/rune.js';
import { CLN_METHODS } from '../src/grade/cln-methods.js';
import { assessRune, methodMayPass } from '../src/grade/rune.js';
import { runeReport } from '../src/rune-report.js';
import { redactRuneContexts } from '../src/scan/rune-context.js';
import { runeFindings } from '../src/scan/runes.js';
import { growth, LINEAR_4X } from './helpers/growth.js';
import { rune } from './support/runes.js';
import { runCampaign } from '../scripts/rune-fuzz-core.mjs';

// Seeded property fuzz of rune decoding, assessment and scan context (CI profile). The same
// properties run for as long as wanted with `npm run fuzz:runes` (RUNE_FUZZ_CASES, RUNE_FUZZ_SEED).
// scripts/rune-fuzz-core.mjs holds the generators and two models written from Core Lightning
// v26.06.8: a reference decoder (ccan base64 and rune coding) and checkrune's per-request check.
// Properties: decode(encode(random restrictions)) round-trips exactly; a mutated text is refused
// or decoded exactly as the reference decodes it, never partially and never with an exception;
// adding a restriction never adds a capability and adding an alternative never removes one;
// contradictions match no method; expiry is claimed only when every request after the deadline
// fails; whatever a concrete request passes, the assessment allows; truncated and over-limit
// values in scan context are never graded below UNASSESSED.

const SEED = 20261009;
const CASES = 4000;
const api = { decodeRuneText, RUNE_TEXT_LIMIT, RUNE_RESTRICTION_LIMIT, RUNE_ALTERNATIVE_LIMIT, assessRune, methodMayPass,
  CLN_METHODS, runeReport, runeFindings };

describe('RUNE/fuzz properties', () => {
  it(`RUNE/fuzz ${CASES} seeded cases (seed ${SEED}) hold every property`, () => {
    const { stats, failures } = runCampaign(api, { seed: SEED, cases: CASES });
    expect(failures).toEqual([]);
    // The profile exercises every kind of case, and enough of each to mean something.
    expect(stats.roundTrip).toBeGreaterThan(CASES / 10);
    expect(stats.mutationsAccepted).toBeGreaterThan(CASES / 50);
    expect(stats.mutationsRefused).toBeGreaterThan(CASES / 50);
    expect(stats.requestsPassed).toBeGreaterThan(CASES / 4);
    expect(stats.overBounds).toBeGreaterThan(0);
    for (const reason of ['not-base64url', 'too-short', 'nul-byte', 'restriction-syntax', 'unique-id-placement', 'exceeds-bounds'])
      expect(stats.reasons[reason], reason).toBeGreaterThan(0);
  }, 60_000);
});

describe('RUNE/fuzz work grows linearly (n against 4n, compared in-process)', () => {
  const at = (restrictions: string) => rune(restrictions, Buffer.alloc(32, 9), 'latin1');
  const repeat = (times: number, work: () => unknown) => () => { for (let i = 0; i < times; i++) work(); };
  // Each input is checked to be decoded (or refused) as intended, so no size is cut short by a bound.
  const decodes = (text: string, expected: true | string) => {
    const result = decodeRuneText(text);
    expect(result.ok ? true : result.reason, `${text.length} characters`).toBe(expected);
    return text;
  };

  it('RUNE/fuzz decoding a value made of escapes', async () => {
    const result = await growth(size => { const text = decodes(at(`=1&f=${String.raw`\&\|\\`.repeat(size)}`), true); return repeat(2000, () => decodeRuneText(text)); }, 250, 4);
    expect(result.ratio, result.summary).toBeLessThan(LINEAR_4X);
  });

  it('RUNE/fuzz decoding many alternatives, and a text refused at its last character', async () => {
    const alternatives = await growth(size => { const text = decodes(at(`=1&${'a!|'.repeat(size)}a!`), true); return repeat(500, () => decodeRuneText(text)); }, 240, 4);
    expect(alternatives.ratio, alternatives.summary).toBeLessThan(LINEAR_4X);
    const refused = await growth(size => { const text = decodes(`${at(`=1&f=${'x'.repeat(size * 3)}`).replace(/=+$/, '')}+`, 'not-base64url'); return repeat(2000, () => decodeRuneText(text)); }, 500, 4);
    expect(refused.ratio, refused.summary).toBeLessThan(LINEAR_4X);
  });

  it('RUNE/fuzz assessing many restrictions and alternatives', async () => {
    const facts = (text: string) => { const decoded = decodeRuneText(text); if (!decoded.ok) throw new Error(decoded.reason); return decoded.facts; };
    const restrictions = await growth(size => { const f = facts(at(`=1${'&method^list|pnamex<5'.repeat(size)}`)); return repeat(20, () => assessRune(f, 1n)); }, 60, 4);
    expect(restrictions.ratio, restrictions.summary).toBeLessThan(LINEAR_4X);
    const alternatives = await growth(size => { const f = facts(at(`=1&${'time<5|'.repeat(size)}method=pay`)); return repeat(20, () => assessRune(f, 1n)); }, 200, 4);
    expect(alternatives.ratio, alternatives.summary).toBeLessThan(LINEAR_4X);
  });

  it('RUNE/fuzz scanning and redacting lines full of rune contexts', async () => {
    const value = at('=1&method=getinfo');
    const context = {};
    const scanned = await growth(size => { const text = `RUNE=${value} `.repeat(size); return repeat(40, () => runeFindings(text, new Date(0), context)); }, 200, 4);
    expect(scanned.ratio, scanned.summary).toBeLessThan(LINEAR_4X);
    const redacted = await growth(size => { const text = `lightning-cli checkrune ${value} rune=${value}\n`.repeat(size); return repeat(40, () => redactRuneContexts(text)); }, 200, 4);
    expect(redacted.ratio, redacted.summary).toBeLessThan(LINEAR_4X);
    // Key names are read back from each match (options, XML elements); one long token of matches stays linear.
    const tokens = await growth(size => { const text = `--${'aRune-'.repeat(size)} <${'xRune.'.repeat(size)}> ${'--rune '.repeat(size)}`;
      return repeat(10, () => runeFindings(text, new Date(0), context)); }, 2000, 4);
    expect(tokens.ratio, tokens.summary).toBeLessThan(LINEAR_4X);
  });
});
