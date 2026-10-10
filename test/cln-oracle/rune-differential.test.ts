import { afterAll, beforeAll, expect, it } from 'vitest';
import { decodeRuneText, RUNE_ALTERNATIVE_LIMIT, RUNE_RESTRICTION_LIMIT, RUNE_TEXT_LIMIT } from '../../src/decode/rune.js';
import { CLN_METHODS } from '../../src/grade/cln-methods.js';
import { assessRune, methodMayPass } from '../../src/grade/rune.js';
import { CLN_VERSION, session, status } from '../fixture/cln-fixture.mjs';
import { runDifferential } from '../../scripts/cln-rune-differential.mjs';

// Differential comparison with the regtest Core Lightning fixture at a CI size (200 runes); the
// full campaign is scripts/cln-rune-campaign.mjs. Runes are created with random restriction sets
// (every condition, escapes, unicode, long values, many alternatives); macwarden's decoding must
// equal native decode, its acceptance of mutated texts must equal checkrune's parser, and every
// request checkrune accepts must be one macwarden reports as possible. Usage counters are
// touched only by runes without rate or per restrictions in the request phase.

const SEED = 20261009;
const RUNES = 200;
let rpc: ReturnType<typeof session>;

beforeAll(() => {
  const identity = status();
  if (!identity) throw new Error('the Core Lightning fixture is not running: npm run fixture:cln:up');
  expect(identity).toEqual({ version: CLN_VERSION, network: 'regtest' });
  rpc = session();
});

afterAll(async () => { await rpc?.close(); });

it(`RUNE/oracle differential: ${RUNES} created runes, their mutations and checkrune requests agree with macwarden (seed ${SEED})`, async () => {
  const api = { decodeRuneText, RUNE_TEXT_LIMIT, RUNE_RESTRICTION_LIMIT, RUNE_ALTERNATIVE_LIMIT, assessRune, methodMayPass, CLN_METHODS };
  const report = await runDifferential(rpc, api, { seed: SEED, runes: RUNES, pairsPerRune: 2, mutationsPerRune: 2 });
  expect(report.failures).toEqual([]);
  expect(report.created).toBe(RUNES);
  expect(report.decodeCompared).toBeGreaterThan(RUNES * 0.9);
  expect(report.mutationAccepted).toBeGreaterThan(RUNES / 10);
  expect(report.mutationRefused).toBeGreaterThan(RUNES / 10);
  expect(report.pairs).toBeGreaterThan(RUNES);
  expect(report.accepted).toBeGreaterThan(RUNES / 10);
  expect(report.otherErrors).toBe(0);
});
