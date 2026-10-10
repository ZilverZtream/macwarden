import { describe, expect, it } from 'vitest';
import { run } from '../src/commands/reconcile.js';
import { LndError } from '../src/errors.js';
import { render } from '../src/output/index.js';
import { Secret } from '../src/secret.js';
import { JOURNAL_LIMIT_BYTES, JOURNAL_RESERVE_BYTES, JOURNAL_START_ROOM_BYTES, PaymentJournal, journalCoverage, parseRecord,
  readJournal } from '../src/watch/payment-journal.js';
import { deletionFacts, paymentFacts } from '../src/watch/payment-request.js';
import { factsCampaign, journalCampaign, reconcileCampaign } from '../scripts/payment-fuzz.mjs';

// Seeded property fuzz of the payment side (CI profile): what watch reads from an intercepted
// payment request, the payment journal writer and reader, and reconcile against a fake LND. The
// same properties run for as long as wanted with `npm run fuzz:payments` (--target, --seed,
// --cases, --jobs); scripts/payment-fuzz.mjs documents them. Failures that a known open defect
// explains (KNOWN_DEFECTS there, each with its reproduction in the campaign report) are counted
// apart; any other failure fails this test.

const SEED = 20261010;
const api = { paymentFacts, deletionFacts, parseRecord, readJournal, journalCoverage, PaymentJournal, JOURNAL_LIMIT_BYTES, JOURNAL_RESERVE_BYTES,
  JOURNAL_START_ROOM_BYTES, Secret, run, render, LndError };
const scratchRoot = process.env.MACWARDEN_TEST_TMP;
type Failure = { known?: string };
const fresh = (failures: Failure[]) => failures.filter(failure => !failure.known);

describe('PAYFUZZ/seeded payment fuzz', () => {
  it(`PAYFUZZ/facts 6000 seeded requests (seed ${SEED}): never throw, documented forms, no secret, the specified facts`, () => {
    const { stats, timing, failures } = factsCampaign(api, { seed: SEED, cases: 6_000, maxFailures: 20 });
    expect(fresh(failures)).toEqual([]);
    // Every kind of request and every extraction outcome is reached, and a fair share is checked against the specification.
    expect(stats.expected).toBeGreaterThan(2_000);
    expect(stats.mutated).toBeGreaterThan(1_500);
    expect(stats.capped).toBeGreaterThan(20);
    for (const extraction of ['complete', 'no-hash', 'amp', 'payload-too-large', 'malformed', 'invoice-invalid', 'invoice-too-long'])
      expect(stats.byExtraction[extraction], extraction).toBeGreaterThan(0);
    expect(timing.maxMs).toBeLessThan(100);
  }, 60_000);

  it(`PAYFUZZ/journal 8 seeded writer runs (seed ${SEED}): readable file, exact accounting, ordered times, consistent coverage, crash repair`, async () => {
    // Case 3 fills a pre-filled file to the size limit; case 5 is cut at a random byte and repaired by a second run.
    const { stats, failures } = await journalCampaign(api, { seed: SEED, cases: 8, scratchRoot, maxFailures: 20 });
    expect(fresh(failures)).toEqual([]);
    expect(stats.fills).toBe(1);
    expect(stats.truncated).toBeGreaterThan(0);
    expect(stats.records).toBeGreaterThan(100);
  }, 60_000);

  it(`PAYFUZZ/reconcile 400 seeded journals against a fake LND (seed ${SEED}): schema, exit codes, attribution invariants`, async () => {
    const { stats, failures } = await reconcileCampaign(api, { seed: SEED, cases: 400, scratchRoot, maxFailures: 20 });
    expect(fresh(failures)).toEqual([]);
    expect(stats.schemaChecked).toBe(400);
    for (const exit of ['0', '1', '2']) expect(stats.exits[exit], `exit ${exit}`).toBeGreaterThan(0);
    expect(stats.ambiguous).toBeGreaterThan(0);
    expect(stats.historical).toBeGreaterThan(0);
    expect(stats.single).toBeGreaterThan(0);
  }, 60_000);
});
