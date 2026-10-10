import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { CORPUS, loadHarness, type Harness } from './helpers/payment-lab-harness.js';

/**
 * The payment lab's model-based state-machine harness (examples/payment-lab/test/harness, design brief
 * 1.3.0 item 1) in the product suite: a fixed-seed campaign of 40 cases of random interleavings of two
 * processes against the oracle of the README's rules, and the replay corpus (one replay per rule) against
 * the current lab source. No node, no Docker, no credential: the stores run on node:sqlite in a temporary
 * directory against a scripted LND. `npm run fuzz:lab` runs the same campaign with 500 cases; the README
 * section "State-machine harness" has the command that runs the corpus against the 1.2.0 sources.
 */

const SEED = 20261010;
let harness: Harness;

beforeAll(async () => { harness = await loadHarness(); });

describe('payment lab state-machine harness', () => {
  it(`40 seeded cases (seed ${SEED}) hold every predicate, and the events reach every part of both state machines`, async () => {
    const result = await harness.campaign({ seed: SEED, cases: 40, steps: 60 });
    expect(result.violations).toEqual([]);
    expect(result.events).toBe(40 * 60);
    // Every kind of event ran and did something in this campaign (a no-op is counted under "<event> (no-op)").
    for (const event of ['intent', 'submit', 'retry', 'reconcile', 'send.arrive', 'send.deliver', 'send.end', 'track.deliver', 'lnd.payment',
      'create', 'answer', 'create.arrive', 'invoice', 'settle', 'cancel', 'rreconcile', 'listen', 'sub.deliver', 'cursor-set', 'age', 'kill', 'abort']) {
      expect(result.coverage[event] ?? 0, event).toBeGreaterThan(0);
    }
    expect(Object.keys(result.configs).some(config => config.startsWith('huge')), 'amounts near 2^62').toBe(true);
  }, 120_000);

  it('the replay corpus has one replay per predicate, and none of them violates anything on the current lab source', async () => {
    for (const predicate of Object.keys(harness.PREDICATES)) {
      const file = join(CORPUS, `${predicate}.json`);
      expect(existsSync(file), file).toBe(true);
      expect(harness.readReplay(file).predicate).toBe(predicate);
    }
    const outcomes = await harness.replay({ path: CORPUS });
    expect(outcomes).toHaveLength(Object.keys(harness.PREDICATES).length);
    for (const outcome of outcomes) expect(outcome.violations.map(item => `${item.predicate}: ${item.message}`), outcome.file).toEqual([]);
  }, 60_000);
});
