import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CORPUS, RUNNER, loadHarness, type Harness } from './helpers/payment-lab-harness.js';

/**
 * The payment lab's model-based state-machine harness (examples/payment-lab/test/harness, design brief
 * 1.3.0 item 1) in the product suite: a fixed-seed campaign of 40 cases of random interleavings of two
 * processes against the oracle of the README's rules, the replay corpus (one replay per rule) against
 * the current lab source, the replay validation, and the kept mutants (each caught by its predicate's
 * replay). No node, no Docker, no credential: the stores run on node:sqlite in a temporary directory
 * against a scripted LND. `npm run fuzz:lab` runs the same campaign with 500 cases; the README section
 * "State-machine harness" has the command that runs the corpus against the 1.2.0 sources.
 */

const SEED = 20261010;
let harness: Harness;
const scratch = mkdtempSync(join(tmpdir(), 'macwarden-harness-test-'));

beforeAll(async () => { harness = await loadHarness(); });
afterAll(() => { try { rmSync(scratch, { recursive: true, force: true }); } catch { /* Windows may still hold a file; the temp directory keeps it */ } });

describe('payment lab state-machine harness', () => {
  it(`40 seeded cases (seed ${SEED}) hold every predicate, and the events reach every part of both state machines`, async () => {
    const result = await harness.campaign({ seed: SEED, cases: 40, steps: 60 });
    expect(result.violations).toEqual([]);
    expect(result.events).toBe(40 * 60);
    // Every kind of event ran and did something in this campaign (a no-op is counted under "<event> (no-op)").
    for (const event of ['intent', 'submit', 'retry', 'reconcile', 'send.arrive', 'send.deliver', 'send.end', 'track.deliver', 'lnd.payment',
      'create', 'answer', 'create.arrive', 'invoice', 'settle', 'cancel', 'rreconcile', 'listen', 'sub.deliver', 'cursor-set', 'age', 'kill', 'abort',
      'outbox']) {
      expect(result.coverage[event] ?? 0, event).toBeGreaterThan(0);
    }
    expect(Object.keys(result.coverage).some(key => key.startsWith('plan payer')), 'a payer plan').toBe(true);
    expect(Object.keys(result.coverage).some(key => key.startsWith('plan receiver')), 'a receiver plan').toBe(true);
    expect(Object.keys(result.configs).some(config => config.startsWith('huge')), 'amounts near 2^62').toBe(true);
  }, 180_000);

  it('the replay corpus has one replay per predicate, and none of them violates anything on the current lab source', async () => {
    for (const predicate of Object.keys(harness.PREDICATES)) {
      const file = join(CORPUS, `${predicate}.json`);
      expect(existsSync(file), file).toBe(true);
      expect(harness.readReplay(file).predicate).toBe(predicate);
    }
    const outcomes = await harness.replay({ path: CORPUS });
    expect(outcomes).toHaveLength(Object.keys(harness.PREDICATES).length);
    for (const outcome of outcomes) {
      expect(outcome.invalid, outcome.file).toBeUndefined();
      expect(outcome.violations.map(item => `${item.predicate}: ${item.message}`), outcome.file).toEqual([]);
    }
  }, 60_000);

  it('mutants pass through the oracle: each kept mutant is caught by its predicate\'s replay (or a 100-case campaign)', async () => {
    const mutants = readdirSync(harness.MUTANTS).filter(name => name.endsWith('.cjs')).sort();
    expect(mutants.length).toBeGreaterThanOrEqual(6);
    for (const name of mutants) {
      const mutant = harness.readMutant(join(harness.MUTANTS, name));
      expect(name, 'a mutant is named after the predicate it proves').toBe(`${mutant.predicate}.cjs`);
      const replay = harness.readReplay(join(CORPUS, `${mutant.predicate}.json`));
      // A replay that names a mutant was recorded on it; a hand-written one (failingStep -1) is the scenario the mutant breaks.
      expect(replay.mutant === undefined ? replay.failingStep : replay.mutant, name).toBe(replay.mutant === undefined ? -1 : name);
      const labSrc = harness.buildMutant(join(harness.MUTANTS, name), mkdtempSync(join(scratch, 'mutant-')));
      const [outcome] = await harness.replay({ path: join(CORPUS, `${mutant.predicate}.json`), labSrc });
      let caught = outcome?.violations.some(item => item.predicate === mutant.predicate) ?? false;
      if (!caught) {
        const campaign = await harness.campaign({ seed: 2, cases: 100, labSrc, collect: true, shrink: false });
        caught = campaign.violations.some(item => item.predicate === mutant.predicate);
      }
      expect(caught, `${name}: ${mutant.description}`).toBe(true);
    }
  }, 300_000);

  it('a replay file is validated before it runs: a bad one is refused with its file and step, and the rest of the directory still runs', async () => {
    const dir = mkdtempSync(join(scratch, 'replays-'));
    copyFileSync(join(CORPUS, 'cursor-moves-only-from-subscription.json'), join(dir, 'a-good.json'));
    const base = harness.readReplay(join(CORPUS, 'cursor-moves-only-from-subscription.json'));
    const bad = (name: string, change: (replay: Record<string, unknown>) => void): void => {
      const replay = JSON.parse(JSON.stringify(base)) as Record<string, unknown>;
      change(replay);
      writeFileSync(join(dir, name), JSON.stringify(replay));
    };
    const events = (replay: Record<string, unknown>): Record<string, unknown>[] => replay.events as Record<string, unknown>[];
    bad('b-kind.json', replay => { (events(replay)[3] as Record<string, unknown>).t = 'teleport'; });
    bad('c-range.json', replay => { (events(replay)[1] as Record<string, unknown>).order = 7; });
    bad('d-process.json', replay => { (events(replay)[0] as Record<string, unknown>).p = 'p9'; });
    bad('e-mode.json', replay => { (events(replay)[2] as Record<string, unknown>).mode = 'stale'; });
    bad('f-scale.json', replay => { (replay.config as Record<string, unknown>).scale = 'enormous'; });
    bad('g-pick.json', replay => { (events(replay)[4] as Record<string, unknown>).pick = 1.5; });
    writeFileSync(join(dir, 'h-json.json'), '{ not json');
    for (const [file, step, text] of [['b-kind.json', 3, 'unknown event kind "teleport"'], ['c-range.json', 1, 'create.order is 7'],
      ['d-process.json', 0, 'listen.p is "p9"'], ['e-mode.json', 2, 'answer mode "stale" is for a lookup only'], ['f-scale.json', undefined, 'config.scale'],
      ['g-pick.json', 4, 'sub.deliver.pick is 1.5']] as const) {
      let error: (Error & { file: string; step: number | undefined }) | undefined;
      try { harness.readReplay(join(dir, file)); } catch (thrown) { error = thrown as Error & { file: string; step: number | undefined }; }
      expect(error, file).toBeInstanceOf(harness.ReplayError);
      expect(error?.file).toBe(join(dir, file));
      expect(error?.step, file).toBe(step);
      expect(error?.message, file).toContain(text);
    }
    const outcomes = await harness.replay({ path: dir });
    expect(outcomes.map(item => [item.file.slice(dir.length + 1), item.invalid === undefined])).toEqual([['a-good.json', true], ['b-kind.json', false],
      ['c-range.json', false], ['d-process.json', false], ['e-mode.json', false], ['f-scale.json', false], ['g-pick.json', false], ['h-json.json', false]]);
    expect(outcomes[0]?.violations).toEqual([]);
    // The runner: 2 for a refused file (distinct from 1, a violation, and 0), and the good file still ran.
    const run = spawnSync(process.execPath, [RUNNER, '--replay', dir], { encoding: 'utf8' });
    expect(run.status, run.stderr).toBe(2);
    expect(run.stdout).toMatch(/ok {3}\S*a-good\.json: no violation/);
    expect(run.stdout).toMatch(/BAD {2}\S*b-kind\.json: refused, nothing of it ran: step 3: unknown event kind "teleport"/);
    expect(run.stdout).toContain('8 replay(s), 0 unexpected, 7 refused');
  }, 60_000);
});
