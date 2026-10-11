import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPrivateDirectory } from '../scripts/private-scratch.mjs';
import { CORPUS, RUNNER, loadHarness, loadHarnessCase, type Harness, type HarnessRun } from './helpers/payment-lab-harness.js';

/**
 * The payment lab's model-based state-machine harness (examples/payment-lab/test/harness, design brief
 * 1.3.0 item 1) in the product suite: a fixed-seed campaign of 40 cases of random interleavings of two
 * processes against the oracle of the README's rules, the replay corpus (a replay per rule, <predicate>.json,
 * and more as <predicate>--<what>.json) against the current lab source, the recorded replays against the
 * 1.2.0 lab sources (git archive v1.2.0: each violates its rule there), the replay validation, and the kept
 * mutants (each caught by its own replay). No node, no Docker, no credential: the stores run on node:sqlite
 * in a temporary directory against a scripted LND. `npm run fuzz:lab` runs the same campaign with 500 cases.
 */

const SEED = 20261010;
/**
 * The kept mutants (at least): the 6 of 1.3.0, the 4 the pre-1.4 audit found surviving the oracle, m6b (caught
 * with a preempt event) and the mutants of the 1.3.0 mutation table that still apply to the source.
 */
const MIN_MUTANTS = 40;
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
    for (const event of ['intent', 'submit', 'retry', 'reconcile', 'send.arrive', 'send.deliver', 'send.end', 'track.deliver', 'track.end', 'lnd.payment',
      'create', 'answer', 'create.arrive', 'invoice', 'settle', 'cancel', 'rreconcile', 'listen', 'sub.deliver', 'sub.end', 'cursor-set', 'age', 'kill',
      'abort', 'outbox', 'preempt', 'preempt delivered']) {
      expect(result.coverage[event] ?? 0, event).toBeGreaterThan(0);
    }
    expect(Object.keys(result.coverage).some(key => key.startsWith('plan payer')), 'a payer plan').toBe(true);
    expect(Object.keys(result.coverage).some(key => key.startsWith('plan receiver')), 'a receiver plan').toBe(true);
    expect(Object.keys(result.configs).some(config => config.startsWith('huge')), 'amounts near 2^62').toBe(true);
  }, 180_000);

  it('the replay corpus has a replay per predicate, and none of them violates anything on the current lab source', async () => {
    for (const predicate of Object.keys(harness.PREDICATES)) {
      const file = join(CORPUS, `${predicate}.json`);
      expect(existsSync(file), file).toBe(true);
      expect(harness.readReplay(file).predicate).toBe(predicate);
    }
    const files = readdirSync(CORPUS).filter(name => name.endsWith('.json')).sort();
    // Every file is named after the predicate it records: <predicate>.json or <predicate>--<what>.json.
    for (const name of files) {
      const predicate = harness.readReplay(join(CORPUS, name)).predicate;
      expect(name === `${predicate}.json` || name.startsWith(`${predicate}--`), name).toBe(true);
    }
    const outcomes = await harness.replay({ path: CORPUS });
    expect(outcomes).toHaveLength(files.length);
    for (const outcome of outcomes) {
      expect(outcome.invalid, outcome.file).toBeUndefined();
      expect(outcome.violations.map(item => `${item.predicate}: ${item.message}`), outcome.file).toEqual([]);
    }
  }, 120_000);

  it('mutants pass through the oracle: each kept mutant is caught by its own replay', async () => {
    const mutants = readdirSync(harness.MUTANTS).filter(name => name.endsWith('.cjs')).sort();
    expect(mutants.length).toBeGreaterThanOrEqual(MIN_MUTANTS);
    const survivors: string[] = [];
    for (const name of mutants) {
      const mutant = harness.readMutant(join(harness.MUTANTS, name));
      // <predicate>.cjs or <predicate>--<what>.cjs, proved by the replay of the same name.
      expect(name === `${mutant.predicate}.cjs` || name.startsWith(`${mutant.predicate}--`), `${name} is named after the predicate it proves`).toBe(true);
      const file = join(CORPUS, name.replace(/\.cjs$/, '.json'));
      const replay = harness.readReplay(file);
      expect(replay.predicate, file).toBe(mutant.predicate);
      // A replay that names a mutant was recorded on it; a hand-written one (failingStep -1) is the scenario the mutant breaks.
      expect(replay.mutant === undefined ? replay.failingStep : replay.mutant, name).toBe(replay.mutant === undefined ? -1 : name);
      const labSrc = harness.buildMutant(join(harness.MUTANTS, name), mkdtempSync(join(scratch, 'mutant-')));
      const [outcome] = await harness.replay({ path: file, labSrc });
      if (!(outcome?.violations.some(item => item.predicate === mutant.predicate) ?? false)) survivors.push(`${name}: ${mutant.description}`);
    }
    expect(survivors).toEqual([]);
  }, 600_000);

  it('every recorded replay violates its own predicate on the 1.2.0 lab sources (git archive v1.2.0), and every predicate has a mutant or such a replay', async () => {
    // No skip: without git or the v1.2.0 tag (a shallow checkout fetches no tags) this test fails.
    const dir = await createPrivateDirectory(tmpdir(), 'macwarden-lab-1.2.0-');
    try {
      const git = spawnSync('git', ['archive', '--format=tar', `--output=${join(dir, 'lab-1.2.0.tar')}`, 'v1.2.0', 'examples/payment-lab/src'], { encoding: 'utf8' });
      expect(git.status, `git archive v1.2.0 examples/payment-lab/src: ${git.stderr}`).toBe(0);
      const tar = spawnSync('tar', ['-xf', 'lab-1.2.0.tar'], { cwd: dir, encoding: 'utf8' });
      expect(tar.status, `tar: ${tar.stderr}`).toBe(0);
      const labSrc = join(dir, 'examples', 'payment-lab', 'src');
      // The lab is ESM (its package.json says so); the archive holds only src/.
      writeFileSync(join(dir, 'examples', 'payment-lab', 'package.json'), '{"type":"module"}\n');
      const recorded = readdirSync(CORPUS).filter(name => name.endsWith('.json')).map(name => harness.readReplay(join(CORPUS, name)))
        .filter(replay => replay.failingStep >= 0 && replay.mutant === undefined);
      expect(recorded.length).toBeGreaterThanOrEqual(11);
      const run = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', RUNNER, '--replay', CORPUS, '--lab-src', labSrc, '--expect-violation'],
        { encoding: 'utf8' });
      expect(run.status, `${run.stdout}${run.stderr}`).toBe(0);
      expect(run.stdout.split('\n').filter(line => line.startsWith('ok   ')), run.stdout).toHaveLength(recorded.length);
      expect(run.stdout).not.toContain('FAIL');
      // Evidence per predicate that the oracle can fire: a kept mutant caught by its replay (above), or a recorded replay that violates it on 1.2.0.
      const mutantOf = new Set(readdirSync(harness.MUTANTS).filter(name => name.endsWith('.cjs')).map(name => harness.readMutant(join(harness.MUTANTS, name)).predicate));
      expect(Object.keys(harness.PREDICATES).filter(predicate => !mutantOf.has(predicate) && !recorded.some(replay => replay.predicate === predicate))).toEqual([]);
    } finally {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* Windows may still hold a file; the temp directory keeps it */ }
    }
  }, 120_000);

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
    // Inherited property names are no event kind, field or predicate (Object.prototype's constructor, toString).
    bad('i-proto-event.json', replay => { (events(replay)[3] as Record<string, unknown>).t = 'constructor'; });
    bad('j-proto-predicate.json', replay => { replay.predicate = 'toString'; });
    bad('k-proto-field.json', replay => { Object.defineProperty(events(replay)[0], 'constructor', { value: 1, enumerable: true }); });
    for (const [file, step, text] of [['b-kind.json', 3, 'unknown event kind "teleport"'], ['c-range.json', 1, 'create.order is 7'],
      ['d-process.json', 0, 'listen.p is "p9"'], ['e-mode.json', 2, 'answer mode "stale" is for a lookup only'], ['f-scale.json', undefined, 'config.scale'],
      ['g-pick.json', 4, 'sub.deliver.pick is 1.5'], ['i-proto-event.json', 3, 'unknown event kind "constructor"'],
      ['j-proto-predicate.json', undefined, 'predicate "toString" is not one of the oracle\'s'], ['k-proto-field.json', 0, 'listen has no field constructor']] as const) {
      let error: (Error & { file: string; step: number | undefined }) | undefined;
      try { harness.readReplay(join(dir, file)); } catch (thrown) { error = thrown as Error & { file: string; step: number | undefined }; }
      expect(error, file).toBeInstanceOf(harness.ReplayError);
      expect(error?.file).toBe(join(dir, file));
      expect(error?.step, file).toBe(step);
      expect(error?.message, file).toContain(text);
    }
    const outcomes = await harness.replay({ path: dir });
    expect(outcomes.map(item => [item.file.slice(dir.length + 1), item.invalid === undefined])).toEqual([['a-good.json', true], ['b-kind.json', false],
      ['c-range.json', false], ['d-process.json', false], ['e-mode.json', false], ['f-scale.json', false], ['g-pick.json', false], ['h-json.json', false],
      ['i-proto-event.json', false], ['j-proto-predicate.json', false], ['k-proto-field.json', false]]);
    expect(outcomes[0]?.violations).toEqual([]);
    // The runner: 2 for a refused file (distinct from 1, a violation, and 0), and the good file still ran.
    const run = spawnSync(process.execPath, [RUNNER, '--replay', dir], { encoding: 'utf8' });
    expect(run.status, run.stderr).toBe(2);
    expect(run.stdout).toMatch(/ok {3}\S*a-good\.json: no violation/);
    expect(run.stdout).toMatch(/BAD {2}\S*b-kind\.json: refused, nothing of it ran: step 3: unknown event kind "teleport"/);
    expect(run.stdout).toContain('11 replay(s), 0 unexpected, 10 refused');
  }, 60_000);

  it('the scripted LND pays with one shard at a time: the successful principals sum to the value LND reports', async () => {
    const { Run, loadLab } = await loadHarnessCase();
    const run = new Run(await loadLab(), { scale: 'small', budget: false, limit: '10000' }, mkdtempSync(join(scratch, 'shards-')));
    try {
      for (const event of [{ t: 'intent', p: 'p0', op: 0, inv: 0 }, { t: 'submit', p: 'p0', op: 0, inv: 0 }, { t: 'send.arrive', pick: 0 }]) await run.step(event);
      expect(await run.step({ t: 'lnd.payment', pick: 0, what: 'attempt' })).toBe(true);
      // A second attempt while one is in flight would carry the whole amount again (max_parts 1): refused as a no-op.
      expect(await run.step({ t: 'lnd.payment', pick: 0, what: 'attempt' })).toBe(false);
      expect(await run.step({ t: 'lnd.payment', pick: 0, what: 'attempt-fail' })).toBe(true);
      expect(await run.step({ t: 'lnd.payment', pick: 0, what: 'attempt' })).toBe(true);
      expect(await run.step({ t: 'lnd.payment', pick: 0, what: 'succeed', amount: 'over' })).toBe(true);
      const [payment] = [...run.lnd.payments.values()];
      const succeeded = payment?.htlcs.filter(item => item.status === 'SUCCEEDED') ?? [];
      expect(payment?.status).toBe('SUCCEEDED');
      expect(succeeded).toHaveLength(1);
      expect(succeeded.reduce((sum, item) => sum + item.principalMsat, 0n)).toBe(payment?.valueMsat);
      expect(succeeded[0]?.route.totalAmtMsat).toBe((payment?.valueMsat ?? 0n) + (payment?.feeMsat ?? 0n));
      expect(succeeded[0]?.route.hops.map(hop => hop.amtToForwardMsat)).toEqual([payment?.valueMsat]);
      expect(payment?.htlcs.map(item => item.status)).toEqual(['FAILED', 'SUCCEEDED']);
      expect(run.oracle.violations).toEqual([]);
    } finally {
      await run.dispose();
    }
  }, 60_000);

  it('the runner refuses an empty replay directory, also with --expect-violation, and takes back every seed it prints', () => {
    const empty = mkdtempSync(join(scratch, 'empty-'));
    for (const extra of [[], ['--expect-violation']]) {
      const run = spawnSync(process.execPath, [RUNNER, '--replay', empty, ...extra], { encoding: 'utf8' });
      expect(run.status, run.stdout).toBe(2);
      expect(run.stderr).toContain('no replay files');
    }
    // Seeds the runner draws go up to 2^31 - 1 and seeds up to 2^32 - 1 are valid; 2^32 is not.
    const seeded = spawnSync(process.execPath, [RUNNER, '--seed', '4294967295', '--cases', '0'], { encoding: 'utf8' });
    expect(seeded.status, seeded.stderr).toBe(0);
    expect(seeded.stdout).toContain('seed 4294967295, 0 cases');
    const over = spawnSync(process.execPath, [RUNNER, '--seed', '4294967296', '--cases', '0'], { encoding: 'utf8' });
    expect(over.status).toBe(2);
    expect(over.stderr).toContain('--seed must be an integer from 0 to 4294967295');
  }, 60_000);

  it('every event the generator draws is one the replay validator accepts: a pick that rounds to 1 is clamped below 1 (1.3.1 audit, H01)', async () => {
    const { Run, loadLab } = await loadHarnessCase();
    const lab = await loadLab();
    const { xorshift, validateReplay, replayOf } = harness as unknown as { xorshift(seed: number): unknown; validateReplay(file: string, value: unknown): unknown;
      replayOf(result: unknown, predicate: string, origin: { seed: number | null; case: number | null; originalSteps: number }): unknown };
    const config = { scale: 'small' as const, budget: false, limit: '10000' };
    const run = new Run(lab, config, scratch) as HarnessRun & { generate(rng: unknown): Record<string, unknown> };
    try {
      // Seed 180367's first draw for cursor-set.pick is 0.99996..., which Number(x.toFixed(4)) rounds to 1: the validator refused the recording.
      const event = run.generate(xorshift(180367));
      expect(event).toMatchObject({ t: 'cursor-set', pick: 0.9999 });
      const replay = { schema: 1, kind: 'macwarden-payment-lab-harness-replay', predicate: 'ledger-balanced', config, failingStep: -1, originalSteps: 1,
        events: [event], states: {} };
      expect(() => validateReplay('generated.json', replay)).not.toThrow();
    } finally {
      await run.dispose();
    }
    // The recording itself checks what it records: a case result with an event the validator refuses is a harness error, not a replay file.
    const result = { config, events: [{ t: 'cursor-set', p: 'p0', pick: 1 }], violations: [{ predicate: 'ledger-balanced', message: 'x', step: 0, states: {} }], counts: {} };
    expect(() => replayOf(result, 'ledger-balanced', { seed: 1, case: 0, originalSteps: 1 })).toThrow(/step 0: cursor-set\.pick is 1/);
  }, 60_000);
});
