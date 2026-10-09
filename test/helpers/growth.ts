import { performance } from 'node:perf_hooks';

// Machine-independent cost checks. A fixed time limit measures the runner as much as the
// code: a loaded two-core CI machine can be several times slower than a workstation. These
// helpers instead compare two timings taken in the same process, alternately, keeping each
// side's fastest round, so a slower or busier machine scales both sides alike and the ratio
// shows how the work grows, not how fast the machine is.

export type Work = () => unknown;

async function once(work: Work): Promise<number> {
  const started = performance.now();
  await work();
  return performance.now() - started;
}

/**
 * Times `small` and `large` alternately, `rounds` times each after one untimed warm-up of
 * each (JIT compilation and first-touch allocation), and returns each side's fastest round.
 * Very short timings are floored at `floorMs` so that timer resolution cannot inflate a ratio.
 */
export async function compare(small: Work, large: Work, rounds = 3, floorMs = 5):
Promise<{ small: number; large: number; ratio: number; summary: string }> {
  await small();
  await large();
  let fastSmall = Infinity, fastLarge = Infinity;
  for (let round = 0; round < rounds; round++) {
    fastSmall = Math.min(fastSmall, await once(small));
    fastLarge = Math.min(fastLarge, await once(large));
  }
  const ratio = fastLarge / Math.max(fastSmall, floorMs);
  return { small: fastSmall, large: fastLarge, ratio,
    summary: `${fastSmall.toFixed(0)} ms against ${fastLarge.toFixed(0)} ms (ratio ${ratio.toFixed(2)})` };
}

/**
 * Bound for work timed at n and 4n. Linear work measured 2.5 to 7 on Linux and Windows,
 * idle, loaded and on two-core CI runners (the larger input pays more garbage collection);
 * the quadratic code these tests guard against measured 16.
 */
export const LINEAR_4X = 10;

/**
 * Times the same operation at size `n` and `factor * n`. Linear work gives a ratio near
 * `factor`; quadratic work gives `factor ** 2`. Callers assert the ratio stays well below
 * the next complexity class, with headroom for noise on either side.
 */
export async function growth(prepare: (size: number) => Work, n: number, factor: number, rounds = 3):
Promise<{ small: number; large: number; ratio: number; summary: string }> {
  return compare(prepare(n), prepare(n * factor), rounds);
}
