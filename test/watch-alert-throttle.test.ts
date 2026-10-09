import { expect, it } from 'vitest';
import type { WatchEvent } from '../src/output/index.js';
import { createAlertRunner, createAlertThrottle } from '../src/watch/alert-throttle.js';

type CanaryEvent = Extract<WatchEvent, { event: 'canary' }>;
const event = (n: number, rootKeyId = '4294967342'): CanaryEvent => ({ event: 'canary', time: `t${n}`,
  method: '/lnrpc.Lightning/GetInfo', rootKeyId, credential: 'id:0123456789abcdef', label: 'decoy', denied: true });

// Manual clock and timers: the test decides exactly when a window ends.
function harness(windowMs = 10_000, maxKeys?: number) {
  let now = 0;
  const pending = new Map<number, { at: number; run: () => void }>();
  let next = 1;
  const alerts: CanaryEvent[] = [];
  const throttle = createAlertThrottle({ now: () => now, alert: e => alerts.push(e), windowMs, maxKeys,
    timers: { set: (run, ms) => { const id = next++; pending.set(id, { at: now + ms, run }); return id; },
      clear: id => { pending.delete(id as number); } } });
  const advance = (ms: number) => {
    now += ms;
    for (const [id, timer] of [...pending].sort((a, b) => a[1].at - b[1].at))
      if (timer.at <= now && pending.has(id)) { pending.delete(id); timer.run(); }
  };
  return { throttle, alerts, advance, timers: pending };
}

it('WATCH/alert-throttle a flood of canary uses produces one alert now and one counted summary per window', () => {
  const { throttle, alerts, advance } = harness();
  for (let n = 0; n < 10_000; n++) throttle.offer('4294967342', event(n));
  expect(alerts).toEqual([event(0)]);
  advance(10_000);
  expect(alerts).toEqual([event(0), { ...event(9_999), repeats: 9_999 }]);
  expect(throttle.suppressed()).toBe(9_999);
});

it('WATCH/alert-throttle a sustained flood yields at most one alert per window, and a quiet canary re-arms', () => {
  const { throttle, alerts, advance } = harness();
  for (let second = 0; second < 60; second++) {
    for (let n = 0; n < 100; n++) throttle.offer('k', event(second * 100 + n));
    advance(1_000);
  }
  // First use plus one summary per elapsed 10 s window.
  expect(alerts.length).toBeLessThanOrEqual(7);
  // A fresh alert stands for one use; a summary stands for the uses it folded.
  expect(alerts.reduce((sum, alert) => sum + (alert.repeats ?? 1), 0)).toBe(6_000);
  advance(30_000);
  const before = alerts.length;
  throttle.offer('k', event(99_999));
  expect(alerts.length).toBe(before + 1);
  expect(alerts.at(-1)!.repeats).toBeUndefined();
});

it('WATCH/alert-throttle separate canaries alert independently, and the number of tracked keys is capped', () => {
  const { throttle, alerts, timers } = harness(10_000, 3);
  for (let key = 0; key < 1_000; key++) throttle.offer(`k${key}`, event(key, String(key)));
  // Three tracked keys plus one shared overflow bucket.
  expect(alerts.map(alert => alert.rootKeyId)).toEqual(['0', '1', '2', '3']);
  expect(timers.size).toBeLessThanOrEqual(4);
});

it('WATCH/alert-throttle flush emits pending summaries and leaves no timer behind', () => {
  const { throttle, alerts, timers } = harness();
  throttle.offer('k', event(0)); throttle.offer('k', event(1)); throttle.offer('k', event(2));
  throttle.flush();
  expect(alerts).toEqual([event(0), { ...event(2), repeats: 2 }]);
  expect(timers.size).toBe(0);
});

it('WATCH/alert-runner at most one alert command runs at a time and only the newest waiting event runs next', async () => {
  let running = 0, peak = 0;
  const ran: CanaryEvent[] = [];
  const releases: (() => void)[] = [];
  const runner = createAlertRunner(async e => {
    running += 1; peak = Math.max(peak, running); ran.push(e);
    await new Promise<void>(resolve => releases.push(resolve));
    running -= 1;
  }, () => undefined);
  for (let n = 0; n < 1_000; n++) runner.submit(event(n));
  expect(ran).toEqual([event(0)]);
  releases.shift()!();
  await new Promise(resolve => setImmediate(resolve));
  expect(ran).toEqual([event(0), event(999)]);
  releases.shift()!();
  await runner.idle();
  expect(peak).toBe(1);
  expect(runner.replaced()).toBe(998);
});

it('WATCH/alert-throttle a batch of uses counts in full: one alert now, the rest in the summary', () => {
  const { throttle, alerts, advance } = harness();
  // The guard hands over everything one event-loop turn collected for a canary at once.
  throttle.offer('k', event(0), 5_000);
  expect(alerts).toEqual([event(0)]);
  throttle.offer('k', event(1), 3);
  advance(10_000);
  expect(alerts).toEqual([event(0), { ...event(1), repeats: 5_002 }]);
  expect(throttle.suppressed()).toBe(5_002);
  throttle.offer('k', event(2), 0);
  expect(alerts).toHaveLength(2);
});

it('WATCH/alert-throttle a window whose timer fired late still reports its folded uses before the next alert', () => {
  let now = 0;
  const alerts: CanaryEvent[] = [];
  // Timers that never fire: the window is closed only by the next offer.
  const throttle = createAlertThrottle({ now: () => now, alert: e => alerts.push(e), windowMs: 10_000,
    timers: { set: () => 0, clear: () => undefined } });
  throttle.offer('k', event(0), 4);
  now = 20_000;
  throttle.offer('k', event(1));
  expect(alerts).toEqual([event(0), { ...event(0), repeats: 3 }, event(1)]);
});

it('WATCH/alert-shutdown stop discards the waiting event, refuses new ones and cancels the running command at one deadline', async () => {
  const ran: CanaryEvent[] = [];
  const signals: AbortSignal[] = [];
  const failures: CanaryEvent[] = [];
  // Honours cancellation, like runAlertCommand: the abort kills the process (tree) and settles.
  const runner = createAlertRunner((e, signal) => {
    ran.push(e); signals.push(signal);
    return new Promise<void>((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('cancelled'))));
  }, e => failures.push(e));
  runner.submit(event(0));
  runner.submit(event(1));
  const started = performance.now();
  await runner.stop(100, 1_000);
  const elapsed = performance.now() - started;
  // The waiting event never starts; it is reported, because no command ran for it.
  expect(ran).toEqual([event(0)]);
  expect(signals[0].aborted).toBe(true);
  expect(failures).toEqual([event(1), event(0)]);
  expect(elapsed).toBeGreaterThanOrEqual(90);
  expect(elapsed).toBeLessThan(1_000);
  // After stop nothing new starts.
  runner.submit(event(2));
  await new Promise(resolve => setImmediate(resolve));
  expect(ran).toEqual([event(0)]);
  expect(failures).toEqual([event(1), event(0), event(2)]);
});

it('WATCH/alert-shutdown stop returns by its deadline even when a run ignores cancellation', async () => {
  const runner = createAlertRunner(() => new Promise<void>(() => undefined), () => undefined);
  runner.submit(event(0));
  const started = performance.now();
  await runner.stop(50, 100);
  expect(performance.now() - started).toBeLessThan(1_000);
});

it('WATCH/alert-shutdown stop does not wait or cancel when the running command finishes first', async () => {
  let release!: () => void;
  const signals: AbortSignal[] = [];
  const runner = createAlertRunner((_e, signal) => { signals.push(signal); return new Promise<void>(resolve => { release = resolve; }); },
    () => undefined);
  runner.submit(event(0));
  setTimeout(() => release(), 20);
  const started = performance.now();
  await runner.stop(10_000, 1_000);
  expect(performance.now() - started).toBeLessThan(2_000);
  expect(signals[0].aborted).toBe(false);
});
