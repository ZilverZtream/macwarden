// Bounds the work an attacker can cause through a canary. Whoever holds a canary
// controls how often it is used, so every alert path must be bounded no matter how
// fast the denied requests arrive:
// - per canary, the first use alerts at once; further uses in the next window are only
//   counted, and one summary alert carries the count when the window ends;
// - at most one --alert-command process runs at a time; while it runs, each canary key has
//   one pending slot holding its newest event, run in the order the keys began waiting, so a
//   flood can never stack processes and one canary's alert never displaces another's;
// - the number of tracked canary keys is capped; overflow shares one bucket.
// LND still gets an immediate denial for every request; only alerting is coalesced.
import type { WatchEvent } from '../output/index.js';

export const ALERT_WINDOW_MS = 10_000;
export const MAX_TRACKED_CANARIES = 1024;
// Waiting alert commands: one per throttle key (tracked canaries plus the overflow bucket).
// A key beyond this is refused and reported, never silently dropped.
export const MAX_PENDING_ALERTS = MAX_TRACKED_CANARIES + 1;
const OVERFLOW_KEY = '\u0000overflow';

type CanaryEvent = Extract<WatchEvent, { event: 'canary' }>;
type Timers = { set: (callback: () => void, ms: number) => unknown; clear: (handle: unknown) => void };

export type AlertThrottle = {
  /** Records `count` denied uses (default 1); alerts now or folds them into the next summary. */
  offer(key: string, event: CanaryEvent, count?: number): void;
  /** Emits every pending summary immediately and stops all timers. */
  flush(): void;
  /** Uses folded into summaries so far (for the run summary). */
  suppressed(): number;
};

export function createAlertThrottle(options: { now: () => number; alert: (event: CanaryEvent, key: string) => void;
  windowMs?: number; maxKeys?: number; timers?: Timers }): AlertThrottle {
  const windowMs = options.windowMs ?? ALERT_WINDOW_MS;
  const maxKeys = options.maxKeys ?? MAX_TRACKED_CANARIES;
  const timers: Timers = options.timers ?? { set: (callback, ms) => setTimeout(callback, ms).unref(), clear: handle => clearTimeout(handle as NodeJS.Timeout) };
  type State = { windowEnd: number; folded: number; last: CanaryEvent; timer: unknown };
  const states = new Map<string, State>();
  let suppressedTotal = 0;

  const close = (key: string, state: State): void => {
    timers.clear(state.timer);
    state.timer = undefined;
    if (state.folded === 0) { states.delete(key); return; }
    // The summary opens a new window, so a sustained flood yields one alert per window.
    options.alert({ ...state.last, repeats: state.folded }, key);
    state.folded = 0;
    state.windowEnd = options.now() + windowMs;
    state.timer = timers.set(() => close(key, state), windowMs);
  };

  return {
    offer(rawKey, event, count = 1) {
      if (count < 1) return;
      const key = states.has(rawKey) || states.size < maxKeys ? rawKey : OVERFLOW_KEY;
      const state = states.get(key);
      if (!state || options.now() >= state.windowEnd) {
        // A window whose timer has not fired yet (a busy event loop) still reports its count.
        if (state) { timers.clear(state.timer); if (state.folded > 0) options.alert({ ...state.last, repeats: state.folded }, key); }
        // The first use alerts now; the rest of this batch is folded into the summary.
        const fresh: State = { windowEnd: options.now() + windowMs, folded: count - 1, last: event, timer: undefined };
        states.set(key, fresh);
        suppressedTotal += count - 1;
        fresh.timer = timers.set(() => close(key, fresh), windowMs);
        options.alert(event, key);
        return;
      }
      state.folded += count;
      state.last = event;
      suppressedTotal += count;
    },
    flush() {
      for (const [key, state] of [...states]) {
        timers.clear(state.timer);
        if (state.folded > 0) options.alert({ ...state.last, repeats: state.folded }, key);
        states.delete(key);
      }
    },
    suppressed: () => suppressedTotal,
  };
}

/**
 * Runs alert commands one at a time. While one runs, each key (a canary, as the throttle
 * names it) keeps only its newest event waiting, and waiting keys run in the order they began
 * waiting: a newer event of the same canary replaces its waiting one (counted in replaced()),
 * but an event of another canary never does, so every canary that alerted gets its command.
 * Callers that pass no key share one slot. More than MAX_PENDING_ALERTS waiting keys: the
 * event is refused and reported through onFailure.
 * Each run gets an AbortSignal: aborting it cancels the command (its process tree is killed).
 * stop() ends alerting for good (watch shutdown, audit MW102-05): nothing new starts, the
 * waiting event is discarded, and the running command gets one deadline after which it is
 * cancelled. Discarded and refused events are reported through onFailure: no command ran.
 */
export function createAlertRunner(run: (event: CanaryEvent, signal: AbortSignal) => Promise<void>,
  onFailure: (event: CanaryEvent) => void) {
  let running: Promise<void> | null = null;
  let control: AbortController | null = null;
  const pending = new Map<string, CanaryEvent>();
  let replaced = 0;
  let stopped = false;
  const start = (event: CanaryEvent): void => {
    const own = new AbortController();
    control = own;
    let attempt: Promise<void>;
    try { attempt = run(event, own.signal); } catch (error) { attempt = Promise.reject(error); }
    running = attempt.catch(() => onFailure(event)).finally(() => {
      running = null;
      control = null;
      const next = stopped ? undefined : pending.entries().next().value;
      if (next) { pending.delete(next[0]); start(next[1]); }
    });
  };
  const wait = (promise: Promise<unknown>, ms: number): Promise<boolean> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    return Promise.race([promise.then(() => true), new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), ms); })])
      .finally(() => clearTimeout(timer));
  };
  // Every waiting event is reported: no command ran for it.
  const discard = (): void => {
    const dropped = [...pending.values()];
    pending.clear();
    for (const event of dropped) onFailure(event);
  };
  return {
    submit(event: CanaryEvent, key = ''): void {
      if (stopped) { onFailure(event); return; }
      if (running) {
        if (pending.has(key)) { replaced += 1; pending.set(key, event); return; }
        if (pending.size >= MAX_PENDING_ALERTS) { onFailure(event); return; }
        pending.set(key, event);
        return;
      }
      start(event);
    },
    /** Resolves once no alert command is running or waiting. */
    async idle(): Promise<void> { while (running) await running; },
    /**
     * Ends new starts at once (watch is shutting down): new events are refused and the waiting
     * ones are discarded, both reported; the running command keeps going until stop() gives it its
     * deadline. Called before shutdown work that takes time (the usage file write), so a waiting
     * alert cannot slip in behind a command that ends meanwhile (1.2.1).
     */
    stopping(): void {
      stopped = true;
      discard();
    },
    /**
     * Stops alerting: refuses new events, discards the waiting ones, lets the running command
     * finish for at most graceMs, then cancels it and waits at most settleMs for it to settle.
     */
    async stop(graceMs: number, settleMs: number): Promise<void> {
      stopped = true;
      discard();
      const active = running;
      if (!active || await wait(active, graceMs)) return;
      control?.abort();
      await wait(active, settleMs);
    },
    /** Waiting events replaced by a newer event of the same key (that key's command still runs). */
    replaced: () => replaced,
  };
}
