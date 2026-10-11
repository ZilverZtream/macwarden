// Regressions from the pre-1.4 watch audit: alert slots per canary, monotonic coverage and
// timers, drop notices after output closed, stream counting after a reconnect, --until before
// the first registration, node identity on reconnect, response charging in the attribution queue.
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, expect, it, vi } from 'vitest';
import { withCancellation } from '../src/cancellation.js';
import { run, type Register } from '../src/commands/watch.js';
import type { MiddlewareCall, MiddlewareEnd } from '../src/lnd/index.js';
import type { WatchEvent } from '../src/output/index.js';
import { macaroonId } from '../src/decode/index.js';
import { decodeMiddlewareRequest, MAX_MACAROON_BYTES, OVERSIZED_MACAROON_PREFIX_BYTES } from '../src/lnd/middleware-proto.js';
import { Secret } from '../src/secret.js';
import { bytes, message, middlewareRequest, uint, varint } from './helpers/payment-proto.js';
import { createAlertRunner, MAX_PENDING_ALERTS } from '../src/watch/alert-throttle.js';
import { createOutputQueue } from '../src/watch/output-queue.js';
import { UsageStore } from '../src/watch/usage.js';

const repo = fileURLToPath(new URL('..', import.meta.url));
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const vector = (name: string) => readFileSync(join(repo, 'test/vectors', `${name}.macaroon`));
const PUBKEY = `02${'ab'.repeat(32)}`;
const OTHER = `03${'cd'.repeat(32)}`;
const dirs: string[] = [];
afterEach(() => { vi.useRealTimers(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

type CanaryEvent = Extract<WatchEvent, { event: 'canary' }>;
const canaryEvent = (label: string): CanaryEvent => ({ event: 'canary', time: 't', method: '/lnrpc.Lightning/GetInfo',
  rootKeyId: '0', credential: 'id:0123456789abcdef', label, denied: true });

function entry(label: string, rootKeyId: string, caveats: { type: string; value: string }[] = []) {
  return { nodePubkey: PUBKEY, label, rootKeyId, permissions: ['info:read'], caveats, grade: 'READ',
    fingerprint: 'fp:0123456789abcdef', outPath: null, createdAt: '2026-10-01T00:00:00Z', verified: true,
    status: 'active', revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null };
}

function setup(entries: object[] = [], canaryName?: string) {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'watch-audit-'));
  dirs.push(dir);
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries }));
  if (canaryName) writeFileSync(`${registry}.canary.json`, JSON.stringify({ schema: 1, caveatName: canaryName }));
  writeFileSync(join(dir, 'tls.cert'), 'not used by the fake middleware');
  writeFileSync(join(dir, 'own.macaroon'), vector('default-admin'));
  return { dir, registry, args: ['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', registry] };
}

function alertFile(dir: string): string {
  const path = join(dir, process.platform === 'win32' ? 'alert.exe' : 'alert');
  writeFileSync(path, 'not run: the test injects deps.alert', { mode: 0o755 });
  return path;
}

type Script = { registrations: { name: string }[]; decide: ((call: MiddlewareCall) => string)[];
  end: ((value: MiddlewareEnd) => void)[]; count: number };

function fakeRegister(script: Script): Register {
  return ((_target, registration, decide, onRegistered) => {
    const index = script.count++;
    script.registrations.push(registration);
    script.decide[index] = decide;
    let settle!: (value: MiddlewareEnd) => void;
    const ended = new Promise<MiddlewareEnd>(resolve => { settle = resolve; });
    script.end[index] = settle;
    queueMicrotask(() => onRegistered());
    return { ended, close: () => settle({ registered: true, code: 4, stage: 'middleware-stream', message: 'closed', disabled: false }) };
  }) as Register;
}
const newScript = (): Script => ({ registrations: [], decide: [], end: [], count: 0 });

function call(kind: MiddlewareCall['kind'], requestId: number, method: string, mac: Buffer | null, extra: Partial<MiddlewareCall> = {}): MiddlewareCall {
  return { kind, requestId: BigInt(requestId), method, isError: false, customCaveatCondition: '', macaroon: mac ? new Secret(mac) : null, ...extra };
}

/** Event-loop turns (setImmediate): attribution and canary handling run on these, no timer involved. */
async function turns(n = 3): Promise<void> { for (let i = 0; i < n; i++) await new Promise(resolve => setImmediate(resolve)); }
/** Waits for a condition (polled every millisecond; no fixed delay); the test timeout bounds it. */
async function until(condition: () => boolean): Promise<void> {
  while (!condition()) await new Promise(resolve => setTimeout(resolve, 1));
}

function start(args: string[], register: Register, deps: Partial<Parameters<typeof run>[1]> = {}) {
  const lines: string[] = [];
  const controller = new AbortController();
  let settled = false;
  const result = withCancellation(controller.signal, () => run(args, {
    lnd: { getInfo: async () => ({ pubkey: PUBKEY, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }) } as never,
    register, fs, env: {}, clock: () => new Date('2026-10-08T12:00:00Z'), emit: line => { lines.push(line); },
    alert: async () => undefined, sleep: async () => undefined, hostname: () => hostname(), pid: process.pid, ...deps,
  })).finally(() => { settled = true; });
  return { lines, result, stop: () => controller.abort(), settled: () => settled };
}

// --- alert slots ---------------------------------------------------------------------------

it('WATCH/alert-slots events of different canaries waiting behind a running command all run, in order', async () => {
  const ran: string[] = [];
  const failures: string[] = [];
  const releases: (() => void)[] = [];
  const runner = createAlertRunner(async event => {
    ran.push(event.label!);
    await new Promise<void>(resolve => releases.push(resolve));
  }, event => failures.push(event.label!));
  runner.submit(canaryEvent('A'), 'canary:1');
  runner.submit(canaryEvent('B'), 'canary:2');
  runner.submit(canaryEvent('C'), 'canary:3');
  // A newer event of the waiting canary B replaces B's waiting one, keeping B's place.
  runner.submit(canaryEvent('B2'), 'canary:2');
  expect(ran).toEqual(['A']);
  for (let i = 0; i < 2; i++) { releases.shift()!(); await turns(); }
  releases.shift()!();
  await runner.idle();
  expect(ran).toEqual(['A', 'B2', 'C']);
  expect(failures).toEqual([]);
  expect(runner.replaced()).toBe(1);
});

it('WATCH/alert-slots waiting keys are bounded; one beyond the bound is reported, never silently dropped', async () => {
  const failures: string[] = [];
  let release!: () => void;
  const runner = createAlertRunner(() => new Promise<void>(resolve => { release = resolve; }), event => failures.push(event.label!));
  runner.submit(canaryEvent('running'), 'k-running');
  for (let key = 0; key < MAX_PENDING_ALERTS; key++) runner.submit(canaryEvent(`w${key}`), `k${key}`);
  runner.submit(canaryEvent('beyond'), 'k-beyond');
  expect(failures).toEqual(['beyond']);
  runner.stopping();
  expect(failures).toHaveLength(MAX_PENDING_ALERTS + 1);
  release();
  await runner.idle();
});

it('WATCH/alert-slots three canaries used during one alert command each get their alert command', async () => {
  const conditions = ['1a1e61423be44ea1', '2a1e61423be44ea2', '3a1e61423be44ea3'];
  const s = setup(conditions.map((condition, n) => entry(`decoy${n}`, String(4294967342 + n),
    [{ type: 'lnd-custom', value: `region-a1a2f213 ${condition}` }])), 'region-a1a2f213');
  const script = newScript();
  const ran: string[] = [];
  const releases: (() => void)[] = [];
  const alert = async (_command: string, event: WatchEvent) => {
    ran.push((event as CanaryEvent).label!);
    await new Promise<void>(resolve => releases.push(resolve));
  };
  const decoy = vector('preset-read-only');
  const h = start([...s.args, '--alert-command', alertFile(s.dir)], fakeRegister(script), { alert });
  await until(() => script.count === 2);
  await turns();
  conditions.forEach((condition, n) => script.decide[1](call('request', 10 + n, '/lnrpc.Lightning/GetInfo', decoy,
    { customCaveatCondition: condition })));
  await until(() => ran.length === 1);
  for (let i = 1; i < 3; i++) { releases.shift()!(); await until(() => ran.length === i + 1); }
  releases.shift()!();
  await turns();
  h.stop();
  const result = await h.result;
  expect(ran.sort()).toEqual(['decoy0', 'decoy1', 'decoy2']);
  expect(result).toMatchObject({ ok: true, result: { canaryAlerts: 3, canaryUses: 3, alertFailures: 0 } });
});

// --- monotonic coverage and timers ---------------------------------------------------------

it('USAGE/coverage a wall clock stepping forward is not counted as observed time', () => {
  const store = new UsageStore();
  const t0 = Date.parse('2026-10-08T12:00:00Z');
  store.beginCoverage(PUBKEY, new Date(t0), 0);
  // NTP steps the clock forward 8 days while 5 s really pass.
  store.extendCoverage(PUBKEY, new Date(t0 + 8 * 86_400_000), 5_000);
  store.extendCoverage(PUBKEY, new Date(t0 + 8 * 86_400_000 + 60_000), 65_000);
  store.endCoverage(PUBKEY, new Date(t0 + 8 * 86_400_000 + 60_000), 65_000);
  expect(store.coverageFor(PUBKEY)!.coveredSeconds).toBe(65);
  // Spans hold no more than what really passed, and none of the step.
  expect(store.coveredSince(PUBKEY, t0)).toBeLessThanOrEqual(65);
  // Ordinary time passing is counted in full.
  const steady = new UsageStore();
  steady.beginCoverage(PUBKEY, new Date(t0), 1_000);
  steady.extendCoverage(PUBKEY, new Date(t0 + 30_500), 31_500);
  steady.endCoverage(PUBKEY, new Date(t0 + 90_000), 91_000);
  expect(steady.coverageFor(PUBKEY)!.coveredSeconds).toBe(90);
  expect(steady.coveredSince(PUBKEY, t0)).toBe(90);
});

it('WATCH/coverage-monotonic watch measures coverage on its monotonic source, not a stepping wall clock', async () => {
  const s = setup();
  const script = newScript();
  let wall = Date.parse('2026-10-08T12:00:00Z');
  let mono = 1_000;
  const h = start(s.args, fakeRegister(script), { clock: () => new Date(wall), monotonic: () => mono });
  await until(() => h.lines.some(line => line.includes('watching')) || script.count === 1);
  await turns();
  wall += 9 * 86_400_000;
  mono += 5_000;
  h.stop();
  await h.result;
  const store = UsageStore.parse(readFileSync(`${s.registry}.usage.json`, 'utf8'));
  expect(store.coverageFor(PUBKEY)!.coveredSeconds).toBe(5);
});

it('WATCH/flush-clock-back periodic usage flushes keep running after the wall clock steps back', async () => {
  // Only the interval timers and Date are faked: fs, setImmediate and setTimeout stay real.
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] });
  vi.setSystemTime(new Date('2026-10-08T12:00:00Z'));
  const s = setup();
  const script = newScript();
  const usageFile = `${s.registry}.usage.json`;
  let renames = 0;
  const counting = { ...fs, rename: (async (from, to) => { await fs.rename(from, to); if (String(to) === usageFile) renames += 1; }) as typeof fs.rename };
  let mono = 0;
  const admin = vector('default-admin');
  const h = start(s.args, fakeRegister(script), { fs: counting, clock: () => new Date(), monotonic: () => mono });
  await until(() => script.count === 1);
  await turns();
  script.decide[0](call('request', 1, '/lnrpc.Lightning/GetInfo', admin));
  await turns();
  mono += 5_000;
  vi.advanceTimersByTime(5_000);
  await vi.waitFor(() => expect(renames).toBe(1), { timeout: 30_000, interval: 5 });
  // NTP steps the wall clock back one hour.
  vi.setSystemTime(Date.now() - 3_600_000);
  script.decide[0](call('request', 2, '/lnrpc.Lightning/ListChannels', admin));
  await turns();
  for (let tick = 0; tick < 2; tick++) { mono += 5_000; vi.advanceTimersByTime(5_000); await turns(); }
  await vi.waitFor(() => expect(renames).toBe(2), { timeout: 30_000, interval: 5 });
  const onDisk = JSON.parse(readFileSync(usageFile, 'utf8')) as { entries: { calls: number }[] };
  expect(onDisk.entries.reduce((sum, item) => sum + item.calls, 0)).toBe(2);
  h.stop();
  await h.result;
}, 60_000);

// --- drop notices --------------------------------------------------------------------------

it('WATCH/output-closed after output closed, the drop notice does not count itself every flush', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
  const s = setup();
  const script = newScript();
  const queue = createOutputQueue(async () => { throw Object.assign(new Error('EPIPE'), { code: 'EPIPE' }); });
  const h = start(s.args, fakeRegister(script), { emit: (line, priority) => queue.push(line, priority), dropped: queue.dropped,
    drainOutput: ms => queue.drain(ms), closeOutput: () => queue.close(), settleOutput: ms => queue.settle(ms) });
  await until(() => queue.dropped() >= 1);
  for (let tick = 0; tick < 12; tick++) { vi.advanceTimersByTime(5_000); await turns(); }
  h.stop();
  const result = await h.result;
  expect(result).toMatchObject({ ok: true });
  expect((result.result as { droppedEvents: number }).droppedEvents).toBeLessThanOrEqual(2);
});

// --- stream counting -----------------------------------------------------------------------

it('WATCH/stream-reconnect a stream seen mid-way after a reconnect counts once more, not once per message', async () => {
  const s = setup();
  const script = newScript();
  const admin = vector('default-admin');
  const h = start(s.args, fakeRegister(script));
  await until(() => script.count === 1);
  script.decide[0](call('stream_auth', 7, '/lnrpc.Lightning/ChannelAcceptor', admin));
  await turns();
  script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
  await until(() => script.count === 2);
  await turns();
  for (let message = 0; message < 3; message++) {
    script.decide[1](call('response', 7, '/lnrpc.Lightning/ChannelAcceptor', null));
    script.decide[1](call('request', 7, '/lnrpc.Lightning/ChannelAcceptor', admin));
  }
  await turns();
  h.stop();
  const result = await h.result;
  // Without LND's stream flag (absent here) the first message seen after the reconnect cannot
  // be told apart from a new call; later messages are not new calls. With the flag, see
  // WATCH/stream-flag below.
  expect(result).toMatchObject({ ok: true, result: { calls: 2, reconnects: 1 } });
});

it('WATCH/stream-keys a caller opening more than 50,000 streams cannot make a live stream count again', async () => {
  const s = setup();
  const script = newScript();
  const h = start(s.args, fakeRegister(script));
  await until(() => script.count === 1);
  const observe = script.decide[0];
  const callLines = () => h.lines.length;
  await turns();
  const base = callLines();
  observe(call('stream_auth', 1, '/lnrpc.Lightning/ChannelAcceptor', null));
  let counted = 1;
  for (let batch = 0; batch < 60; batch++) {
    for (let n = 0; n < 1_000; n++) observe(call('stream_auth', 2 + batch * 1_000 + n, '/lnrpc.Lightning/SubscribeInvoices', null));
    counted += 1_000;
    // The live stream sends a message now and then.
    observe(call('request', 1, '/lnrpc.Lightning/ChannelAcceptor', null));
    await until(() => callLines() - base >= counted);
  }
  await turns();
  h.stop();
  const result = await h.result;
  expect(result).toMatchObject({ ok: true, result: { calls: 60_001, droppedAttributions: 0 } });
}, 60_000);

// --- --until before registration -----------------------------------------------------------

it('WATCH/until-before-register --until running out before LND confirms the registration says so', async () => {
  const s = setup();
  const silent: Register = (() => {
    let end!: (value: MiddlewareEnd) => void;
    const ended = new Promise<MiddlewareEnd>(resolve => { end = resolve; });
    return { ended, close: () => end({ registered: false, code: 4, stage: 'middleware-stream', message: 'closed', disabled: false }) };
  }) as Register;
  const h = start([...s.args, '--until', '1s'], silent);
  const result = await h.result;
  expect(result).toMatchObject({ ok: false, error: { code: 4, step: 'W7' } });
  expect(result.error!.message).toContain('--until expired before LND confirmed the middleware registration');
  expect(result.error!.message).toContain('localhost:10009');
  expect(result.error!.message).not.toMatch(/could not register/);
});

// --- node identity on reconnect ------------------------------------------------------------

it('WATCH/node-changed a different node behind the endpoint after a reconnect ends the run', async () => {
  const s = setup();
  const script = newScript();
  const pubkeys = [PUBKEY, OTHER];
  let asked = 0;
  const lnd = { getInfo: async () => ({ pubkey: pubkeys[Math.min(asked++, 1)], alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }) } as never;
  const h = start(s.args, fakeRegister(script), { lnd });
  await until(() => script.count === 1);
  await turns();
  script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
  await until(() => h.settled() || script.count === 2);
  h.stop();
  const result = await h.result;
  expect(script.count).toBe(1);
  expect(result).toMatchObject({ ok: false, error: { code: 4, step: 'W5' } });
  expect(result.error!.message).toContain(OTHER);
});

it('WATCH/node-same the same node after a reconnect is registered again', async () => {
  const s = setup();
  const script = newScript();
  const h = start(s.args, fakeRegister(script));
  await until(() => script.count === 1);
  await turns();
  script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
  await until(() => script.count === 2);
  h.stop();
  expect(await h.result).toMatchObject({ ok: true, result: { reconnects: 1 } });
});

// --- attribution queue charging ------------------------------------------------------------

it('WATCH/response-bytes responses are not charged their macaroon size in the attribution queue', async () => {
  const s = setup();
  const script = newScript();
  const h = start(s.args, fakeRegister(script));
  await until(() => script.count === 1);
  await turns();
  const large = 60 * 1024;
  // In one turn, so nothing drains in between: 200 requests fit the 16 MiB queue, their
  // responses must not push it over.
  for (let n = 0; n < 200; n++) {
    script.decide[0](call('request', n, '/lnrpc.Lightning/GetInfo', null, { macaroonBytes: large }));
    script.decide[0](call('response', n, '/lnrpc.Lightning/GetInfo', null, { macaroonBytes: large }));
  }
  await turns();
  h.stop();
  expect(await h.result).toMatchObject({ ok: true, result: { calls: 200, droppedAttributions: 0 } });
});

// --- session isolation of deferred attribution ---------------------------------------------

it('WATCH/session-isolation attribution queued by a lost session never correlates with a reused request ID of the next', async () => {
  const s = setup();
  const admin = vector('default-admin');
  const app = vector('preset-read-only');
  const script = newScript();
  const lines: string[] = [];
  const old = () => lines.filter(line => line.includes('SubscribeChannelEvents')).length;
  let oldAtReconnect = -1;
  const base = fakeRegister(script);
  // Notes, when the next session registers, whether the lost session's work was still queued.
  const register = ((...args: Parameters<Register>) => {
    const session = base(...args);
    if (script.count === 2) oldAtReconnect = old();
    return session;
  }) as Register;
  const h = start([...s.args, '--json'], register, { emit: line => { lines.push(line); } });
  await until(() => script.count === 1);
  await turns();
  // In one turn: a backlog of ordinary calls, then a stream opened under request ID 5, then
  // the session is lost; attribution of all of it is still queued when the next one begins.
  for (let n = 0; n < 5_000; n++) script.decide[0](call('request', 1_000 + n, '/lnrpc.Lightning/GetInfo', null));
  script.decide[0](call('stream_auth', 5, '/lnrpc.Lightning/SubscribeChannelEvents', admin));
  script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
  await until(() => script.count === 2);
  // LND restarted request IDs: ID 5 is now a different call by a different credential.
  script.decide[1](call('request', 5, '/lnrpc.Lightning/WalletBalance', app));
  script.decide[1](call('response', 5, '/lnrpc.Lightning/WalletBalance', null, { isError: true }));
  await until(() => lines.some(line => line.includes('"event":"error"')) || lines.filter(line => line.includes('"event":"call"')).length >= 5_002);
  await turns();
  h.stop();
  const result = await h.result;
  // Precondition: the lost session's stream was attributed only after the next session began.
  expect(oldAtReconnect).toBe(0);
  expect(result).toMatchObject({ ok: true, result: { calls: 5_002, errors: 1, reconnects: 1, droppedAttributions: 0 } });
  const events = lines.map(line => JSON.parse(line) as { event: string; method?: string; credential?: string });
  const wallet = events.find(event => event.event === 'call' && event.method === '/lnrpc.Lightning/WalletBalance');
  const stream = events.find(event => event.event === 'call' && event.method === '/lnrpc.Lightning/SubscribeChannelEvents');
  expect(wallet).toBeDefined();
  expect(wallet!.credential).not.toBe(stream!.credential);
  expect(events.filter(event => event.event === 'error')).toEqual([
    expect.objectContaining({ method: '/lnrpc.Lightning/WalletBalance', credential: wallet!.credential })]);
}, 60_000);

it('WATCH/session-isolation a response of a lost session still queued at the reconnect is recorded before its IDs are forgotten', async () => {
  const s = setup();
  const admin = vector('default-admin');
  const app = vector('preset-read-only');
  const script = newScript();
  const lines: string[] = [];
  const errorsSeen = () => lines.filter(line => line.includes('"event":"error"')).length;
  let errorsAtReconnect = -1;
  const base = fakeRegister(script);
  // Notes, when the next session registers, whether the lost session's error was still queued.
  const register = ((...args: Parameters<Register>) => {
    const session = base(...args);
    if (script.count === 2) errorsAtReconnect = errorsSeen();
    return session;
  }) as Register;
  const h = start([...s.args, '--json'], register, { emit: line => { lines.push(line); } });
  await until(() => script.count === 1);
  await turns();
  // A stream opened under request ID 5 and attributed (its key is known to this session).
  script.decide[0](call('stream_auth', 5, '/lnrpc.Lightning/SubscribeChannelEvents', admin, { streamRpc: true }));
  await turns();
  // In one turn: a backlog of ordinary calls, then the stream's final error, then the session is
  // lost; the error's attribution is still queued when the next session begins.
  for (let n = 0; n < 5_000; n++) script.decide[0](call('request', 1_000 + n, '/lnrpc.Lightning/GetInfo', null));
  script.decide[0](call('response', 5, '/lnrpc.Lightning/SubscribeChannelEvents', null, { streamRpc: true, isError: true }));
  script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
  await until(() => script.count === 2);
  // LND restarted request IDs: ID 5 is now a different call by a different credential.
  script.decide[1](call('request', 5, '/lnrpc.Lightning/WalletBalance', app));
  script.decide[1](call('response', 5, '/lnrpc.Lightning/WalletBalance', null, { isError: true }));
  await until(() => lines.filter(line => line.includes('"event":"call"')).length >= 5_002);
  await turns();
  h.stop();
  const result = await h.result;
  // Precondition: the lost session's error was still queued when the next session began.
  expect(errorsAtReconnect).toBe(0);
  expect(result).toMatchObject({ ok: true, result: { calls: 5_002, errors: 2, reconnects: 1, droppedAttributions: 0 } });
  const events = lines.map(line => JSON.parse(line) as { event: string; method?: string; credential?: string });
  const stream = events.find(event => event.event === 'call' && event.method === '/lnrpc.Lightning/SubscribeChannelEvents');
  const wallet = events.find(event => event.event === 'call' && event.method === '/lnrpc.Lightning/WalletBalance');
  expect(stream!.credential).toBe(macaroonId(new Secret(admin)).id);
  expect(wallet!.credential).toBe(macaroonId(new Secret(app)).id);
  // The lost session's error, then the next session's, each under its own credential.
  expect(events.filter(event => event.event === 'error')).toEqual([
    expect.objectContaining({ method: '/lnrpc.Lightning/SubscribeChannelEvents', credential: stream!.credential }),
    expect.objectContaining({ method: '/lnrpc.Lightning/WalletBalance', credential: wallet!.credential })]);
  const usage = JSON.parse(readFileSync(`${s.registry}.usage.json`, 'utf8')) as { entries: { method: string; calls: number; errors: number }[] };
  expect(usage.entries).toContainEqual(expect.objectContaining({ method: '/lnrpc.Lightning/SubscribeChannelEvents', calls: 1, errors: 1 }));
}, 60_000);

// --- streams that outlive a session ------------------------------------------------------------
// LND numbers requests per process (rpcperms/interceptor.go lastRequestID), not per middleware
// session: a server-streaming RPC opened under session N keeps its ID and is still intercepted
// after watch re-registers, so its later responses and final error arrive in session N+1.

it('WATCH/stream-carried the final error of a stream opened before an interceptor-only reconnect is counted under the credential that opened it', async () => {
  const s = setup();
  const admin = vector('default-admin');
  const script = newScript();
  const lines: string[] = [];
  const h = start([...s.args, '--json'], fakeRegister(script), { emit: line => { lines.push(line); } });
  await until(() => script.count === 1);
  await turns();
  // Session 1: SubscribeInvoices opened (stream_auth, then its single request message), one update delivered.
  script.decide[0](call('stream_auth', 5, '/lnrpc.Lightning/SubscribeInvoices', admin, { streamRpc: true }));
  script.decide[0](call('request', 5, '/lnrpc.Lightning/SubscribeInvoices', admin, { streamRpc: true }));
  script.decide[0](call('response', 5, '/lnrpc.Lightning/SubscribeInvoices', null, { streamRpc: true }));
  await until(() => lines.some(line => line.includes('"event":"call"')));
  await turns();
  // Only the interceptor stream is lost; LND keeps running and the subscription stays open.
  script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
  await until(() => script.count === 2);
  await turns(10);
  // The subscription's final error arrives in session 2 with the ID it was opened under.
  script.decide[1](call('response', 5, '/lnrpc.Lightning/SubscribeInvoices', null, { streamRpc: true, isError: true }));
  await until(() => lines.some(line => line.includes('"event":"error"')));
  await turns();
  h.stop();
  const result = await h.result;
  expect(result).toMatchObject({ ok: true, result: { errors: 1, calls: 1, reconnects: 1, droppedAttributions: 0 } });
  const events = lines.map(line => JSON.parse(line) as { event: string; method?: string; credential?: string });
  expect(events.filter(event => event.event === 'error')).toEqual([
    expect.objectContaining({ method: '/lnrpc.Lightning/SubscribeInvoices', credential: macaroonId(new Secret(admin)).id })]);
  const usage = JSON.parse(readFileSync(`${s.registry}.usage.json`, 'utf8')) as { entries: { method: string; calls: number; errors: number }[] };
  expect(usage.entries).toContainEqual(expect.objectContaining({ method: '/lnrpc.Lightning/SubscribeInvoices', calls: 1, errors: 1 }));
}, 60_000);

it('WATCH/stream-carried a new stream_auth reusing the ID after a reconnect (LND restarted) forgets the carried stream; its error counts under the new credential', async () => {
  const s = setup();
  const admin = vector('default-admin');
  const app = vector('preset-read-only');
  const script = newScript();
  const lines: string[] = [];
  const h = start([...s.args, '--json'], fakeRegister(script), { emit: line => { lines.push(line); } });
  await until(() => script.count === 1);
  await turns();
  script.decide[0](call('stream_auth', 5, '/lnrpc.Lightning/SubscribeInvoices', admin, { streamRpc: true }));
  script.decide[0](call('request', 5, '/lnrpc.Lightning/SubscribeInvoices', admin, { streamRpc: true }));
  await until(() => lines.some(line => line.includes('"event":"call"')));
  await turns();
  script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
  await until(() => script.count === 2);
  await turns(10);
  // LND restarted, so every earlier stream is gone and ID 5 opens a new stream by another credential.
  script.decide[1](call('stream_auth', 5, '/lnrpc.Lightning/SubscribeInvoices', app, { streamRpc: true }));
  script.decide[1](call('request', 5, '/lnrpc.Lightning/SubscribeInvoices', app, { streamRpc: true }));
  script.decide[1](call('response', 5, '/lnrpc.Lightning/SubscribeInvoices', null, { streamRpc: true, isError: true }));
  await until(() => lines.some(line => line.includes('"event":"error"')));
  await turns();
  h.stop();
  const result = await h.result;
  expect(result).toMatchObject({ ok: true, result: { errors: 1, calls: 2, reconnects: 1, droppedAttributions: 0 } });
  const events = lines.map(line => JSON.parse(line) as { event: string; method?: string; credential?: string });
  expect(events.filter(event => event.event === 'error')).toEqual([
    expect.objectContaining({ method: '/lnrpc.Lightning/SubscribeInvoices', credential: macaroonId(new Secret(app)).id })]);
  const usage = JSON.parse(readFileSync(`${s.registry}.usage.json`, 'utf8')) as { entries: { credential: string; method: string; calls: number; errors: number }[] };
  expect(usage.entries).toContainEqual(expect.objectContaining({ credential: macaroonId(new Secret(admin)).id, method: '/lnrpc.Lightning/SubscribeInvoices', calls: 1, errors: 0 }));
  expect(usage.entries).toContainEqual(expect.objectContaining({ credential: macaroonId(new Secret(app)).id, method: '/lnrpc.Lightning/SubscribeInvoices', calls: 1, errors: 1 }));
}, 60_000);

// --- the remembered set holds open streams only -----------------------------------------------

it('WATCH/stream-idle an idle server stream outlives 50,000 unary calls answered meanwhile: its final error is counted', async () => {
  const s = setup();
  const admin = vector('default-admin');
  const script = newScript();
  const lines: string[] = [];
  const calls = () => lines.filter(line => line.includes('"event":"call"')).length;
  const h = start([...s.args, '--json'], fakeRegister(script), { emit: line => { lines.push(line); } });
  await until(() => script.count === 1);
  await turns();
  script.decide[0](call('stream_auth', 99_999, '/lnrpc.Lightning/SubscribeChannelEvents', admin, { streamRpc: true }));
  script.decide[0](call('request', 99_999, '/lnrpc.Lightning/SubscribeChannelEvents', admin, { streamRpc: true }));
  await until(() => calls() === 1);
  // 50,000 unary calls, each answered, paced so attribution drains between batches.
  for (let batch = 0; batch < 50; batch++) {
    for (let n = 0; n < 1_000; n++) {
      const id = batch * 1_000 + n;
      script.decide[0](call('request', id, '/lnrpc.Lightning/GetInfo', admin));
      script.decide[0](call('response', id, '/lnrpc.Lightning/GetInfo', null));
    }
    await until(() => calls() === 1 + (batch + 1) * 1_000);
  }
  // The idle stream's final error (it sent no further request meanwhile).
  script.decide[0](call('response', 99_999, '/lnrpc.Lightning/SubscribeChannelEvents', null, { streamRpc: true, isError: true }));
  await turns(20);
  h.stop();
  const result = await h.result;
  expect(result).toMatchObject({ ok: true, result: { calls: 50_001, errors: 1, droppedAttributions: 0 } });
  const events = lines.map(line => JSON.parse(line) as { event: string; method?: string; credential?: string });
  expect(events.filter(event => event.event === 'error')).toEqual([
    expect.objectContaining({ method: '/lnrpc.Lightning/SubscribeChannelEvents', credential: macaroonId(new Secret(admin)).id })]);
}, 60_000);

it('WATCH/stream-evicted a stream forgotten at the 50,000 limit by 50,000 further open streams counts as a dropped attribution', async () => {
  const s = setup();
  const admin = vector('default-admin');
  const script = newScript();
  const lines: string[] = [];
  const calls = () => lines.filter(line => line.includes('"event":"call"')).length;
  const h = start([...s.args, '--json'], fakeRegister(script), { emit: line => { lines.push(line); } });
  await until(() => script.count === 1);
  await turns();
  script.decide[0](call('stream_auth', 1, '/lnrpc.Lightning/SubscribeChannelEvents', admin, { streamRpc: true }));
  await until(() => calls() === 1);
  // 50,000 more streams by a recorded credential, left open: the first stream is the least recently seen.
  for (let batch = 0; batch < 50; batch++) {
    for (let n = 0; n < 1_000; n++) script.decide[0](call('stream_auth', 2 + batch * 1_000 + n, '/lnrpc.Lightning/SubscribeInvoices', admin, { streamRpc: true }));
    await until(() => calls() === 1 + (batch + 1) * 1_000);
  }
  script.decide[0](call('response', 1, '/lnrpc.Lightning/SubscribeChannelEvents', null, { streamRpc: true, isError: true }));
  await turns(20);
  h.stop();
  const result = await h.result;
  // The forgotten stream's error cannot be attributed; the loss is counted, so usage is marked incomplete.
  expect(result).toMatchObject({ ok: true, result: { calls: 50_001, errors: 0, droppedAttributions: 1 } });
  const usage = JSON.parse(readFileSync(`${s.registry}.usage.json`, 'utf8')) as { droppedAttributions: number };
  expect(usage.droppedAttributions).toBe(1);
}, 60_000);

// --- the stream flag ------------------------------------------------------------------------

it('LND/middleware-proto RPCMessage.stream_rpc (field 2) is decoded; false or absent is false; stream_auth is a stream', () => {
  // RPCMiddlewareRequest{request_id 1, msg_id 7, request 5 | response 6 | stream_auth 4}; RPCMessage{method 1, stream_rpc 2, is_error 5}.
  const frame = (kind: number, rpc: Buffer) => message(uint(1, 7), bytes(kind, rpc), uint(7, 9));
  const method = '/lnrpc.Lightning/SubscribeChannelEvents';
  expect(decodeMiddlewareRequest(frame(5, message(bytes(1, method), uint(2, 1))))).toMatchObject({ kind: 'request', method, streamRpc: true });
  expect(decodeMiddlewareRequest(frame(6, message(bytes(1, method), uint(2, 1), uint(5, 1)))))
    .toMatchObject({ kind: 'response', streamRpc: true, isError: true });
  expect(decodeMiddlewareRequest(frame(5, message(bytes(1, method), uint(2, 0))))).toMatchObject({ kind: 'request', streamRpc: false });
  expect(decodeMiddlewareRequest(frame(5, bytes(1, method)))).toMatchObject({ kind: 'request', streamRpc: false });
  expect(decodeMiddlewareRequest(frame(4, bytes(1, method)))).toMatchObject({ kind: 'stream_auth', streamRpc: true });
  // The flag of one message never leaks into the next decode.
  expect(decodeMiddlewareRequest(message(uint(1, 8), bytes(5, bytes(1, '/lnrpc.Lightning/GetInfo')), uint(7, 10))).streamRpc).toBe(false);
});

it('WATCH/stream-flag a stream already open at reconnect counts once: its later messages carry the stream flag', async () => {
  const s = setup();
  const script = newScript();
  const admin = vector('default-admin');
  const h = start(s.args, fakeRegister(script));
  await until(() => script.count === 1);
  script.decide[0](call('stream_auth', 7, '/lnrpc.Lightning/SubscribeChannelEvents', admin, { streamRpc: true }));
  await turns();
  script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
  await until(() => script.count === 2);
  await turns();
  for (let n = 0; n < 3; n++) {
    script.decide[1](call('response', 7, '/lnrpc.Lightning/SubscribeChannelEvents', null, { streamRpc: true }));
    script.decide[1](call('request', 7, '/lnrpc.Lightning/SubscribeChannelEvents', admin, { streamRpc: true }));
  }
  // The stream's final error is still recorded, once.
  script.decide[1](call('response', 7, '/lnrpc.Lightning/SubscribeChannelEvents', null, { streamRpc: true, isError: true }));
  await turns();
  h.stop();
  expect(await h.result).toMatchObject({ ok: true, result: { calls: 1, errors: 1, reconnects: 1 } });
});

it('WATCH/stream-flag with the flag, unary calls and newly opened streams are still counted once each', async () => {
  const s = setup();
  const script = newScript();
  const admin = vector('default-admin');
  const h = start(s.args, fakeRegister(script));
  await until(() => script.count === 1);
  script.decide[0](call('request', 1, '/lnrpc.Lightning/GetInfo', admin, { streamRpc: false }));
  script.decide[0](call('response', 1, '/lnrpc.Lightning/GetInfo', null, { streamRpc: false }));
  script.decide[0](call('stream_auth', 2, '/lnrpc.Lightning/SubscribeInvoices', admin, { streamRpc: true }));
  script.decide[0](call('request', 2, '/lnrpc.Lightning/SubscribeInvoices', admin, { streamRpc: true }));
  await turns();
  h.stop();
  expect(await h.result).toMatchObject({ ok: true, result: { calls: 2 } });
});

// --- oversized macaroon with a padded location ----------------------------------------------

it('LND/middleware-proto an oversized macaroon whose location is padded still yields its header identity', () => {
  const admin = vector('default-admin');
  // v2: version 2, location packet (type 1), identifier packet (type 2), end of section, caveats.
  expect([admin[0], admin[1]]).toEqual([2, 1]);
  const afterLocation = 3 + admin[2];
  // Synthetic: the unsigned location is padded to 20 KiB, pushing the identifier past 4 KiB.
  const relocated = (size: number) => Buffer.concat([Buffer.from([2, 1]), varint(size), Buffer.alloc(size, 0x78), admin.subarray(afterLocation)]);
  const oversized = (mac: Buffer) => Buffer.concat([mac, Buffer.alloc(Math.max(0, MAX_MACAROON_BYTES + 1 - mac.length), 0x61)]);
  const decode = (mac: Buffer) => decodeMiddlewareRequest(middlewareRequest({ method: '/lnrpc.Lightning/GetInfo', serialized: Buffer.alloc(1), macaroon: mac }));
  const padded = oversized(relocated(20 * 1024));
  const request = decode(padded);
  expect(request.oversizedMacaroon).toBe(true);
  expect(request.rawMacaroon.length).toBeGreaterThan(OVERSIZED_MACAROON_PREFIX_BYTES);
  expect(request.rawMacaroon.length).toBeLessThanOrEqual(MAX_MACAROON_BYTES);
  expect(macaroonId(new Secret(request.rawMacaroon)).id).toBe(macaroonId(new Secret(admin)).id);
  // A header that does not end within the bound falls back to the fixed prefix (fails closed).
  const unbounded = oversized(relocated(MAX_MACAROON_BYTES));
  expect(decode(unbounded).rawMacaroon.length).toBe(OVERSIZED_MACAROON_PREFIX_BYTES);
  // Not a v2 header: the fixed prefix.
  expect(decode(Buffer.alloc(MAX_MACAROON_BYTES + 1, 0x61)).rawMacaroon.length).toBe(OVERSIZED_MACAROON_PREFIX_BYTES);
});
