import { spawn, spawnSync } from 'node:child_process';
import { getEventListeners } from 'node:events';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { UsageStore, writeUsage } from '../src/watch/usage.js';
import { ALERT_KILL_MS } from '../src/watch/alert.js';
import { afterEach, expect, it, vi } from 'vitest';
import { withCancellation } from '../src/cancellation.js';
import { MAX_TIMER_MS, run, scheduleDeadline, type Register } from '../src/commands/watch.js';
import { addFirstPartyCaveat } from '../src/decode/index.js';
import type { MiddlewareCall, MiddlewareEnd } from '../src/lnd/index.js';
import type { WatchEvent } from '../src/output/index.js';
import { Secret } from '../src/secret.js';
import { render } from '../src/output/index.js';
import { expectDocumentValid, expectSchemaValid, expectWatchEventValid } from './helpers/output-schema.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const vector = (name: string) => readFileSync(join(repo, 'test/vectors', `${name}.macaroon`));
const PUBKEY = `02${'ab'.repeat(32)}`;
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

// Independent identity: SHA-256 of the identifier packet (macaroon v2: version byte, then
// [type][length][data] packets; the identifier is packet type 2 in the header section).
function identityOf(bytes: Buffer): string {
  const varint = (at: number): [number, number] => { let value = 0, shift = 0; for (;;) { const b = bytes[at++]; value += (b & 0x7f) * 2 ** shift; if (!(b & 0x80)) return [value, at]; shift += 7; } };
  let at = 1;
  for (;;) {
    const [type, afterType] = varint(at);
    const [length, start] = varint(afterType);
    if (type === 2) return `id:${createHash('sha256').update(bytes.subarray(start, start + length)).digest('hex').slice(0, 16)}`;
    at = start + length;
  }
}

function entry(label: string, rootKeyId: string, caveats: { type: string; value: string }[] = []) {
  return { nodePubkey: PUBKEY, label, rootKeyId, permissions: ['info:read'], caveats, grade: 'READ',
    fingerprint: 'fp:0123456789abcdef', outPath: null, createdAt: '2026-10-01T00:00:00Z', verified: true,
    status: 'active', revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null };
}

function setup(entries: object[] = [], canaryName?: string, own = 'default-admin') {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'watch-cmd-'));
  dirs.push(dir);
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries }));
  if (canaryName) writeFileSync(`${registry}.canary.json`, JSON.stringify({ schema: 1, caveatName: canaryName }));
  writeFileSync(join(dir, 'tls.cert'), 'not used by the fake middleware');
  writeFileSync(join(dir, 'own.macaroon'), vector(own));
  return { dir, registry, args: ['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', registry] };
}

/** A real executable file for --alert-command validation; the test injects deps.alert, so it never runs. */
function alertFile(dir: string): string {
  const path = join(dir, process.platform === 'win32' ? 'alert.exe' : 'alert');
  writeFileSync(path, 'not run: the test injects deps.alert', { mode: 0o755 });
  return path;
}

type Script = { registrations: { name: string; readOnly: boolean; caveatName?: string }[];
  decide: ((call: MiddlewareCall) => string)[]; end: ((value: MiddlewareEnd) => void)[]; ready: Promise<void> };

/** A scripted middleware session: the test drives intercepts and decides when sessions end. */
function fakeRegister(script: Script, onRegister?: (index: number) => void): Register {
  let count = 0;
  let notify!: () => void;
  script.ready = new Promise(resolve => { notify = resolve; });
  return ((_target, registration, decide, onRegistered) => {
    const index = count++;
    script.registrations.push(registration);
    script.decide[index] = decide;
    let settle!: (value: MiddlewareEnd) => void;
    const ended = new Promise<MiddlewareEnd>(resolve => { settle = resolve; });
    script.end[index] = settle;
    queueMicrotask(() => { onRegistered(); onRegister?.(index); notify(); });
    return { ended, close: () => settle({ registered: true, code: 4, stage: 'middleware-stream', message: 'closed', disabled: false }) };
  }) as Register;
}

function call(kind: MiddlewareCall['kind'], requestId: number, method: string, mac: Buffer | null, extra: Partial<MiddlewareCall> = {}): MiddlewareCall {
  return { kind, requestId: BigInt(requestId), method, isError: false, customCaveatCondition: '', macaroon: mac ? new Secret(mac) : null, ...extra };
}

const settle = () => new Promise(resolve => setTimeout(resolve, 20));

async function watchUntil(args: string[], register: Register, drive: (stop: () => void) => Promise<void>,
  extra: { alerts?: WatchEvent[]; sleeps?: number[]; deps?: Partial<Parameters<typeof run>[1]> } = {}) {
  const lines: string[] = [];
  const controller = new AbortController();
  const result = withCancellation(controller.signal, () => run(args, {
    lnd: { getInfo: async () => ({ pubkey: PUBKEY, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }) } as never,
    register, fs, env: {}, clock: () => new Date('2026-10-08T12:00:00Z'), emit: line => { lines.push(line); },
    alert: async (_command, event) => { extra.alerts?.push(event); }, sleep: async ms => { extra.sleeps?.push(ms); },
    hostname: () => hostname(), pid: process.pid, ...extra.deps,
  }));
  await drive(() => controller.abort());
  const settled = await result;
  // Every run's final document, and every --json event line, matches the shipped schemas.
  expectSchemaValid(settled);
  if (args.includes('--json')) for (const line of lines) expectWatchEventValid(line);
  return { result: settled, lines };
}

it('WATCH/attribution calls are attributed per baked credential; client caveats do not split identities', async () => {
  const app = vector('preset-read-only');
  const admin = vector('default-admin');
  // lncli adds a fresh timeout caveat per call: different bytes, same baked credential.
  const first = addFirstPartyCaveat(new Secret(app), 'time-before 2026-10-08T12:01:00Z');
  const second = addFirstPartyCaveat(new Secret(app), 'time-before 2026-10-08T12:01:05Z');
  const s = setup([entry('app1', '4294967341')]);
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const { result, lines } = await watchUntil([...s.args, '--json'], fakeRegister(script), async stop => {
    await script.ready;
    const observe = script.decide[0];
    expect(observe(call('request', 1, '/lnrpc.Lightning/GetInfo', null, { macaroon: first }))).toBe('');
    expect(observe(call('request', 2, '/lnrpc.Lightning/GetInfo', null, { macaroon: second }))).toBe('');
    // A stream: stream_auth then a request with the same request ID counts once.
    observe(call('stream_auth', 3, '/lnrpc.Lightning/SubscribeInvoices', admin));
    observe(call('request', 3, '/lnrpc.Lightning/SubscribeInvoices', admin));
    // An error response is attributed to its request.
    observe(call('request', 4, '/lnrpc.Lightning/ListChannels', admin));
    observe(call('response', 4, '/lnrpc.Lightning/ListChannels', admin, { isError: true }));
    await settle();
    stop();
  });
  expect(script.registrations).toEqual([{ name: 'macwarden-watch', readOnly: true }]);
  expect(result).toMatchObject({ ok: true, result: { calls: 4, errors: 1, credentials: 2, canaryAlerts: 0, reconnects: 0 } });
  const events = lines.map(line => JSON.parse(line) as Extract<WatchEvent, { event: 'call' | 'error' }> & { schema: number });
  const calls = events.filter(event => event.event === 'call');
  expect(calls.map(event => [event.method, 'credential' in event ? event.credential : '', 'label' in event ? event.label : ''])).toEqual([
    ['/lnrpc.Lightning/GetInfo', identityOf(app), null],
    ['/lnrpc.Lightning/GetInfo', identityOf(app), null],
    ['/lnrpc.Lightning/SubscribeInvoices', identityOf(admin), null],
    ['/lnrpc.Lightning/ListChannels', identityOf(admin), null],
  ]);
  // The read-only vector uses root key 0: never attributed to a label.
  expect(calls[0]).toMatchObject({ rootKeyId: '0' });
  const usage = JSON.parse(readFileSync(`${s.registry}.usage.json`, 'utf8'));
  // The file is written in recency order (no sorting on the hot path), so compare as a set.
  const byKey = (a: unknown[], b: unknown[]) => `${a[0]}${a[1]}`.localeCompare(`${b[0]}${b[1]}`);
  expect(usage.entries.map((record: Record<string, unknown>) => [record.credential, record.method, record.calls, record.errors]).sort(byKey)).toEqual(
    [[identityOf(app), '/lnrpc.Lightning/GetInfo', 2, 0], [identityOf(admin), '/lnrpc.Lightning/ListChannels', 1, 1],
      [identityOf(admin), '/lnrpc.Lightning/SubscribeInvoices', 1, 0]].sort((a, b) => `${a[0]}${a[1]}`.localeCompare(`${b[0]}${b[1]}`)));
  // No macaroon bytes in any form reach output or the usage file.
  const text = lines.join('') + readFileSync(`${s.registry}.usage.json`, 'utf8');
  for (const bytes of [app, admin, Buffer.from(first.fingerprint)])
    for (const form of [bytes.toString('hex'), bytes.toString('base64'), bytes.toString('base64url')])
      if (form.length > 40) expect(text).not.toContain(form);
  expect(existsSync(`${s.registry}.watch.lock`)).toBe(false);
});

it('WATCH/labels a registered non-zero root key is attributed to its label', async () => {
  const s = setup([entry('app1', '18446744073709551615')]);
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const { lines } = await watchUntil(s.args, fakeRegister(script), async stop => {
    await script.ready;
    script.decide[0](call('request', 1, '/lnrpc.Lightning/AddInvoice', vector('root-max')));
    await settle();
    stop();
  });
  expect(lines.find(line => line.includes('AddInvoice'))).toBe(
    `2026-10-08T12:00:00.000Z  /lnrpc.Lightning/AddInvoice  root key 18446744073709551615  ${identityOf(vector('root-max'))}  app1
`);
});

it('WATCH/canary a canary caveat is guarded: the call is denied, alerted once and the alert carries no secret', async () => {
  const s = setup([entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }])], 'region-a1a2f213');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const alerts: WatchEvent[] = [];
  const decoy = vector('preset-read-only');
  const { result, lines } = await watchUntil([...s.args, '--alert-command', alertFile(s.dir)],
    fakeRegister(script), async stop => {
      await script.ready;
      await settle();
      expect(script.registrations).toEqual([{ name: 'macwarden-watch', readOnly: true },
        { name: 'macwarden-watch-guard', readOnly: false, caveatName: 'region-a1a2f213' }]);
      expect(script.decide[1](call('request', 9, '/lnrpc.Lightning/GetInfo', decoy, { customCaveatCondition: '3a1e61423be44eaf' })))
        .toBe('permission denied');
      // Responses to an already denied call are not re-denied.
      expect(script.decide[1](call('response', 9, '/lnrpc.Lightning/GetInfo', decoy))).toBe('');
      await settle();
      stop();
    }, { alerts });
  expect(result).toMatchObject({ ok: true, result: { canaryAlerts: 1, canaries: 1 } });
  expect(alerts).toEqual([{ event: 'canary', time: '2026-10-08T12:00:00.000Z', method: '/lnrpc.Lightning/GetInfo',
    rootKeyId: '0', credential: identityOf(decoy), label: 'decoy', denied: true }]);
  expect(lines.find(line => line.includes('ALERT'))).toBe(
    `2026-10-08T12:00:00.000Z  ALERT canary decoy used: /lnrpc.Lightning/GetInfo  root key 0  ${identityOf(decoy)}  decoy  request denied\n`);
  expect(JSON.stringify(alerts)).not.toContain(decoy.toString('hex').slice(0, 40));
});

it('WATCH/canary-flood thousands of canary uses are all denied but alert at most twice, one alert command at a time', async () => {
  // Whoever holds the canary controls the request rate; alerting must stay bounded.
  const s = setup([entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }])], 'region-a1a2f213');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const decoy = vector('preset-read-only');
  const runs: WatchEvent[] = [];
  let running = 0, peak = 0;
  const slowAlert = async (_command: string, event: WatchEvent) => {
    running += 1; peak = Math.max(peak, running); runs.push(event);
    await new Promise(resolve => setTimeout(resolve, 20));
    running -= 1;
  };
  let denied = 0;
  const { result, lines } = await watchUntil([...s.args, '--alert-command', alertFile(s.dir)],
    fakeRegister(script), async stop => {
      await script.ready;
      await settle();
      for (let n = 0; n < 5_000; n++)
        if (script.decide[1](call('request', 10 + n, '/lnrpc.Lightning/GetInfo', decoy, { customCaveatCondition: '3a1e61423be44eaf' })) === 'permission denied') denied += 1;
      await settle();
      // Stop once the first alert command finished: the shutdown flush then runs the summary
      // (a summary still waiting behind a running command at shutdown is discarded, MW102-05).
      for (let i = 0; i < 100 && (running || runs.length === 0); i++) await settle();
      stop();
    }, { deps: { alert: slowAlert } });
  expect(denied).toBe(5_000);
  expect(result).toMatchObject({ ok: true, result: { canaryUses: 5_000, canaryAlerts: 2 } });
  // The first use alerts at once; the rest arrive as one counted summary.
  expect(runs.map(event => (event as { repeats?: number }).repeats)).toEqual([undefined, 4_999]);
  expect(peak).toBe(1);
  expect(lines.filter(line => line.includes('ALERT canary'))).toHaveLength(2);
  expect(lines.find(line => line.includes('+4999 more denied uses since the last alert'))).toBeDefined();
});

it('WATCH/canary-churn conditions an attacker invents share one alert bucket: thousands of them alert at most twice', async () => {
  // Anyone holding a canary can append custom caveats, so the condition string is attacker data.
  const s = setup([entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }])], 'region-a1a2f213');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const decoy = vector('preset-read-only');
  const alerts: WatchEvent[] = [];
  let denied = 0;
  const { result } = await watchUntil([...s.args, '--alert-command', alertFile(s.dir)], fakeRegister(script), async stop => {
    await script.ready;
    await settle();
    for (let n = 0; n < 5_000; n++) {
      const condition = n.toString(16).padStart(16, 'f');
      if (script.decide[1](call('request', 10 + n, '/lnrpc.Lightning/GetInfo', decoy, { customCaveatCondition: condition })) === 'permission denied') denied += 1;
    }
    await settle();
    stop();
  }, { alerts });
  expect(denied).toBe(5_000);
  expect(result).toMatchObject({ ok: true, result: { canaryUses: 5_000, canaryAlerts: 2 } });
  expect(alerts.map(event => (event as { repeats?: number }).repeats)).toEqual([undefined, 4_999]);
});

it('WATCH/credential-cap a node sending ever more distinct credentials cannot grow the summary set without bound', async () => {
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const base = vector('preset-read-only');
  // LND identifier: version byte, then protobuf field 1 (tag 0x0a, length 0x10) holding the
  // 16-byte nonce; changing nonce bytes gives a new credential ID and still decodes.
  let at = 1, idStart = -1;
  const varint = (pos: number): [number, number] => { let value = 0, shift = 0; for (;;) { const b = base[pos++]; value += (b & 0x7f) * 2 ** shift; if (!(b & 0x80)) return [value, pos]; shift += 7; } };
  for (;;) { const [type, afterType] = varint(at); const [length, start] = varint(afterType); if (type === 2) { idStart = start; break; } at = start + length; }
  const { result } = await watchUntil(s.args, fakeRegister(script), async stop => {
    await script.ready;
    for (let n = 0; n < 10_050; n++) {
      const mac = Buffer.from(base);
      mac.writeUInt32BE(n, idStart + 3);
      script.decide[0](call('request', n, '/lnrpc.Lightning/GetInfo', mac));
    }
    await settle();
    stop();
  });
  expect(result).toMatchObject({ ok: true, result: { calls: 10_050, credentials: 10_000 } });
}, 30_000);

it('WATCH/lock a failed lock write leaves no lock, a lock without owner record is explained, and release never removes another lock', async () => {
  const s = setup();
  const lock = `${s.registry}.watch.lock`;
  const full = { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    if (String(args[0]) === lock) return Object.assign(handle, { writeFile: async () => { throw Object.assign(new Error('disk full'), { code: 'ENOSPC' }); } });
    return handle;
  }) as typeof fs.open };
  const first = await watchUntil(s.args, fakeRegister({ registrations: [], decide: [], end: [] } as unknown as Script), async () => undefined,
    { deps: { fs: full } });
  expect(first.result).toMatchObject({ ok: false, error: { code: 3, step: 'W6' } });
  expect(existsSync(lock)).toBe(false);

  writeFileSync(lock, '');
  const ownerless = await watchUntil(s.args, fakeRegister({ registrations: [], decide: [], end: [] } as unknown as Script), async () => undefined);
  expect(ownerless.result).toMatchObject({ ok: false, error: { code: 3, step: 'W6' } });
  expect(ownerless.result.error!.message).toContain('holds no owner record');
  expect(ownerless.result.error!.message).toContain(lock);
  rmSync(lock);

  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const foreign = JSON.stringify({ pid: 1, hostname: 'another-host' });
  const { result } = await watchUntil(s.args, fakeRegister(script), async stop => {
    await script.ready;
    // Someone replaces the lock while this watch runs: on exit it must not delete theirs.
    rmSync(lock);
    writeFileSync(lock, foreign);
    stop();
  });
  expect(result.ok).toBe(true);
  expect(readFileSync(lock, 'utf8')).toBe(foreign);
});

it('WATCH/canary-reload a canary baked while watch runs is guarded without a restart', async () => {
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const decoy = vector('preset-read-only');
  let verdict = '';
  const { result } = await watchUntil(s.args, fakeRegister(script), async stop => {
    await script.ready;
    expect(script.registrations).toEqual([{ name: 'macwarden-watch', readOnly: true }]);
    // bake --canary runs now: sidecar and registry entry appear.
    writeFileSync(`${s.registry}.canary.json`, JSON.stringify({ schema: 1, caveatName: 'region-a1a2f213' }));
    writeFileSync(s.registry, JSON.stringify({ schema: 1, entries: [entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }])] }));
    for (let i = 0; i < 100 && script.registrations.length < 3; i++) await settle();
    expect(script.registrations.slice(1)).toEqual([{ name: 'macwarden-watch', readOnly: true },
      { name: 'macwarden-watch-guard', readOnly: false, caveatName: 'region-a1a2f213' }]);
    verdict = script.decide[2](call('request', 7, '/lnrpc.Lightning/GetInfo', decoy, { customCaveatCondition: '3a1e61423be44eaf' }));
    await settle();
    stop();
  }, { deps: { canaryReloadMs: 30 } });
  expect(verdict).toBe('permission denied');
  // Re-registering for new canaries is not a reconnect after a failure.
  expect(result).toMatchObject({ ok: true, result: { canaryAlerts: 1, canaries: 1, reconnects: 0 } });
});

it('WATCH/shutdown an alert command that never finishes cannot hold the lock, the usage file or the process', async () => {
  const s = setup([entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }])], 'region-a1a2f213');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const decoy = vector('preset-read-only');
  const lock = `${s.registry}.watch.lock`;
  let releasedWhileAlertPending = false;
  const started = performance.now();
  const { result } = await watchUntil([...s.args, '--alert-command', alertFile(s.dir)], fakeRegister(script), async stop => {
    await script.ready;
    await settle();
    // One ordinary call, so there is usage to persist, then a canary use whose alert never finishes.
    script.decide[0](call('request', 8, '/lnrpc.Lightning/GetInfo', decoy));
    script.decide[1](call('request', 9, '/lnrpc.Lightning/GetInfo', decoy, { customCaveatCondition: '3a1e61423be44eaf' }));
    await settle();
    stop();
    for (let i = 0; i < 100 && existsSync(lock); i++) await settle();
    releasedWhileAlertPending = !existsSync(lock) && existsSync(`${s.registry}.usage.json`);
  }, { deps: { alert: () => new Promise<void>(() => undefined) } });
  expect(releasedWhileAlertPending).toBe(true);
  expect(result.ok).toBe(true);
  // Bounded by the alert command's kill deadline plus a second.
  expect(performance.now() - started).toBeLessThan(ALERT_KILL_MS + 4_000);
}, 30_000);

it('WATCH/capacity at 100,000 calls per second every intercept is answered promptly and excess attribution is dropped, not queued', async () => {
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const caller = vector('preset-read-only');
  const latency: number[] = [];
  let answered = 0;
  const { result } = await watchUntil(s.args, fakeRegister(script), async stop => {
    await script.ready;
    // Built before the clock starts, so the driver measures watch, not itself.
    const shared = new Secret(caller);
    const calls = Array.from({ length: 100_000 }, (_, n) => ({ ...call('request', n, '/lnrpc.Lightning/GetInfo', null), macaroon: shared, macaroonBytes: caller.length }));
    // Intercepts arrive at 100,000 per second for one second. Like a socket, everything that
    // arrived while the loop was busy is delivered at the next turn; a call's latency is the
    // time from its arrival to its answer.
    await new Promise<void>(done => {
      const started = performance.now();
      let next = 0;
      const deliver = () => {
        const now = performance.now();
        const due = Math.min(calls.length, Math.floor((now - started) * 100));
        for (; next < due; next++) {
          if (script.decide[0](calls[next]) === '') answered += 1;
          latency.push(performance.now() - (started + next / 100));
        }
        if (next < calls.length) setTimeout(deliver, 1); else done();
      };
      setTimeout(deliver, 1);
    });
    stop();
  });
  latency.sort((a, b) => a - b);
  const p99 = latency[Math.floor(latency.length * 0.99)];
  const summary = result.result as { calls: number; droppedAttributions: number };
  process.stdout.write(`capacity: answer latency p50 ${latency[latency.length >> 1].toFixed(1)} ms, p99 ${p99.toFixed(1)} ms, `
    + `max ${latency.at(-1)!.toFixed(1)} ms; attributed ${summary.calls}, dropped ${summary.droppedAttributions}\n`);
  expect(answered).toBe(100_000);
  // Bounded by one attribution batch plus timer granularity, whatever the call rate.
  expect(p99).toBeLessThan(100);
  expect(summary.calls + summary.droppedAttributions).toBe(100_000);
}, 60_000);

it('WATCH/backoff a session that registers and drops at once does not reset the backoff (it grows to 30 s)', async () => {
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const sleeps: number[] = [];
  const flap = (index: number) => setTimeout(() => script.end[index]({ registered: true, code: 4, stage: 'middleware-stream',
    message: 'LND transport failure', disabled: false }), 1);
  await watchUntil(s.args, fakeRegister(script, flap), async stop => {
    await script.ready;
    for (let i = 0; i < 500 && sleeps.length < 6; i++) await settle();
    stop();
  }, { sleeps });
  expect(sleeps.slice(0, 6)).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 30_000]);
});

it('WATCH/reconnect-storm 4,000 reconnects stay linear: no listener accumulates per reconnect', async () => {
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const sleeps: number[] = [];
  const drop = (index: number) => script.end[index]({ registered: true, code: 4, stage: 'middleware-stream',
    message: 'LND transport failure', disabled: false });
  // Every AbortSignal that receives an abort listener, to count what stays registered.
  const signals = new Set<AbortSignal>();
  const add = AbortSignal.prototype.addEventListener;
  AbortSignal.prototype.addEventListener = function (this: AbortSignal, ...args: Parameters<AbortSignal['addEventListener']>) {
    if (args[0] === 'abort') signals.add(this);
    return add.apply(this, args);
  } as AbortSignal['addEventListener'];
  let mostListeners = 0;
  const started = performance.now();
  const timings: number[] = [];
  try {
  await watchUntil(s.args, fakeRegister(script, drop), async stop => {
    await script.ready;
    // Marks after every 1,000 reconnects; registry re-reads are debounced (RECONNECT_RELOAD_MS).
    while (sleeps.length < 4_000 && performance.now() - started < 45_000) {
      await new Promise(resolve => setTimeout(resolve, 2));
      if (sleeps.length >= (timings.length + 1) * 1_000) timings.push(performance.now() - started);
    }
    for (const signal of signals) mostListeners = Math.max(mostListeners, getEventListeners(signal, 'abort').length);
    stop();
  }, { sleeps });
  } finally { AbortSignal.prototype.addEventListener = add; }
  process.stdout.write(`reconnect-storm: most abort listeners on one signal ${mostListeners}; ${sleeps.length} reconnects in ${(performance.now() - started).toFixed(0)} ms (marks ${timings.map(t => t.toFixed(0)).join(', ')})\n`);
  expect(sleeps.length).toBeGreaterThanOrEqual(4_000);
  // One listener per run, not one per reconnect (the old loop left 4,000 on its stop signal).
  expect(mostListeners).toBeLessThanOrEqual(3);
  // Linear: the last 1,000 reconnects take about as long as the first 1,000.
  expect(timings.at(-1)! - timings.at(-2)!).toBeLessThan(3 * timings[0] + 500);
}, 60_000);

it('WATCH/disabled a node without rpcmiddleware.enable stops at W7 with the fix and no retry', async () => {
  const s = setup();
  let registrations = 0;
  const register = ((() => {
    registrations += 1;
    return { ended: Promise.resolve({ registered: false, code: 4, stage: 'middleware-register', message: 'LND RPC middleware is disabled', disabled: true }),
      close: () => undefined };
  }) as unknown) as Register;
  const { result } = await watchUntil(s.args, register, async () => undefined);
  expect(registrations).toBe(1);
  expect(result).toMatchObject({ ok: false, error: { code: 4, step: 'W7' } });
  expect(result.error!.message).toContain('rpcmiddleware.enable=true');
  expect(result.error!.message).toContain('do not set rpcmiddleware.addmandatory');
});

it('WATCH/reconnect a lost stream is re-registered with backoff and reported', async () => {
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const sleeps: number[] = [];
  let seen = 0;
  let second!: () => void;
  const reRegistered = new Promise<void>(resolve => { second = resolve; });
  const { result, lines } = await watchUntil(s.args, fakeRegister(script, () => { seen += 1; if (seen === 2) second(); }), async stop => {
    await script.ready;
    script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
    await reRegistered;
    stop();
  }, { sleeps });
  expect(result).toMatchObject({ ok: true, result: { reconnects: 1 } });
  expect(sleeps).toEqual([1000]);
  expect(lines.filter(line => /watching|reconnecting/.test(line))).toHaveLength(3);
});

it('WATCH/lock a live watcher on the same registry is refused; a dead owner is replaced', async () => {
  const s = setup();
  // A genuinely live other process holds the lock (this process's own PID now counts as stale).
  const other = spawn(process.execPath, ['-e', 'setTimeout(() => undefined, 60000)'], { stdio: 'ignore' });
  try {
    writeFileSync(`${s.registry}.watch.lock`, JSON.stringify({ pid: other.pid, hostname: hostname() }));
    const script = { registrations: [], decide: [], end: [] } as unknown as Script;
    const refused = await watchUntil(s.args, fakeRegister(script), async () => undefined);
    expect(refused.result).toMatchObject({ ok: false, error: { code: 3, step: 'W6' } });
    expect(script.registrations).toHaveLength(0);
  } finally { other.kill(); }
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const exited = spawnSync(process.execPath, ['-e', 'process.exit(0)']);
  writeFileSync(`${s.registry}.watch.lock`, JSON.stringify({ pid: exited.pid, hostname: hostname() }));
  const replaced = await watchUntil(s.args, fakeRegister(script), async stop => { await script.ready; stop(); });
  expect(replaced.result.ok).toBe(true);
  expect(existsSync(`${s.registry}.watch.lock`)).toBe(false);
});

it('WATCH/lock-own-pid a lock left by a crashed watch with this process\'s PID (container PID 1) does not block a restart', async () => {
  const s = setup();
  // The recorded PID is alive (it is this very process), exactly as for PID 1 in a restarted container.
  writeFileSync(`${s.registry}.watch.lock`, JSON.stringify({ pid: process.pid, hostname: hostname() }));
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const restarted = await watchUntil(s.args, fakeRegister(script), async stop => { await script.ready; stop(); }, { deps: { pid: process.pid } });
  expect(restarted.result.ok).toBe(true);
  expect(script.registrations.length).toBeGreaterThan(0);
  expect(existsSync(`${s.registry}.watch.lock`)).toBe(false);
});

it('WATCH/own-permission an own macaroon without macaroon:write is refused before any connection', async () => {
  const s = setup([], undefined, 'default-readonly');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const { result } = await watchUntil(s.args, fakeRegister(script), async () => undefined);
  expect(result).toMatchObject({ ok: false, error: { code: 4, step: 'W3' } });
  expect(result.error!.message).toContain('macaroon:write');
  expect(script.registrations).toHaveLength(0);
});

it('WATCH/stream-once a bidirectional stream counts once however many messages it carries, and its final error is recorded', async () => {
  const admin = vector('default-admin');
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const { result } = await watchUntil(s.args, fakeRegister(script), async stop => {
    await script.ready;
    const observe = script.decide[0];
    // LND intercepts every message on a stream with the same request ID (ChannelAcceptor style).
    observe(call('stream_auth', 5, '/lnrpc.Lightning/ChannelAcceptor', admin));
    for (let message = 0; message < 3; message++) {
      observe(call('request', 5, '/lnrpc.Lightning/ChannelAcceptor', admin));
      observe(call('response', 5, '/lnrpc.Lightning/ChannelAcceptor', admin));
    }
    observe(call('response', 5, '/lnrpc.Lightning/ChannelAcceptor', admin, { isError: true }));
    await settle();
    stop();
  });
  expect(result).toMatchObject({ ok: true, result: { calls: 1, errors: 1 } });
  const usage = JSON.parse(readFileSync(`${s.registry}.usage.json`, 'utf8')) as { entries: { method: string; calls: number; errors: number }[] };
  expect(usage.entries).toEqual([expect.objectContaining({ method: '/lnrpc.Lightning/ChannelAcceptor', calls: 1, errors: 1 })]);
});

it('WATCH/session-keys request IDs restart with LND, so keys from a lost session are never reused', async () => {
  const admin = vector('default-admin');
  const app = vector('preset-read-only');
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const { result, lines } = await watchUntil([...s.args, '--json'], fakeRegister(script), async stop => {
    await script.ready;
    script.decide[0](call('stream_auth', 2, '/lnrpc.Lightning/SubscribeChannelEvents', admin));
    await settle();
    script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
    await settle();
    // After LND restarted, request ID 2 is a different call by a different credential.
    script.decide[1](call('request', 2, '/lnrpc.Lightning/WalletBalance', app));
    script.decide[1](call('response', 2, '/lnrpc.Lightning/WalletBalance', app, { isError: true }));
    await settle();
    stop();
  });
  expect(result).toMatchObject({ ok: true, result: { calls: 2, errors: 1, reconnects: 1 } });
  const errors = lines.map(line => JSON.parse(line) as { event: string; method?: string; credential?: string })
    .filter(event => event.event === 'error');
  expect(errors).toEqual([expect.objectContaining({ method: '/lnrpc.Lightning/WalletBalance', credential: identityOf(app) })]);
});

it('WATCH/stale-registration "already registered" after an earlier successful session is retried, not fatal', async () => {
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const sleeps: number[] = [];
  let sessions = 0;
  const register: Register = ((target, registration, decide, onRegistered) => {
    const index = sessions++;
    script.registrations.push(registration);
    script.decide[index] = decide;
    let settleEnd!: (value: MiddlewareEnd) => void;
    const ended = new Promise<MiddlewareEnd>(resolve => { settleEnd = resolve; });
    script.end[index] = settleEnd;
    // Session 1 registers then is lost; LND still holds its name, so session 2 is refused.
    if (index === 0) queueMicrotask(() => { onRegistered(); queueMicrotask(() => settleEnd({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false })); });
    else if (index === 1) queueMicrotask(() => settleEnd({ registered: false, code: 3, stage: 'middleware-register', message: 'a middleware with this name or caveat is already registered', disabled: false }));
    else queueMicrotask(() => onRegistered());
    return { ended, close: () => settleEnd({ registered: true, code: 4, stage: 'middleware-stream', message: 'closed', disabled: false }) };
  }) as Register;
  const { result } = await watchUntil(s.args, register, async stop => {
    for (let wait = 0; wait < 100 && sessions < 3; wait++) await settle();
    await settle();
    stop();
  }, { sleeps });
  expect(sessions).toBe(3);
  expect(result).toMatchObject({ ok: true, result: { reconnects: 2 } });
  expect(sleeps).toEqual([1000, 2000]);
});

it('WATCH/usage-validation an error for a call without a valid credential is not recorded and the usage file stays readable', async () => {
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const { result } = await watchUntil(s.args, fakeRegister(script), async stop => {
    await script.ready;
    script.decide[0](call('request', 7, '/lnrpc.Lightning/GetInfo', null));
    script.decide[0](call('response', 7, '/lnrpc.Lightning/GetInfo', null, { isError: true }));
    await settle();
    stop();
  });
  expect(result).toMatchObject({ ok: true, result: { calls: 1, errors: 1 } });
  // A second watch reads the file it left behind.
  // Stopped once registered: a stop while GetInfo still waits is an interrupt (WATCH/interrupted).
  const second = { registrations: [], decide: [], end: [] } as unknown as Script;
  const again = await watchUntil(s.args, fakeRegister(second), async stop => { await second.ready; await settle(); stop(); });
  expect(again.result).toMatchObject({ ok: true });
  expect(again.result.warnings).not.toContainEqual(expect.objectContaining({ code: 'usage-file-quarantined' }));
  const store = new UsageStore();
  expect(store.record(PUBKEY, 'id:none', 'none', '/lnrpc.Lightning/GetInfo', new Date())).toBe(false);
  expect(store.record(PUBKEY, 'id:0123456789abcdef', '18446744073709551616', '/lnrpc.Lightning/GetInfo', new Date())).toBe(false);
  expect(store.entries()).toEqual([]);
});

it('WATCH/corrupt-usage a corrupt usage file is moved aside (never deleted) and watch continues with a warning', async () => {
  const s = setup();
  writeFileSync(`${s.registry}.usage.json`, '{"schema":1,"dropped":0,"entries":[{"credential":"id:none"}]}');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const { result } = await watchUntil(s.args, fakeRegister(script), async stop => { await script.ready; await settle(); stop(); });
  expect(result).toMatchObject({ ok: true });
  expect(result.warnings).toContainEqual(expect.objectContaining({ code: 'usage-file-quarantined' }));
  const aside = (await fs.readdir(s.dir)).filter(name => name.startsWith('registry.json.usage.json.corrupt-'));
  expect(aside).toHaveLength(1);
  expect(readFileSync(join(s.dir, aside[0]), 'utf8')).toContain('id:none');
});

it('WATCH/alert-validation an alert command that cannot run without a shell is refused before anything starts', async () => {
  const s = setup();
  const run1 = async (path: string, platform: NodeJS.Platform) => (await watchUntil([...s.args, '--alert-command', path],
    fakeRegister({ registrations: [], decide: [], end: [] } as unknown as Script), async stop => { await settle(); stop(); },
    { deps: { platform } })).result;
  const script = join(s.dir, 'page.cmd');
  writeFileSync(script, '@echo paged');
  expect(await run1(script, 'win32')).toMatchObject({ ok: false, error: { code: 2, step: 'W1', message: expect.stringContaining('.exe or .com') } });
  expect(await run1(join(s.dir, 'missing.exe'), 'win32')).toMatchObject({ ok: false, error: { code: 2, step: 'W1', message: expect.stringContaining('does not exist') } });
  const plain = join(s.dir, 'page');
  writeFileSync(plain, '#!/bin/sh\n', { mode: 0o644 });
  expect(await run1(plain, 'linux')).toMatchObject({ ok: false, error: { code: 2, step: 'W1', message: '--alert-command is not executable' } });
  expect(await run1(s.dir, 'linux')).toMatchObject({ ok: false, error: { code: 2, step: 'W1', message: '--alert-command must be a regular file' } });
});

it('WATCH/alert-failed a failing alert command is reported as a warning, a status event and a count', async () => {
  const s = setup([entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }])], 'region-a1a2f213');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const { result, lines } = await watchUntil([...s.args, '--alert-command', alertFile(s.dir)], fakeRegister(script), async stop => {
    await script.ready;
    script.decide[1](call('request', 9, '/lnrpc.Lightning/GetInfo', vector('preset-read-only'), { customCaveatCondition: '3a1e61423be44eaf' }));
    await settle(); await settle();
    stop();
  }, { deps: { alert: async () => { throw new Error('alert command failed'); } } });
  expect(result).toMatchObject({ ok: true, result: { canaryAlerts: 1, alertFailures: 1 } });
  expect(result.warnings).toContainEqual(expect.objectContaining({ code: 'alert-failed' }));
  expect(lines.some(line => line.includes('ALERT COMMAND FAILED for canary decoy'))).toBe(true);
});

it('WATCH/output-dropped lines the output could not keep up with are reported and counted', async () => {
  const s = setup();
  const priority: boolean[] = [];
  const lines: string[] = [];
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const { result } = await watchUntil(s.args, fakeRegister(script), async stop => { await script.ready; await settle(); stop(); },
    { deps: { emit: (line, important) => { lines.push(line); priority.push(important === true); }, dropped: () => 5 } });
  expect(result).toMatchObject({ ok: true, result: { droppedEvents: 5 } });
  const notice = lines.findIndex(line => line.includes('output fell behind: 5 event lines dropped'));
  expect(notice).toBeGreaterThanOrEqual(0);
  expect(priority[notice]).toBe(true);
});

it('WATCH/usage-flush a record made while the file is being written is not lost', async () => {
  const s = setup();
  const store = new UsageStore();
  store.record(PUBKEY, 'id:0123456789abcdef', '1', '/lnrpc.Lightning/GetInfo', new Date('2026-10-08T12:00:00Z'));
  const path = `${s.registry}.usage.json`;
  const slow = { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    return Object.assign(handle, { sync: async () => {
      // A call recorded between the snapshot and the rename.
      store.record(PUBKEY, 'id:0123456789abcdef', '1', '/lnrpc.Lightning/ListChannels', new Date('2026-10-08T12:00:01Z'));
      return handle.datasync();
    } });
  }) as typeof fs.open };
  await writeUsage(path, store, slow);
  expect(store.changed).toBe(true);
  await writeUsage(path, store, fs);
  const written = JSON.parse(readFileSync(path, 'utf8')) as { entries: { method: string }[] };
  expect(written.entries.map(entry => entry.method).sort()).toEqual(['/lnrpc.Lightning/GetInfo', '/lnrpc.Lightning/ListChannels']);
});

it('WATCH/canary-burst a canary used in the same turn as 25,000 ordinary calls still alerts, and the drops mark usage incomplete', async () => {
  // The attribution queue holds 20,000 calls; a burst beyond it is dropped. Canary uses must
  // never share that fate, and the usage file must say that calls went unattributed.
  const s = setup([entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }])], 'region-a1a2f213');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const alerts: WatchEvent[] = [];
  const caller = vector('preset-read-only');
  const decoy = vector('preset-read-only');
  const { result } = await watchUntil([...s.args, '--alert-command', alertFile(s.dir)], fakeRegister(script), async stop => {
    await script.ready;
    await settle();
    const shared = new Secret(caller);
    for (let n = 0; n < 25_000; n++)
      script.decide[0]({ ...call('request', n, '/lnrpc.Lightning/AddInvoice', null), macaroon: shared, macaroonBytes: caller.length });
    expect(script.decide[1](call('request', 99_999, '/lnrpc.Lightning/GetInfo', decoy, { customCaveatCondition: '3a1e61423be44eaf' })))
      .toBe('permission denied');
    await settle();
    stop();
  }, { alerts });
  const summary = result.result as { canaryAlerts: number; canaryUses: number; droppedAttributions: number; calls: number };
  expect(summary).toMatchObject({ canaryAlerts: 1, canaryUses: 1 });
  expect(alerts).toHaveLength(1);
  expect(alerts[0]).toMatchObject({ event: 'canary', label: 'decoy', denied: true });
  expect(summary.droppedAttributions).toBeGreaterThan(0);
  expect(summary.calls + summary.droppedAttributions).toBe(25_000);
  const usage = UsageStore.parse(readFileSync(`${s.registry}.usage.json`, 'utf8'));
  expect(usage.droppedAttributions).toBe(summary.droppedAttributions);
  expect(usage.lastAttributionDrop).toBe(new Date(usage.lastAttributionDrop!).toISOString());
  expect(usage.maybeIncomplete()).toBe(true);
}, 60_000);

it('WATCH/reload-debounce reconnects re-read the registry at most once per RECONNECT_RELOAD_MS; the periodic reload still runs', async () => {
  const s = setup();
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  let reads = 0;
  const counting = { ...fs, readFile: ((...args: Parameters<typeof fs.readFile>) => {
    if (String(args[0]) === s.registry) reads += 1;
    return fs.readFile(...args);
  }) as typeof fs.readFile };
  const sleeps: number[] = [];
  const drop = (index: number) => script.end[index]({ registered: true, code: 4, stage: 'middleware-stream',
    message: 'LND transport failure', disabled: false });
  await watchUntil(s.args, fakeRegister(script, drop), async stop => {
    await script.ready;
    while (sleeps.length < 500) await new Promise(resolve => setTimeout(resolve, 2));
    stop();
  }, { sleeps, deps: { fs: counting } });
  // Startup reads, then one reload for the first reconnect pass: never one per reconnect.
  expect(sleeps.length).toBeGreaterThanOrEqual(500);
  expect(reads).toBeGreaterThan(0);
  expect(reads).toBeLessThanOrEqual(4);
}, 60_000);

it('WATCH/unreachable a gRPC endpoint that never registers fails with exit 4 after a few tries instead of looping', async () => {
  // Found live against Polar: the REST port was right, the default gRPC port was not.
  const s = setup();
  let attempts = 0;
  const sleeps: number[] = [];
  const refused: Register = (() => {
    attempts += 1;
    return { ended: Promise.resolve({ registered: false, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false }),
      close: () => undefined };
  }) as Register;
  const { result } = await watchUntil(s.args, refused, async () => { await new Promise(resolve => setTimeout(resolve, 50)); }, { sleeps });
  expect(result).toMatchObject({ ok: false, error: { code: 4, step: 'W7' } });
  expect(result.error!.message).toContain('localhost:10009');
  expect(result.error!.message).toContain('the default port 10009 on the --lnd-rest host');
  expect(result.error!.message).toContain('--lnd-grpc');
  expect(attempts).toBe(3);
  expect(sleeps.length).toBe(2);
});

it('WATCH/unreachable a run stopped before any session registered does not report success', async () => {
  const s = setup();
  // Stop once watch is waiting on its first registration, not after a fixed delay: a slow
  // runner could otherwise still be in GetInfo, which is a different case (WATCH/interrupted).
  let opened!: () => void;
  const registering = new Promise<void>(resolve => { opened = resolve; });
  const silent: Register = (() => {
    let end!: (value: MiddlewareEnd) => void;
    const ended = new Promise<MiddlewareEnd>(resolve => { end = resolve; });
    opened();
    return { ended, close: () => end({ registered: false, code: 4, stage: 'middleware-stream', message: 'closed', disabled: false }) };
  }) as Register;
  const { result } = await watchUntil([...s.args, '--lnd-grpc', 'localhost:10001'], silent, async stop => {
    await registering; await settle(); stop();
  });
  expect(result).toMatchObject({ ok: false, error: { code: 4, step: 'W7' } });
  expect(result.error!.message).toContain('localhost:10001 (from --lnd-grpc)');
});

it('WATCH/interrupted an interrupt while GetInfo waits on the node exits 6 cancelled, not an internal failure', async () => {
  const s = setup();
  let asked!: () => void;
  const waiting = new Promise<void>(resolve => { asked = resolve; });
  const lnd = { getInfo: () => { asked(); return new Promise(() => undefined); } } as never;
  const { result } = await watchUntil(s.args, (() => { throw new Error('must not register'); }) as unknown as Register, async stop => {
    await waiting; stop();
  }, { deps: { lnd } });
  expect(result).toMatchObject({ ok: false, result: null, error: { code: 6, step: 'cancelled', message: 'interrupted' } });
});

it('WATCH/canary-usage denied canary uses and the registered time are written to the usage file', async () => {
  const s = setup([entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }])], 'region-a1a2f213');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const decoy = vector('preset-read-only');
  let now = Date.parse('2026-10-08T12:00:00Z');
  await watchUntil([...s.args, '--alert-command', alertFile(s.dir)], fakeRegister(script), async stop => {
    await script.ready;
    await settle();
    for (const id of [9, 10, 11]) script.decide[1](call('request', id, '/lnrpc.Lightning/GetInfo', decoy, { customCaveatCondition: '3a1e61423be44eaf' }));
    await settle();
    now += 90_000;
    stop();
  }, { deps: { clock: () => new Date(now) } });
  const store = UsageStore.parse(readFileSync(`${s.registry}.usage.json`, 'utf8'));
  expect(store.canaryUsesFor(PUBKEY, '4294967342')).toEqual({ nodePubkey: PUBKEY, rootKeyId: '4294967342', uses: 3,
    firstUse: '2026-10-08T12:00:00.000Z', lastUse: '2026-10-08T12:00:00.000Z' });
  expect(store.coverageFor(PUBKEY)).toEqual({ nodePubkey: PUBKEY, firstStart: '2026-10-08T12:00:00.000Z',
    lastEnd: '2026-10-08T12:01:30.000Z', coveredSeconds: 90, sessions: 1 });
});

it('WATCH/alert-shutdown an alert waiting behind the running one at shutdown never starts; watch returns when the running one ends', async () => {
  // Audit MW102-05: a summary queued behind a running alert started after stop and outlived the budget.
  const s = setup([entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }])], 'region-a1a2f213');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const decoy = vector('preset-read-only');
  let started = 0, active = 0, stoppedAt = 0;
  const alert = () => {
    started += 1; active += 1;
    // The running command ends 300 ms after watch was asked to stop.
    return new Promise<void>(resolve => {
      const wait = setInterval(() => { if (stoppedAt && performance.now() - stoppedAt >= 300) { clearInterval(wait); active -= 1; resolve(); } }, 10);
    });
  };
  const use = (n: number) => script.decide[1](call('request', n, '/lnrpc.Lightning/GetInfo', decoy, { customCaveatCondition: '3a1e61423be44eaf' }));
  const { result, lines } = await watchUntil([...s.args, '--alert-command', alertFile(s.dir)], fakeRegister(script), async stop => {
    await script.ready;
    await settle();
    use(10);
    await settle();
    // Folded into the window; the shutdown flush turns it into a summary that would wait.
    use(11);
    await settle();
    stoppedAt = performance.now();
    stop();
  }, { deps: { alert } });
  const elapsed = performance.now() - stoppedAt;
  expect(started).toBe(1);
  expect(active).toBe(0);
  expect(elapsed).toBeLessThan(ALERT_KILL_MS);
  // The summary is still printed, and the alert command it did not get is reported.
  expect(lines.find(line => line.includes('+1 more denied uses since the last alert'))).toBeDefined();
  expect(result).toMatchObject({ ok: true, result: { canaryAlerts: 2, canaryUses: 2, alertFailures: 1 } });
  await new Promise(resolve => setTimeout(resolve, 400));
  expect(started).toBe(1);
}, 30_000);

it('WATCH/until-long durations beyond the 32-bit timer limit do not expire early (fake timers)', () => {
  // Audit MW102-09: Node clamps a setTimeout above 2^31-1 ms to 1 ms, so `--until 25d` ended at once.
  vi.useFakeTimers();
  try {
    const now = () => Date.now();
    for (const ms of [MAX_TIMER_MS, MAX_TIMER_MS + 1, MAX_TIMER_MS + 2, 25 * 86_400_000]) {
      let expired = 0;
      const timer = scheduleDeadline(ms, () => { expired += 1; }, now);
      vi.advanceTimersByTime(1);
      expect(expired, `${ms} after 1 ms`).toBe(0);
      vi.advanceTimersByTime(ms - 2);
      expect(expired, `${ms} 1 ms early`).toBe(0);
      vi.advanceTimersByTime(1);
      expect(expired, `${ms} on time`).toBe(1);
      vi.advanceTimersByTime(MAX_TIMER_MS);
      expect(expired).toBe(1);
      timer.clear();
    }
    // The largest accepted value (999999d) runs in bounded chunks against one deadline.
    let expired = 0;
    const longest = 999_999 * 86_400_000;
    scheduleDeadline(longest, () => { expired += 1; }, now);
    vi.advanceTimersByTime(MAX_TIMER_MS + 1);
    expect(expired).toBe(0);
    vi.advanceTimersByTime(longest - MAX_TIMER_MS - 2);
    expect(expired).toBe(0);
    vi.advanceTimersByTime(1);
    expect(expired).toBe(1);
    // Cleared before it is due: never fires.
    let cleared = 0;
    scheduleDeadline(MAX_TIMER_MS + 10, () => { cleared += 1; }, now).clear();
    vi.advanceTimersByTime(2 * MAX_TIMER_MS);
    expect(cleared).toBe(0);
  } finally { vi.useRealTimers(); }
});

it('WATCH/until-long `watch --until 25d` keeps watching instead of stopping at once', async () => {
  const s = setup();
  let registered = false, closed = false, closedBeforeStop = true;
  const register = ((_target, _registration, _decide, onRegistered) => {
    let settle!: (value: MiddlewareEnd) => void;
    const ended = new Promise<MiddlewareEnd>(resolve => { settle = resolve; });
    queueMicrotask(() => { registered = true; onRegistered(); });
    return { ended, close: () => { closed = true; settle({ registered: true, code: 4, stage: 'middleware-stream', message: 'closed', disabled: false }); } };
  }) as Register;
  const { result } = await watchUntil([...s.args, '--until', '25d'], register, async stop => {
    for (let i = 0; i < 100 && !registered; i++) await settle();
    await new Promise(resolve => setTimeout(resolve, 500));
    // Still registered half a second later: the deadline did not fire early.
    closedBeforeStop = closed;
    stop();
  });
  expect(registered).toBe(true);
  expect(closedBeforeStop).toBe(false);
  expect(result.ok).toBe(true);
});

it('WATCH/schema every --json event type and the final document validate against the shipped schemas', async () => {
  const s = setup([entry('decoy', '4294967342', [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }]), entry('app1', '4294967341')],
    'region-a1a2f213');
  const script = { registrations: [], decide: [], end: [] } as unknown as Script;
  const lines: string[] = [];
  let seen = 0;
  let second!: () => void;
  const reRegistered = new Promise<void>(resolve => { second = resolve; });
  const app = vector('preset-read-only');
  const { result } = await watchUntil([...s.args, '--json', '--alert-command', alertFile(s.dir)],
    fakeRegister(script, () => { seen += 1; if (seen === 3) second(); }), async stop => {
      await script.ready;
      const observe = script.decide[0];
      observe(call('request', 1, '/lnrpc.Lightning/GetInfo', app));
      observe(call('request', 2, '/lnrpc.Lightning/ListChannels', null));
      observe(call('request', 3, '/lnrpc.Lightning/AddInvoice', app));
      observe(call('response', 3, '/lnrpc.Lightning/AddInvoice', null, { isError: true }));
      // Two uses in one window: an alert, then a summary alert with repeats at stop.
      script.decide[1](call('request', 9, '/lnrpc.Lightning/GetInfo', app, { customCaveatCondition: '3a1e61423be44eaf' }));
      await settle();
      script.decide[1](call('request', 10, '/lnrpc.Lightning/GetInfo', app, { customCaveatCondition: '3a1e61423be44eaf' }));
      await settle(); await settle();
      script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
      await reRegistered;
      stop();
    }, { deps: { alert: async () => { throw new Error('alert command failed'); }, emit: line => { lines.push(line); }, dropped: () => 5 } });
  expect(result.ok).toBe(true);
  for (const line of lines) expectWatchEventValid(line);
  const events = lines.map(line => JSON.parse(line) as { event: string; status?: string; credential?: string; repeats?: number });
  const kinds = new Set(events.map(item => item.status ? `status:${item.status}` : item.event));
  expect([...kinds].sort()).toEqual(['call', 'canary', 'error', 'status:alert-failed', 'status:output-dropped', 'status:reconnecting', 'status:registered']);
  expect(events.some(item => item.credential === 'id:none')).toBe(true);
  expect(events.some(item => item.event === 'canary' && item.repeats === 1)).toBe(true);
  // The final document is what watch --json prints as its last line.
  expectDocumentValid(JSON.parse(render(result, 'json')));
  const failed = await watchUntil([...s.args, '--json', '--until', '0s'], fakeRegister(script), async () => undefined);
  expect(failed.result).toMatchObject({ ok: false, error: { code: 2, step: 'W1' } });
});
