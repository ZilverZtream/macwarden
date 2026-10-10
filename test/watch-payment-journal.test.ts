import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { withCancellation } from '../src/cancellation.js';
import { run, type Register } from '../src/commands/watch.js';
import type { MiddlewareCall, MiddlewareEnd } from '../src/lnd/index.js';
import { Secret } from '../src/secret.js';
import { readJournal } from '../src/watch/payment-journal.js';
import { JOURNALED_METHODS } from '../src/watch/payment-request.js';
import { expectSchemaValid, expectWatchEventValid } from './helpers/output-schema.js';
import { bytes, customRecord, invoice, message, uint } from './helpers/payment-proto.js';
import { expectLinesValid, identityOf, vector } from './helpers/payment-journal.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const PUBKEY = `02${'ab'.repeat(32)}`;
const SEND = '/routerrpc.Router/SendPaymentV2';
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const hash = (text: string) => createHash('sha256').update(text).digest();

function setup() {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'watch-journal-'));
  dirs.push(dir);
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }));
  writeFileSync(join(dir, 'tls.cert'), 'not used by the fake middleware');
  writeFileSync(join(dir, 'own.macaroon'), vector('default-admin'));
  return { dir, registry, journal: join(dir, 'payments.journal'), args: ['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', registry] };
}

type Script = { registrations: { name: string; readOnly: boolean }[]; options: unknown[]; decide: ((call: MiddlewareCall) => string)[];
  end: ((value: MiddlewareEnd) => void)[] };

/** A scripted middleware session: the test drives intercepts and decides when sessions end. */
function fakeRegister(script: Script): Register {
  let count = 0;
  return ((_target, registration, decide, onRegistered, options) => {
    const index = count++;
    script.registrations.push(registration);
    script.options[index] = options;
    script.decide[index] = decide;
    let settle!: (value: MiddlewareEnd) => void;
    const ended = new Promise<MiddlewareEnd>(done => { settle = done; });
    script.end[index] = settle;
    queueMicrotask(() => onRegistered());
    return { ended, close: () => settle({ registered: true, code: 4, stage: 'middleware-stream', message: 'closed', disabled: false }) };
  }) as Register;
}

function request(requestId: number, method: string, macaroon: Buffer | null, payload: Buffer | null, kind: MiddlewareCall['kind'] = 'request'): MiddlewareCall {
  return { kind, requestId: BigInt(requestId), method, isError: false, customCaveatCondition: '', macaroon: macaroon ? new Secret(macaroon) : null,
    payload, payloadBytes: payload?.length ?? 0, macaroonBytes: macaroon?.length ?? 0 };
}

/** A call whose payload must never be read: reading it fails the test. */
function sealed(requestId: number, method: string, macaroon: Buffer, kind: MiddlewareCall['kind'] = 'request'): MiddlewareCall {
  return { kind, requestId: BigInt(requestId), method, isError: false, customCaveatCondition: '', macaroon: new Secret(macaroon),
    get payload(): never { throw new Error(`payload of ${method} (${kind}) was read`); }, payloadBytes: 40, macaroonBytes: macaroon.length };
}

const turn = () => new Promise(done => setTimeout(done, 20));
async function until(condition: () => boolean): Promise<void> {
  for (let i = 0; i < 200 && !condition(); i++) await turn();
  expect(condition()).toBe(true);
}

async function watchWith(args: string[], register: Register, drive: (stop: () => void) => Promise<void>,
  deps: Partial<Parameters<typeof run>[1]> = {}) {
  const lines: string[] = [];
  const controller = new AbortController();
  const result = withCancellation(controller.signal, () => run(args, {
    lnd: { getInfo: async () => ({ pubkey: PUBKEY, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }) } as never,
    register, fs, env: {}, clock: () => new Date('2026-10-09T12:00:00Z'), emit: line => { lines.push(line); },
    sleep: async () => undefined, hostname: () => hostname(), pid: process.pid, processDomain: async () => null, ...deps,
  }));
  await drive(() => controller.abort());
  const settled = await result;
  expectSchemaValid(settled);
  if (args.includes('--json')) for (const line of lines) expectWatchEventValid(line);
  return { result: settled, lines };
}

it('WATCH/payment-journal payments are journaled per credential across a reconnect; other payloads are never read', async () => {
  const s = setup();
  const script: Script = { registrations: [], options: [], decide: [], end: [] };
  const app = vector('preset-pay-only');
  const other = vector('root-max');
  const preimage = Buffer.from('7a'.repeat(32), 'hex');
  const first = hash('first'), second = hash('second');
  const text = invoice({ hash: first, amount: '3u' });
  const { result, lines } = await watchWith([...s.args, '--payment-journal', s.journal, '--json'], fakeRegister(script), async stop => {
    await until(() => script.decide[0] !== undefined);
    // Only the observer selects payloads, and only for the journaled methods.
    expect(script.options[0]).toEqual({ payloadMethods: JOURNALED_METHODS });
    const observe = script.decide[0];
    expect(observe(request(1, SEND, app, message(bytes(5, text), uint(13, 900))))).toBe('');
    // Not journaled: other methods, responses and stream authentication never have their payload read.
    expect(observe(sealed(2, '/lnrpc.Lightning/GetInfo', app))).toBe('');
    expect(observe(sealed(1, SEND, app, 'response'))).toBe('');
    expect(observe(sealed(3, SEND, app, 'stream_auth'))).toBe('');
    await turn();
    // The stream drops; watch re-registers and journals the gap.
    script.end[0]({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure', disabled: false });
    await until(() => script.decide[1] !== undefined);
    await turn();
    script.decide[1](request(4, SEND, other, message(bytes(3, second), uint(2, 50), customRecord(11, 5482373484n, preimage))));
    await turn();
    stop();
  });
  expect(result).toMatchObject({ ok: true, result: { reconnects: 1, paymentJournal: { payments: 2, deletions: 0, dropped: 0, stopped: null } } });
  const journalText = readFileSync(s.journal, 'utf8');
  expectLinesValid(journalText, (ok, detail) => expect(ok, detail).toBe(true));
  const records = (await readJournal(s.journal)).records;
  expect(records.map(item => item.type)).toEqual(['run-start', 'registered', 'payment', 'unregistered', 'registered', 'payment',
    'unregistered', 'run-end']);
  expect(records[0]).toMatchObject({ node: PUBKEY });
  expect(records[2]).toMatchObject({ credential: identityOf(app), rootKeyId: '0', paymentHash: first.toString('hex'), amountMsat: '300000',
    feeLimitMsat: '900', requestId: '1' });
  expect(records[3]).toMatchObject({ session: 1, reason: 'stream-lost' });
  expect(records[5]).toMatchObject({ credential: identityOf(other), rootKeyId: '18446744073709551615', paymentHash: second.toString('hex'),
    amountMsat: '50000', requestId: '4' });
  expect(records[6]).toMatchObject({ session: 2, reason: 'stopping' });
  // Neither the journal nor the event output carries a macaroon, the invoice or the keysend preimage.
  const everything = journalText + lines.join('');
  for (const value of [app.toString('hex'), app.toString('base64'), other.toString('hex'), text, preimage.toString('hex')])
    expect(everything).not.toContain(value);
  expect(existsSync(`${s.journal}.lock`)).toBe(false);
  expect(existsSync(`${s.registry}.watch.lock`)).toBe(false);
});

it('WATCH/payment-journal without the flag no payload is selected or read', async () => {
  const s = setup();
  const script: Script = { registrations: [], options: [], decide: [], end: [] };
  const { result } = await watchWith(s.args, fakeRegister(script), async stop => {
    await until(() => script.decide[0] !== undefined);
    expect(script.options[0]).toEqual({});
    expect(script.decide[0](sealed(1, SEND, vector('preset-pay-only')))).toBe('');
    await turn();
    stop();
  });
  expect(result.ok).toBe(true);
  expect((result.result as Record<string, unknown>).paymentJournal).toBeUndefined();
});

it('WATCH/payment-journal a journal that cannot be opened stops watch at W6, before anything registers', async () => {
  const s = setup();
  writeFileSync(s.journal, 'someone else\'s file\n', { mode: 0o600 });
  let registered = false;
  const register = (() => { registered = true; throw new Error('must not register'); }) as unknown as Register;
  const { result } = await watchWith([...s.args, '--payment-journal', s.journal], register, async () => undefined);
  expect(result).toMatchObject({ ok: false, error: { code: 3, step: 'W6', message: 'not a macwarden payment journal' } });
  expect(registered).toBe(false);
  expect(readFileSync(s.journal, 'utf8')).toBe('someone else\'s file\n');
  // The watch lock was released: the registry is free for the next watch.
  expect(existsSync(`${s.registry}.watch.lock`)).toBe(false);
  const protectedPath = await watchWith([...s.args, '--payment-journal', join(s.dir, 'wallet.db')], register, async () => undefined);
  expect(protectedPath.result).toMatchObject({ ok: false, error: { code: 3, step: 'W6' } });
});

it('WATCH/payment-journal flag values are checked at W1', async () => {
  const s = setup();
  const register = (() => { throw new Error('must not register'); }) as unknown as Register;
  for (const args of [[...s.args, '--payment-journal', ' '], [...s.args, '--payment-journal'],
    [...s.args, '--payment-journal', s.journal, '--payment-journal', s.journal]]) {
    const { result } = await watchWith(args, register, async () => undefined);
    expect(result, args.join(' ')).toMatchObject({ ok: false, error: { code: 2, step: 'W1' } });
  }
});

it('WATCH/payment-journal a journal that stops is reported once as a status event and a warning; watch keeps running', async () => {
  const s = setup();
  const script: Script = { registrations: [], options: [], decide: [], end: [] };
  let opened = 0;
  // Writes to the journal fail after its run-start, as on a full disk.
  const failingFs = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    if (!String(args[0]).endsWith('payments.journal')) return handle;
    opened += 1;
    let writes = 0;
    return new Proxy(handle, { get(target, key) {
      if (key === 'write') return async (...rest: unknown[]) => {
        if (++writes > 1) throw Object.assign(new Error('no space left'), { code: 'ENOSPC' });
        return (target.write as (...items: unknown[]) => Promise<unknown>)(...rest);
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs;
  const { result, lines } = await watchWith([...s.args, '--payment-journal', s.journal, '--json'], fakeRegister(script), async stop => {
    await until(() => script.decide[0] !== undefined);
    script.decide[0](request(1, SEND, vector('preset-pay-only'), bytes(3, hash('x'))));
    await turn();
    script.decide[0](request(2, SEND, vector('preset-pay-only'), bytes(3, hash('y'))));
    await turn();
    stop();
  }, { fs: failingFs });
  // One descriptor writes the journal. On Windows a new journal is first created owner-only through
  // a separate, exclusive handle that is closed before the writing one is opened (1.2.1).
  expect(opened).toBe(process.platform === 'win32' ? 2 : 1);
  expect(result).toMatchObject({ ok: true, result: { paymentJournal: { stopped: 'write-failed', payments: 0, dropped: 2 } } });
  const codes = result.warnings.map(item => typeof item === 'string' ? item : item.code);
  expect(codes).toEqual(expect.arrayContaining(['payment-journal-stopped', 'payment-journal-dropped']));
  const stops = lines.map(line => JSON.parse(line) as Record<string, unknown>).filter(event => event.status === 'payment-journal-stopped');
  expect(stops).toEqual([expect.objectContaining({ event: 'status', reason: 'write-failed' })]);
  expect((await readJournal(s.journal)).records.map(item => item.type)).toEqual(['run-start']);
});
