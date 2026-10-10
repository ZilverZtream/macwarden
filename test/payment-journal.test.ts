import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { run as reconcileRun } from '../src/commands/reconcile.js';
import { addFirstPartyCaveat } from '../src/decode/index.js';
import snapshot from '../src/grade/lnd-permissions.json' with { type: 'json' };
import type { LndAdapter, MiddlewareCall, PaymentLookup } from '../src/lnd/index.js';
import { Secret } from '../src/secret.js';
import { JOURNAL_INTAKE_ITEMS, JOURNAL_LIMIT_BYTES, JOURNAL_RESERVE_BYTES, JOURNAL_START_ROOM_BYTES, JournalError, journalCoverage, parseRecord, readJournal,
  type JournalRecord } from '../src/watch/payment-journal.js';
import { revealSecret } from './helpers/secret-bytes.js';
import { bytes, customRecord, invoice, message, uint } from './helpers/payment-proto.js';
import { NODE, OTHER_NODE, expectLinesValid, identityOf, openJournal, paymentCall, settle, vector } from './helpers/payment-journal.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const dirs: string[] = [];
afterEach(() => { vi.useRealTimers(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function scratch(): string {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'payment-journal-'));
  dirs.push(dir);
  return dir;
}
const SEND = '/routerrpc.Router/SendPaymentV2';
const ROUTE = '/routerrpc.Router/SendToRouteV2';
const hash = (text: string) => createHash('sha256').update(text).digest();
const lines = (path: string) => readFileSync(path, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line) as JournalRecord);
const RUN = '11111111-2222-4333-8444-555555555555';
const RUN2 = '66666666-7777-4888-9999-aaaaaaaaaaaa';
const at = (seconds: number) => new Date(Date.parse('2026-10-09T10:00:00.000Z') + seconds * 1_000).toISOString();
const record = (type: string, seconds: number, extra: Record<string, unknown> = {}, run = RUN) =>
  JSON.stringify({ v: 1, type, time: at(seconds), run, ...extra });
const start = (seconds: number, run = RUN, node = NODE, repairedTail = false) =>
  record('run-start', seconds, { node, version: '1.2.0', repairedTail }, run);

it('PAYJ/journal payments, deletions and coverage markers are written in order, each a valid version 1 record', async () => {
  const dir = scratch();
  const path = join(dir, 'payments.journal');
  const app = vector('preset-pay-only');
  const journal = await openJournal(path);
  journal.registered();
  const paymentHash = hash('one');
  journal.capture(paymentCall(SEND, message(bytes(5, invoice({ hash: paymentHash, amount: '5u' })), uint(13, 2_000)), app, 10n));
  const routeHash = hash('route');
  const hop = bytes(4, message(uint(6, 40_000)));
  journal.capture(paymentCall(ROUTE, message(bytes(1, routeHash), bytes(2, message(hop, uint(6, 40_100)))), vector('root-max'), 11n));
  journal.capture(paymentCall('/lnrpc.Lightning/DeletePayment', bytes(1, paymentHash), app, 12n));
  await settle();
  journal.unregistered('stream-lost');
  journal.registered();
  const stats = await journal.close();
  expect(stats).toEqual({ path: await fs.realpath(path), payments: 2, deletions: 1, dropped: 0, stopped: null });
  const text = readFileSync(path, 'utf8');
  expectLinesValid(text, (ok, detail) => expect(ok, detail).toBe(true));
  const written = lines(path);
  expect(written.map(item => item.type)).toEqual(['run-start', 'registered', 'payment', 'payment', 'deletion', 'unregistered', 'registered',
    'unregistered', 'run-end']);
  expect(new Set(written.map(item => item.run)).size).toBe(1);
  expect(written[0]).toMatchObject({ node: NODE, version: '1.2.0-test', repairedTail: false });
  expect(written[2]).toMatchObject({ method: SEND, requestId: '10', credential: identityOf(app), rootKeyId: '0',
    paymentHash: paymentHash.toString('hex'), amountMsat: '500000', amountSource: 'invoice', feeLimitMsat: '2000', amp: false, extraction: 'complete' });
  expect(written[3]).toMatchObject({ method: ROUTE, rootKeyId: '18446744073709551615', paymentHash: routeHash.toString('hex'),
    amountMsat: '40000', amountSource: 'route', feeLimitMsat: '100' });
  expect(written[4]).toMatchObject({ type: 'deletion', scope: 'payment', paymentHash: paymentHash.toString('hex') });
  expect(written[5]).toMatchObject({ session: 1, reason: 'stream-lost' });
  expect(written[7]).toMatchObject({ session: 2, reason: 'stopping' });
  expect(written[8]).toMatchObject({ payments: 2, deletions: 1, dropped: 0 });
  // Times never decrease along the file.
  const times = written.map(item => Date.parse(item.time));
  expect(times).toEqual([...times].sort((a, b) => a - b));
  const read = await readJournal(path);
  expect(read).toMatchObject({ tornTail: false, repairedLines: 0 });
  expect(read.records).toEqual(written);
});

it('PAYJ/identity the journal names the credential ID, shared by copies with added caveats; never the exact-token fingerprint', async () => {
  const dir = scratch();
  const path = join(dir, 'identity.journal');
  const app = vector('preset-pay-only');
  const copy = revealSecret(addFirstPartyCaveat(new Secret(app), 'time-before 2026-10-09T11:00:00Z'));
  const journal = await openJournal(path);
  journal.registered();
  journal.capture(paymentCall(SEND, bytes(3, hash('a')), app, 1n));
  journal.capture(paymentCall(SEND, bytes(3, hash('b')), copy, 2n));
  journal.capture(paymentCall(SEND, bytes(3, hash('c')), null, 3n));
  journal.capture(paymentCall(SEND, bytes(3, hash('d')), null, 4n, { oversizedMacaroon: true }));
  journal.capture(paymentCall(SEND, bytes(3, hash('e')), Buffer.from('not a macaroon'), 5n));
  await journal.close();
  const payments = lines(path).filter(item => item.type === 'payment') as Extract<JournalRecord, { type: 'payment' }>[];
  expect(payments.map(item => [item.credential, item.rootKeyId])).toEqual([[identityOf(app), '0'], [identityOf(app), '0'],
    ['id:none', 'none'], ['id:undecodable', 'none'], ['id:undecodable', 'none']]);
  expect(readFileSync(path, 'utf8')).not.toMatch(/fp:[0-9a-f]{16}/);
});

it('PAYJ/redaction no macaroon, invoice text, preimage or custom record reaches the journal; the copied payload is zeroed', async () => {
  const dir = scratch();
  const path = join(dir, 'redaction.journal');
  const sentinel = readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
  const preimage = Buffer.from('5e'.repeat(32), 'hex');
  const text = invoice({ hash: hash('redaction'), amount: '1m' });
  const payloads = [message(bytes(5, text)), message(bytes(3, createHash('sha256').update(preimage).digest()), uint(2, 10),
    customRecord(11, 5482373484n, preimage), customRecord(11, 34349334n, Buffer.from('a private message')))];
  const journal = await openJournal(path);
  journal.registered();
  const calls = payloads.map((payload, index) => paymentCall(SEND, payload, sentinel, BigInt(index + 1)));
  const copies = calls.map(call => call.payload!);
  for (const call of calls) journal.capture(call);
  await journal.close();
  for (const copy of copies) expect(copy.every(byte => byte === 0), 'payload copy zeroed after decoding').toBe(true);
  const written = readFileSync(path);
  const forbidden = [sentinel.toString('hex'), sentinel.toString('hex').toUpperCase(), sentinel.toString('base64'),
    sentinel.toString('base64url'), text, text.slice(0, 40), preimage.toString('hex'), preimage.toString('base64'), 'a private message'];
  for (const value of forbidden) expect(written.includes(Buffer.from(value)), value.slice(0, 16)).toBe(false);
  expect(written.includes(sentinel)).toBe(false);
  expect(written.includes(preimage)).toBe(false);
});

it('PAYJ/durability a write cut short by a crash is ignored, and the next run repairs it explicitly', async () => {
  const dir = scratch();
  const path = join(dir, 'crash.journal');
  // A run that registered, journaled one payment and died while appending the next: part of a
  // record, no newline, no run-end (its lock went with it, as after a reboot).
  const payment = record('payment', 2, { requestId: '1', method: SEND, credential: identityOf(vector('preset-pay-only')), rootKeyId: '0',
    paymentHash: hash('before crash').toString('hex'), amountMsat: null, amountSource: null, feeLimitMsat: '0', amp: false, extraction: 'complete' });
  const partial = '{"v":1,"type":"payment","time":"2026-10-09T10:5';
  writeFileSync(path, `${[start(0), record('registered', 1, { session: 1 }), payment].join('\n')}\n${partial}`, { mode: 0o600 });
  const torn = await readJournal(path);
  expect(torn.tornTail).toBe(true);
  expect(torn.records.map(item => item.type)).toEqual(['run-start', 'registered', 'payment']);
  // The crashed run's coverage ends at its last record: nothing after it is implied.
  const crashed = journalCoverage(torn.records, NODE, Date.parse(at(0)), Date.parse(at(3_600)));
  expect(crashed.gaps.at(-1)).toMatchObject({ from: Date.parse(at(2)), reason: 'unconfirmed' });
  const second = await openJournal(path);
  await second.close();
  const after = await readJournal(path);
  expect(after).toMatchObject({ tornTail: false, repairedLines: 1 });
  expect(after.records.map(item => item.type)).toEqual(['run-start', 'registered', 'payment', 'run-start', 'run-end']);
  expect(after.records[3]).toMatchObject({ repairedTail: true });
  // Every line but the crash's leftover matches the record schema.
  expectLinesValid(readFileSync(path, 'utf8').split('\n').filter(line => line !== partial).join('\n'),
    (ok, detail) => expect(ok, detail).toBe(true));
});

it('PAYJ/durability a crash after a complete record but before its newline is repaired too', async () => {
  const dir = scratch();
  const path = join(dir, 'newline.journal');
  writeFileSync(path, `${start(0)}\n${record('registered', 1, { session: 1 })}`, { mode: 0o600 });
  expect((await readJournal(path)).tornTail).toBe(true);
  const journal = await openJournal(path);
  await journal.close();
  const read = await readJournal(path);
  expect(read.tornTail).toBe(false);
  expect(read.records.map(item => item.type)).toEqual(['run-start', 'registered', 'run-start', 'run-end']);
  expect(read.records[2]).toMatchObject({ repairedTail: true });
});

it('PAYJ/reader an invalid line anywhere but where a crash leaves it makes the whole journal invalid', async () => {
  const dir = scratch();
  const cases: [string, string[]][] = [
    ['garbage between records', [start(0), 'not json', record('registered', 1, { session: 1 })]],
    ['garbage before an unrepaired run', [start(0), '{"v":1}', start(5, RUN2)]],
    ['record before any run-start', [record('registered', 1, { session: 1 })]],
    ['time going back within a run', [start(10), record('registered', 5, { session: 1 })]],
    ['unregistered without registered', [start(0), record('unregistered', 1, { session: 1, reason: 'stopping' })]],
    ['registered twice', [start(0), record('registered', 1, { session: 1 }), record('registered', 2, { session: 2 })]],
    ['session mismatch', [start(0), record('registered', 1, { session: 1 }), record('unregistered', 2, { session: 2, reason: 'stopping' })]],
    ['record after run-end', [start(0), record('run-end', 1, { payments: 0, deletions: 0, dropped: 0 }), record('alive', 2)]],
    ['record after full', [start(0), record('full', 1), record('alive', 2)]],
    ['record of another run', [start(0), record('alive', 1, {}, RUN2)]],
    ['unknown key', [start(0), record('alive', 1, { extra: true }), record('alive', 3)]],
    ['unknown version', [start(0), JSON.stringify({ v: 2, type: 'alive', time: at(1), run: RUN }), record('alive', 3)]],
    ['impossible instant', [start(0), JSON.stringify({ v: 1, type: 'alive', time: '2026-02-30T10:00:00.000Z', run: RUN }), record('alive', 3)]],
    ['over-long line', [start(0), `{"v":1,"type":"alive","time":"${at(1)}","run":"${RUN}","pad":"${'x'.repeat(3_000)}"}`, record('alive', 3)]],
  ];
  for (const [name, content] of cases) {
    const path = join(dir, `${name.replaceAll(' ', '-')}.journal`);
    writeFileSync(path, `${content.join('\n')}\n`, { mode: 0o600 });
    await expect(readJournal(path), name).rejects.toThrow(JournalError);
  }
  // The same over-long line directly before a repaired run-start is a crash's leftover: accepted.
  const tolerated = join(dir, 'tolerated.journal');
  writeFileSync(tolerated, `${[start(0), 'x'.repeat(3_000), start(5, RUN2, NODE, true)].join('\n')}\n`, { mode: 0o600 });
  expect(await readJournal(tolerated)).toMatchObject({ repairedLines: 1, tornTail: false });
});

it('PAYJ/reader record values outside their documented form are refused', () => {
  const payment = (extra: Record<string, unknown>) => record('payment', 1, { requestId: '1', method: SEND, credential: 'id:0123456789abcdef',
    rootKeyId: '0', paymentHash: 'ab'.repeat(32), amountMsat: '1000', amountSource: 'request', feeLimitMsat: '0', amp: false,
    extraction: 'complete', ...extra });
  expect(parseRecord(payment({}))).not.toBeNull();
  for (const extra of [{ requestId: '01' }, { method: '/lnrpc.Lightning/GetInfo' }, { credential: 'fp:0123456789abcdef' },
    { rootKeyId: '18446744073709551616' }, { paymentHash: 'AB'.repeat(32) }, { amountMsat: 1000 }, { amountMsat: '-1' },
    { amountSource: null }, { extraction: 'no-hash' }, { paymentHash: null }, { amp: 'false' }, { amountMsat: '99999999999999999999' }])
    expect(parseRecord(payment(extra)), JSON.stringify(extra)).toBeNull();
  expect(parseRecord(payment({ paymentHash: null, extraction: 'amp', amp: true }))).not.toBeNull();
  expect(parseRecord(record('drop', 5, { count: 3, first: at(1), last: at(6), reason: 'overload' }))).toBeNull();
  expect(parseRecord(record('drop', 5, { count: 0, first: at(1), last: at(2), reason: 'overload' }))).toBeNull();
  expect(parseRecord(record('drop', 5, { count: 3, first: at(3), last: at(2), reason: 'overload' }))).toBeNull();
  expect(parseRecord(record('drop', 5, { count: 3, first: at(1), last: at(2), reason: 'overload' }))).not.toBeNull();
});

it('PAYJ/reader the path rules of the other sidecars: protected names, non-files and size are refused before reading', async () => {
  const dir = scratch();
  await expect(readJournal(join(dir, 'wallet.db'))).rejects.toThrow('protected payment journal path');
  await expect(readJournal(join(dir, 'seed.journal'))).rejects.toThrow('protected payment journal path');
  await expect(readJournal(join(dir, 'missing.journal'))).rejects.toThrow('payment journal not found');
  await expect(readJournal(dir)).rejects.toThrow('payment journal is not a regular file');
  const large = join(dir, 'large.journal');
  writeFileSync(large, `${start(0)}\n`, { mode: 0o600 });
  truncateSync(large, JOURNAL_LIMIT_BYTES + 1);
  await expect(readJournal(large)).rejects.toThrow('payment journal too large');
});

it('PAYJ/overload a burst beyond the intake is dropped with a counted drop record; capture of a dropped call reads nothing', async () => {
  const dir = scratch();
  const path = join(dir, 'burst.journal');
  const journal = await openJournal(path);
  journal.registered();
  await settle();
  const app = vector('preset-pay-only');
  for (let i = 0; i < JOURNAL_INTAKE_ITEMS; i++) journal.capture(paymentCall(SEND, bytes(3, hash(`p${i}`)), app, BigInt(i + 1)));
  // A dropped call costs a counter: neither its macaroon nor its payload is read.
  const untouched = { kind: 'request', requestId: 99_999n, method: SEND, isError: false, customCaveatCondition: '', payloadBytes: 10, macaroonBytes: 10,
    get macaroon(): never { throw new Error('macaroon read for a dropped call'); },
    get payload(): never { throw new Error('payload read for a dropped call'); } };
  for (let i = 0; i < 76; i++) journal.capture(untouched as never);
  const stats = await journal.close();
  expect(stats).toMatchObject({ payments: JOURNAL_INTAKE_ITEMS, dropped: 76, stopped: null });
  const written = lines(path);
  const drops = written.filter(item => item.type === 'drop') as Extract<JournalRecord, { type: 'drop' }>[];
  expect(drops.reduce((total, item) => total + item.count, 0)).toBe(76);
  expect(written.at(-1)).toMatchObject({ type: 'run-end', payments: JOURNAL_INTAKE_ITEMS, dropped: 76 });
  const read = await readJournal(path);
  const coverage = journalCoverage(read.records, NODE, Date.parse(read.records[0].time), Date.parse(read.records.at(-1)!.time));
  expect(coverage.gaps.filter(gap => gap.reason === 'dropped').reduce((total, gap) => total + gap.dropped, 0)).toBe(76);
});

it('PAYJ/backpressure a disk that stalls never blocks capture: records beyond the line queue are dropped and counted', async () => {
  const dir = scratch();
  const path = join(dir, 'slow.journal');
  let gate: (() => void) | null = null;
  let held = false;
  const slowFs = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'write') return async (...writeArgs: unknown[]) => {
        if (held) await new Promise<void>(release => { gate = release; });
        return (target.write as (...items: unknown[]) => Promise<unknown>)(...writeArgs);
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs;
  const journal = await openJournal(path, { fs: slowFs });
  held = true;
  journal.registered();
  const app = vector('preset-pay-only');
  let id = 0n;
  for (let batch = 0; batch < 6; batch++) {
    const before = performance.now();
    for (let i = 0; i < 900; i++) journal.capture(paymentCall(SEND, bytes(3, hash(`slow${id}`)), app, ++id));
    // Capture is synchronous and cheap whatever the disk does.
    expect(performance.now() - before).toBeLessThan(2_000);
    await settle(30);
  }
  held = false;
  (gate as (() => void) | null)?.();
  const stats = await journal.close();
  expect(stats.dropped).toBeGreaterThan(0);
  expect(stats.payments + stats.dropped).toBe(Number(id));
  const written = lines(path);
  const payments = written.filter(item => item.type === 'payment').length;
  const dropped = (written.filter(item => item.type === 'drop') as Extract<JournalRecord, { type: 'drop' }>[])
    .reduce((total, item) => total + item.count, 0);
  expect(payments).toBe(stats.payments);
  expect(dropped).toBe(stats.dropped);
  expect(written.at(-1)).toMatchObject({ type: 'run-end', dropped: stats.dropped });
  expect((await readJournal(path)).tornTail).toBe(false);
});

it('PAYJ/failure a failed write stops journaling for the run; nothing more is written and coverage is not implied', async () => {
  const dir = scratch();
  const path = join(dir, 'failing.journal');
  let fail = false;
  const failingFs = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'write' && fail) return async () => { throw Object.assign(new Error('no space'), { code: 'ENOSPC' }); };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs;
  const stops: string[] = [];
  const journal = await openJournal(path, { fs: failingFs, onStop: reason => stops.push(reason) });
  fail = true;
  journal.registered();
  journal.capture(paymentCall(SEND, bytes(3, hash('lost')), vector('preset-pay-only')));
  await settle();
  journal.capture(paymentCall(SEND, bytes(3, hash('after')), vector('preset-pay-only')));
  const stats = await journal.close();
  expect(stats.stopped).toBe('write-failed');
  expect(stops).toEqual(['write-failed']);
  expect(stats.payments).toBe(0);
  expect(stats.dropped).toBe(2);
  const read = await readJournal(path);
  expect(read.records.map(item => item.type)).toEqual(['run-start']);
  const coverage = journalCoverage(read.records, NODE, Date.parse(read.records[0].time), Date.parse(read.records[0].time) + 60_000);
  expect(coverage.covered).toEqual([]);
});

it('PAYJ/size the journal never grows past its limit: a full record ends coverage; a nearly full file is refused at start', async () => {
  const dir = scratch();
  const path = join(dir, 'full.journal');
  // An earlier run, then filler that leaves just enough room for watch to start and less than 200 records.
  const head = `${start(0)}\n`;
  const room = JOURNAL_START_ROOM_BYTES + 2_000;
  const filler = JOURNAL_LIMIT_BYTES - JOURNAL_RESERVE_BYTES - room - Buffer.byteLength(head) - 1;
  writeFileSync(path, Buffer.concat([Buffer.from(head), Buffer.alloc(filler, 0x78), Buffer.from('\n')]), { mode: 0o600 });
  const stops: string[] = [];
  const journal = await openJournal(path, { onStop: reason => stops.push(reason) });
  journal.registered();
  for (let batch = 0; batch < 4; batch++) {
    for (let i = 0; i < 100; i++) journal.capture(paymentCall(SEND, bytes(3, hash(`f${batch}-${i}`)), vector('preset-pay-only'), BigInt(batch * 100 + i + 1)));
    await settle(10);
  }
  const stats = await journal.close();
  expect(stats.stopped).toBe('full');
  expect(stops).toEqual(['full']);
  expect(stats.payments + stats.dropped).toBe(400);
  expect(stats.dropped).toBeGreaterThan(0);
  expect(statSync(path).size).toBeLessThanOrEqual(JOURNAL_LIMIT_BYTES);
  const read = await readJournal(path);
  expect(read.repairedLines).toBe(1);
  expect(read.records.at(-1)!.type).toBe('full');
  const runStart = [...read.records].reverse().find(item => item.type === 'run-start')!;
  const coverage = journalCoverage(read.records, NODE, Date.parse(runStart.time), Date.parse(read.records.at(-1)!.time) + 60_000);
  expect(coverage.gaps.at(-1)).toMatchObject({ reason: 'journal-full' });
  // The next watch refuses to start on it: nothing can be journaled any more.
  await expect(openJournal(path)).rejects.toThrow('payment journal is full');
});

it('PAYJ/open refusals: protected names, directories, other files, a second writer and (POSIX) a file that is not owner-only', async () => {
  const dir = scratch();
  await expect(openJournal(join(dir, 'wallet.db'))).rejects.toThrow(JournalError);
  await expect(openJournal(join(dir, 'my-password.journal'))).rejects.toThrow(JournalError);
  await expect(openJournal(dir)).rejects.toThrow('payment journal is not a regular file');
  const other = join(dir, 'notes.txt');
  writeFileSync(other, 'my notes\n', { mode: 0o600 });
  await expect(openJournal(other)).rejects.toThrow('not a macwarden payment journal');
  expect(readFileSync(other, 'utf8')).toBe('my notes\n');
  const path = join(dir, 'locked.journal');
  const first = await openJournal(path);
  await expect(openJournal(path)).rejects.toThrow('another watch writes this payment journal');
  await first.close();
  const again = await openJournal(path);
  await again.close();
  // The owner-only rule, judged from the open descriptor (injected stat: mode 0644, then another owner).
  const statFs = (mode: number, uid: number) => ({ ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'stat') return async () => {
        const real = await target.stat();
        return { isFile: () => true, dev: real.dev, ino: real.ino, size: real.size, mode, uid };
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } }) as typeof fs;
  await expect(openJournal(path, { fs: statFs(0o100644, 1000), platform: 'linux', uid: 1000 })).rejects.toThrow('owner-only');
  await expect(openJournal(path, { fs: statFs(0o100600, 1001), platform: 'linux', uid: 1000 })).rejects.toThrow('owned by another user');
  const ok = await openJournal(path, { fs: statFs(0o100600, 1000), platform: 'linux', uid: 1000 });
  await ok.close();
});

it('PAYJ/time a clock that steps back never makes a record earlier than its predecessor', async () => {
  const dir = scratch();
  const path = join(dir, 'clock.journal');
  const times = [10, 20, 5, 6, 30, 1, 2, 3, 4, 5, 6, 7, 8].map(seconds => Date.parse('2026-10-09T10:00:00.000Z') + seconds * 1_000);
  let index = 0;
  const journal = await openJournal(path, { clock: () => new Date(times[Math.min(index++, times.length - 1)]) });
  journal.registered();
  journal.capture(paymentCall(SEND, bytes(3, hash('t1')), vector('preset-pay-only')));
  await settle();
  journal.capture(paymentCall(SEND, bytes(3, hash('t2')), vector('preset-pay-only')));
  await journal.close();
  const read = await readJournal(path);
  const stamps = read.records.map(item => Date.parse(item.time));
  expect(stamps).toEqual([...stamps].sort((a, b) => a - b));
});

it('PAYJ/time a clock that returns NaN or jumps past the year 9999 never crashes the writer or writes a time the reader refuses (audit 1.2.1 N3)', async () => {
  const dir = scratch();
  const path = join(dir, 'bad-clock.journal');
  const good = Date.parse('2026-10-09T10:00:00.000Z');
  const year10000 = Date.parse('+010000-01-01T00:00:00.000Z');
  let now = good;
  const journal = await openJournal(path, { clock: () => new Date(now) });
  now = good + 1_000; journal.registered();
  // NaN once: for a call record and for a marker.
  now = NaN; journal.capture(paymentCall(SEND, bytes(3, hash('nan')), vector('preset-pay-only'), 1n));
  await settle();
  journal.unregistered('stream-lost');
  now = good + 2_000; journal.registered();
  await settle();
  // Past the year 9999, and past what Date can hold at all.
  now = year10000; journal.capture(paymentCall(SEND, bytes(3, hash('far')), vector('preset-pay-only'), 2n));
  await settle();
  journal.unregistered('stream-lost');
  now = 9e15; journal.registered();
  const stats = await journal.close();
  expect(stats).toMatchObject({ payments: 2, dropped: 0, stopped: null });
  const text = readFileSync(path, 'utf8');
  expectLinesValid(text, (ok, detail) => expect(ok, detail).toBe(true));
  const read = await readJournal(path);
  expect(read).toMatchObject({ tornTail: false, repairedLines: 0 });
  expect(read.records.map(item => item.type)).toEqual(['run-start', 'registered', 'payment', 'unregistered', 'registered', 'payment',
    'unregistered', 'registered', 'unregistered', 'run-end']);
  // An invalid clock reading falls back to the last good time, never earlier than the previous record.
  expect(read.records.map(item => item.time)).toEqual(['2026-10-09T10:00:00.000Z', '2026-10-09T10:00:01.000Z', '2026-10-09T10:00:01.000Z',
    '2026-10-09T10:00:01.000Z', '2026-10-09T10:00:02.000Z', '2026-10-09T10:00:02.000Z', '2026-10-09T10:00:02.000Z', '2026-10-09T10:00:02.000Z',
    '2026-10-09T10:00:02.000Z', '2026-10-09T10:00:02.000Z']);
  // The run-start has no earlier record to fall back on: an invalid clock is refused at open, nothing written.
  for (const [name, clock] of [['nan', () => new Date(NaN)], ['year-10000', () => new Date(year10000)],
    ['throws', () => { throw new Error('no clock'); }]] as const) {
    const refused = join(dir, `${name}.journal`);
    await expect(openJournal(refused, { clock })).rejects.toThrow(new JournalError('cannot open payment journal: the system clock is invalid'));
    expect(existsSync(refused)).toBe(false); // refused before anything is created
  }
});

it('PAYJ/alive while registered an alive record is written after 5 quiet minutes', async () => {
  const dir = scratch();
  const path = join(dir, 'alive.journal');
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] });
  const journal = await openJournal(path);
  journal.registered();
  await settle();
  vi.advanceTimersByTime(6 * 60_000);
  await settle();
  await journal.close();
  vi.useRealTimers();
  expect(lines(path).map(item => item.type)).toEqual(['run-start', 'registered', 'alive', 'unregistered', 'run-end']);
});

it('PAYJ/coverage gaps carry their reason; coverage exists only between registered and what ends it', () => {
  const records = [
    start(100), record('registered', 110, { session: 1 }), record('unregistered', 200, { session: 1, reason: 'stream-lost' }),
    record('registered', 230, { session: 2 }),
    record('drop', 260, { count: 4, first: at(250), last: at(255), reason: 'overload' }),
    record('unregistered', 300, { session: 2, reason: 'stopping' }), record('run-end', 301, { payments: 0, deletions: 0, dropped: 4 }),
    start(400, RUN2), record('registered', 405, { session: 1 }, RUN2), record('alive', 500, {}, RUN2),
  ].map(line => parseRecord(line)!);
  const from = Date.parse(at(0)), to = Date.parse(at(600));
  const coverage = journalCoverage(records, NODE, from, to);
  const shape = coverage.gaps.map(gap => [(gap.from - from) / 1_000, (gap.to - from) / 1_000, gap.reason, gap.dropped]);
  expect(shape).toEqual([
    [0, 110, 'before-journal', 0],
    [200, 230, 'not-registered', 0],
    [250, 255, 'dropped', 4],
    [300, 405, 'not-running', 0],
    [500, 600, 'unconfirmed', 0],
  ]);
  expect(coverage.coveredMs).toBe((90 + 20 + 45 + 95) * 1_000);
  // A window inside coverage has no gap; one in the middle of a gap takes that gap's reason.
  expect(journalCoverage(records, NODE, Date.parse(at(120)), Date.parse(at(190))).gaps).toEqual([]);
  expect(journalCoverage(records, NODE, Date.parse(at(310)), Date.parse(at(320))).gaps.map(gap => gap.reason)).toEqual(['not-running']);
  // Another node's runs never cover this node.
  expect(journalCoverage(records, OTHER_NODE, from, to).gaps).toEqual([{ from, to, reason: 'before-journal', dropped: 0 }]);
  // A journal that filled up stops coverage at its full record.
  const full = [start(0), record('registered', 1, { session: 1 }), record('full', 50)].map(line => parseRecord(line)!);
  expect(journalCoverage(full, NODE, Date.parse(at(0)), Date.parse(at(100))).gaps.map(gap => gap.reason)).toEqual(['not-registered', 'journal-full']);
  // A drop that lasted no measurable time is still listed, with its count.
  const instant = [start(0), record('registered', 1, { session: 1 }), record('drop', 10, { count: 1, first: at(5), last: at(5), reason: 'overload' }),
    record('unregistered', 20, { session: 1, reason: 'stopping' })].map(line => parseRecord(line)!);
  expect(journalCoverage(instant, NODE, Date.parse(at(1)), Date.parse(at(20))).gaps)
    .toEqual([{ from: Date.parse(at(5)), to: Date.parse(at(5)), reason: 'dropped', dropped: 1 }]);
});

// 1.2.1: coverage is computed in sorted sweeps. A hostile journal holds hundreds of thousands of
// drop records; pairing each with every span was quadratic.
it('PAYJ/coverage-linear tens of thousands of disjoint drop windows cost linear time', async () => {
  const { compare, LINEAR_4X } = await import('./helpers/growth.js');
  const journalOf = (drops: number) => {
    const lines = [start(0), record('registered', 1, { session: 1 })];
    for (let index = 0; index < drops; index++)
      lines.push(record('drop', 12 + 3 * index, { count: 1, first: at(10 + 3 * index), last: at(11 + 3 * index), reason: 'overload' }));
    lines.push(record('unregistered', 20 + 3 * drops, { session: 1, reason: 'stopping' }));
    const records = lines.map(line => parseRecord(line)!);
    return () => {
      const coverage = journalCoverage(records, NODE, Date.parse(at(0)), Date.parse(at(30 + 3 * drops)));
      expect(coverage.gaps.filter(gap => gap.reason === 'dropped')).toHaveLength(drops);
      expect(coverage.gaps.reduce((total, gap) => total + gap.dropped, 0)).toBe(drops);
      expect(coverage.covered).toHaveLength(drops + 1);
    };
  };
  const timing = await compare(async () => journalOf(5_000)(), async () => journalOf(20_000)());
  expect(timing.ratio, timing.summary).toBeLessThan(LINEAR_4X);
}, 120_000);

// 1.2.1: a write may complete partially; every byte of a line is written before it counts.
it('PAYJ/short-write a descriptor that writes a few bytes at a time still lands every record; one that makes no progress stops the run', async () => {
  const dir = scratch();
  const chunked = (limit: number) => ({ ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'write') return async (data: Buffer | string, offset = 0, length?: number, position?: number | null) => {
        const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
        const take = Math.min(limit, (length ?? buffer.length - offset));
        return target.write(buffer, offset, take, position ?? null);
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs);
  const path = join(dir, 'chunked.journal');
  const journal = await openJournal(path, { fs: chunked(7) });
  journal.registered();
  journal.capture(paymentCall(SEND, bytes(3, hash('seven')), vector('preset-pay-only')));
  journal.capture(paymentCall(SEND, bytes(3, hash('eight')), vector('preset-pay-only'), 2n));
  const stats = await journal.close();
  expect(stats).toMatchObject({ payments: 2, dropped: 0, stopped: null });
  const read = await readJournal(path);
  expect(read.tornTail).toBe(false);
  expect(read.records.filter(item => item.type === 'payment').map(item => (item as { paymentHash: string }).paymentHash))
    .toEqual([hash('seven').toString('hex'), hash('eight').toString('hex')]);
  expect(read.records.map(item => item.type)).toEqual(['run-start', 'registered', 'payment', 'payment', 'unregistered', 'run-end']);

  const stuck = join(dir, 'stuck.journal');
  const stops: string[] = [];
  let open = true;
  const noProgress = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'write' && !open) return async () => ({ bytesWritten: 0, buffer: Buffer.alloc(0) });
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs;
  const second = await openJournal(stuck, { fs: noProgress, onStop: reason => stops.push(reason) });
  open = false;
  second.registered();
  second.capture(paymentCall(SEND, bytes(3, hash('never')), vector('preset-pay-only')));
  const ended = await second.close();
  expect(ended.stopped).toBe('write-failed');
  expect(stops).toEqual(['write-failed']);
  expect((await readJournal(stuck)).records.map(item => item.type)).toEqual(['run-start']);
});

// 1.2.1: an amount the journal cannot record (above int64 millisatoshi) is written as no amount,
// so the reader still accepts the file.
it('PAYJ/bounds a request whose fee limit or amount overflows the journal range is journaled without it, and the journal stays readable', async () => {
  const dir = scratch();
  const path = join(dir, 'overflow.journal');
  const journal = await openJournal(path);
  journal.registered();
  const max = (1n << 63n) - 1n;
  journal.capture(paymentCall(SEND, message(bytes(3, hash('overflow')), uint(2, 1n << 62n), uint(7, max)), vector('preset-pay-only')));
  journal.capture(paymentCall(SEND, message(bytes(3, hash('fine')), uint(12, max), uint(13, max)), vector('preset-pay-only'), 2n));
  const stats = await journal.close();
  expect(stats).toMatchObject({ payments: 2, dropped: 0, stopped: null });
  const read = await readJournal(path);
  const payments = read.records.filter(item => item.type === 'payment') as Array<Record<string, unknown>>;
  expect(payments[0]).toMatchObject({ paymentHash: hash('overflow').toString('hex'), amountMsat: null, amountSource: null, feeLimitMsat: null, extraction: 'complete' });
  expect(payments[1]).toMatchObject({ paymentHash: hash('fine').toString('hex'), amountMsat: max.toString(), feeLimitMsat: max.toString() });
});

// 1.2.1: the reader validates lines as it reads them and refuses a long run of unreadable lines.
it('PAYJ/reader more than 64 consecutive unreadable lines make the journal invalid wherever they are; 64 at the tail are a torn tail', async () => {
  const dir = scratch();
  const prefix = `${start(0)}\n${record('registered', 1, { session: 1 })}\n`;
  const tolerated = join(dir, 'tolerated.journal');
  writeFileSync(tolerated, prefix + '\n'.repeat(64));
  const read = await readJournal(tolerated);
  expect(read.records.map(item => item.type)).toEqual(['run-start', 'registered']);
  expect(read.tornTail).toBe(true);
  const refused = join(dir, 'refused.journal');
  writeFileSync(refused, prefix + '\n'.repeat(65));
  await expect(readJournal(refused)).rejects.toThrow('invalid payment journal (line 67)');
  // A file of nothing but newlines fails at once, not after holding every line.
  const empties = join(dir, 'empties.journal');
  writeFileSync(empties, `${start(0)}\n${'\n'.repeat(4_000_000)}`);
  const started = performance.now();
  await expect(readJournal(empties)).rejects.toThrow(/invalid payment journal/);
  expect(performance.now() - started).toBeLessThan(5_000);
}, 60_000);

// 1.2.1: decoding has the same 20 % time budget as attribution, so a flood of slow payloads
// cannot keep the event loop busy; the intake fills and drops instead.
it('PAYJ/budget a flood of 64 KiB payloads never blocks the event loop for long: decoding is budgeted and the rest is dropped', async () => {
  const dir = scratch();
  const path = join(dir, 'budget.journal');
  const journal = await openJournal(path);
  journal.registered();
  // A SendToRouteV2 request with 2,000 repeated route messages of 16 empty hops: slow to decode, under the 64 KiB cap.
  const hop = Buffer.from([0x22, 0x00]);
  const route = Buffer.concat([Buffer.from([0x30, 0x05]), ...Array.from({ length: 16 }, () => hop)]);
  const payload = message(bytes(1, hash('flood')), ...Array.from({ length: 1_750 }, () => bytes(2, route)));
  expect(payload.length).toBeLessThan(64 * 1024);
  let worstGap = 0;
  let last = performance.now();
  const watchdog = setInterval(() => { const now = performance.now(); worstGap = Math.max(worstGap, now - last); last = now; }, 1);
  const began = performance.now();
  try {
    for (let round = 0; round < 6; round++) {
      for (let index = 0; index < 400; index++) journal.capture(paymentCall(ROUTE, payload, vector('preset-pay-only'), BigInt(round * 400 + index + 1)));
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  } finally { clearInterval(watchdog); }
  const stats = await journal.close();
  const elapsed = performance.now() - began;
  console.log(`PAYJ/budget worst loop gap ${worstGap.toFixed(0)} ms over ${elapsed.toFixed(0)} ms; journaled ${stats.payments}, dropped ${stats.dropped}`);
  expect(stats.payments + stats.dropped).toBe(2_400);
  expect(stats.dropped).toBeGreaterThan(0);
  expect(worstGap).toBeLessThan(150);
  const read = await readJournal(path);
  expect(read.records.filter(item => item.type === 'drop').length).toBeGreaterThan(0);
}, 60_000);

// 1.2.1 (owner finding): a coverage marker carries the time of the event, not of the queue turn
// that wrote it; a backlog once moved an unregistered and the next registered to the same instant.
it('PAYJ/marker-time registration changes are journaled at the time they happened, however late the queue writes them', async () => {
  const dir = scratch();
  const path = join(dir, 'marker-time.journal');
  let now = Date.parse('2026-10-09T10:00:00.000Z');
  const clock = () => new Date(now);
  const journal = await openJournal(path, { clock });
  now += 1_000; journal.registered();
  // The stream drops at second 10 and comes back at second 30, while the queue is still busy
  // with payloads captured before: both markers must keep their own time.
  now += 9_000; journal.unregistered('stream-lost');
  now += 20_000; journal.registered();
  now += 5_000;
  const stats = await journal.close();
  expect(stats.stopped).toBeNull();
  const read = await readJournal(path);
  const times = read.records.filter(item => item.type === 'registered' || item.type === 'unregistered').map(item => `${item.type}@${item.time}`);
  expect(times).toEqual(['registered@2026-10-09T10:00:01.000Z', 'unregistered@2026-10-09T10:00:10.000Z', 'registered@2026-10-09T10:00:30.000Z',
    'unregistered@2026-10-09T10:00:35.000Z']);
  const coverage = journalCoverage(read.records, NODE, Date.parse('2026-10-09T10:00:00.000Z'), Date.parse('2026-10-09T10:00:35.000Z'));
  expect(coverage.gaps.map(gap => [gap.reason, (gap.to - gap.from) / 1_000])).toEqual([['not-registered', 1], ['not-registered', 20]]);
});

it('PAYJ/full-drop payments discarded when the journal fills leave a drop record before the full record, and coverage ends where the loss began', async () => {
  const dir = scratch();
  const path = join(dir, 'full-drop.journal');
  const head = `${start(0)}\n`;
  const filler = JOURNAL_LIMIT_BYTES - JOURNAL_RESERVE_BYTES - (JOURNAL_START_ROOM_BYTES + 2_000) - Buffer.byteLength(head) - 1;
  writeFileSync(path, Buffer.concat([Buffer.from(head), Buffer.alloc(filler, 0x78), Buffer.from('\n')]), { mode: 0o600 });
  let now = Date.parse(at(0));
  const stops: string[] = [];
  const journal = await openJournal(path, { clock: () => new Date(now), onStop: reason => stops.push(reason) });
  now = Date.parse(at(1));
  journal.registered();
  // Fill the room left before the reserve with payment records of one fixed length (four-digit request IDs).
  const app = vector('preset-pay-only');
  let id = 1_000n;
  journal.capture(paymentCall(SEND, bytes(3, hash(`fill${id}`)), app, id++));
  await settle();
  const line = Buffer.byteLength(`${readFileSync(path, 'utf8').split('\n').at(-2)!}\n`);
  const before = statSync(path).size;
  const fit = Math.floor((JOURNAL_LIMIT_BYTES - JOURNAL_RESERVE_BYTES - before) / line);
  for (let i = 0; i < fit; i++) journal.capture(paymentCall(SEND, bytes(3, hash(`fill${id}`)), app, id++));
  // Decoding is budgeted: wait until every filler record is on disk.
  for (let turn = 0; turn < 200 && statSync(path).size < before + fit * line; turn++) await settle();
  expect(stops).toEqual([]);
  expect(JOURNAL_LIMIT_BYTES - JOURNAL_RESERVE_BYTES - statSync(path).size).toBeLessThan(line);
  // The owner's reproduction: payments captured at seconds 10 and 20 do not fit; watch stops at second 30.
  now = Date.parse(at(10));
  journal.capture(paymentCall(SEND, bytes(3, hash('lost-10')), app, id++));
  now = Date.parse(at(20));
  journal.capture(paymentCall(SEND, bytes(3, hash('lost-20')), app, id));
  await settle();
  now = Date.parse(at(30));
  const stats = await journal.close();
  expect(stats.stopped).toBe('full');
  expect(stops).toEqual(['full']);
  expect(stats.dropped).toBe(2);
  expect(stats.payments).toBe(fit + 1);
  expect(statSync(path).size).toBeLessThanOrEqual(JOURNAL_LIMIT_BYTES);
  const read = await readJournal(path);
  expect(read.records.slice(-2)).toEqual([
    { v: 1, type: 'drop', time: at(20), run: journal.run, count: 2, first: at(10), last: at(20), reason: 'overload' },
    { v: 1, type: 'full', time: at(20), run: journal.run },
  ]);
  const coverage = journalCoverage(read.records, NODE, Date.parse(at(0)), Date.parse(at(60)));
  expect(coverage.covered).toEqual([[Date.parse(at(1)), Date.parse(at(10))]]);
  // No time after second 10 is covered: the loss is listed with its count, and the gap from it keeps the reason journal-full.
  expect(coverage.gaps).toEqual([
    { from: Date.parse(at(0)), to: Date.parse(at(1)), reason: 'not-registered', dropped: 0 },
    { from: Date.parse(at(10)), to: Date.parse(at(20)), reason: 'dropped', dropped: 2 },
    { from: Date.parse(at(10)), to: Date.parse(at(60)), reason: 'journal-full', dropped: 0 },
  ]);
  expect(coverage.coveredMs).toBe(9_000);
});

/**
 * A journal with room for exactly JOURNAL_INTAKE_ITEMS payment lines, filled by one full intake
 * captured at second 5; three more calls (`drop`, at seconds 10, 11 and 12) find the intake full
 * and are dropped at capture. The drop record that reports them reaches the write queue only
 * after the journal has no room left.
 */
async function intakeDropAtLimit(drop: (seconds: number) => MiddlewareCall) {
  const dir = scratch();
  const app = vector('preset-pay-only');
  const fill = (id: bigint) => paymentCall(SEND, bytes(3, hash(`fill${id}`)), app, id);
  // The length of one fill line (four-digit request IDs), measured by the real writer.
  const calibrate = await openJournal(join(dir, 'calibrate.journal'), { clock: () => new Date(at(0)) });
  calibrate.registered();
  calibrate.capture(fill(1_000n));
  await settle();
  const line = Buffer.byteLength(`${readFileSync(join(dir, 'calibrate.journal'), 'utf8').split('\n').at(-2)!}\n`);
  await calibrate.close();
  const path = join(dir, 'intake-drop.journal');
  const head = `${start(-1)}\n`;
  const run = '00000000-0000-4000-8000-000000000000';
  const opened = Buffer.byteLength(`${JSON.stringify({ v: 1, type: 'run-start', time: at(0), run, node: NODE, version: '1.2.0-test', repairedTail: true })}\n`)
    + Buffer.byteLength(`${JSON.stringify({ v: 1, type: 'registered', time: at(1), run, session: 1 })}\n`);
  const filler = JOURNAL_LIMIT_BYTES - JOURNAL_RESERVE_BYTES - JOURNAL_INTAKE_ITEMS * line - opened - Buffer.byteLength(head) - 1;
  writeFileSync(path, Buffer.concat([Buffer.from(head), Buffer.alloc(filler, 0x78), Buffer.from('\n')]), { mode: 0o600 });
  let now = Date.parse(at(0));
  const stops: string[] = [];
  const journal = await openJournal(path, { clock: () => new Date(now), onStop: reason => stops.push(reason) });
  now = Date.parse(at(1));
  journal.registered();
  await settle();
  const room = () => JOURNAL_LIMIT_BYTES - JOURNAL_RESERVE_BYTES - statSync(path).size;
  expect(room()).toBe(JOURNAL_INTAKE_ITEMS * line);
  now = Date.parse(at(5));
  for (let i = 0; i < JOURNAL_INTAKE_ITEMS; i++) journal.capture(fill(BigInt(1_000 + i)));
  for (const seconds of [10, 11, 12]) { now = Date.parse(at(seconds)); journal.capture(drop(seconds)); }
  for (let turn = 0; turn < 400 && room() > 0; turn++) await settle();
  expect(room()).toBe(0);
  expect(stops).toEqual([]);
  return { path, journal, stops, setNow: (seconds: number) => { now = Date.parse(at(seconds)); } };
}

/** reconcile over the journal with an LND that lists no payment: the dropped calls left none behind. */
async function reconcileEmpty(path: string, since: number, until: number) {
  const dir = scratch();
  writeFileSync(join(dir, 'tls.cert'), 'not used by the fake adapter');
  writeFileSync(join(dir, 'own.macaroon'), vector('default-readonly'));
  writeFileSync(join(dir, 'registry.json'), JSON.stringify({ schema: 1, entries: [] }));
  const unexpected = (): never => { throw new Error('unexpected adapter call'); };
  const lnd = {
    getInfo: async () => ({ pubkey: NODE, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }),
    listPermissions: async () => snapshot.methods as Record<string, string[]>,
    listMacaroonIds: unexpected, bakeMacaroon: unexpected, deleteMacaroonId: unexpected, checkMacaroon: unexpected,
    listPayments: async ({ indexOffset }: { indexOffset: bigint }) => ({ payments: [], lastIndexOffset: indexOffset }),
    trackPayment: async () => null,
  } as unknown as LndAdapter & PaymentLookup;
  return reconcileRun(['--payment-journal', path, '--lnd-rest', 'localhost:8080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', join(dir, 'registry.json'), '--since', at(since), '--until', at(until)],
  { lnd, fs, env: {}, clock: () => new Date('2026-10-09T12:00:00.000Z') });
}

it('PAYJ/full-drop a drop record of calls dropped at capture that is itself lost at the limit still counts them from their first capture', async () => {
  const app = vector('preset-pay-only');
  const j = await intakeDropAtLimit(seconds => paymentCall(SEND, bytes(3, hash(`intake-drop-${seconds}`)), app, BigInt(8_000 + seconds)));
  // The next call flushes the intake drop (count 3, 10..12 s) into the queue ahead of it; neither fits.
  j.setNow(20);
  j.journal.capture(paymentCall(SEND, bytes(3, hash('lost-20')), app, 9_020n));
  await settle();
  j.setNow(30);
  const stats = await j.journal.close();
  expect(stats).toMatchObject({ payments: JOURNAL_INTAKE_ITEMS, dropped: 4, stopped: 'full' });
  expect(j.stops).toEqual(['full']);
  expect(statSync(j.path).size).toBeLessThanOrEqual(JOURNAL_LIMIT_BYTES);
  const read = await readJournal(j.path);
  expect(read.records.slice(-2)).toEqual([
    { v: 1, type: 'drop', time: at(20), run: j.journal.run, count: 4, first: at(10), last: at(20), reason: 'overload' },
    { v: 1, type: 'full', time: at(20), run: j.journal.run },
  ]);
  const coverage = journalCoverage(read.records, NODE, Date.parse(at(1)), Date.parse(at(30)));
  expect(coverage.covered).toEqual([[Date.parse(at(1)), Date.parse(at(10))]]);
  expect(coverage.gaps).toEqual([
    { from: Date.parse(at(10)), to: Date.parse(at(20)), reason: 'dropped', dropped: 4 },
    { from: Date.parse(at(10)), to: Date.parse(at(30)), reason: 'journal-full', dropped: 0 },
  ]);
  const output = await reconcileEmpty(j.path, 2, 11);
  expect(output.exitCode).toBe(1);
  expect((output.result as { coverage: { complete: boolean } }).coverage.complete).toBe(false);
});

it('PAYJ/full-drop a lost drop record followed only by markers still leaves a drop record: dropped DeletePayment calls never read as covered', async () => {
  const app = vector('preset-pay-only');
  const j = await intakeDropAtLimit(seconds => paymentCall('/lnrpc.Lightning/DeletePayment', bytes(1, hash(`deleted-${seconds}`)), app,
    BigInt(8_000 + seconds)));
  // close() flushes the intake drop, then unregistered and run-end at 30 s: none of them fits.
  j.setNow(30);
  const stats = await j.journal.close();
  expect(stats).toMatchObject({ payments: JOURNAL_INTAKE_ITEMS, deletions: 0, dropped: 3, stopped: 'full' });
  const read = await readJournal(j.path);
  expect(read.records.slice(-2)).toEqual([
    { v: 1, type: 'drop', time: at(30), run: j.journal.run, count: 3, first: at(10), last: at(30), reason: 'overload' },
    { v: 1, type: 'full', time: at(30), run: j.journal.run },
  ]);
  const coverage = journalCoverage(read.records, NODE, Date.parse(at(1)), Date.parse(at(30)));
  expect(coverage.covered).toEqual([[Date.parse(at(1)), Date.parse(at(10))]]);
  expect(coverage.gaps).toEqual(expect.arrayContaining([
    { from: Date.parse(at(10)), to: Date.parse(at(30)), reason: 'dropped', dropped: 3 },
    { from: Date.parse(at(10)), to: Date.parse(at(30)), reason: 'journal-full', dropped: 0 },
  ]));
  expect(coverage.gaps).toHaveLength(2);
  // LND lists nothing (the payments were deleted), so only coverage can say the window is incomplete.
  const output = await reconcileEmpty(j.path, 2, 11);
  expect(output.exitCode).toBe(1);
  expect((output.result as { coverage: { complete: boolean } }).coverage.complete).toBe(false);
});
