// Audit 1.4.0 (JOURNAL section): record times across a clock step, coverage before a run
// registers, an fsync failure after a complete write, and calls captured while closing.
import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { JOURNAL_CLOCK_STEP_MS, journalCoverage, parseRecord, readJournal, type JournalRecord } from '../src/watch/payment-journal.js';
import { bytes } from './helpers/payment-proto.js';
import { NODE, identityOf, openJournal, paymentCall, settle, vector } from './helpers/payment-journal.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function scratch(): string {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'journal-audit-'));
  dirs.push(dir);
  return dir;
}
const SEND = '/routerrpc.Router/SendPaymentV2';
const hash = (text: string) => createHash('sha256').update(text).digest();
const lines = (path: string) => readFileSync(path, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line) as JournalRecord);
const T0 = Date.parse('2026-10-09T10:00:00.000Z');
const MINUTE = 60_000;

it('JOURNAL-AUDIT/clock a forward step that is then corrected neither pins later records nor hides a real gap', async () => {
  const path = join(scratch(), 'step.journal');
  let wall = T0;
  let mono = 0;
  const journal = await openJournal(path, { clock: () => new Date(wall), monotonic: () => mono });
  wall = T0 + 1_000; mono = 1_000; journal.registered(); await settle();
  // Five minutes in, the system clock reads an hour ahead; a deletion is journaled meanwhile.
  wall = T0 + 65 * MINUTE; mono = 5 * MINUTE;
  journal.capture(paymentCall('/lnrpc.Lightning/DeletePayment', Buffer.alloc(0), null)); await settle();
  // NTP corrects the clock; the stream drops at 10:10 and watch registers again at 10:15.
  wall = T0 + 10 * MINUTE; mono = 10 * MINUTE; journal.unregistered('stream-lost'); await settle();
  wall = T0 + 15 * MINUTE; mono = 15 * MINUTE; journal.registered(); await settle();
  wall = T0 + 20 * MINUTE; mono = 20 * MINUTE;
  await journal.close();
  const iso = (ms: number) => new Date(T0 + ms).toISOString();
  expect(lines(path).map(item => `${item.type}@${item.time}`)).toEqual([`run-start@${iso(0)}`, `registered@${iso(1_000)}`,
    `deletion@${iso(5 * MINUTE)}`, `unregistered@${iso(10 * MINUTE)}`, `registered@${iso(15 * MINUTE)}`, `unregistered@${iso(20 * MINUTE)}`,
    `run-end@${iso(20 * MINUTE)}`]);
  const { records } = await readJournal(path);
  const coverage = journalCoverage(records, NODE, T0 + 1_000, T0 + 60 * MINUTE);
  expect(coverage.gaps.map(gap => [gap.from - T0, gap.to - T0, gap.reason])).toEqual([
    [10 * MINUTE, 15 * MINUTE, 'not-registered'], [20 * MINUTE, 60 * MINUTE, 'not-running']]);
});

it('JOURNAL-AUDIT/clock the system clock is followed while it moves with the monotonic clock, and again once a step is corrected', async () => {
  const path = join(scratch(), 'follow.journal');
  let wall = T0;
  let mono = 0;
  const journal = await openJournal(path, { clock: () => new Date(wall), monotonic: () => mono });
  // A small adjustment within the tolerance is followed.
  wall = T0 + 10_000 + JOURNAL_CLOCK_STEP_MS; mono = 10_000; journal.registered(); await settle();
  // A step back beyond it is not: the record continues on the monotonic clock instead of pinning.
  wall = T0 - 3_600_000; mono = 20_000; journal.unregistered('stream-lost'); await settle();
  // The clock returns to agreement: followed again.
  wall = T0 + 30_000 + JOURNAL_CLOCK_STEP_MS; mono = 30_000; journal.registered(); await settle();
  wall = T0 + 40_000 + JOURNAL_CLOCK_STEP_MS; mono = 40_000;
  await journal.close();
  const at = (ms: number) => new Date(T0 + ms + JOURNAL_CLOCK_STEP_MS).toISOString();
  expect(lines(path).map(item => item.time)).toEqual([new Date(T0).toISOString(), at(10_000), at(20_000), at(30_000), at(40_000), at(40_000)]);
});

it('JOURNAL-AUDIT/coverage the time from a run-start to its registration is not-registered, before and between runs', () => {
  const RUN = '11111111-2222-4333-8444-555555555555';
  const RUN2 = '66666666-7777-4888-9999-aaaaaaaaaaaa';
  const record = (type: string, seconds: number, extra: Record<string, unknown> = {}, run = RUN) =>
    parseRecord(JSON.stringify({ v: 1, type, time: new Date(T0 + seconds * 1_000).toISOString(), run, ...extra }))!;
  const start = (seconds: number, run = RUN) => record('run-start', seconds, { node: NODE, version: '1.3.0', repairedTail: false }, run);
  const end = (seconds: number, run = RUN) => record('run-end', seconds, { payments: 0, deletions: 0, dropped: 0 }, run);
  const shape = (records: JournalRecord[], from: number, to: number) => journalCoverage(records, NODE, T0 + from * 1_000, T0 + to * 1_000)
    .gaps.map(gap => [(gap.from - T0) / 1_000, (gap.to - T0) / 1_000, gap.reason]);
  // The first run starts at 100 and registers at 200.
  expect(shape([start(100), record('registered', 200, { session: 1 }), record('unregistered', 300, { session: 1, reason: 'stopping' }), end(300)], 0, 400))
    .toEqual([[0, 100, 'before-journal'], [100, 200, 'not-registered'], [300, 400, 'not-running']]);
  // A second run starts at 500 and registers only at 900, after a clean stop and after a crash.
  const second = [start(500, RUN2), record('registered', 900, { session: 1 }, RUN2), record('unregistered', 1_000, { session: 1, reason: 'stopping' }, RUN2),
    end(1_000, RUN2)];
  expect(shape([start(100), record('registered', 110, { session: 1 }), record('unregistered', 300, { session: 1, reason: 'stopping' }), end(300),
    ...second], 100, 1_000)).toEqual([[100, 110, 'not-registered'], [300, 500, 'not-running'], [500, 900, 'not-registered']]);
  expect(shape([start(100), record('registered', 110, { session: 1 }), record('alive', 300), ...second], 100, 1_000))
    .toEqual([[100, 110, 'not-registered'], [300, 500, 'unconfirmed'], [500, 900, 'not-registered']]);
  // A window that starts between a run-start and its registration.
  expect(shape(second, 600, 1_000)).toEqual([[600, 900, 'not-registered']]);
});

it('JOURNAL-AUDIT/sync a failed fsync after a complete write keeps the written records counted and stops the run', async () => {
  const path = join(scratch(), 'sync.journal');
  const stops: string[] = [];
  let failSync = false;
  const syncFails = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'sync' && failSync) return async () => { throw Object.assign(new Error('EIO'), { code: 'EIO' }); };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs;
  const journal = await openJournal(path, { fs: syncFails, onStop: reason => stops.push(reason) });
  failSync = true;
  journal.registered();
  journal.capture(paymentCall(SEND, bytes(3, hash('landed')), vector('preset-pay-only')));
  await settle();
  expect(stops).toEqual(['write-failed']);
  const stats = await journal.close();
  // The record is in the file: it is counted as journaled, not as dropped.
  const read = await readJournal(path);
  expect(read.records.map(item => item.type)).toEqual(['run-start', 'registered', 'payment']);
  expect(stats).toMatchObject({ payments: 1, dropped: 0, stopped: 'write-failed' });
});

// Documented behaviour (close()): a call captured after close began is not journaled and is counted
// as dropped in the statistics only; the run-end record was queued before it.
it('JOURNAL-AUDIT/close a call captured after close began is counted as dropped in the statistics, not in the run-end record', async () => {
  const path = join(scratch(), 'closing.journal');
  const journal = await openJournal(path);
  journal.registered();
  journal.capture(paymentCall(SEND, bytes(3, hash('before')), vector('preset-pay-only')));
  const closing = journal.close();
  journal.capture(paymentCall(SEND, bytes(3, hash('after')), vector('preset-pay-only'), 2n));
  const stats = await closing;
  const last = lines(path).at(-1)!;
  expect(last).toMatchObject({ type: 'run-end', payments: 1, deletions: 0, dropped: 0 });
  expect(stats).toMatchObject({ payments: 1, deletions: 0, dropped: 1, stopped: null });
});

// The journal side of identifying an oversized macaroon: when the middleware passes a bounded
// prefix that holds the header (flagged oversized), the record names the credential from it; a
// prefix that ends inside the header stays id:undecodable (and reconcile attributes it to none).
it('JOURNAL-AUDIT/identity an oversized macaroon passed as a header prefix is journaled with its credential ID', async () => {
  const path = join(scratch(), 'prefix.journal');
  const journal = await openJournal(path);
  journal.registered();
  const admin = vector('default-admin');
  // Cut inside the signature: everything after the header is missing or incomplete.
  const prefix = admin.subarray(0, admin.length - 30);
  journal.capture(paymentCall(SEND, bytes(3, hash('prefix')), prefix, 1n, { oversizedMacaroon: true, macaroonBytes: prefix.length }));
  journal.capture(paymentCall(SEND, bytes(3, hash('cut')), admin.subarray(0, 4), 2n, { oversizedMacaroon: true, macaroonBytes: 4 }));
  await journal.close();
  const payments = lines(path).filter(item => item.type === 'payment').map(item => (item as { credential: string }).credential);
  expect(payments).toEqual([identityOf(admin), 'id:undecodable']);
});

// The journal path and its lock path are refused when they are symbolic links (docs/spec.md, Payment
// journal, File rules): the given path was once resolved before it was checked, so a link to a
// journal was followed. Portable without symlink privilege: the file system reports a link at the
// path, and realpath, stat and open follow it to the real journal, as they would for a real link.
it('JOURNAL-AUDIT/links a journal path or lock path that is a symbolic link is refused and nothing is written', async () => {
  const dir = scratch();
  const real = join(dir, 'real.journal');
  await (await openJournal(real)).close();
  const before = readFileSync(real, 'utf8');
  const linked = (link: string, to: string) => {
    const same = (path: unknown) => resolve(String(path)) === resolve(link);
    type Call = (...args: unknown[]) => Promise<unknown>;
    const follow = (call: unknown): never => (async (path: string, ...rest: unknown[]) => (call as Call)(same(path) ? to : path, ...rest)) as never;
    return { ...fs, realpath: follow(fs.realpath), stat: follow(fs.stat), open: follow(fs.open),
      lstat: (async (path: string, ...rest: unknown[]) => {
        const meta = await (fs.lstat as (...args: unknown[]) => Promise<import('node:fs').Stats>)(same(path) ? to : path, ...rest);
        return same(path) ? Object.assign(Object.create(Object.getPrototypeOf(meta)), meta, { isFile: () => false, isSymbolicLink: () => true }) : meta;
      }) as typeof fs.lstat } as typeof fs;
  };
  const link = join(dir, 'link.journal');
  let locked = 0;
  const lock = async () => { locked += 1; return async () => undefined; };
  await expect(openJournal(link, { fs: linked(link, real), lock })).rejects.toThrow('payment journal is not a regular file');
  // A lock path that is a link (here to the real journal) is refused before the lock is taken.
  const fresh = join(dir, 'fresh.journal');
  await expect(openJournal(fresh, { fs: linked(`${fresh}.lock`, real), lock })).rejects.toThrow('is not a regular file');
  expect(locked).toBe(0);
  expect(readFileSync(real, 'utf8')).toBe(before);
  expect(existsSync(fresh)).toBe(false);
});
