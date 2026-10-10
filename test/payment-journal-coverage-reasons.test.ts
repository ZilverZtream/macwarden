// journalCoverage keeps the reason that ended coverage even when nothing covered precedes it
// (audit N06): a drop that consumes a whole registered span, or a run that starts and ends without
// a registration, must still change the reason of the gap that follows.
import { expect, it } from 'vitest';
import { journalCoverage, parseRecord } from '../src/watch/payment-journal.js';
import { NODE } from './helpers/payment-journal.js';

const RUN = '11111111-2222-4333-8444-555555555555';
const base = Date.parse('2026-10-09T10:00:00.000Z');
const at = (seconds: number) => new Date(base + seconds * 1_000).toISOString();
const record = (type: string, seconds: number, extra: Record<string, unknown> = {}) =>
  parseRecord(JSON.stringify({ v: 1, type, time: at(seconds), run: RUN, ...extra }))!;
const start = (seconds: number) => record('run-start', seconds, { node: NODE, version: '1.2.0', repairedTail: false });
function shape(records: ReturnType<typeof record>[], from: number, to: number) {
  const coverage = journalCoverage(records, NODE, base + from * 1_000, base + to * 1_000);
  return { covered: coverage.coveredMs / 1_000,
    gaps: coverage.gaps.map(gap => [(gap.from - base) / 1_000, (gap.to - base) / 1_000, gap.reason, gap.dropped]) };
}

const consumed = [start(0), record('registered', 1, { session: 1 }),
  record('drop', 2, { count: 3, first: at(1), last: at(2), reason: 'overload' }), record('full', 2)];

it('a drop consuming the whole registered span keeps journal-full from the full record on', () => {
  expect(shape(consumed, 0, 10)).toEqual({ covered: 0, gaps: [
    [0, 1, 'not-registered', 0], [1, 2, 'dropped', 3], [2, 10, 'journal-full', 0]] });
  // A window starting after it takes the end reason too.
  expect(shape(consumed, 5, 10)).toEqual({ covered: 0, gaps: [[5, 10, 'journal-full', 0]] });
});

it('a run that ends without a registration ends with its own reason', () => {
  expect(shape([start(0), record('run-end', 5, { payments: 0, deletions: 0, dropped: 0 })], 0, 10))
    .toEqual({ covered: 0, gaps: [[0, 5, 'not-registered', 0], [5, 10, 'not-running', 0]] });
  expect(shape([start(0), record('full', 5)], 0, 10))
    .toEqual({ covered: 0, gaps: [[0, 5, 'not-registered', 0], [5, 10, 'journal-full', 0]] });
  expect(shape([start(0), record('run-end', 5, { payments: 0, deletions: 0, dropped: 0 })], 7, 10))
    .toEqual({ covered: 0, gaps: [[7, 10, 'not-running', 0]] });
});

it('a run that lost its stream and then ended is not running after its run-end', () => {
  const records = [start(0), record('registered', 1, { session: 1 }),
    record('unregistered', 3, { session: 1, reason: 'stream-lost' }), record('run-end', 4, { payments: 0, deletions: 0, dropped: 0 })];
  expect(shape(records, 0, 10)).toEqual({ covered: 2, gaps: [
    [0, 1, 'not-registered', 0], [3, 4, 'not-registered', 0], [4, 10, 'not-running', 0]] });
});

it('an end reason equal to the current one never splits a gap', () => {
  const records = [start(0), record('registered', 1, { session: 1 }),
    record('unregistered', 3, { session: 1, reason: 'stopping' }), record('run-end', 4, { payments: 0, deletions: 0, dropped: 0 })];
  expect(shape(records, 0, 10)).toEqual({ covered: 2, gaps: [[0, 1, 'not-registered', 0], [3, 10, 'not-running', 0]] });
});
