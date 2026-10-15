import { expect, it } from 'vitest';
import { CANARY_LIMIT, COVERAGE_LIMIT, UsageStore } from '../src/watch/usage.js';

// Audit 1.4.0: a usage file holding more records than the store's limit keeps the most recently
// seen ones. Its instants may differ in precision (`…:00Z` and `…:00.900Z`); compared as text the
// earlier `…:00Z` sorted last and was kept in place of the later record.
it('a usage file over the limit keeps the most recently seen record across mixed-precision instants', () => {
  const node = `02${'a'.repeat(64)}`;
  const store = new UsageStore();
  store.record(node, 'id:0000000000000001', '1', '/lnrpc.Lightning/GetInfo', new Date('2026-10-01T00:00:00.900Z'));
  store.record(node, 'id:0000000000000002', '2', '/lnrpc.Lightning/GetInfo', new Date('2026-10-01T00:00:00.000Z'));
  const file = JSON.parse(store.toText()) as { entries: { credential: string; firstSeen: string; lastSeen: string }[] };
  // The earlier record written without a fraction, as another writer may.
  const earlier = file.entries.find(item => item.credential === 'id:0000000000000002')!;
  earlier.firstSeen = earlier.lastSeen = '2026-10-01T00:00:00Z';
  const parsed = UsageStore.parse(JSON.stringify(file), 1);
  const kept = JSON.parse(parsed.toText()) as { evictions: number; lastEviction: string | null; entries: { credential: string }[] };
  expect(kept.entries.map(item => item.credential)).toEqual(['id:0000000000000001']);
  expect(kept.evictions).toBe(1);
});

// Audit 1.3.2: canary uses and coverage records over their bounds are ordered the same way.
const NODE = `02${'a'.repeat(64)}`;
const nodeOf = (n: number) => `02${n.toString(16).padStart(64, '0')}`;
const canary = (rootKeyId: string, lastUse: string) => ({ nodePubkey: NODE, rootKeyId, uses: 1, firstUse: '2026-09-01T00:00:00Z', lastUse });
const coverage = (nodePubkey: string, lastEnd: string) => ({ nodePubkey, firstStart: '2026-09-01T00:00:00Z', lastEnd, coveredSeconds: 60, sessions: 1 });
const file = (fields: object) => JSON.stringify({ schema: 1, dropped: 0, entries: [], ...fields });

it('canary uses and coverage over their bounds keep the most recent across mixed-precision instants', () => {
  // The bound plus one: the earliest is evicted. The later `…:00.900Z` must stay, not the earlier `…:00Z`.
  const fillers = Array.from({ length: CANARY_LIMIT - 1 }, (_, n) => canary(String(100 + n), '2026-10-02T00:00:00Z'));
  const canaries = UsageStore.parse(file({ canaryUses: [canary('1', '2026-10-01T00:00:00.900Z'), canary('2', '2026-10-01T00:00:00Z'), ...fillers] }));
  expect(canaries.canaryUsesFor(NODE, '1')).not.toBeNull();
  expect(canaries.canaryUsesFor(NODE, '2')).toBeNull();
  const nodes = Array.from({ length: COVERAGE_LIMIT - 1 }, (_, n) => coverage(nodeOf(100 + n), '2026-10-02T00:00:00Z'));
  const covered = UsageStore.parse(file({ coverage: [coverage(nodeOf(1), '2026-10-01T00:00:00.900Z'), coverage(nodeOf(2), '2026-10-01T00:00:00Z'), ...nodes] }));
  expect(covered.coverageFor(nodeOf(1))).not.toBeNull();
  expect(covered.coverageFor(nodeOf(2))).toBeNull();
});

it('a duplicate key is refused even when its first copy is evicted at the bound', () => {
  const store = new UsageStore();
  for (const [n, at] of [[1, '2026-10-01T00:00:01Z'], [2, '2026-10-01T00:00:02Z'], [3, '2026-10-01T00:00:03Z']] as const)
    store.record(NODE, `id:000000000000000${n}`, '1', '/lnrpc.Lightning/GetInfo', new Date(at));
  const records = JSON.parse(store.toText()) as { entries: { lastSeen: string }[] };
  // Limit 2, four records: the first and last share a key, and the first is evicted before the last is read.
  const duplicate = { ...records.entries[0], firstSeen: '2026-10-01T00:00:04Z', lastSeen: '2026-10-01T00:00:04Z' };
  expect(() => UsageStore.parse(JSON.stringify({ ...records, entries: [...records.entries, duplicate] }), 2)).toThrow('invalid usage file');
  const canaries = [canary('1', '2026-10-01T00:00:00Z'), ...Array.from({ length: CANARY_LIMIT }, (_, n) => canary(String(100 + n), '2026-10-02T00:00:00Z')),
    canary('1', '2026-10-03T00:00:00Z')];
  expect(() => UsageStore.parse(file({ canaryUses: canaries }))).toThrow('invalid usage file');
  const nodes = [coverage(nodeOf(1), '2026-10-01T00:00:00Z'), ...Array.from({ length: COVERAGE_LIMIT }, (_, n) => coverage(nodeOf(100 + n), '2026-10-02T00:00:00Z')),
    coverage(nodeOf(1), '2026-10-03T00:00:00Z')];
  expect(() => UsageStore.parse(file({ coverage: nodes }))).toThrow('invalid usage file');
  // Spans for a node whose coverage was not kept are dropped, but a duplicate is still refused.
  const span = { nodePubkey: nodeOf(9), spans: [['2026-10-01T00:00:00Z', '2026-10-01T00:01:00Z']] };
  expect(() => UsageStore.parse(file({ coverageSpans: [span, span] }))).toThrow('invalid usage file');
});
