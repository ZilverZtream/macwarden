import { expect, it } from 'vitest';
import { UsageStore } from '../src/watch/usage.js';

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
