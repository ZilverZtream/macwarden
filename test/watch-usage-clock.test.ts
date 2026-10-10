import { expect, it } from 'vitest';
import { UsageStore } from '../src/watch/usage.js';

const written = (store: UsageStore) => (JSON.parse(store.toText()) as { lastAttributionDrop: string | null }).lastAttributionDrop;

it('USAGE/attribution-drop the last drop time follows the clock and never moves back when the clock steps back', () => {
  const store = new UsageStore();
  store.noteDroppedAttribution(Date.parse('2030-01-02T03:04:05.000Z'));
  expect(written(store)).toBe('2030-01-02T03:04:05.000Z');
  store.noteDroppedAttribution(Date.parse('2030-01-02T03:00:00.000Z'));
  expect(written(store)).toBe('2030-01-02T03:04:05.000Z');
  store.noteDroppedAttribution(Date.parse('2030-01-02T03:05:00.000Z'));
  expect(written(store)).toBe('2030-01-02T03:05:00.000Z');
  // A time read from the file is kept against an earlier clock too.
  const reread = UsageStore.parse(store.toText());
  reread.noteDroppedAttribution(Date.parse('2029-12-31T00:00:00.000Z'));
  expect(written(reread)).toBe('2030-01-02T03:05:00.000Z');
  expect(reread.droppedAttributions).toBe(4);
});
