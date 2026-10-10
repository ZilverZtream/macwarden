// The Windows private-file helper's create reply: a helper that exits without printing CREATED
// or EXISTS failed; a null wait must never be read as "the path already exists" (1.2.1).
import { expect, it } from 'vitest';
import { creationOutcome } from '../src/private-file.js';

type Prefix = 'CREATED ' | 'EXISTS';
const later = <T>(value: T) => new Promise<T>(settle => setTimeout(() => settle(value), 5));
const helper = (replies: Record<Prefix, Promise<string | null>>) => ({ next: (prefix: string) => replies[prefix as Prefix] });

it('a helper that exits without a reply is a failure, whichever wait settles first', async () => {
  expect(await creationOutcome(helper({ 'EXISTS': Promise.resolve(null), 'CREATED ': later(null) }))).toEqual({ kind: 'failed' });
  expect(await creationOutcome(helper({ 'CREATED ': Promise.resolve(null), 'EXISTS': later(null) }))).toEqual({ kind: 'failed' });
  expect(await creationOutcome(helper({ 'CREATED ': Promise.resolve(null), 'EXISTS': Promise.resolve(null) }))).toEqual({ kind: 'failed' });
});

it('EXISTS and CREATED keep their meaning, also when the other wait settles null first', async () => {
  expect(await creationOutcome(helper({ 'CREATED ': Promise.resolve(null), 'EXISTS': later('') }))).toEqual({ kind: 'exists' });
  const line = '{"sid":"S-1-5-21-1"}';
  expect(await creationOutcome(helper({ 'EXISTS': Promise.resolve(null), 'CREATED ': later(line) }))).toEqual({ kind: 'created', line });
});
