// Parser review 2026-10-08, LOW-4: bakery checks time-before with Go's
// time.Parse(time.RFC3339Nano), which falls back to its general parser and so accepts a
// one-digit hour, a zone offset hour of 24 and an offset minute of 60. macwarden called those
// unparseable, so an LND-enforced expiry was shown as unknown. Verdicts come from the LND
// v0.21.4 oracle recorded in test/vectors/lnd-oracle/l4.json.
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { addFirstPartyCaveat, decodeMacaroon, parseTimeBefore } from '../src/decode/index.js';
import { Secret } from '../src/secret.js';
import { TIMES } from './vectors/lnd-oracle/cases.mjs';

type TimeCase = { value: string; lnd: { ok: true; unixSeconds: string; nanos: number } | { ok: false } };
const repo = resolve();
const fixture = JSON.parse(readFileSync(join(repo, 'test/vectors/lnd-oracle/l4.json'), 'utf8')) as { cases: TimeCase[] };

it('PARSERS-L4/the fixture is the committed corpus and holds both lenient forms', () => {
  expect(fixture.cases.map(item => item.value)).toEqual(TIMES);
  const accepted = (value: string) => fixture.cases.find(item => item.value === value)!.lnd.ok;
  expect(accepted('2027-10-08T1:00:00Z')).toBe(true);
  expect(accepted('2027-10-08T23:00:00+24:00')).toBe(true);
  expect(accepted('2027-10-08T01:00:00+00:60')).toBe(true);
  expect(fixture.cases.filter(item => !item.lnd.ok).length).toBeGreaterThanOrEqual(15);
});

it.each(fixture.cases)('PARSERS-L4/$value parses to the instant LND enforces', ({ value, lnd }) => {
  expect(parseTimeBefore(value)).toBe(lnd.ok ? BigInt(lnd.unixSeconds) * 1_000_000_000n + BigInt(lnd.nanos) : undefined);
});

it('PARSERS-L4/an expiry with a one-digit hour earlier today is shown as expired, not unknown', () => {
  const own = new Secret(readFileSync(join(repo, 'test/vectors/default-readonly.macaroon')));
  const facts = decodeMacaroon(addFirstPartyCaveat(own, 'time-before 2026-10-08T1:00:00Z'));
  expect(facts.warnings).not.toContain('bad-time-before');
  const caveat = facts.caveats.at(-1)!;
  expect(caveat).toMatchObject({ type: 'time-before', value: '2026-10-08T1:00:00Z' });
  expect(parseTimeBefore(caveat.value)! <= BigInt(Date.parse('2026-10-08T12:00:00Z')) * 1_000_000n).toBe(true);
});
