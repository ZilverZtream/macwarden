import { writeFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { run as rotate } from '../src/commands/rotate.js';
import { openRegistry } from '../src/registry/index.js';
import { fixture, oldId } from './helpers/cp038-online.js';

// RL-03 (SPEC 6 S5/S11, Registry format): rotate S11 adds time-before with O's recorded `requested`
// duration. A malformed value was parsed only after BakeMacaroon (exit 7, a dangling root key).
// It is now refused when the registry is read, and S5 checks the duration again before any LND call.

it('RL-03/a malformed recorded expiry duration is refused before BakeMacaroon, not after', async () => {
  const f = fixture();
  // Hand-edited or legacy metadata: "1y" is not an accepted --expires value (n m|h|d).
  f.save([{ ...f.old, caveats: [{ type: 'time-before', value: '2027-01-01T00:00:00Z', requested: '1y' }] }]);
  f.lnd.ids = [0n, oldId];
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 3, step: 'S3' });
  expect(f.lnd.calls).toEqual([]);
  expect(f.rows()).toHaveLength(1);
});

it.each([
  ['a year unit', [{ type: 'time-before', value: '2027-01-01T00:00:00Z', requested: '1y' }]],
  ['zero', [{ type: 'time-before', value: '2027-01-01T00:00:00Z', requested: '0d' }]],
  ['six digits', [{ type: 'time-before', value: '2027-01-01T00:00:00Z', requested: '100000d' }]],
  ['a leading zero', [{ type: 'time-before', value: '2027-01-01T00:00:00Z', requested: '090d' }]],
  ['a non-string', [{ type: 'time-before', value: '2027-01-01T00:00:00Z', requested: 90 }]],
  ['a caveat other than time-before', [{ type: 'ipaddr', value: '127.0.0.1', requested: '90d' }]],
])('RL-03/the registry refuses a recorded duration with %s', async (_name, caveats) => {
  const f = fixture();
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [{ ...f.old, caveats }] }));
  await expect(openRegistry(f.registry)).rejects.toMatchObject({ code: 3 });
});

it.each(['2026-02-30T00:00:00Z', '2026-10-05T24:00:00Z', '2026-13-01T00:00:00Z'])(
  'RL-03/the registry refuses the impossible creation time %s instead of rolling it over', async createdAt => {
    const f = fixture();
    writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [{ ...f.old, createdAt }] }));
    await expect(openRegistry(f.registry)).rejects.toMatchObject({ code: 3 });
  });

it('RL-03/an accepted duration still reads, and rotate carries it to the replacement', async () => {
  const f = fixture();
  f.save([{ ...f.old, caveats: [{ type: 'time-before', value: '2027-01-01T00:00:00Z', requested: '90d' }] }]);
  f.lnd.ids = [0n, oldId];
  expect((await openRegistry(f.registry)).entries).toHaveLength(1);
  const staged = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(staged.error).toBeNull();
  expect((staged.result as { new: { caveats: unknown[] } }).new.caveats)
    .toEqual([{ type: 'time-before', value: '2027-01-03T12:00:00Z', requested: '90d' }]);
});

it('RL-03/a recorded duration that cannot be applied at stage time is refused at S5 before any LND call', async () => {
  const f = fixture();
  // A valid duration whose instant would pass the end of the Date range from this clock.
  const late = new Date(8.64e15 - 86_400_000);
  f.deps.clock = () => late;
  f.save([{ ...f.old, caveats: [{ type: 'time-before', value: '2027-01-01T00:00:00Z', requested: '99999d' }] }]);
  f.lnd.ids = [0n, oldId];
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 3, step: 'S5' });
  expect(f.lnd.calls).toEqual([]);
});
