import { expect, it } from 'vitest';
import { run as rotate } from '../src/commands/rotate.js';
import { run as respond } from '../src/commands/respond.js';
import { run as inventory } from '../src/commands/inventory.js';
import { fixture, nextId, oldId } from './helpers/cp038-online.js';

// RL-02 (SPEC 6 S3/S13/F3, 10 P5): a replacement "created before O" is tampering. 1.1.0 recorded
// N.createdAt as the clock at S10, so a clock behind O's recorded creation time made rotate write
// a link that finish, respond and inventory then rejected. N.createdAt is now max(now, O.createdAt),
// and a backwards link of exactly the shape 1.1.0's stage wrote is accepted.

const ahead = '2026-10-05T12:01:00Z'; // O recorded one minute after the clock rotate reads (12:00)

it('RL-02/a replacement staged while the clock is behind the original\'s createdAt can be finished', async () => {
  const f = fixture();
  f.save([{ ...f.old, createdAt: ahead }]);
  f.lnd.ids = [0n, oldId];
  const staged = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(staged.error).toBeNull();
  // Never earlier than the credential it replaces.
  const recorded = f.rows().find(row => row.replaces === String(oldId))!;
  expect(Date.parse(recorded.createdAt)).toBe(Date.parse(ahead));
  const finished = await rotate(['Alice', '--finish', '--yes', ...f.flags], f.deps);
  expect(finished.error).toBeNull();
  expect(f.lnd.deleted).toEqual([oldId]);
});

it('RL-02/the self-written link does not make respond refuse the node as tampered', async () => {
  const f = fixture();
  f.save([{ ...f.old, createdAt: ahead }]);
  f.lnd.ids = [0n, oldId];
  expect((await rotate(['Alice', '--out', f.out, ...f.flags], f.deps)).error).toBeNull();
  const planned = await respond(['--finish', '--dry-run', ...f.flags], f.deps);
  expect(planned.error).toBeNull();
  expect((planned.result as { items: { action: string }[] }).items).toEqual([expect.objectContaining({ action: 'finish' })]);
});

it('RL-02/a link 1.1.0 already wrote under a clock behind O is accepted by finish, respond and inventory', async () => {
  const f = fixture();
  // What 1.1.0's S13 recorded: O's permissions and grade, no caveat, createdAt from toISOString, 1 minute behind O.
  f.save([{ ...f.old, createdAt: ahead }, { ...f.next, createdAt: '2026-10-05T12:00:00.000Z' }]);
  f.lnd.ids = [0n, oldId, nextId];
  expect((await respond(['--finish', '--dry-run', ...f.flags], f.deps)).error).toBeNull();
  const listed = await inventory([...f.flags], f.deps);
  const rows = (listed.result as { rootKeys: { rootKeyId: string; flags: string[] }[] }).rootKeys;
  expect(rows.find(row => row.rootKeyId === String(nextId))!.flags).not.toContain('invalid-replacement');
  const finished = await rotate(['Alice', '--finish', '--yes', ...f.flags], f.deps);
  expect(finished.error).toBeNull();
  expect(f.lnd.deleted).toEqual([oldId]);
});

it.each([
  ['broader permissions', { permissions: ['info:read', 'invoices:read', 'invoices:write', 'offchain:write'], grade: 'SPEND' }],
  ['a caveat rotate does not write', { caveats: [{ type: 'ipaddr', value: '127.0.0.1' }] }],
  ['a gap larger than a clock error', { createdAt: '2026-10-04T12:00:00.000Z' }],
  ['a hand-written timestamp', { createdAt: '2026-10-05T12:00:00Z' }],
])('RL-02/a backwards link with %s is still tampering, with the abandon recovery named', async (_name, change) => {
  const f = fixture();
  f.save([{ ...f.old, createdAt: ahead }, { ...f.next, createdAt: '2026-10-05T12:00:00.000Z', ...change }]);
  f.lnd.ids = [0n, oldId, nextId];
  const planned = await respond(['--finish', '--dry-run', ...f.flags], f.deps);
  expect(planned.error).toMatchObject({ code: 3, step: 'P5' });
  expect(planned.error!.message).toContain(`macwarden revoke ${nextId}`);
  const finished = await rotate(['Alice', '--finish', '--yes', ...f.flags], f.deps);
  expect(finished.error).toMatchObject({ code: 3, step: 'F3' });
  expect(f.lnd.deleted).toEqual([]);
});
