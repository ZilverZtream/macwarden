import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { run as rotate } from '../src/commands/rotate.js';
import { run as respond } from '../src/commands/respond.js';
import { run as inventory } from '../src/commands/inventory.js';
import { declareStagedFiles, declareStaging, entry, fixture, nextId, oldId } from './helpers/cp038-online.js';

// RL-07 (SPEC 6 S3, 10 P5): "A pending replacement for entry O is an active entry N for the same
// node with replaces: O.rootKeyId". An entry whose `replaces` names an entry no longer in the
// registry (the revoked original was pruned) is not a pending replacement: rotate and respond both
// treat it as an original that can be rotated again.

afterEach(() => { declareStagedFiles(); });

it('RL-07/an active credential whose replaced original was pruned is planned and rotated consistently', async () => {
  const f = fixture();
  // N finished a rotation long ago (replaces oldId); the revoked oldId entry was later pruned.
  const current = entry(nextId, 'Alice', String(oldId));
  f.save([current]);
  f.lnd.ids = [0n, nextId];
  const plan = await respond(['--dry-run', ...f.flags], f.deps);
  const items = (plan.result as { items: { rootKeyId: string; action: string }[] }).items;
  expect(items).toEqual([expect.objectContaining({ rootKeyId: String(nextId), action: 'stage' })]);
  expect((await rotate(['Alice', '--out', join(f.dir, 'direct.macaroon'), '--dry-run', ...f.flags], f.deps)).error).toBeNull();
  const staged = await respond(['--out-dir', declareStaging(join(f.dir, 'staged')), '--yes', ...f.flags], f.deps);
  expect(staged.error).toBeNull();
  expect((staged.result as { items: { status: string }[] }).items[0].status).toBe('staged');
  // The new replacement links to the survivor, and finishing revokes it.
  const finished = await respond(['--finish', '--yes', ...f.flags], f.deps);
  expect(finished.error).toBeNull();
  expect(f.lnd.deleted).toEqual([nextId]);
});

it('RL-07/respond --finish reports such a credential as not staged, as rotate --finish does', async () => {
  const f = fixture();
  f.save([entry(nextId, 'Alice', String(oldId))]);
  f.lnd.ids = [0n, nextId];
  const planned = await respond(['--finish', '--dry-run', ...f.flags], f.deps);
  expect((planned.result as { items: { status: string }[] }).items).toEqual([expect.objectContaining({ status: 'not-staged' })]);
  const finish = await rotate(['Alice', '--finish', '--dry-run', ...f.flags], f.deps);
  expect(finish.error).toMatchObject({ code: 2, step: 'F3' });
  expect(finish.error!.message).toMatch(/nothing staged/);
});

it('RL-07/inventory does not flag it as a replacement', async () => {
  const f = fixture();
  f.save([entry(nextId, 'Alice', String(oldId))]);
  f.lnd.ids = [0n, nextId];
  const rows = ((await inventory([...f.flags], f.deps)).result as { rootKeys: { rootKeyId: string; flags: string[] }[] }).rootKeys;
  expect(rows.find(row => row.rootKeyId === String(nextId))!.flags).toEqual([]);
});
