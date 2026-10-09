import * as fs from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { withCancellation } from '../src/cancellation.js';
import { run as bake } from '../src/commands/bake/index.js';
import { run as rotate } from '../src/commands/rotate.js';
import { run as respond } from '../src/commands/respond.js';
import { declare, fixture, oldId, type Fixture } from './helpers/cp038-online.js';

// RL-08 (SPEC Registry and lock): "Pre-mutation interruption reports exit 6, step cancelled, message
// interrupted", and exit 6 (like exit 3 "nothing sent to LND") means nothing is changed. rotate S10
// and bake B11 save the pending allocation before BakeMacaroon; a signal during that save, or a save
// that fails after its rename, left an active pending record behind such an exit. The record is now
// removed again, or, if that fails, the exit is 7 and the message names it with its recovery.

/**
 * Registry renames that run, then optionally abort the run or fail, as a signal or an I/O error
 * would; `refuse` makes a rename fail without replacing the registry.
 */
function onRegistryRename(f: Fixture, after: (count: number) => void, refuse: (count: number) => boolean = () => false): void {
  const rename = f.deps.fs.rename;
  let count = 0;
  f.deps.fs = { ...f.deps.fs, rename: (async (from: string, to: string) => {
    if (to === f.registry && refuse(count + 1)) { count++; throw ioError(); }
    await rename(from, to);
    if (to === f.registry) after(++count);
  }) as typeof fs.rename };
}

const ioError = () => Object.assign(new Error('injected I/O error after rename'), { code: 'EIO' });

it('RL-08/rotate: an interrupt during the pending-allocation save exits 6 and leaves the registry as before', async () => {
  const f = fixture();
  f.lnd.ids = [0n, oldId];
  const before = readFileSync(f.registry, 'utf8');
  const controller = new AbortController();
  onRegistryRename(f, count => { if (count === 1) controller.abort(); });
  const result = await withCancellation(controller.signal, () => rotate(['Alice', '--out', f.out, ...f.flags], f.deps));
  expect(f.lnd.calls).not.toContain('BakeMacaroon');
  expect(result.error).toEqual({ code: 6, step: 'cancelled', message: 'interrupted' });
  expect(JSON.parse(readFileSync(f.registry, 'utf8'))).toEqual(JSON.parse(before));
  expect(existsSync(f.out)).toBe(false);
  // respond therefore finds no incomplete replacement.
  f.deps.fs = { ...fs };
  const plan = await respond(['--dry-run', ...f.flags], f.deps);
  expect((plan.result as { items: { status: string }[] }).items[0].status).toBe('planned');
});

it('RL-08/bake: an interrupt during the pending-allocation save exits 6 and leaves the label free', async () => {
  const f = fixture();
  const out = join(f.dir, 'bob.macaroon'); declare(out);
  const before = readFileSync(f.registry, 'utf8');
  const controller = new AbortController();
  onRegistryRename(f, count => { if (count === 1) controller.abort(); });
  const args = ['--label', 'Bob', '--preset', 'invoice-only', '--out', out, ...f.flags];
  const result = await withCancellation(controller.signal, () => bake(args, f.deps));
  expect(f.lnd.calls).not.toContain('BakeMacaroon');
  expect(result.error).toEqual({ code: 6, step: 'cancelled', message: 'interrupted' });
  expect(JSON.parse(readFileSync(f.registry, 'utf8'))).toEqual(JSON.parse(before));
  // The label is not blocked by a leftover pending record: the same bake now succeeds.
  f.deps.fs = { ...fs };
  expect((await bake(args, f.deps)).error).toBeNull();
});

it.each(['rotate', 'bake'] as const)('RL-08/%s: a pending save that fails after its rename is rolled back before exit 3', async command => {
  const f = fixture();
  f.lnd.ids = [0n, oldId];
  const out = join(f.dir, `${command}.macaroon`); declare(out);
  const before = readFileSync(f.registry, 'utf8');
  onRegistryRename(f, count => { if (count === 1) throw ioError(); });
  const result = command === 'rotate' ? await rotate(['Alice', '--out', out, ...f.flags], f.deps)
    : await bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', out, ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 3, step: command === 'rotate' ? 'S10' : 'B11' });
  expect(result.error!.message).toMatch(/nothing sent to LND/);
  expect(f.lnd.calls).not.toContain('BakeMacaroon');
  expect(JSON.parse(readFileSync(f.registry, 'utf8'))).toEqual(JSON.parse(before));
});

it.each(['rotate', 'bake'] as const)('RL-08/%s: a pending record that cannot be removed again is named with its recovery (exit 7)', async command => {
  const f = fixture();
  f.lnd.ids = [0n, oldId];
  const out = join(f.dir, `${command}-stuck.macaroon`); declare(out);
  const controller = new AbortController();
  // The record lands, the signal arrives, and every later registry save fails before its rename.
  onRegistryRename(f, count => { if (count === 1) controller.abort(); }, count => count > 1);
  const result = await withCancellation(controller.signal, () => command === 'rotate'
    ? rotate(['Alice', '--out', out, ...f.flags], f.deps)
    : bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', out, ...f.flags], f.deps));
  expect(f.lnd.calls).not.toContain('BakeMacaroon');
  const pending = f.rows().find(row => row.verified === false && row.fingerprint === null)!;
  expect(result.error).toMatchObject({ code: 7, step: 'cancelled' });
  expect(result.error!.message).toContain('nothing sent to LND');
  expect(result.error!.message).toContain(`macwarden revoke ${pending.rootKeyId}`);
});
