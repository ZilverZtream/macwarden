import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { entry, register, wireFixture } from './helpers/cp026-revoke-support.mjs';
import * as revoke from './helpers/cp027-revoke-support.js';
import * as rotate from './helpers/cp029-rotate-support.js';
// Each test runs the command and the leak check over the scratch tree (findLeaks); under a loaded full
// suite that took 17-21 s against the 15 s default, so these tests get 90 s (as RECONCILE/bounds did in 1.2.1).

// SAFE-03: root key ID 0 is never deleted, whichever way it is reached. These reach it
// through registry data and target files rather than a literal "0" argument.

it('ROOT-KEY-0/revoke a label that resolves to a hand-edited entry with root key ID 0 is refused at V6', async () =>
  revoke.scratch(async f => {
    const zero = entry('root-max', '0', { label: 'Zero' });
    revoke.save(f, [f.target, f.other, zero]);
    const before = revoke.bytes(f);
    const result = await revoke.invoke(f, ['--yes'], 'Zero');
    revoke.failure(result, 2, 'V6');
    expect(result.error!.message).toBe('cannot revoke root key ID 0');
    expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
    expect(f.calls).not.toContain('DeleteMacaroonID');
    revoke.unchanged(f, before); revoke.released(f);
  }), 90_000);

it('ROOT-KEY-0/revoke a --target-file that decodes to root key ID 0 is refused at V3 before any LND call', async () =>
  revoke.scratch(async f => {
    const file = register(wireFixture('root-max', '0'));
    const before = revoke.bytes(f);
    const result = await revoke.invoke(f, ['--yes', '--target-file', file]);
    revoke.failure(result, 2, 'V3');
    expect(result.error!.message).toBe('target file uses root key ID 0');
    expect(f.calls).toEqual([]); // not even GetInfo (docs/security-model.md SAFE-03)
    revoke.unchanged(f, before); revoke.released(f);
  }), 90_000);

it('ROOT-KEY-0/rotate finish whose staged replacement has root key ID 0 is refused at F3 before any LND call', async () =>
  rotate.scratch(async f => {
    const zero = entry('preset-invoice-only', '0', { replaces: rotate.oldId });
    rotate.save(f, [f.old, f.other, zero]);
    const before = readFileSync(f.registry);
    const result = await rotate.invoke(f);
    rotate.failure(result, 2, 'F3');
    expect(result.error!.message).toBe('cannot rotate root key ID 0');
    expect(f.calls).toEqual([]);
    rotate.unchanged(f, before); rotate.released(f);
  }), 90_000);
