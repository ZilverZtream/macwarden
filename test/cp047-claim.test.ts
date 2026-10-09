import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { openRegistry } from '../src/registry/index.js';
import { crashClaimControl, ownershipClaimControls, staleProductLockControl } from './support/cp047-claim.js';
import { scratch } from './support/cp041-controls.js';

it('CP-047/B1 live process ownership prevents a second registry view from breaking its lock', async () => {
  await scratch(async dir => {
    const path = join(dir, 'registry.json');
    const lockPath = path + '.lock';
    writeFileSync(path, JSON.stringify({ schema: 1, entries: [] }));
    const owner = await openRegistry(path);
    await owner.lock({ breakLock: false });
    try {
      const before = readFileSync(lockPath);
      const contender = await openRegistry(path);
      for (const breakLock of [false, true]) {
        await expect(contender.lock({ breakLock })).rejects.toMatchObject({ code: 3 });
        expect(readFileSync(lockPath).equals(before), 'original live-owner lock bytes remain preserved').toBe(true);
      }
    } finally {
      await owner.unlock();
    }
    expect(existsSync(lockPath), 'owned unlock removes the original lock').toBe(false);
  });
});

it('CP-047/B2 killed claim-window writer preserves orphan and provides exact recovery guidance', crashClaimControl);

it('CP-047/B3 orphan claim refusal provides exact safe offline recovery guidance', crashClaimControl);

it('CP-047/B2 live child claims, replacement pathnames and ambiguous nonempty records survive both acquisitions', ownershipClaimControls);

it('CP-047/B1 provably stale product-created lock recovers through break-lock', staleProductLockControl);
