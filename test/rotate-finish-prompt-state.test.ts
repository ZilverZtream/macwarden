// rotate --finish observes LND again after the confirmation prompt (audit N01, N09): the
// replacement's acceptance and, on the F6 absent-old repair, the old root key's absence are as old
// as the prompt. A replacement deleted from LND meanwhile must not let O be deleted; an old root
// key restored meanwhile must be deleted, never recorded revoked while LND holds it.
import { readFileSync } from 'node:fs';
import { expect, it, vi } from 'vitest';
import { absent, failure, invoke, newId, oldId, prefix, released, scratch, success, unchanged } from './helpers/cp029-rotate-support.js';

vi.setConfig({ testTimeout: 60_000 });

for (const repaired of [false, true]) {
  it(`rotate --finish refuses when LND stops accepting the replacement during confirmation${repaired ? ' (absent-old repair)' : ''}`,
    async () => scratch(async f => {
      if (repaired) absent(f);
      const real = f.lnd.checkMacaroon.getMockImplementation()!;
      let confirmed = false;
      f.lnd.checkMacaroon.mockImplementation(async (mac, permissions, ...extra) => {
        const result = await real(mac, permissions, ...extra);
        // Another operator removed N's permission to authenticate (or N itself) while the prompt was open.
        return confirmed && f.calls.at(-1) === `Check:${newId}`
          ? { valid: false as const, reason: 'other' as const, message: 'permission denied' } : result;
      });
      f.prompt.mockImplementation(async () => { confirmed = true; return 'Alice'; });
      const before = readFileSync(f.registry), ids = [...f.ids];
      const result = await invoke(f, []);
      failure(result, 5, 'F7');
      expect(result.error!.message).toMatch(/new credential is not accepted after confirmation; nothing changed/);
      expect(result.error!.message).toContain(`macwarden revoke ${newId}`);
      expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); expect(f.deps.fs.rename).not.toHaveBeenCalled();
      expect(f.ids).toEqual(ids); unchanged(f, before); released(f);
    }));
}

it('rotate --finish refuses when the replacement root key is deleted from LND during confirmation', async () => scratch(async f => {
  f.prompt.mockImplementation(async () => { absent(f, newId); return 'Alice'; });
  const before = readFileSync(f.registry);
  const result = await invoke(f, []);
  failure(result, 5, 'F7');
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); expect(f.ids).toContain(oldId);
  unchanged(f, before); released(f);
}));

it('rotate --finish repair refuses when the replacement root key is deleted from LND during confirmation', async () => scratch(async f => {
  absent(f);
  f.prompt.mockImplementation(async () => { absent(f, newId); return 'Alice'; });
  const before = readFileSync(f.registry);
  const result = await invoke(f, []);
  failure(result, 5, 'F6');
  expect(result.error!.message).toContain('staged replacement is not in LND; nothing changed');
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); unchanged(f, before); released(f);
}));

it('rotate --finish repair deletes an old root key restored during confirmation instead of recording it revoked',
  async () => scratch(async f => {
    absent(f);
    f.prompt.mockImplementation(async () => { f.ids.splice(1, 0, oldId); return 'Alice'; });
    const result = await invoke(f, []);
    // The old file is O's and LND accepts it again, so the normal F7 baseline proves rejection.
    success(f, result, 'rejected', false);
    expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1);
    expect(f.calls.slice(0, 4)).toEqual([...prefix, `Check:${newId}`]);
    expect(f.calls.slice(4, 8)).toEqual(['ListMacaroonIDs', `Check:${oldId}`, `Check:${newId}`, 'DeleteMacaroonID']);
  }));

it('rotate --finish repair with --yes still re-lists and re-proves before recording', async () => scratch(async f => {
  absent(f);
  success(f, await invoke(f, ['--yes']), 'by-id-only', true);
  expect(f.calls).toEqual([...prefix, `Check:${newId}`, 'ListMacaroonIDs', `Check:${newId}`]);
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
}));
