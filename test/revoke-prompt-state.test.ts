// revoke's V7 absent-ID repair observes LND again after the confirmation prompt (audit N07): the
// absence is as old as the prompt, and a root key restored meanwhile (a node backup restore, another
// operator) must be deleted, never recorded revoked while LND holds it.
import { expect, it, vi } from 'vitest';
import { maxId } from './helpers/cp026-revoke-support.mjs';
import { absent, bytes, failure, invoke, onlineFault, prefix, released, save, scratch, success, unchanged } from './helpers/cp027-revoke-support.js';

vi.setConfig({ testTimeout: 60_000 });

it('revoke repair deletes a root key restored during confirmation, with the V8 baseline proof', async () => scratch(async f => {
  absent(f);
  f.prompt.mockImplementation(async () => { f.ids.splice(1, 0, maxId); return 'Alice'; });
  success(f, await invoke(f, []), 'rejected', false);
  expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1);
  expect(f.calls).toEqual([...prefix, 'ListMacaroonIDs', 'CheckMacaroonPermissions', 'DeleteMacaroonID',
    'ListMacaroonIDs', 'CheckMacaroonPermissions']);
}));

it('revoke repair without a usable target file deletes a restored root key by ID only', async () => scratch(async f => {
  absent(f);
  f.lnd.checkMacaroon.mockImplementation(async () => { throw new Error('no baseline expected without a target file'); });
  f.prompt.mockImplementation(async () => { f.ids.splice(1, 0, maxId); return 'Alice'; });
  // No recorded file: the proof is by ID only.
  f.target.outPath = null as unknown as string; save(f);
  success(f, await invoke(f, []), 'by-id-only', false);
  expect(f.calls).toEqual([...prefix, 'ListMacaroonIDs', 'DeleteMacaroonID', 'ListMacaroonIDs']);
}));

it('revoke repair still records an ID absent after confirmation, after one more list', async () => scratch(async f => {
  absent(f);
  success(f, await invoke(f, []), 'by-id-only', true);
  expect(f.calls).toEqual([...prefix, 'ListMacaroonIDs']); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
}));

it('revoke repair refuses when LND cannot be listed after confirmation, registry unchanged', async () => scratch(async f => {
  absent(f); const before = bytes(f);
  f.lnd.listMacaroonIds.mockImplementationOnce(async () => { f.calls.push('ListMacaroonIDs'); return f.ids.map(BigInt); })
    .mockImplementationOnce(async () => { f.calls.push('ListMacaroonIDs'); throw onlineFault(); });
  failure(await invoke(f, []), 4, 'V7');
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); unchanged(f, before); released(f);
}));
