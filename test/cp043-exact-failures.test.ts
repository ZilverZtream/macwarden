import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { scratch, invoke, failure, fault, recovery, unchanged } from './helpers/cp028-rotate-support.js';
import { scratch as finishScratch, invoke as finishInvoke, failure as finishFailure,
  fault as finishFault, unchanged as finishUnchanged, oldId, newId, released, success } from './helpers/cp029-rotate-support.js';
import { revealSecret } from './helpers/secret-bytes.js';

const observed: Array<{ id: string; branch: string; exit: number; step: string; oldPresent: boolean }> = [];

it.each(['failed issue', 'lost response'])('CP-030/FI-1 faulty-Deps %s preserves old and provides executable new-ID recovery', async kind => scratch(async f => {
  const original = f.lnd.bakeMacaroon.getMockImplementation()!;
  f.lnd.bakeMacaroon.mockImplementationOnce(async (...args) => {
    if (kind === 'lost response') await original(...args);
    else f.calls.push('BakeMacaroon');
    throw fault();
  });
  const before = readFileSync(f.registry);
  const result = await invoke(f); failure(f, result, kind === 'lost response' ? 7 : 4, 'S10');
  if (kind === 'lost response') recovery(f, result); else unchanged(f, before);
  expect(f.state.ids).toContain(f.old.rootKeyId);
  observed.push({ id: 'CP-030/FI-1', branch: kind, exit: result.error!.code, step: result.error!.step, oldPresent: f.state.ids.includes(f.old.rootKeyId) });
}), 30_000); // owner-approved 2026-10-07: >5 s under full-suite load
it.each(['rejected replacement', 'verify timeout'])('CP-030/FI-2 faulty-Deps %s preserves old authority', async kind => scratch(async f => {
  const original = f.lnd.checkMacaroon.getMockImplementation()!;
  const oldBytes = readFileSync(f.oldBytesPath);
  f.lnd.checkMacaroon.mockImplementation(async (mac, permissions) => {
    if (Buffer.from(revealSecret(mac)).equals(oldBytes)) return original(mac, permissions);
    f.calls.push('CheckMacaroonPermissions');
    f.state.failedAt = f.calls.length - 1;
    if (kind === 'verify timeout') throw fault();
    return { valid: false, reason: 'signature-mismatch', message: 'independent injected rejection' };
  });
  const result = await invoke(f); failure(f, result, 7, 'S12'); recovery(f, result);
  expect(f.state.ids).toContain(f.old.rootKeyId);
  observed.push({ id: 'CP-030/FI-2', branch: kind, exit: result.error!.code, step: result.error!.step, oldPresent: f.state.ids.includes(f.old.rootKeyId) });
}));
it.each(['failed delete', 'completed lost response'])('CP-030/FI-4 faulty-Deps %s reconciles observed state without retry', async kind => finishScratch(async f => {
  const remove = f.lnd.deleteMacaroonId.getMockImplementation()!;
  f.lnd.deleteMacaroonId.mockImplementationOnce(async id => {
    if (kind === 'completed lost response') await remove(id);
    else f.calls.push('DeleteMacaroonID');
    throw finishFault();
  });
  const before = readFileSync(f.registry), result = await finishInvoke(f);
  if (kind === 'failed delete') { finishFailure(result, 5, 'F10'); finishUnchanged(f, before); }
  else success(f, result);
  expect(f.ids.includes(oldId)).toBe(kind === 'failed delete');
  expect(f.ids).toContain(newId); expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1); released(f);
  observed.push({ id: 'CP-030/FI-4', branch: kind, exit: result.error?.code ?? 0, step: result.error?.step ?? 'complete', oldPresent: f.ids.includes(oldId) });
}));
it('CP-031/FI-7 faulty-Deps registry save failure after deletion exits seven with accurate recovery', async () => finishScratch(async f => {
  const before = readFileSync(f.registry); f.state.registryFails = true;
  const result = await finishInvoke(f); finishFailure(result, 7, 'F12');
  finishUnchanged(f, before); expect(f.ids).not.toContain(oldId); expect(f.ids).toContain(newId);
  expect(result.error!.message).toContain('macwarden rotate Alice --finish'); released(f);
  f.state.registryFails = false;
  f.lnd.deleteMacaroonId.mockClear();
  success(f, await finishInvoke(f), 'by-id-only', true);
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
  observed.push({ id: 'CP-031/FI-7', branch: 'registry save', exit: result.error!.code, step: result.error!.step ?? '', oldPresent: f.ids.includes(oldId) });
}));

it('CP-043/B2-exact-missing-failure-cases independently audits executed exact FI identities and observed outcomes', () => {
  expect(observed).toEqual([
    { id: 'CP-030/FI-1', branch: 'failed issue', exit: 4, step: 'S10', oldPresent: true },
    { id: 'CP-030/FI-1', branch: 'lost response', exit: 7, step: 'S10', oldPresent: true },
    { id: 'CP-030/FI-2', branch: 'rejected replacement', exit: 7, step: 'S12', oldPresent: true },
    { id: 'CP-030/FI-2', branch: 'verify timeout', exit: 7, step: 'S12', oldPresent: true },
    { id: 'CP-030/FI-4', branch: 'failed delete', exit: 5, step: 'F10', oldPresent: true },
    { id: 'CP-030/FI-4', branch: 'completed lost response', exit: 0, step: 'complete', oldPresent: false },
    { id: 'CP-031/FI-7', branch: 'registry save', exit: 7, step: 'F12', oldPresent: false },
  ]);
});
