import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { decodeMacaroon } from '../src/decode/index.js';
import { failure, fault, invoke, newId, oldId, released, scratch, success, unchanged } from './helpers/cp029-rotate-support.js';
import { scratch as stageScratch, invoke as stageInvoke, failure as stageFailure, fault as stageFault,
  afterFailure as stageAfterFailure } from './helpers/cp028-rotate-support.js';
// Each test runs the command and the leak check over the scratch tree (findLeaks); under a loaded full
// suite that took 17-21 s against the 15 s default, so these tests get 90 s (as RECONCILE/bounds did in 1.2.1).

it('CP-031/FI-5 delete success with old still accepted fails proof and retains active registry', async () => scratch(async f => {
  f.lnd.deleteMacaroonId.mockImplementationOnce(async () => { f.calls.push('DeleteMacaroonID'); return { deleted: true }; });
  const before = readFileSync(f.registry), result = await invoke(f); failure(result, 7, 'F11');
  expect(f.calls).toContain(`Check:${oldId}`);
  expect(f.ids).toContain(oldId); expect(f.ids).toContain(newId);
  expect(result.error!.message).toContain('macwarden inventory'); unchanged(f, before); released(f);
}), 90_000);
it('CP-031/FI-6 stage unavailable between GetInfo and permissions stops before issuance', async () => stageScratch(async f => {
  f.lnd.listPermissions.mockImplementationOnce(async () => { f.calls.push('ListPermissions'); throw stageFault(); });
  const before = readFileSync(f.registry), result = await stageInvoke(f); stageFailure(f, result, 4, 'S8');
  stageAfterFailure(f, 'ListPermissions'); expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  expect(readFileSync(f.registry).equals(before)).toBe(true);
}), 90_000);
it.each(['old proof', 'new proof'])('CP-031/FI-6 finish unavailable after deletion at %s stops without false registry completion', async kind => scratch(async f => {
  const check = f.lnd.checkMacaroon.getMockImplementation()!;
  f.lnd.checkMacaroon.mockImplementation(async (mac, permissions, ...extra) => {
    const id = String(decodeMacaroon(mac).rootKeyId);
    if (f.calls.includes('DeleteMacaroonID') && id === (kind === 'old proof' ? oldId : newId)) {
      f.calls.push(`Check:${id}`); throw fault();
    }
    return check(mac, permissions, ...extra);
  });
  const before = readFileSync(f.registry), result = await invoke(f); failure(result, 7, 'F11');
  const failed = f.calls.lastIndexOf(`Check:${kind === 'old proof' ? oldId : newId}`);
  const tail = f.calls.slice(failed + 1); expect(tail.length).toBeLessThanOrEqual(1);
  expect(tail.every(call => call === 'ListMacaroonIDs')).toBe(true);
  expect(result.error!.message).toContain('macwarden inventory');
  expect(f.ids).not.toContain(oldId); expect(f.ids).toContain(newId); unchanged(f, before); released(f);
}), 90_000);
it.each(['permissions', 'new baseline'])('CP-031/FI-6 finish unavailable before deletion at %s stops with unchanged authority', async kind => scratch(async f => {
  if (kind === 'permissions') f.lnd.listPermissions.mockImplementationOnce(async () => { f.calls.push('ListPermissions'); throw fault(); });
  else {
    const check = f.lnd.checkMacaroon.getMockImplementation()!;
    f.lnd.checkMacaroon.mockImplementation(async (mac, permissions, ...extra) => {
      const id = String(decodeMacaroon(mac).rootKeyId);
      if (id === (kind === 'new baseline' ? newId : oldId)) { f.calls.push(`Check:${id}`); throw fault(); }
      return check(mac, permissions, ...extra);
    });
  }
  const before = readFileSync(f.registry), result = await invoke(f);
  failure(result, 4, kind === 'permissions' ? 'F5' : 'F7');
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); expect(f.ids).toContain(oldId); expect(f.ids).toContain(newId);
  const failed = kind === 'permissions' ? 'ListPermissions' : `Check:${kind === 'new baseline' ? newId : oldId}`;
  const tail = f.calls.slice(f.calls.lastIndexOf(failed) + 1); expect(tail.length).toBeLessThanOrEqual(1);
  expect(tail.every(call => call === 'ListMacaroonIDs')).toBe(true); unchanged(f, before); released(f);
}), 90_000);
it('CP-031/FI-6 unavailable old baseline stops before delete with unchanged authority', async () => scratch(async f => {
  const check = f.lnd.checkMacaroon.getMockImplementation()!;
  f.lnd.checkMacaroon.mockImplementation(async (mac, permissions, ...extra) => {
    const id = String(decodeMacaroon(mac).rootKeyId);
    if (id === oldId) { f.calls.push(`Check:${id}`); throw fault(); }
    return check(mac, permissions, ...extra);
  });
  const before = readFileSync(f.registry), result = await invoke(f);
  failure(result, 4, 'F7'); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
  expect(f.ids).toContain(oldId); expect(f.ids).toContain(newId); unchanged(f, before); released(f);
  expect(f.calls.slice(f.calls.lastIndexOf(`Check:${oldId}`) + 1)).toEqual([]);
}), 90_000);
it.each(['before delete', 'after delete'])('CP-031/FI-8 interruption %s inventories actual state and confirmed finish recovers without mutation retry', async kind => scratch(async f => {
  if (kind === 'before delete') f.lnd.deleteMacaroonId.mockImplementationOnce(async () => {
    f.calls.push('DeleteMacaroonID'); throw fault();
  });
  else {
    const check = f.lnd.checkMacaroon.getMockImplementation()!;
    f.lnd.checkMacaroon.mockImplementation(async (mac, permissions, ...extra) => {
      if (f.calls.includes('DeleteMacaroonID')) { f.calls.push('InterruptedProof'); throw fault(); }
      return check(mac, permissions, ...extra);
    });
  }
  const before = readFileSync(f.registry), result = await invoke(f);
  failure(result, kind === 'before delete' ? 5 : 7, kind === 'before delete' ? 'F10' : 'F11');
  expect(result.error!.message).toContain(kind === 'before delete' ? 'macwarden rotate Alice --finish' : 'macwarden inventory');
  unchanged(f, before); released(f);
  const inventory = await import('../src/commands/inventory.js');
  const observed = await inventory.run(f.args.slice(2), f.deps); expect(observed.error).toBeNull();
  const rows = (observed.result as unknown as { rootKeys: Array<{ rootKeyId: string; inLnd: boolean; flags: string[] }> }).rootKeys;
  expect(rows.find(row => row.rootKeyId === oldId)?.inLnd).toBe(kind === 'before delete');
  expect(rows.find(row => row.rootKeyId === newId)?.inLnd).toBe(true);
  f.lnd.deleteMacaroonId.mockClear(); f.calls.length = 0;
  if (kind === 'after delete') f.lnd.checkMacaroon.mockImplementation(async mac => {
    const id = String(decodeMacaroon(mac).rootKeyId); f.calls.push(`Check:${id}`);
    return f.ids.includes(id) ? { valid: true } : { valid: false, reason: 'root-key-missing', message: 'injected missing root key' };
  });
  success(f, await invoke(f), kind === 'after delete' ? 'by-id-only' : 'rejected', kind === 'after delete');
  expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(kind === 'after delete' ? 0 : 1);
}), 90_000);
