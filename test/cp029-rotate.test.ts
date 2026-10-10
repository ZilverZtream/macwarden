import { liveProductLock } from './helpers/cp042-lock-process.js';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it, vi } from 'vitest';
import { render } from './helpers/render-adversarial.js';
import { entry, otherPubkey, ownId, permissionsResponse, register, wireFixture } from './helpers/cp026-revoke-support.mjs';
import { absent, afterFailure, failure, fault, invoke, newId, oldId, prefix, released,
  save, scratch, success, unchanged } from './helpers/cp029-rotate-support.js';

vi.setConfig({ testTimeout: 60_000 });
it.each(['out', 'allow-admin'])(
  'CP-029/F1-F3 %s is refused at F1 before unsafe ENV and registry', async kind => scratch(async f => {
    if (kind === 'out') f.args.push('--out', join(f.dir, 'forbidden.macaroon'));
    if (kind === 'allow-admin') f.args.push('--allow-admin');
    f.deps.env.NODE_DEBUG = 'https'; const before = readFileSync(f.registry);
    failure(await invoke(f), 2, 'F1'); expect(f.calls).toEqual([]); unchanged(f, before); released(f);
  }));
it('CP-029/F1-F3 unsafe ENV https stops at F2 offline', async () => scratch(async f => {
    f.deps.env.NODE_DEBUG = 'https';
    const before = readFileSync(f.registry); failure(await invoke(f), 2, 'F2');
    expect(f.calls).toEqual([]); unchanged(f, before); released(f);
  }));
it('CP-029/F1-F3 invalid JSON registry fails at F3 without network', async () => scratch(async f => {
    writeFileSync(f.registry, '{');
    failure(await invoke(f), 3, 'F3'); expect(f.calls).toEqual([]); released(f);
  }));
it('CP-029/F1-F3 no replacement reports the exact stage command offline', async () => scratch(async f => {
    save(f, [f.old, f.other]);
    const before = readFileSync(f.registry), result = await invoke(f); failure(result, 2, 'F3');
    expect(result.error!.message).toContain('nothing staged');
    expect(result.error!.message).toContain('macwarden rotate Alice --out <file>');
    expect(f.calls).toEqual([]); unchanged(f, before); released(f);
  }));
it('CP-029/F4-F5 OWN missing write exits 4 before network', async () => scratch(async f => {
    const permissions = entry('default-admin', ownId).permissions.filter((p: string) => p !== 'macaroon:write');
    f.args[f.args.indexOf('--macaroon') + 1] = register(wireFixture('default-admin', ownId, permissions));
    const before = readFileSync(f.registry); failure(await invoke(f), 4, 'F4');
    expect(f.calls).toEqual([]); unchanged(f, before); released(f);
  }));
it.each(['own ID', 'root zero'])(
  'CP-029/F4-F5 %s cannot be finished before any network call', async kind => scratch(async f => {
    f.old.rootKeyId = kind === 'own ID' ? ownId : '0'; f.next.replaces = f.old.rootKeyId; save(f);
    const before = readFileSync(f.registry), result = await invoke(f);
    expect(result.error?.code).toBe(2); if (kind === 'own ID') expect(result.error?.step).toBe('F4');
    expect(f.calls).toEqual([]); unchanged(f, before); released(f);
  }));
it('CP-029/F4-F5 GetInfo transport error exits unchanged at F5', async () => scratch(async f => {
    f.lnd.getInfo.mockImplementationOnce(async () => { f.calls.push('GetInfo'); throw fault(); });
    const before = readFileSync(f.registry); failure(await invoke(f), 4, 'F5');
    afterFailure(f, 'GetInfo'); unchanged(f, before); released(f);
  }));
it('CP-029/F4-F5 pubkey mismatch stops after GetInfo without mutation', async () => scratch(async f => {
  f.lnd.getInfo.mockImplementationOnce(async () => { f.calls.push('GetInfo'); return { pubkey: otherPubkey, alias: 'fixture', version: '0.21.4-beta', network: 'regtest' }; });
  failure(await invoke(f), 2, 'F5'); expect(f.calls).toEqual(['GetInfo']); released(f);
}));
it('CP-029/F6 list transport failure stops with unchanged registry', async () => scratch(async f => {
    f.lnd.listMacaroonIds.mockImplementationOnce(async () => { f.calls.push('ListMacaroonIDs'); throw fault(); });
    const before = readFileSync(f.registry); failure(await invoke(f), 4, 'F6');
    afterFailure(f, 'ListMacaroonIDs'); unchanged(f, before); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); released(f);
  }));
it('CP-029/F6 missing replacement with old present gives numeric cleanup before proof', async () => scratch(async f => {
    absent(f, newId);
    const before = readFileSync(f.registry), result = await invoke(f); failure(result, 5, 'F6');
    expect(result.error!.message).toContain('staged replacement is not in LND');
    expect(result.error!.message).toContain(`macwarden revoke ${newId}`);
    expect(f.lnd.checkMacaroon).not.toHaveBeenCalled(); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
    unchanged(f, before); released(f);
  }));
it.each(['dry-run', 'declined', 'yes'])(
  'CP-029/F6 absent old %s proves replacement before repair and never deletes twice', async kind => scratch(async f => {
    absent(f); const before = readFileSync(f.registry);
    if (kind === 'declined') f.prompt.mockResolvedValueOnce('wrong');
    const result = await invoke(f, kind === 'dry-run' ? ['--dry-run'] : kind === 'yes' ? ['--yes'] : []);
    // After the confirmation (or --yes) the repair lists IDs again and re-proves the replacement (N01, N09).
    expect(f.calls).toEqual([...prefix, `Check:${newId}`, ...(kind === 'yes' ? ['ListMacaroonIDs', `Check:${newId}`] : [])]);
    expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
    if (kind === 'dry-run') {
      expect(result.error).toBeNull(); expect(result.result).toMatchObject({ dryRun: true, stage: 'finish', old: f.old,
        permissions: f.old.permissions, grade: 'RECEIVE' });
      expect(f.prompt).not.toHaveBeenCalled(); unchanged(f, before);
    } else if (kind === 'declined') { failure(result, 6, 'F8'); unchanged(f, before); }
    else success(f, result, 'by-id-only', true);
    released(f);
  }));
it.each(['missing file', 'fingerprint mismatch', 'rejected'])(
  'CP-029/F6 absent old with %s replacement cannot plan confirm or complete repair', async kind => scratch(async f => {
    absent(f);
    if (kind === 'missing file') f.next.outPath = join(f.dir, 'missing.macaroon');
    if (kind === 'fingerprint mismatch') f.next.fingerprint = 'fp:0000000000000000';
    if (kind === 'rejected') f.lnd.checkMacaroon.mockImplementationOnce(async () => {
      f.calls.push(`Check:${newId}`); return { valid: false as const, reason: 'other' as const, message: 'permission denied' };
    });
    save(f); const before = readFileSync(f.registry);
    failure(await invoke(f, []), kind === 'rejected' ? 5 : 3, 'F7');
    expect(f.prompt).not.toHaveBeenCalled(); expect(f.deps.fs.rename).not.toHaveBeenCalled();
    expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); unchanged(f, before); released(f);
  }));

it('CP-029/F7 rejected replacement refuses before deletion with nothing changed', async () => scratch(async f => {
    f.lnd.checkMacaroon.mockImplementationOnce(async () => {
      f.calls.push(`Check:${newId}`);
      return { valid: false as const, reason: 'other' as const, message: 'permission denied' };
    });
    save(f); const before = readFileSync(f.registry), result = await invoke(f);
    failure(result, 5, 'F7');
    expect(result.error!.message).toContain('new credential is not accepted; nothing changed');
    expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); expect(f.prompt).not.toHaveBeenCalled();
    expect(f.ids).toContain(oldId); unchanged(f, before); released(f);
  }));
it('CP-029/F8 dry-run shows the complete plan without locking prompting or mutating', async () => scratch(async f => {
  const { bytes: lockBytes } = await liveProductLock(f.registry);
  const lock = lockBytes.toString('utf8');
  const before = readFileSync(f.registry), ids = [...f.ids];
  f.lnd.listPermissions.mockResolvedValueOnce(permissionsResponse({}));
  const result = await invoke(f, ['--dry-run', '--json']); expect(result.error).toBeNull();
  expect(result.result).toMatchObject({ dryRun: true, stage: 'finish', old: f.old, grade: 'RECEIVE', permissions: f.old.permissions });
  expect(result.warnings.map((warning: string | { code: string }) => typeof warning === 'string' ? warning : warning.code)).toContain('snapshot-drift');
  const text = render(result, 'text');
  for (const value of [oldId, newId, f.next.outPath, 'RECEIVE', ...f.old.permissions]) expect(text).toContain(value);
  expect(f.prompt).not.toHaveBeenCalled(); expect(f.deps.fs.rename).not.toHaveBeenCalled();
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); expect(f.ids).toEqual(ids); unchanged(f, before);
  expect(readFileSync(`${f.registry}.lock`, 'utf8')).toBe(lock);
}));
it.each(['EOF', 'non-TTY'])(
  'CP-029/F8 %s declines without lock or mutation', async kind => scratch(async f => {
    f.prompt.mockResolvedValueOnce(kind === 'EOF' ? null : 'wrong');
    if (kind === 'non-TTY') { f.prompt.isTTY = false; f.stdin.isTTY = false; }
    const before = readFileSync(f.registry); failure(await invoke(f, []), 6, 'F8');
    expect(f.prompt.mock.calls.length).toBe(kind === 'non-TTY' ? 0 : 1);
    if (kind !== 'non-TTY') expect(f.prompt.mock.calls[0][0]).toBe(
      `Finishing revokes root key ID ${oldId}. Continue only if every replica and config copy of Alice now uses ${f.next.outPath}. Type Alice to continue:`);
    expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); unchanged(f, before); released(f);
  }));
it('CP-029/F8 typed confirmation waits with an unlocked registry after displaying the full plan', async () => scratch(async f => {
  let resume: (value: string) => void;
  let ready: () => void;
  const reached = new Promise<void>(resolve => { ready = resolve; });
  f.prompt.mockImplementation(async question => {
    expect(question).toBe(`Finishing revokes root key ID ${oldId}. Continue only if every replica and config copy of Alice now uses ${f.next.outPath}. Type Alice to continue:`);
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    for (const value of [oldId, newId, 'RECEIVE', ...f.old.permissions, f.next.outPath]) expect(f.outputs.join('')).toContain(value);
    ready(); return new Promise<string>(resolve => { resume = resolve; });
  });
  // A rejected command must reject this race promptly, including a missing module.
  const pending = invoke(f, []);
  await Promise.race([reached, pending.then(() => { throw new Error('Command returned without confirmation'); })]);
  expect(existsSync(`${f.registry}.lock`)).toBe(false); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
  resume!('Alice'); success(f, await pending);
  const deletion = f.calls.indexOf('DeleteMacaroonID');
  expect(f.calls.indexOf(`Check:${newId}`)).toBeLessThan(deletion);
  expect(f.calls.indexOf(`Check:${oldId}`)).toBeLessThan(deletion);
  expect(f.calls.filter(call => call === `Check:${oldId}`)).toHaveLength(2);
}));

it('CP-029/F9-F10 present old refuses held live lock and preserves its owner', async () => scratch(async f => {
    const { bytes: lockBytes, owner } = await liveProductLock(f.registry);
    const lock = lockBytes.toString('utf8');
     const before = readFileSync(f.registry);
    const result = await invoke(f, ['--yes', '--break-lock']); failure(result, 3, 'F9');
    for (const value of [String(owner.pid), owner.hostname, owner.startedAt]) expect(result.error!.message).toContain(value);
    expect(readFileSync(`${f.registry}.lock`, 'utf8')).toBe(lock);
    expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); unchanged(f, before);
  }));
it('CP-029/F9-F10 new permissions during confirmation refuses after lock and preserves concurrent registry', async () => scratch(async f => {
    let changed: Buffer;
    f.prompt.mockImplementation(async () => {
      expect(existsSync(`${f.registry}.lock`)).toBe(false);
      const old = { ...f.old }, next = { ...f.next };
      next.permissions = ['info:read'];
      save(f, [old, f.other, next]);
      changed = readFileSync(f.registry); return 'Alice';
    });
    failure(await invoke(f, []), 3, 'F9'); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
    unchanged(f, changed!); released(f);
  }));
for (const outcome of ['present', 'absent', 'unknown']) {
  it(
    `CP-029/F9-F10 failed delete with old ${outcome} reconciles once and never retries mutation`, async () => scratch(async f => {
      f.lnd.deleteMacaroonId.mockImplementation(async id => {
        f.calls.push('DeleteMacaroonID'); expect(id).toBe(BigInt(oldId));
        if (outcome === 'absent') absent(f);
        throw fault();
      });
      if (outcome === 'unknown') f.lnd.listMacaroonIds.mockImplementationOnce(async () => {
        f.calls.push('ListMacaroonIDs'); return ([...f.ids]).map(BigInt);
      }).mockImplementationOnce(async () => { f.calls.push('ListMacaroonIDs'); throw fault(); });
      const before = readFileSync(f.registry), result = await invoke(f);
      expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1); expect(f.lnd.listMacaroonIds).toHaveBeenCalledTimes(2);
      const tail = f.calls.slice(f.calls.indexOf('DeleteMacaroonID') + 1);
      expect(tail[0]).toBe('ListMacaroonIDs');
      if (outcome === 'absent') {
        expect(tail.slice(1).sort()).toEqual([`Check:${oldId}`, `Check:${newId}`].sort()); success(f, result);
      } else {
        failure(result, outcome === 'present' ? 5 : 7, 'F10'); expect(tail).toEqual(['ListMacaroonIDs']);
        expect(result.error!.message).toMatch(outcome === 'present' ? /still|present|valid/i : /LND state unknown/i);
        if (outcome === 'unknown') expect(result.error!.message).toContain('macwarden inventory');
        unchanged(f, before); released(f);
      }
    }));
}

it.each(['old other rejection', 'new rejected'])(
  'CP-029/F11-F12 %s proof fails without recording false revocation', async kind => scratch(async f => {
    const real = f.lnd.checkMacaroon.getMockImplementation()!;
    f.lnd.checkMacaroon.mockImplementation(async (mac, permissions, ...extra) => {
      const id = String((await import('../src/decode/index.js')).decodeMacaroon(mac).rootKeyId);
      if (f.calls.includes('DeleteMacaroonID') && ((id === oldId && kind.startsWith('old')) || (id === newId && kind.startsWith('new')))) {
        f.calls.push(`Check:${id}`);
        return { valid: false as const, reason: 'other' as const, message: 'permission denied' };
      }
      return real(mac, permissions, ...extra);
    });
    const before = readFileSync(f.registry), result = await invoke(f); failure(result, 7, 'F11');
    expect(result.error!.message).toMatch(/present|absent|unknown/i); expect(result.error!.message).toContain('macwarden inventory');
    expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1); unchanged(f, before); released(f);
  }));
it('CP-029/F11-F12 normal finish save failure reports exact repair and rerun proves new without deleting', async () => scratch(async f => {
    f.state.registryFails = true;
    const before = readFileSync(f.registry), result = await invoke(f); failure(result, 7, 'F12');
    expect(result.error!.message).toMatch(/absent/i); expect(result.error!.message).toContain('macwarden rotate Alice --finish');
    unchanged(f, before); released(f); expect(f.ids).not.toContain(oldId);
    f.state.registryFails = false; f.calls.length = 0; f.lnd.deleteMacaroonId.mockClear();
    success(f, await invoke(f), 'by-id-only', true);
    expect(f.calls).toEqual([...prefix, `Check:${newId}`, 'ListMacaroonIDs', `Check:${newId}`]);
    expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
  }));

it('CP-029/abandon numeric revoke of staged ID preserves old authority and removes pending inventory', async () => scratch(async f => {
  const result = await invoke(f, ['--yes'], 'revoke', newId); expect(result.error).toBeNull();
  expect(f.ids).toContain(oldId); expect(f.ids).not.toContain(newId);
  expect(f.rows()).toContainEqual(f.old);
  expect(f.rows().find(row => row.rootKeyId === newId)).toMatchObject({ status: 'revoked', revokeEvidence: 'rejected' });

  const inventory = await import('../src/commands/inventory.js');
  const output = await inventory.run(f.args.slice(2), f.deps);
  expect(output.error, output.error?.message).toBeNull(); expect(render(output, 'text')).not.toContain('pending-replacement');
  expect(render(output, 'text')).not.toMatch(/\[replacement\]|flags:.*replacement/);
  released(f);
}));
it('CP-029/dry-runs finish preserves IDs registry and both credential files', async () => scratch(async f => {
  const before = readFileSync(f.registry), old = readFileSync(f.oldPath), next = readFileSync(f.next.outPath), ids = [...f.ids];
  const result = await invoke(f, ['--dry-run']); expect(result.error).toBeNull();
  expect(f.ids).toEqual(ids); unchanged(f, before);
  expect(readFileSync(f.oldPath).equals(old)).toBe(true); expect(readFileSync(f.next.outPath).equals(next)).toBe(true);
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); expect(f.deps.fs.rename).not.toHaveBeenCalled(); released(f);
  for (const [path, flags] of vi.mocked(f.deps.fs.open).mock.calls)
    if (path === f.oldPath || path === f.next.outPath) expect(String(flags)).not.toMatch(/[wax+]/);
  // The completed stage/finish dry-run sequence is independently covered by the live reference test.
}));
