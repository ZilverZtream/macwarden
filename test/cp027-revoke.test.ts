import { liveProductLock } from './helpers/cp042-lock-process.js';
import { revealSecret } from './helpers/secret-bytes.js';
import { existsSync, readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it, vi } from 'vitest';
import { render } from './helpers/render-adversarial.js';
import { entry, maxId, otherPubkey } from './helpers/cp026-revoke-support.mjs';
import { absent, bytes, failure, instant, invoke, onlineFault, prefix, released, save, scratch,
  success, unchanged } from './helpers/cp027-revoke-support.js';

it.each(['unregistered', 'revoked entry'])('CP-027/V7-repair absent %s has nothing to revoke',
  async kind => scratch(async f => {
    absent(f);
    if (kind === 'unregistered') save(f, [f.other]);
    else { f.target.status = 'revoked'; f.target.revokedAt = instant; f.target.revokeEvidence = 'by-id-only'; save(f); }
    const before = bytes(f);
    const result = await invoke(f, ['--unregistered', '--yes'], maxId);
    failure(result, 5, 'V7'); expect(result.error!.message).toMatch(/nothing to revoke/i);
    expect(f.calls).toEqual(prefix); unchanged(f, before); released(f);
  }));
it.each(['--dry-run', '--dry-run --yes', '--dry-run --json']) (
  'CP-027/V7-repair %s plans already-absent repair without later LND calls or lock', async flags => scratch(async f => {
    absent(f); const before = bytes(f);
    const result = await invoke(f, flags.split(' '));
    expect(result.error).toBeNull();
    expect(result.result).toEqual({ dryRun: true, rootKeyId: maxId, label: 'Alice', grade: 'READ', proof: 'by-id-only' });
    expect(render(result, 'text')).toMatch(/already absent/i);
    expect(f.calls).toEqual(prefix); expect(f.prompt).not.toHaveBeenCalled(); unchanged(f, before); released(f);
  }));
it.each(['wrong text', 'EOF', 'non-TTY'])('CP-027/V7-repair %s declines absence repair with unchanged record',
  async kind => scratch(async f => {
    absent(f); const before = bytes(f);
    f.prompt.mockResolvedValue(kind === 'EOF' ? null : 'wrong');
    if (kind === 'non-TTY') { f.prompt.isTTY = false; f.stdin.isTTY = false; }
    failure(await invoke(f, []), 6, 'V9');
    expect(f.calls).toEqual(prefix); unchanged(f, before); released(f);
    expect(f.prompt.mock.calls.length).toBe(kind === 'non-TTY' ? 0 : 1);
  }));
it.each(['typed label', '--yes'])('CP-027/V7-repair %s records by-id-only without any LND call after absence',
  async kind => scratch(async f => {
    absent(f); success(f, await invoke(f, kind === '--yes' ? ['--yes'] : []), 'by-id-only', true);
    expect(f.calls).toEqual(prefix); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
  }));

it.each(['present', 'absent repair'])('CP-027/V10 %s refuses a held lock without deleting or altering its owner',
  async kind => scratch(async f => {
    if (kind === 'absent repair') absent(f);
    const { bytes: lockBytes, owner } = await liveProductLock(f.registry);
    const lock = lockBytes.toString('utf8');
     const before = bytes(f);
    const result = await invoke(f, ['--yes', '--break-lock']); failure(result, 3, 'V10');
    for (const value of [String(owner.pid), owner.hostname, owner.startedAt]) expect(result.error!.message).toContain(value);
    expect(readFileSync(`${f.registry}.lock`, 'utf8')).toBe(lock);
    expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); unchanged(f, before);
  }));
it.each(['status', 'fingerprint', 'outPath', 'permissions', 'label', 'removed', 'absent repair']) (
  'CP-027/V10 entry %s changed during unlocked confirmation prevents mutation', async kind => scratch(async f => {
    if (kind === 'absent repair') absent(f);
    let changed: Buffer;
    f.prompt.mockImplementation(async (question: string) => {
      expect(existsSync(`${f.registry}.lock`)).toBe(false); f.outputs.push(question);
      const row = { ...f.target };
      if (kind === 'status' || kind === 'absent repair') Object.assign(row, { status: 'revoked', revokedAt: instant, revokeEvidence: 'by-id-only' });
      if (kind === 'fingerprint') row.fingerprint = 'fp:0000000000000000';
      if (kind === 'outPath') row.outPath = null;
      if (kind === 'permissions') {
        const changedPermissions = ['invoices:read'];
        expect(changedPermissions).not.toEqual(f.target.permissions);
        row.permissions = changedPermissions;
      }
      if (kind === 'label') row.label = 'Changed';
      save(f, kind === 'removed' ? [f.other] : [row, f.other]); changed = bytes(f); return 'Alice';
    });
    failure(await invoke(f, []), 3, 'V10');
    expect(f.prompt).toHaveBeenCalledTimes(1); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
    unchanged(f, changed!); released(f);
  }));
it('CP-027/V10 registry reread failure after confirmation releases the acquired lock', async () => scratch(async f => {
  f.deps.fs.readFile = vi.fn(async (...args: Parameters<typeof fs.readFile>) => {
    if (args[0] === f.registry && existsSync(`${f.registry}.lock`))
      throw Object.assign(new Error('injected reread failure'), { code: 'EACCES' });
    return fs.readFile(...args);
  }) as typeof fs.readFile;
  const before = bytes(f); failure(await invoke(f), 3, 'V10');
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); unchanged(f, before); released(f);
}));
it('CP-027/V10 unrelated-node record change is preserved while the resolved entry stays stable', async () => scratch(async f => {
  const foreign = { ...f.target, nodePubkey: otherPubkey, label: 'Foreign', outPath: null };
  f.prompt.mockImplementation(async () => {
    expect(existsSync(`${f.registry}.lock`)).toBe(false); save(f, [f.target, f.other, foreign]); return 'Alice';
  });
  f.lnd.deleteMacaroonId.mockImplementation(async id => {
    f.calls.push('DeleteMacaroonID'); expect(id).toBe(BigInt(maxId)); absent(f); return { deleted: true };
  });
  success(f, await invoke(f, []));
  expect(JSON.parse(bytes(f).toString()).entries).toContainEqual(foreign);
}));
it('CP-027/V10 an unregistered ID gaining a registry entry during input is refused before deletion', async () => scratch(async f => {
  save(f, [f.other]); let changed: Buffer;
  f.prompt.mockImplementation(async question => {
    expect(existsSync(`${f.registry}.lock`)).toBe(false); expect(question).toContain(maxId);
    save(f); changed = bytes(f); return maxId;
  });
  failure(await invoke(f, ['--unregistered'], maxId), 3, 'V10');
  unchanged(f, changed!); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); released(f);
}));

it.each(['error', 'deleted false'])('CP-027/V11 %s with ID still present stops after one reconciliation',
  async kind => scratch(async f => {
    f.lnd.deleteMacaroonId.mockImplementation(async id => {
      f.calls.push('DeleteMacaroonID'); expect(id).toBe(BigInt(maxId));
      if (kind === 'error') throw onlineFault(); return { deleted: false };
    });
    const before = bytes(f); const result = await invoke(f); failure(result, 5, 'V11');
    expect(result.error!.message).toMatch(/still|present|valid/i);
    expect(f.calls).toEqual([...prefix, 'CheckMacaroonPermissions', 'DeleteMacaroonID', 'ListMacaroonIDs']);
    expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1); unchanged(f, before); released(f);
  }));
it.each(['error', 'deleted false'])('CP-027/V11 %s after completed deletion permits only the prescribed rejection proof',
  async kind => scratch(async f => {
    f.lnd.deleteMacaroonId.mockImplementation(async id => {
      f.calls.push('DeleteMacaroonID'); expect(id).toBe(BigInt(maxId)); absent(f);
      if (kind === 'error') throw onlineFault(); return { deleted: false };
    });
    success(f, await invoke(f));
    expect(f.calls).toEqual([...prefix, 'CheckMacaroonPermissions', 'DeleteMacaroonID', 'ListMacaroonIDs', 'CheckMacaroonPermissions']);
    expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1); expect(f.lnd.listMacaroonIds).toHaveBeenCalledTimes(2);
  }));
it.each(['error', 'deleted false'])('CP-027/V11 %s with unreadable reconciliation reports unknown state and inventory recovery',
  async kind => scratch(async f => {
    f.lnd.deleteMacaroonId.mockImplementation(async () => {
      f.calls.push('DeleteMacaroonID'); if (kind === 'error') throw onlineFault(); return { deleted: false };
    });
    f.lnd.listMacaroonIds.mockImplementationOnce(async () => {
      f.calls.push('ListMacaroonIDs'); return ([...f.ids]).map(BigInt);
    }).mockImplementationOnce(async () => { f.calls.push('ListMacaroonIDs'); throw onlineFault(); });
    const before = bytes(f); const result = await invoke(f); failure(result, 7, 'V11');
    expect(result.error!.message).toContain('LND state unknown'); expect(result.error!.message).toContain('macwarden inventory');
    expect(f.calls).toEqual([...prefix, 'CheckMacaroonPermissions', 'DeleteMacaroonID', 'ListMacaroonIDs']);
    unchanged(f, before); released(f);
  }));
it('CP-027/V11 absent reconciliation with unusable target records by ID only without another list', async () => scratch(async f => {
  f.target.outPath = null; save(f);
  f.lnd.deleteMacaroonId.mockImplementation(async () => { f.calls.push('DeleteMacaroonID'); absent(f); throw onlineFault(); });
  success(f, await invoke(f), 'by-id-only');
  expect(f.calls).toEqual([...prefix, 'DeleteMacaroonID', 'ListMacaroonIDs']);
}));

it.each(['still present', 'list failure', 'still accepted', 'other rejection', 'transport']) (
  'CP-027/V12 %s determines whether the independent proof is sufficient', async kind => scratch(async f => {
    const before = bytes(f);
    if (kind === 'still present') f.lnd.deleteMacaroonId.mockImplementation(async () => {
      f.calls.push('DeleteMacaroonID'); return { deleted: true };
    });
    if (kind === 'list failure') f.lnd.listMacaroonIds.mockImplementationOnce(async () => {
      f.calls.push('ListMacaroonIDs'); return ([...f.ids]).map(BigInt);
    }).mockImplementationOnce(async () => { f.calls.push('ListMacaroonIDs'); throw onlineFault(); });
    if (!['still present', 'list failure'].includes(kind)) {
      f.lnd.checkMacaroon.mockImplementationOnce(async () => { f.calls.push('CheckMacaroonPermissions'); return { valid: true }; })
        .mockImplementationOnce(async () => {
          f.calls.push('CheckMacaroonPermissions');
          if (kind === 'transport') throw onlineFault();
          return kind === 'still accepted' ? { valid: true } : { valid: false as const, reason: 'other' as const, message: 'permission denied' };
        });
    }
    const result = await invoke(f);
    failure(result, 7, 'V12'); unchanged(f, before); released(f);
    expect(result.error!.message).toMatch(/present|absent|unknown/i);
    expect(result.error!.message).toContain('macwarden inventory');
    expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1); expect(f.lnd.listMacaroonIds).toHaveBeenCalledTimes(2);
    expect(f.lnd.checkMacaroon.mock.calls.length).toBe(['still present', 'list failure'].includes(kind) ? 1 : 2);
  }));
it('CP-027/V12 accepted URI target is checked with exactly its decoded URI permissions after deletion', async () => scratch(async f => {
  f.target = entry('grade-uri-read-pair', maxId); save(f);
  f.lnd.checkMacaroon.mockImplementation(async (mac, perms, ...extra) => {
    f.calls.push('CheckMacaroonPermissions');
    expect(Buffer.from(revealSecret(mac)).equals(readFileSync(f.target.outPath))).toBe(true);
    expect(perms).toEqual(f.target.permissions); expect(perms.every((p: string) => p.startsWith('uri:'))).toBe(true);
    expect(extra).toEqual([]);
    return f.ids.includes(maxId) ? { valid: true } : { valid: false as const, reason: 'root-key-missing', message: 'root key missing' };
  });
  success(f, await invoke(f)); expect(f.lnd.checkMacaroon).toHaveBeenCalledTimes(2);
}));
it('CP-027/V12 rejection proof failure after lost delete response stops without another reconciliation', async () => scratch(async f => {
  f.lnd.deleteMacaroonId.mockImplementation(async () => { f.calls.push('DeleteMacaroonID'); absent(f); throw onlineFault(); });
  f.lnd.checkMacaroon.mockImplementationOnce(async () => { f.calls.push('CheckMacaroonPermissions'); return { valid: true }; })
    .mockImplementationOnce(async () => { f.calls.push('CheckMacaroonPermissions'); throw onlineFault(); });
  const before = bytes(f); const result = await invoke(f); failure(result, 7, 'V12');
  expect(result.error!.message).toContain('macwarden inventory'); unchanged(f, before); released(f);
  expect(f.calls).toEqual([...prefix, 'CheckMacaroonPermissions', 'DeleteMacaroonID', 'ListMacaroonIDs', 'CheckMacaroonPermissions']);
}));
it.each(['missing file', 'fingerprint mismatch', 'expired', 'baseline rejected', 'empty permissions']) (
  'CP-027/V12 %s uses ID-only proof and never claims credential rejection', async kind => scratch(async f => {
    if (kind === 'missing file') f.target.outPath = join(f.dir, 'missing.macaroon');
    if (kind === 'fingerprint mismatch') f.target.fingerprint = 'fp:0000000000000000';
    if (kind === 'expired') f.target = entry('time-before', maxId);
    if (kind === 'empty permissions') f.target = entry('root-max', maxId, { outPath: null, permissions: [], grade: 'UNASSESSED' });
    save(f);
    // ID-only branches must not attempt to read/check an unusable target in V12.
    f.lnd.checkMacaroon.mockImplementation(async () => {
      f.calls.push('CheckMacaroonPermissions'); return { valid: false as const, reason: 'other' as const, message: 'baseline refusal' };
    });
    success(f, await invoke(f), 'by-id-only');
    expect(f.lnd.checkMacaroon.mock.calls.length).toBe(kind === 'baseline rejected' ? 1 : 0);
    expect(f.lnd.listMacaroonIds).toHaveBeenCalledTimes(2);
  }));

it.each(['--yes', 'typed label', '--json'])('CP-027/V13 %s saves verified revocation with exact result and scope',
  async kind => scratch(async f => {
    success(f, await invoke(f, kind === 'typed label' ? [] : kind === '--json' ? ['--yes', '--json'] : ['--yes']));
    expect(f.lnd.deleteMacaroonId).toHaveBeenCalledWith(BigInt(maxId));
    expect(f.calls).toEqual([...prefix, 'CheckMacaroonPermissions', 'DeleteMacaroonID', 'ListMacaroonIDs', 'CheckMacaroonPermissions']);
    expect(f.prompt.mock.calls.length).toBe(kind === 'typed label' ? 1 : 0);
    expect(JSON.parse(bytes(f).toString()).entries[0]).toEqual({ ...f.target, status: 'revoked', revokedAt: expect.any(String), revokeEvidence: 'rejected' });
  }));
it('CP-027/V13 unregistered numeric target creates label-null record without changing foreign ownership', async () => scratch(async f => {
  const foreign = { ...f.other, nodePubkey: otherPubkey, label: 'Foreign' };
  save(f, [f.other, foreign]);
  f.lnd.deleteMacaroonId.mockImplementation(async id => {
    f.calls.push('DeleteMacaroonID'); expect(id).toBe(BigInt(maxId)); absent(f); return { deleted: true };
  });
  success(f, await invoke(f, ['--unregistered', '--yes'], maxId), 'by-id-only', false, null);
  expect(JSON.parse(bytes(f).toString()).entries).toContainEqual(foreign);
  expect(f.calls).toEqual([...prefix, 'DeleteMacaroonID', 'ListMacaroonIDs']);
}));
it('CP-027/V13 unregistered typed ID confirms only after an unlocked complete plan', async () => scratch(async f => {
  save(f, [f.other]);
  f.prompt.mockImplementation(async question => {
    expect(existsSync(`${f.registry}.lock`)).toBe(false); expect(question).toContain(maxId); return maxId;
  });
  f.lnd.deleteMacaroonId.mockImplementation(async id => {
    f.calls.push('DeleteMacaroonID'); expect(id).toBe(BigInt(maxId)); absent(f); return { deleted: true };
  });
  success(f, await invoke(f, ['--unregistered'], maxId), 'by-id-only', false, null);
  expect(f.prompt).toHaveBeenCalledTimes(1);
}));
it.each(['write', 'rename', 'repair write'])('CP-027/V13 %s failure preserves registry and prints exact rerun that repairs absence',
  async kind => scratch(async f => {
    if (kind === 'repair write') absent(f);
    const before = bytes(f);
    if (kind === 'rename') f.deps.fs.rename = vi.fn(async () => { throw Object.assign(new Error('injected save rename failure'), { code: 'EACCES' }); });
    else {
      const denied = () => { throw Object.assign(new Error('injected save write failure'), { code: 'EACCES' }); };
      f.deps.fs.writeFile = fs.writeFile;
      f.deps.fs.open = vi.fn(async (...args: Parameters<typeof fs.open>) => {
        const handle = await fs.open(...args);
        if (!String(args[0]).startsWith(f.registry) || String(args[0]).startsWith(f.registry + '.lock')) return handle;
        return new Proxy(handle, { get(target, key) {
          if (['write', 'writeFile', 'writev'].includes(String(key))) return async () => denied();
          const value = Reflect.get(target, key, target); return typeof value === 'function' ? value.bind(target) : value;
        } });
      });
    }
    const result = await invoke(f); failure(result, 7, 'V13');
    expect(result.error!.message).toMatch(/absent/i); expect(result.error!.message).toContain('macwarden revoke Alice');
    // The follow-up must identify the explicit registry/online configuration so it reaches the same entry and node.
    for (const value of ['--registry', f.registry, '--lnd-rest', '127.0.0.1:1', '--tls-cert', '--macaroon', f.own])
      expect(result.error!.message).toContain(value);
    unchanged(f, before); released(f); expect(f.ids).not.toContain(maxId);
    f.deps.fs.writeFile = fs.writeFile; f.deps.fs.rename = fs.rename; f.deps.fs.open = fs.open; f.calls.length = 0;
    f.lnd.deleteMacaroonId.mockClear(); f.lnd.checkMacaroon.mockClear(); f.lnd.listMacaroonIds.mockClear();
    success(f, await invoke(f), 'by-id-only', true);
    expect(f.calls).toEqual(prefix); expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
  }));

it('CP-027/revoke-live-flow injected command flow removes only its target and preserves another ID and record', async () => scratch(async f => {
  const otherBefore = readFileSync(f.other.outPath); success(f, await invoke(f));
  expect(f.ids).toEqual(['0', f.other.rootKeyId]); expect(readFileSync(f.other.outPath).equals(otherBefore)).toBe(true);
  // Live credential acceptance is established separately by the independent lncli reference cases.
}));
it('CP-027/revoke-live-flow command root-zero refusal remains before all LND calls', async () => scratch(async f => {
  const before = bytes(f); failure(await invoke(f, ['--yes', '--unregistered'], '0'), 2, 'V1');
  expect(f.calls).toEqual([]); unchanged(f, before); released(f);
}));

it.each(['rejected', 'by-id-only'] as const)(
  'F12/V13 a recorded-revoked root key held again by LND (backup restore) is re-revoked with this run\'s time and evidence (old evidence %s)',
  async oldEvidence => scratch(async f => {
    const earlier = '2026-09-02T00:00:00.000Z';
    // The registry already records the revocation; LND holds the root key again.
    save(f, [{ ...f.target, status: 'revoked', revokedAt: earlier, revokeEvidence: oldEvidence }, f.other]);
    f.lnd.deleteMacaroonId.mockImplementation(async id => {
      f.calls.push('DeleteMacaroonID'); f.ids.splice(f.ids.indexOf(String(id)), 1); return { deleted: true };
    });
    // This run cannot prove rejection (an unreadable default file): evidence differs from the old record.
    f.lnd.checkMacaroon.mockImplementation(async () => { f.calls.push('CheckMacaroonPermissions'); return { valid: false, reason: 'other', message: 'x' } as never; });
    const result = await invoke(f, ['--yes'], maxId);
    success(f, result, 'by-id-only');
    expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1);
    const row = result.result!.entry as Record<string, unknown>;
    expect(row).toMatchObject({ revokedAt: instant, revokeEvidence: 'by-id-only' });
    expect(row.revokeEvidence).toBe(result.result!.evidence);
    expect(result.warnings).toContainEqual({ code: 'revoked-but-present',
      message: expect.stringContaining(`recorded revoked at ${earlier} (evidence ${oldEvidence})`) });
  }));

// 1.2.1 (F12 follow-up): when the save after re-revoking a revoked-but-present root key fails, the
// entry still records the earlier revocation; no output claims it records this one, and the message
// prints no rerun (V7 refuses an absent, already revoked ID with exit 5, so a rerun cannot record it).
it('F12/V13 a failed save after re-revoking a revoked-but-present key is reported truthfully, without a rerun', async () => scratch(async f => {
  const earlier = '2026-09-02T00:00:00.000Z';
  save(f, [{ ...f.target, status: 'revoked', revokedAt: earlier, revokeEvidence: 'rejected' }, f.other]);
  f.lnd.deleteMacaroonId.mockImplementation(async id => {
    f.calls.push('DeleteMacaroonID'); f.ids.splice(f.ids.indexOf(String(id)), 1); return { deleted: true };
  });
  const before = bytes(f);
  f.deps.fs.rename = vi.fn(async () => { throw Object.assign(new Error('injected save rename failure'), { code: 'EACCES' }); });
  const result = await invoke(f, ['--yes'], maxId);
  f.deps.fs.rename = fs.rename;
  failure(result, 7, 'V13');
  unchanged(f, before); released(f); expect(f.ids).not.toContain(maxId);
  expect(result.warnings.some(w => typeof w !== 'string' && w.code === 'revoked-but-present')).toBe(false);
  expect(JSON.stringify(result)).not.toMatch(/entry now records this revocation/);
  expect(result.error!.message).toContain(`deleted from LND again`);
  expect(result.error!.message).toContain(`still records it revoked at ${earlier} (evidence rejected)`);
  expect(result.error!.message).toMatch(/no further action is needed/);
  expect(result.error!.message).not.toContain('macwarden revoke');
  // What the message says a rerun would do is what it does: nothing to revoke, registry unchanged.
  f.calls.length = 0;
  failure(await invoke(f, ['--yes'], maxId), 5, 'V7');
  unchanged(f, before); released(f);
}));
