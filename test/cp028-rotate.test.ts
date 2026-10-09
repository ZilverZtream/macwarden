import { liveProductLock } from './helpers/cp042-lock-process.js';
import { revealSecret } from './helpers/secret-bytes.js';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it, vi } from 'vitest';
import { Secret } from '../src/secret.js';
import { decodeMacaroon } from '../src/decode/index.js';
import { render } from './helpers/render-adversarial.js';
import { directory, entry, otherPubkey, ownId, permissionsResponse, register, wireFixture } from './helpers/cp026-revoke-support.mjs';
import { afterFailure, failure, fault, fingerprint, instant, invoke, newId, oldId, recovery,
  safe, save, scratch, unchanged } from './helpers/cp028-rotate-support.js';
import { isolateLeakSuite } from './helpers/leak-suite.js';

isolateLeakSuite('cp028');

// Control the entropy dependency, leaving allocation and rotate unmocked.
const entropy = vi.hoisted(() => ({ values: [] as bigint[], draws: 0 }));
vi.mock('node:crypto', async importOriginal => {
  const real = await importOriginal<typeof import('node:crypto')>();
  return { ...real, randomBytes: (size: number) => {
    if (size !== 8) return real.randomBytes(size);
    entropy.draws++; const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(entropy.values.shift() ?? 4294967390n); return bytes;
  } };
});
const prefix = ['GetInfo', 'ListPermissions', 'ListMacaroonIDs'];
vi.setConfig({ testTimeout: 60_000 });

it.each(['numeric label', 'punctuation label', 'long label', 'missing out', 'yes without finish', 'unknown flag'])(
  'CP-028/S1-S2 %s is refused before registry or network access', async kind => scratch(async f => {
    if (kind === 'numeric label') f.args[0] = '123';
    if (kind === 'punctuation label') f.args[0] = '-bad';
    if (kind === 'long label') f.args[0] = 'A'.repeat(65);
    if (kind === 'missing out') f.args.splice(f.args.indexOf('--out'), 2);
    if (kind === 'yes without finish') f.args.push('--yes');
    if (kind === 'unknown flag') f.args.push('--unknown-stage-option');
    const before = readFileSync(f.registry); f.deps.env.NODE_DEBUG = 'https';
    const result = await invoke(f); failure(f, result, 2, 'S1');
    expect(f.calls).toEqual([]); expect(f.deps.fs.open).not.toHaveBeenCalled(); unchanged(f, before);
  }));
it.each(['http', 'HTTPS', 'tls', 'net', 'fs,https', '--report-on-fatalerror'])(
  'CP-028/S1-S2 unsafe ENV %s stops at S2 before OWN and registry', async value => scratch(async f => {
    f.deps.env[value.startsWith('--') ? 'NODE_OPTIONS' : 'NODE_DEBUG'] = value;
    const before = readFileSync(f.registry); failure(f, await invoke(f), 2, 'S2');
    expect(f.calls).toEqual([]); expect(f.deps.fs.open).not.toHaveBeenCalled(); unchanged(f, before);
  }));

it.each(['invalid JSON', 'invalid schema', 'unreadable'])(
  'CP-028/S3 %s registry exits input error offline', async kind => scratch(async f => {
    if (kind === 'invalid JSON') writeFileSync(f.registry, '{');
    if (kind === 'invalid schema') writeFileSync(f.registry, JSON.stringify({ schema: 9, entries: [] }));
    if (kind === 'unreadable') f.deps.fs.readFile = vi.fn(async (...params: Parameters<typeof fs.readFile>) => {
      if (params[0] === f.registry) throw Object.assign(new Error('registry read fault'), { code: 'EACCES' });
      return fs.readFile(...params);
    }) as typeof fs.readFile;
    failure(f, await invoke(f), 3, 'S3'); expect(f.calls).toEqual([]);
  }));
it.each(['missing label', 'revoked old'])(
  'CP-028/S3 %s cannot resolve an eligible old credential offline', async kind => scratch(async f => {
    if (kind === 'missing label') save(f, [f.other]);
    if (kind === 'revoked old') { f.old.status = 'revoked'; f.old.revokedAt = instant; f.old.revokeEvidence = 'by-id-only'; save(f); }
    const before = readFileSync(f.registry); const result = await invoke(f); failure(f, result, 2, 'S3');
    expect(f.calls).toEqual([]); unchanged(f, before);
  }));
// SPEC 6 S3 changed in 1.1.1 (RL-07): an entry whose `replaces` names an entry no longer in the
// registry (the revoked original was pruned) is not a pending replacement, so it is the original
// rotate resolves, as respond already planned it. Before, rotate refused it ("replacement only").
it('CP-028/S3 an entry whose replaced original was pruned resolves as the original', async () => scratch(async f => {
  f.old.replaces = '4294967320'; save(f);
  const before = readFileSync(f.registry); const result = await invoke(f, ['--dry-run']);
  expect(result.error).toBeNull();
  expect(result.result).toMatchObject({ dryRun: true, stage: 'stage', old: f.old }); unchanged(f, before);
}));
// SPEC 6 S3 changed in 1.1.1 (RL-04): a label active on several nodes of one registry (which bake
// allows) is resolved against the connected node with a read-only GetInfo instead of refused.
it('CP-028/S3 a label active on several nodes resolves to the connected node', async () => scratch(async f => {
  save(f, [f.old, f.other, { ...f.old, nodePubkey: otherPubkey }]);
  const before = readFileSync(f.registry); const result = await invoke(f, ['--dry-run']);
  expect(result.error).toBeNull();
  expect(result.result).toMatchObject({ dryRun: true, stage: 'stage', old: f.old });
  expect(f.calls[0]).toBe('GetInfo'); unchanged(f, before);
}));
it.each([true, false])('CP-028/S3 pending replacement verified=%s lists both IDs and both safe exits', async verified => scratch(async f => {
  const next = entry('preset-invoice-only', newId, { replaces: oldId, verified, outPath: verified ? f.out : null });
  save(f, [f.old, f.other, next]); const before = readFileSync(f.registry);
  const result = await invoke(f); failure(f, result, 2, 'S3');
  for (const text of [oldId, newId, 'macwarden rotate Alice --finish', `macwarden revoke ${newId}`]) expect(result.error!.message).toContain(text);
  expect(result.error!.message).toMatch(/confirm|app uses/i);
  if (verified) expect(result.error!.message).toContain(f.out);
  expect(f.calls).toEqual([]); unchanged(f, before);
}));

it('CP-028/S4-S5 matching credential with different registry permissions stops at S4 before an existing output', async () => scratch(async f => {
  f.old.permissions = ['info:read']; f.old.grade = 'READ'; save(f); writeFileSync(f.out, 'existing noncredential');
  const result = await invoke(f); failure(f, result, 3, 'S4', true);
  expect(result.error!.message).toContain('registry entry does not match the credential'); expect(f.calls).toEqual([]);
  expect(readFileSync(f.out, 'utf8')).toBe('existing noncredential');
}));
it.each(['UNASSESSED', 'ADMIN'])('CP-028/S4-S5 %s authority is regraded and refused at S5 offline', async grade => scratch(async f => {
  const v = entry(grade === 'ADMIN' ? 'default-admin' : 'grade-unknown-entity', oldId);
  Object.assign(f.old, v, { grade }); save(f);
  const before = readFileSync(f.registry); const result = await invoke(f); failure(f, result, 2, 'S5');
  expect(result.error!.message).toMatch(grade === 'ADMIN' ? /allow-admin/i : /unassessed/i);
  expect(f.calls).toEqual([]); unchanged(f, before);
}));
it('CP-028/S4-S5 allow-admin does not bypass unassessed authority warnings', async () => scratch(async f => {
  Object.assign(f.old, entry('grade-admin-unknown', oldId)); save(f);
  const result = await invoke(f, ['--allow-admin']); failure(f, result, 2, 'S5');
  expect(result.error!.message).toMatch(/unassessed/i); expect(f.calls).toEqual([]);
}));
it('CP-028/S4-S5 existing output is preserved and refused before OWN', async () => scratch(async f => {
  writeFileSync(f.out, 'operator file'); f.args[f.args.indexOf('--macaroon') + 1] = join(f.dir, 'missing-own.macaroon');
  const result = await invoke(f); failure(f, result, 3, 'S5', true);
  expect(readFileSync(f.out, 'utf8')).toBe('operator file'); expect(f.calls).toEqual([]);
}));
it.each(['absent path', 'null path', 'fingerprint mismatch', 'revoked replacement', 'other node replacement'])(
  'CP-028/S4-S5 %s falls back to registry permissions or ignores an ineligible replacement', async kind => scratch(async f => {
    if (kind === 'absent path') f.old.outPath = join(f.dir, 'missing.macaroon');
    if (kind === 'null path') f.old.outPath = null;
    if (kind === 'fingerprint mismatch') f.old.fingerprint = 'fp:0000000000000000';
    const rows = [f.old, f.other];
    if (kind === 'revoked replacement') rows.push(entry('preset-invoice-only', newId, {
      replaces: oldId, status: 'revoked', revokedAt: instant, revokeEvidence: 'by-id-only' }));
    if (kind === 'other node replacement') rows.push(entry('preset-invoice-only', newId, { replaces: oldId, nodePubkey: otherPubkey }));
    save(f, rows); const before = readFileSync(f.registry); const result = await invoke(f, ['--dry-run']);
    if (kind === 'fingerprint mismatch') {
      failure(f, result, 3, 'S4'); expect(f.calls).toEqual([]); unchanged(f, before); return;
    }
    expect(result.error).toBeNull(); expect(result.result).toMatchObject({ dryRun: true, stage: 'stage', old: f.old,
      grade: 'RECEIVE', permissions: f.old.permissions });
    // 1.1.1 (RL-04, RL-07): the other node's entry no longer replaces an active entry there, so it is
    // that node's Alice; S3 resolves the label against the connected node with one read-only GetInfo.
    expect(f.calls).toEqual([...(kind === 'other node replacement' ? ['GetInfo'] : []),
      ...(['absent path', 'null path'].includes(kind) ? prefix : [...prefix, 'CheckMacaroonPermissions'])]);
    unchanged(f, before);
  }));

it.each(['missing cert', 'missing own', 'undecodable own', 'missing generate', 'missing read', 'missing info'])(
  'CP-028/S6-S7 OWN %s exits 4 without LND calls', async kind => scratch(async f => {
    if (kind === 'missing cert') f.args[f.args.indexOf('--tls-cert') + 1] = join(f.dir, 'missing.cert');
    if (kind === 'missing own') f.args[f.args.indexOf('--macaroon') + 1] = join(f.dir, 'missing.macaroon');
    if (kind === 'undecodable own') f.args[f.args.indexOf('--macaroon') + 1] = register(Buffer.from('not a macaroon'));
    if (kind.startsWith('missing ') && !['missing cert', 'missing own'].includes(kind)) {
      const missing = { 'missing generate': 'macaroon:generate', 'missing read': 'macaroon:read', 'missing info': 'info:read' }[kind];
      const own = entry('default-admin', ownId).permissions.filter((permission: string) => permission !== missing);
      f.args[f.args.indexOf('--macaroon') + 1] = register(wireFixture('default-admin', ownId, own));
    }
    failure(f, await invoke(f), 4, 'S6'); expect(f.calls).toEqual([]);
  }));
it.each(['own ID', 'root zero'])('CP-028/S6-S7 refuses %s before any network call', async kind => scratch(async f => {
  f.old.rootKeyId = kind === 'own ID' ? ownId : '0'; f.old.outPath = null; save(f);
  const prompt = vi.fn<(message: string) => Promise<string>>(async () => 'Alice');
  if (kind === 'own ID') Object.assign(f.deps, {
    stdin: Object.assign(Readable.from([]), { isTTY: true }), prompt,
  });
  const result = await invoke(f); expect(result.error?.code).toBe(2); expect(f.calls).toEqual([]);
  expect(existsSync(f.out)).toBe(false); expect(existsSync(`${f.registry}.lock`)).toBe(false);
  if (kind === 'own ID') {
    expect(result.error?.step).toBe('S6');
    expect(prompt).toHaveBeenCalledTimes(1);
    const informedPrompt = f.outputs.join('') + prompt.mock.calls[0][0];
    for (const value of [f.old.grade, ...f.old.permissions]) expect(informedPrompt).toContain(value);
    expect(informedPrompt).toMatch(/cannot prove/i);
    expect(informedPrompt).toMatch(/type\s+Alice/i);
  } else {
    expect(prompt).not.toHaveBeenCalled();
    expect(f.outputs.join('')).not.toMatch(/type\s+Alice/i);
  }
}));
it('CP-028/S6-S7 held lock preserves owner metadata and refuses before reservation or LND', async () => scratch(async f => {
  const { bytes: lockBytes, owner } = await liveProductLock(f.registry);
    const lock = lockBytes.toString('utf8');
  
  const result = await invoke(f, ['--break-lock']); expect(result.error).toMatchObject({ code: 3, step: 'S7' });
  for (const value of [String(owner.pid), owner.hostname, owner.startedAt]) expect(result.error!.message).toContain(value);
  expect(readFileSync(`${f.registry}.lock`, 'utf8')).toBe(lock); expect(f.calls).toEqual([]); expect(existsSync(f.out)).toBe(false);
}));
it.each(['changed old', 'new pending', 'reread failure'])('CP-028/S6-S7 %s after lock stops with nothing sent', async kind => scratch(async f => {
  let changed!: Buffer;
  f.deps.fs.readFile = vi.fn(async (...params: Parameters<typeof fs.readFile>) => {
    if (params[0] === f.registry && existsSync(`${f.registry}.lock`)) {
      if (kind === 'reread failure') throw Object.assign(new Error('reread fault'), { code: 'EACCES' });
      const rows = [f.old, f.other];
      if (kind === 'changed old') rows[0] = { ...f.old, fingerprint: 'fp:0000000000000000' };
      else rows.push(entry('preset-invoice-only', newId, { replaces: oldId }));
      save(f, rows); changed = readFileSync(f.registry);
    }
    return fs.readFile(...params);
  }) as typeof fs.readFile;
  const before = readFileSync(f.registry); failure(f, await invoke(f), 3, 'S7');
  expect(f.calls).toEqual([]); unchanged(f, changed ?? before);
}));
it('CP-028/S6-S7 failed exclusive reservation releases lock without contacting LND', async () => scratch(async f => {
  f.deps.fs.open = vi.fn(async (...params: Parameters<typeof fs.open>) => {
    if (params[0] === f.out) throw Object.assign(new Error('reserve fault'), { code: 'EACCES' });
    return fs.open(...params);
  }) as typeof fs.open;
  failure(f, await invoke(f), 3, 'S7'); expect(f.calls).toEqual([]);
}));

for (const method of ['getInfo', 'listMacaroonIds'] as const) {
  it.each(['transport', 'LND'])(`CP-028/S8-S9 ${method} %s failure has matching unchanged-state exit`, async kind => scratch(async f => {
    const call = method === 'getInfo' ? 'GetInfo' : 'ListMacaroonIDs';
    f.lnd[method].mockImplementationOnce(async () => { f.calls.push(call); throw fault(kind); });
    const before = readFileSync(f.registry); failure(f, await invoke(f), kind === 'transport' ? 4 : 5, 'S8');
    expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled(); afterFailure(f, call); unchanged(f, before);
  }));
}
it('CP-028/S8-S9 pubkey mismatch refuses at S8 before further node calls', async () => scratch(async f => {
  f.lnd.getInfo.mockImplementationOnce(async () => { f.calls.push('GetInfo'); return { pubkey: otherPubkey, alias: 'fixture', version: '0.21.4-beta', network: 'regtest' }; });
  failure(f, await invoke(f), 2, 'S8'); expect(f.calls).toEqual(['GetInfo']);
}));
it('CP-028/S8-S9 absent old ID exits 5 with the required message and no bake', async () => scratch(async f => {
  f.lnd.listMacaroonIds.mockImplementationOnce(async () => { f.calls.push('ListMacaroonIDs'); return (['0']).map(BigInt); });
  const result = await invoke(f); failure(f, result, 5, 'S8');
  expect(result.error!.message).toContain('old root key ID is not in LND'); expect(f.calls).toEqual(prefix);
}));
it('CP-028/S8-S9 snapshot drift warns while dry-run reports both plans without locking or reserving', async () => scratch(async f => {
  f.old.caveats = [{ type: 'time-before', value: '2027-01-01T00:00:00Z', requested: '90d' }]; save(f);
  f.lnd.listPermissions.mockImplementationOnce(async () => {
    f.calls.push('ListPermissions'); return permissionsResponse({});
  });
  writeFileSync(`${f.registry}.lock`, JSON.stringify({ pid: process.pid, hostname: hostname(), startedAt: instant }));
  const before = readFileSync(f.registry), lock = readFileSync(`${f.registry}.lock`);
  const result = await invoke(f, ['--dry-run']); expect(result.error).toBeNull();
  expect(result.result).toMatchObject({ dryRun: true, stage: 'stage', old: f.old, grade: 'RECEIVE', permissions: f.old.permissions });
  expect(result.warnings.map(w => typeof w === 'string' ? w : w.code)).toContain('snapshot-drift');
  const text = render(result, 'text');
  for (const expected of [oldId, 'RECEIVE', ...f.old.permissions, 'time-before', 'stage', 'finish']) expect(text.toLowerCase()).toContain(expected.toLowerCase());
  expect(f.lnd.listPermissions).toHaveBeenCalledTimes(1);
  expect(f.calls).toEqual([...prefix, 'CheckMacaroonPermissions']); expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  for (const [path, flags] of vi.mocked(f.deps.fs.open).mock.calls) {
    expect(path).not.toBe(f.out);
    expect(path).not.toBe(`${f.registry}.lock`);
    expect([f.oldBytesPath, f.own, resolve('test/fixture/wrong-tls.cert')]).toContain(path);
    if (typeof flags === 'number') {
      const { constants } = await import('node:fs');
      expect(flags & (constants.O_WRONLY | constants.O_RDWR | constants.O_CREAT |
        constants.O_TRUNC | constants.O_APPEND)).toBe(0);
    } else expect(flags).toMatch(/^r[s]?$/);
  }
  expect(existsSync(f.out)).toBe(false); unchanged(f, before);
  expect(readFileSync(`${f.registry}.lock`).equals(lock)).toBe(true);
}));

it('CP-028/S10-S12 fresh allocation rejects node and revoked-registry collisions before baking once', async () => scratch(async f => {
  const revoked = entry('preset-invoice-only', '4294967350', { label: 'Retired', status: 'revoked', revokedAt: instant, revokeEvidence: 'by-id-only' });
  save(f, [f.old, f.other, revoked]); entropy.values = [BigInt(oldId), BigInt(revoked.rootKeyId), BigInt(newId)]; entropy.draws = 0;
  expect((await invoke(f)).error).toBeNull(); expect(entropy.draws).toBe(3);
  expect(f.lnd.bakeMacaroon).toHaveBeenCalledTimes(1); expect(f.state.chosen).toBe(newId);
  expect(f.rows()).toContainEqual(revoked); expect(f.rows()).toContainEqual(f.old);
}));
it('CP-028/S10-S12 sixteen colliding draws exit 5 at S10 without issuance', async () => scratch(async f => {
  entropy.values = Array(16).fill(BigInt(oldId)); entropy.draws = 0;
  const before = readFileSync(f.registry); failure(f, await invoke(f), 5, 'S10');
  expect(entropy.draws).toBe(16); expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled(); unchanged(f, before);
}));
it('CP-040/B11-meaningful-tests rotation refuses a failed preflight journal save without changing old authority', async () => scratch(async f => {
  const before = readFileSync(f.registry), oldBefore = readFileSync(f.oldBytesPath);
  f.deps.fs.rename = vi.fn(async (...params: Parameters<typeof fs.rename>) => {
    if (params[1] === f.registry) throw Object.assign(new Error('preflight journal unavailable'), { code: 'EACCES' });
    return fs.rename(...params);
  }) as typeof fs.rename;
  const result = await invoke(f);
  expect(result.error).toMatchObject({ code: 3 });
  expect(result.result).toBeNull();
  expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
  expect(f.state.ids).toContain(oldId);
  expect(readFileSync(f.oldBytesPath).equals(oldBefore)).toBe(true);
  unchanged(f, before);
  expect(existsSync(f.out)).toBe(false);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
}));
for (const observation of ['absent', 'present', 'unknown']) {
  it.each(['transport', 'LND'])(`CP-028/S10-S12 bake %s failure with new ID ${observation} reconciles only once`, async kind => scratch(async f => {
    const before = readFileSync(f.registry);
    f.lnd.bakeMacaroon.mockImplementationOnce(async (_permissions, id) => {
      f.calls.push('BakeMacaroon'); f.state.chosen = String(id);
      if (observation === 'present') f.state.ids.push(String(id)); throw fault(kind);
    });
    f.lnd.listMacaroonIds.mockImplementation(async () => {
      f.calls.push('ListMacaroonIDs'); if (f.state.chosen && observation === 'unknown') throw fault();
      return ([...f.state.ids]).map(BigInt);
    });
    const result = await invoke(f); failure(f, result, observation === 'absent' ? (kind === 'transport' ? 4 : 5) : 7, 'S10');
    expect(f.calls).toEqual([...prefix, 'CheckMacaroonPermissions', 'BakeMacaroon', 'ListMacaroonIDs']);
    if (observation === 'absent') unchanged(f, before);
    else expect(f.rows()).toEqual([f.old, f.other, expect.objectContaining({
      rootKeyId: f.state.chosen, replaces: oldId, verified: false,
      fingerprint: null, outPath: null })]);
    if (observation === 'present') {
      expect(result.error!.message).toContain(`macwarden revoke ${f.state.chosen}`);
      expect(result.error!.message).not.toContain('--unregistered');
      expect(result.error!.message).not.toContain('macwarden revoke Alice');
    }
    if (observation === 'unknown') {
      expect(result.error!.message).toContain('LND state unknown'); expect(result.error!.message).toContain('macwarden inventory');
    }
  }));
}
const postBake = [
  ['wrong ID', 'S11'], ['wrong permissions', 'S11'], ['undecodable response', 'S11'],
  ['rejected', 'S12'], ['LND error', 'S12'], ['timeout', 'S12'], ['write', 'S12'], ['flush', 'S12'], ['close', 'S12'],
] as const;
for (const [kind, step] of postBake) {
  it(`CP-028/S10-S12 ${kind} after issuance records an ID-specific unverified replacement`, async () => scratch(async f => {
    if (kind === 'wrong ID') f.state.responseId = '4294967399';
    if (kind === 'wrong permissions') f.state.responsePermissions = ['info:read'];
    if (kind === 'undecodable response') f.state.corrupt = true;
    if (['write', 'flush', 'close'].includes(kind)) f.state.writeFault = kind as 'write' | 'flush' | 'close';
    if (['rejected', 'LND error', 'timeout'].includes(kind)) {
      const verify = f.lnd.checkMacaroon.getMockImplementation()!;
      f.lnd.checkMacaroon.mockImplementation(async (mac, permissions, ...extra) => {
        const bytes = Buffer.from(revealSecret(mac));
        if (bytes.equals(readFileSync(f.oldBytesPath))) return verify(mac, permissions, ...extra);
        expect(String(decodeMacaroon(mac).rootKeyId)).toBe(f.state.chosen);
        expect(permissions.slice().sort()).toEqual(f.old.permissions.slice().sort());
        expect(permissions.length).toBeGreaterThan(0); expect(extra).toEqual([]);
      f.calls.push('CheckMacaroonPermissions'); register(Buffer.from(revealSecret(mac)));
      f.state.failedAt = f.calls.length - 1;
      if (kind === 'rejected') return { valid: false as const, reason: 'other' as const, message: 'injected verification refusal' };
      throw kind === 'timeout' ? Object.assign(new Error('verify timeout'), { code: 'ETIMEDOUT' }) : fault('LND');
      });
    }
    const result = await invoke(f); failure(f, result, 7, step); recovery(f, result);
    if (step === 'S11') expect(f.lnd.checkMacaroon.mock.calls.map(([mac]) =>
      Buffer.from(revealSecret(mac)).equals(readFileSync(f.oldBytesPath)))).toEqual([true]);
    if (['rejected', 'LND error', 'timeout'].includes(kind)) expect(f.events).not.toContain('write');
    afterFailure(f, step === 'S11' ? 'BakeMacaroon' : 'CheckMacaroonPermissions');
  }));
}
it('CP-028/S10-S12 failed recovery save retains durable pending N and uses its registered ID', async () => scratch(async f => {
  f.state.registryFails = true; f.state.responsePermissions = ['info:read'];
  const before = readFileSync(f.registry), result = await invoke(f); failure(f, result, 7, 'S11');
  recovery(f, result);
  const original = JSON.parse(before.toString('utf8')) as { entries: unknown[] };
  const pending = f.rows().find(row => row.rootKeyId === f.state.chosen);
  expect(f.rows()).toEqual([...original.entries, pending]);
  expect(pending).toEqual({ ...f.old, rootKeyId: f.state.chosen, replaces: oldId,
    caveats: [], verified: false, outPath: null, fingerprint: null, createdAt: expect.any(String) });
  expect(result.error!.message).not.toContain('--unregistered');
}));
it('CP-028/S10-S12 requested duration creates a fresh second-precision UTC caveat and verifies final bytes', async () => scratch(async f => {
  f.old.caveats = [{ type: 'time-before', value: '2026-10-06T00:00:00Z', requested: '90d' }]; save(f);
  const result = await invoke(f); expect(result.error).toBeNull();
  const next = result.result!.new as Record<string, unknown>;
  expect(next.caveats).toEqual([{ type: 'time-before', value: '2027-01-03T09:00:00Z', requested: '90d' }]);
  expect(decodeMacaroon(new Secret(f.state.checked)).caveats).toEqual([{ type: 'time-before', value: '2027-01-03T09:00:00Z' }]);
  expect(f.state.checked.equals(f.state.issued)).toBe(false); expect(readFileSync(f.out).equals(f.state.checked)).toBe(true);
  expect(f.events.indexOf('verify')).toBeLessThan(f.events.indexOf('write')); expect(f.rows()).toContainEqual(f.old);
}));
it('CP-028/S10-S12 unexpected failure after issuance reports internal and inventory without leaking input', async () => scratch(async f => {
  f.lnd.bakeMacaroon.mockImplementationOnce(async (_permissions, id) => {
    f.calls.push('BakeMacaroon'); f.state.chosen = String(id); f.state.ids.push(String(id));
    throw new TypeError('unexpected stage fault');
  });
  const result = await invoke(f); failure(f, result, 8, 'internal');
  expect(result.error!.message).toContain('macwarden inventory'); afterFailure(f, 'BakeMacaroon');
}));
it('CP-028/S10-S12 unexpected clock fault while renewing expiry removes reservation and preserves O', async () => scratch(async f => {
  f.old.caveats = [{ type: 'time-before', value: '2026-10-06T00:00:00Z', requested: '90d' }]; save(f);
  f.deps.clock = () => { if (f.state.chosen) throw new TypeError('unexpected attenuation clock fault'); return new Date(instant); };
  const result = await invoke(f); failure(f, result, 8, 'internal');
  expect(result.error!.message).toContain('macwarden inventory'); expect(f.events).not.toContain('write');
  expect(f.lnd.checkMacaroon.mock.calls.map(([mac]) =>
    Buffer.from(revealSecret(mac)).equals(readFileSync(f.oldBytesPath)))).toEqual([true]);
  afterFailure(f, 'BakeMacaroon');
}));

it.each(['preset-invoice-only', 'preset-read-only', 'preset-pay-only', 'default-admin'])(
  'CP-028/S13 %s stage records verified N and preserves O with actionable text and JSON', async name => scratch(async f => {
    const result = await invoke(f, name === 'default-admin' ? ['--allow-admin'] : []);
    expect(result.error).toBeNull(); const next = result.result!.new as Record<string, unknown>;
    expect(result.result).toEqual({ stage: 'staged', old: f.old, new: next });
    expect(next).toEqual({ ...f.old, rootKeyId: f.state.chosen, caveats: [], replaces: oldId,
      fingerprint: fingerprint(readFileSync(f.out)), outPath: f.out, createdAt: expect.any(String), verified: true });
    expect(f.rows()).toEqual([f.old, f.other, next]); expect(f.state.ids).toContain(f.state.chosen);
    expect(f.calls).toEqual([...prefix, 'CheckMacaroonPermissions', 'BakeMacaroon', 'CheckMacaroonPermissions']);
    expect(readFileSync(f.out).equals(f.state.checked)).toBe(true);
    for (const [first, second] of [['reserve', 'bake'], ['verify', 'write'], ['write', 'flush'], ['flush', 'close'], ['close', 'save']])
      expect(f.events.indexOf(first)).toBeLessThan(second === 'save' ? f.events.lastIndexOf(second) : f.events.indexOf(second));
    expect(f.events.indexOf('save')).toBeLessThan(f.events.indexOf('bake'));
    expect(existsSync(`${f.registry}.lock`)).toBe(false); expect(f.state.handle!.fd).toBe(-1);
    if (process.platform !== 'win32') expect(statSync(f.out).mode & 0o777).toBe(0o600);
    const text = render(result, 'text');
    for (const value of ['staged', f.out, f.old.grade, ...f.old.permissions, oldId, 'macwarden rotate Alice --finish', `macwarden revoke ${f.state.chosen}`]) expect(text).toContain(value);
    expect(text).toMatch(/every.*replica/i); expect(text).toMatch(/config/i); expect(text).toMatch(/unchanged.*valid|valid.*unchanged/i);
    expect(text).not.toContain('macwarden revoke Alice');
    expect(JSON.parse(render(result, 'json'))).toEqual(result);
  }, name));
it('CP-028/S13 registry save failure retains the verified valid file and names journaled N cleanup', async () => scratch(async f => {
  f.state.registryFails = true;
  const result = await invoke(f); failure(f, result, 7, 'S13', true);
  expect(f.rows()).toEqual([f.old, f.other, expect.objectContaining({
    rootKeyId:f.state.chosen,verified:false,fingerprint:null,outPath:null,replaces:oldId})]);
  expect(readFileSync(f.out).equals(f.state.checked)).toBe(true);
  for (const value of [f.state.chosen, f.out, fingerprint(readFileSync(f.out)), 'replaces', oldId,
    `macwarden revoke ${f.state.chosen}`]) expect(result.error!.message).toContain(value);
  expect(result.error!.message).toMatch(/file.*valid|valid.*file/i); expect(result.error!.message).not.toContain('macwarden revoke Alice');
}));
it('CP-028/leak-check standing sentinel check covers declared outputs and registry artifacts', () => {
  safe('', [directory('MACWARDEN_TEST_TMP')]);
}, 60_000);
