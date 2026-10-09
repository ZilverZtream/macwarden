import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import { expect, it, vi } from 'vitest';
import { scratch, invoke, save, unchanged, failure, afterFailure } from './helpers/cp028-rotate-support.js';
import { entry, ownId, register, wireFixture } from './helpers/cp026-revoke-support.mjs';
import { isolateLeakSuite } from './helpers/leak-suite.js';
import { render } from './helpers/render-adversarial.js';
import { revealSecret } from './helpers/secret-bytes.js';

isolateLeakSuite('cp045');
it('CP-045/B1 OWN requires CheckMacaroonPermissions authority before stage network or output', async () => scratch(async f => {
  // Exact URI grants every ordinary stage method, excluding the proof method.
  const permissions = ['GetInfo','ListPermissions','ListMacaroonIDs','BakeMacaroon'].map(name => `uri:/lnrpc.Lightning/${name}`);
  f.args[f.args.indexOf('--macaroon') + 1] = register(wireFixture('default-admin', ownId, permissions));
  const before = readFileSync(f.registry);
  const result = await invoke(f, ['--dry-run']);
  expect(result.error?.code, 'verification authority is an offline prerequisite').toBe(4);
  expect(result.error?.step).toBe('S6');
  unchanged(f, before); expect(existsSync(f.out)).toBe(false);
  expect(f.calls.length).toBe(0);
}));
it('CP-045/B2 unrelated SPEND root cannot prove recorded READ authority despite matching fingerprint', async () => scratch(async f => {
  const unrelated = entry('preset-pay-only', '4294967500');
  Object.assign(f.old, { outPath: unrelated.outPath, fingerprint: unrelated.fingerprint,
    permissions: unrelated.permissions, grade: unrelated.grade });
  save(f);
  const before = readFileSync(f.registry);
  const result = await invoke(f, ['--dry-run']);
  expect(result.error?.code, 'root identity must match independently registered root').toBe(3);
  expect(result.error?.step).toBe('S4');
  unchanged(f, before); expect(existsSync(f.out)).toBe(false);
  expect(f.calls.length).toBe(0);
}, 'preset-read-only'));
it('CP-045/B2 rejected old signature cannot provide silent staging proof', async () => scratch(async f => {
  // Reference correction: normalized negative proof refuses at S8, without S4 fallback.
  f.deps.lnd.checkMacaroon = vi.fn(async (mac, permissions, ...extra) => {
    f.calls.push('CheckMacaroonPermissions');
    expect(Buffer.from(revealSecret(mac)).equals(readFileSync(f.oldBytesPath))).toBe(true);
    expect(permissions).toEqual(f.old.permissions);
    expect(permissions.length).toBeGreaterThan(0);
    expect(extra).toEqual([]);
    return { valid: false as const, reason: 'other' as const, message: 'signature mismatch' };
  });
  const before = readFileSync(f.registry);
  const result = await invoke(f, ['--dry-run']);
  failure(f, result, 5, 'S8');
  expect(/unproven|cannot|unable|not.*prov/i.test(render(result, 'text')),
    'dry-run visibly identifies the lack of proof').toBe(true);
  expect(f.deps.lnd.checkMacaroon).toHaveBeenCalledTimes(1);
  expect(f.calls.slice(0, 4)).toEqual([
    'GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'CheckMacaroonPermissions',
  ]);
  afterFailure(f, 'CheckMacaroonPermissions');
  expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  unchanged(f, before); expect(existsSync(f.out)).toBe(false);
}));
it('CP-045/B3 missing old-file dry-run and non-TTY decline preserve unproven authority and state', async () => scratch(async f => {
  f.old.outPath = `${f.dir}/missing.macaroon`;
  save(f);
  const before = readFileSync(f.registry), idsBefore = [...f.state.ids];
  const prompt = Object.assign(vi.fn(async () => 'Alice'), { isTTY: false });
  Object.assign(f.deps, {
    prompt,
    stdin: Object.assign(Readable.from([]), { isTTY: false }),
  });
  const argsLength = f.args.length;
  const dry = await invoke(f, ['--dry-run']);
  expect(dry.error).toBeNull();
  expect(dry.result).toMatchObject({
    dryRun: true, stage: 'stage', grade: 'RECEIVE', permissions: f.old.permissions,
  });
  const text = f.outputs.join('') + render(dry, 'text');
  expect(/unproven|cannot.*prov|unable.*prov|not.*prov/i.test(text)).toBe(true);
  expect(text).toContain('RECEIVE');
  for (const permission of f.old.permissions) expect(text).toContain(permission);
  expect(prompt).not.toHaveBeenCalled();
  expect(f.deps.lnd.checkMacaroon).not.toHaveBeenCalled();
  expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  expect(f.events).not.toContain('reserve');
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
  unchanged(f, before); expect(existsSync(f.out)).toBe(false);
  expect(f.state.ids).toEqual(idsBefore);

  f.args.splice(argsLength);
  f.calls.length = 0;
  const decline = await invoke(f);
  failure(f, decline, 6, 'S4');
  expect(f.calls).toEqual([]);
  expect(prompt).not.toHaveBeenCalled();
  expect(f.deps.lnd.checkMacaroon).not.toHaveBeenCalled();
  expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  expect(f.events).not.toContain('reserve');
  unchanged(f, before); expect(existsSync(f.out)).toBe(false);
  expect(f.state.ids).toEqual(idsBefore);
}));
it('CP-045/B3 missing old-file non-TTY refusal precedes unreadable OWN at S6', async () => scratch(async f => {
  f.old.outPath = `${f.dir}/missing.macaroon`;
  save(f);
  const missingOwn = `${f.dir}/missing-own.macaroon`;
  expect(existsSync(missingOwn)).toBe(false);
  f.args[f.args.indexOf('--macaroon') + 1] = missingOwn;
  const before = readFileSync(f.registry), idsBefore = [...f.state.ids];
  const prompt = Object.assign(vi.fn(async () => 'Alice'), { isTTY: false });
  Object.assign(f.deps, {
    prompt,
    stdin: Object.assign(Readable.from([]), { isTTY: false }),
  });

  const result = await invoke(f);
  failure(f, result, 6, 'S4');
  expect(prompt).not.toHaveBeenCalled();
  expect(f.calls).toEqual([]);
  expect(f.deps.lnd.checkMacaroon).not.toHaveBeenCalled();
  expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  expect(f.events).not.toContain('reserve');
  expect(vi.mocked(f.deps.fs.open).mock.calls.some(([path]) =>
    String(path).startsWith(`${f.registry}.lock`))).toBe(false);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
  expect(f.state.handle).toBeUndefined();
  unchanged(f, before); expect(existsSync(f.out)).toBe(false);
  expect(f.state.ids).toEqual(idsBefore);
}));
it('CP-045/B3 missing old-file typed decline precedes existing output at S5', async () => scratch(async f => {
  f.old.outPath = `${f.dir}/missing.macaroon`;
  save(f);
  writeFileSync(f.out, 'original output\n', { mode: 0o600 });
  const outputBefore = readFileSync(f.out);
  const before = readFileSync(f.registry), idsBefore = [...f.state.ids];
  const prompt = Object.assign(vi.fn(async () => 'decline'), { isTTY: true });
  Object.assign(f.deps, {
    prompt,
    stdin: Object.assign(Readable.from(['decline\n']), { isTTY: true }),
  });

  const result = await invoke(f);
  failure(f, result, 6, 'S4', true);
  expect(prompt).toHaveBeenCalledTimes(1);
  expect(f.calls).toEqual([]);
  expect(f.deps.lnd.checkMacaroon).not.toHaveBeenCalled();
  expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
  expect(f.events).not.toContain('reserve');
  expect(vi.mocked(f.deps.fs.open).mock.calls.some(([path]) =>
    String(path).startsWith(`${f.registry}.lock`))).toBe(false);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
  expect(f.state.handle).toBeUndefined();
  unchanged(f, before);
  expect(readFileSync(f.out).equals(outputBefore)).toBe(true);
  expect(f.state.ids).toEqual(idsBefore);
}));
