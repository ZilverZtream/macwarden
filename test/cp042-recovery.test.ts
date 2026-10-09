import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { hostname } from 'node:os';
import { expect, it } from 'vitest';
import { run as rotate } from '../src/commands/rotate.js';
import { run as revoke } from '../src/commands/revoke.js';
import { openRegistry } from '../src/registry/index.js';
import { fixture, oldId } from './helpers/cp038-online.js';
import { deadProductLock } from './helpers/cp042-lock-process.js';
import { render } from './helpers/render-adversarial.js';
import { revealSecret } from './helpers/secret-bytes.js';

function rejectReplacement(f: ReturnType<typeof fixture>) {
  const original = f.lnd.checkMacaroon.bind(f.lnd);
  const oldBytes = readFileSync(f.old.outPath!);
  f.lnd.checkMacaroon = async (mac, permissions) => {
    if (Buffer.from(revealSecret(mac)).equals(oldBytes)) return original(mac, permissions);
    f.lnd.calls.push('CheckMacaroonPermissions');
    return { valid: false, reason: 'signature-mismatch', message: 'independent injected rejection' };
  };
}

it('CP-042/B1-owned-stale-lock independently exited same-host process permits real lock recovery', async () => {
  const f = fixture();
  await deadProductLock(f.registry);
  const result = await revoke(['Alice', '--yes', '--break-lock', ...f.flags], f.deps);
  expect(result.error).toBeNull(); expect(f.lnd.deleted).toEqual([oldId]); expect(existsSync(f.registry + '.lock')).toBe(false);
});
it.each(['live', 'foreign', 'malformed'] as const)('CP-042/B2-ambiguous-lock-refusal %s lock remains unchanged without mutation', async kind => {
  const f = fixture(), path = f.registry + '.lock';
  const bytes = kind === 'malformed' ? '{}' : JSON.stringify({ pid: process.pid, hostname: kind === 'foreign' ? 'foreign-test-host' : hostname(), startedAt: new Date().toISOString() });
  writeFileSync(path, bytes);
  const result = await revoke(['Alice', '--yes', '--break-lock', ...f.flags], f.deps);
  expect(result.error?.code).toBe(3); expect(f.lnd.deleted).toEqual([]); expect(readFileSync(path, 'utf8')).toBe(bytes);
});
it.each(['grade', 'fingerprint', 'permissions'] as const)('CP-042/B3-rotation-proven-permissions readable old credential rejects inconsistent %s', async kind => {
  const f = fixture();
  if (kind === 'grade') f.old.grade = 'SPEND';
  if (kind === 'fingerprint') f.old.fingerprint = 'fp:0123456789abcdef';
  if (kind === 'permissions') { f.old.permissions = ['offchain:write']; f.old.grade = 'SPEND'; }
  f.save(); const before = readFileSync(f.registry);
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 3, step: 'S4' }); expect(f.lnd.baked).toEqual([]);
  expect(readFileSync(f.registry).equals(before)).toBe(true); expect(existsSync(f.out)).toBe(false);
});
it.each(['missing', 'null'] as const)('CP-042/B4-rotation-fallback-approval edited SPEND with %s path requires informed approval before resources', async path => {
  const f = fixture(); f.old.outPath = path === 'null' ? null : f.out + '.missing';
  f.old.permissions = ['offchain:write']; f.old.grade = 'SPEND'; f.save();
  const before = readFileSync(f.registry); let question = '';
  f.deps.prompt = Object.assign(async (text: string) => {
    question = text; expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry + '.lock')).toBe(false);
    expect(f.lnd.baked).toEqual([]); return 'wrong';
  }, { isTTY: true });
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(question).toContain('SPEND'); expect(question).toContain('offchain:write'); expect(question).toMatch(/unproven|cannot|unable|not.*prov/i);
  expect(result.error?.code).toBe(6); expect(f.lnd.baked).toEqual([]); expect(readFileSync(f.registry).equals(before)).toBe(true);
  expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry + '.lock')).toBe(false);
});
it('CP-042/B4-rotation-fallback-approval non-TTY stage with yes cannot authorize fallback', async () => {
  const f = fixture(); f.old.outPath = null; f.save();
  Object.assign(f.deps.stdin, { isTTY: false }); Object.assign(f.deps.prompt, { isTTY: false });
  const result = await rotate(['Alice', '--out', f.out, '--yes', ...f.flags], f.deps);
  expect(result.error?.code).toBe(2); expect(f.lnd.baked).toEqual([]); expect(existsSync(f.out)).toBe(false);
});
it('CP-042/B4-rotation-fallback-approval non-TTY fallback without yes declines before resources', async () => {
  const f = fixture(); f.old.outPath = null; f.save(); const before = readFileSync(f.registry);
  Object.assign(f.deps.stdin, { isTTY: false }); Object.assign(f.deps.prompt, { isTTY: false });
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(result.error?.code).toBe(6); expect(f.lnd.baked).toEqual([]); expect(readFileSync(f.registry).equals(before)).toBe(true);
  expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry + '.lock')).toBe(false);
});
it('CP-042/B4-rotation-fallback-approval explicit informed approval stages only displayed recorded authority', async () => {
  const f = fixture(); f.old.outPath = null; f.save(); let approved = false;
  f.deps.prompt = Object.assign(async (question: string) => {
    expect(question).toContain(f.old.grade); for (const permission of f.old.permissions) expect(question).toContain(permission);
    expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry + '.lock')).toBe(false);
    expect(f.lnd.baked).toEqual([]); approved = true; return 'Alice';
  }, { isTTY: true });
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(approved).toBe(true); expect(result.error).toBeNull();
  expect(f.rows().find(row => row.replaces === f.old.rootKeyId)).toMatchObject({ permissions: f.old.permissions, grade: f.old.grade });
  expect(f.lnd.deleted).toEqual([]); expect(f.lnd.ids).toContain(oldId);
});
it('CP-042/B4-rotation-fallback-approval dry-run shows fallback authority and expiry without approval or changes', async () => {
  const f = fixture(); f.old.outPath = null; f.old.caveats = [{ type: 'time-before', value: '2026-11-01T00:00:00Z', requested: '90d' }]; f.save();
  const before = readFileSync(f.registry); let prompted = false;
  f.deps.prompt = Object.assign(async () => { prompted = true; return ''; }, { isTTY: true });
  const result = await rotate(['Alice', '--out', f.out, '--dry-run', ...f.flags], f.deps);
  expect(result.error).toBeNull(); expect(prompted).toBe(false);
  const text = render(result, 'text'); expect(text).toContain(f.old.grade); for (const permission of f.old.permissions) expect(text).toContain(permission);
  expect(text).toContain('90d'); expect(text).toMatch(/unproven|cannot|unable|not.*prov/i);
  expect(readFileSync(f.registry).equals(before)).toBe(true); expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry + '.lock')).toBe(false);
  expect(f.lnd.baked).toEqual([]);
});
it.each(['yes', 'dry-run', 'decline'] as const)('CP-042/B5-unregistered-tombstone-repair absent ID %s has nothing to revoke and stores no tombstone', async mode => {
  const f = fixture(); f.save([]); f.lnd.ids = [0n]; const before = readFileSync(f.registry);
  f.deps.prompt = Object.assign(async () => 'wrong', { isTTY: true });
  const result = await revoke(['912042', '--unregistered', ...(mode === 'yes' ? ['--yes'] : mode === 'dry-run' ? ['--dry-run'] : []), ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 5, step: 'V7' }); expect(result.error!.message).toMatch(/nothing to revoke/i);
  expect(f.lnd.deleted).toEqual([]); expect(readFileSync(f.registry).equals(before)).toBe(true);
  expect(existsSync(f.registry + '.lock')).toBe(false);
});
it('CP-042/B5-unregistered-tombstone-repair V13 save failure after deleting an unregistered ID prints no rerun', async () => {
  const f = fixture(); f.save([]); f.lnd.ids = [0n, 912042n]; const before = readFileSync(f.registry);
  const rename = f.deps.fs.rename;
  f.deps.fs.rename = (async (...args: Parameters<typeof fs.rename>) => {
    if (String(args[1]) === f.registry) throw Object.assign(new Error('injected save failure'), { code: 'EIO' });
    return rename(...args);
  }) as typeof fs.rename;
  const result = await revoke(['912042', '--unregistered', '--yes', ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 7, step: 'V13' }); expect(f.lnd.deleted).toEqual([912042n]);
  expect(result.error!.message).toMatch(/deleted from LND/i); expect(result.error!.message).toMatch(/no further action/i);
  expect(result.error!.message).not.toMatch(/macwarden revoke/);
  expect(readFileSync(f.registry).equals(before)).toBe(true); expect(existsSync(f.registry + '.lock')).toBe(false);
  f.deps.fs.rename = rename;
  const rerun = await revoke(['912042', '--unregistered', '--yes', ...f.flags], f.deps);
  expect(rerun.error).toMatchObject({ code: 5, step: 'V7' }); expect(f.lnd.deleted).toEqual([912042n]);
});
it.each(['success', 'primary-failure'] as const)('CP-042/B7-post-mutation-and-cleanup-failure unlock failure is visible after %s and retains recovery', async kind => {
  const f = fixture(); if (kind === 'primary-failure') rejectReplacement(f);
  f.deps.fs.unlink = (async (...args: Parameters<typeof fs.unlink>) => {
    if (String(args[0]) === f.registry + '.lock') throw Object.assign(new Error('private cleanup detail'), { code: 'EIO' });
    return fs.unlink(...args);
  }) as typeof fs.unlink;
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(result.error?.code).toBe(7); if (kind === 'primary-failure') expect(result.error?.step).toBe('S12');
  const text = render(result, 'text'); expect(text).toMatch(/cleanup|unlock|lock.*fail/i); expect(text).not.toContain('private cleanup detail');
  expect(f.lnd.ids).toContain(oldId); expect(f.lnd.deleted).toEqual([]); expect(existsSync(f.registry + '.lock')).toBe(true);
});
it('CP-042/B8-registry-error-identity registry usage error has a distinct public name and exit', async () => {
  const f = fixture(), view = await openRegistry(f.registry); await view.lock();
  try {
    let caught: (Error & { code?: number; exitCode?: number }) | undefined;
    try { await view.add({ ...f.old, label: null }); } catch (error) { caught = error as typeof caught; }
    expect(caught?.name).toBe('RegistryUsageError'); expect(caught?.code ?? caught?.exitCode).toBe(2);
  }
  finally { await view.unlock(); }
});
it('CP-042/B7-post-mutation-and-cleanup-failure unwritten reservation discard failure remains visible with primary step', async () => {
  const f = fixture(); rejectReplacement(f);
  f.deps.fs.unlink = (async (...args: Parameters<typeof fs.unlink>) => {
    if (String(args[0]) === f.out) throw Object.assign(new Error('private discard detail'), { code: 'EIO' });
    return fs.unlink(...args);
  }) as typeof fs.unlink;
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 7, step: 'S12' }); expect(render(result, 'text')).toMatch(/cleanup|discard|reservation.*fail/i);
  expect(result.error?.message).toContain(`macwarden revoke ${f.lnd.baked[0]}`);
  expect(existsSync(f.out)).toBe(true); expect(readFileSync(f.out).length).toBe(0); expect(f.lnd.ids).toContain(oldId);
});
