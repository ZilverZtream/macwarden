import { randomUUID } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { hostname } from 'node:os';
import { expect, it, vi } from 'vitest';
import { openRegistry } from '../src/registry/index.js';
import { ownProcessDomain } from '../src/registry/process-domain.js';
import { fixture } from './helpers/cp038-online.js';

// Every lock record here carries this invocation's real process domain, so the
// recovery decision reaches the pid, hostname and identity checks instead of being
// refused early as a legacy record without a domain.
const startedAt = '2026-10-04T00:00:00.000Z';
const deadPid = 900_001;

async function domain() {
  const value = await ownProcessDomain();
  expect(value, 'process domain must be provable on the test platform').not.toBeNull();
  return value!;
}
async function staleLock(path: string, overrides: Record<string, unknown> = {}) {
  const record = { pid: deadPid, hostname: 'host-a', startedAt, processDomain: await domain(), ...overrides };
  const text = JSON.stringify(record);
  writeFileSync(path + '.lock', text);
  return { record, text };
}
const locked = (record: { pid: unknown; hostname: unknown }) =>
  `registry locked by pid ${record.pid} on ${record.hostname} since ${startedAt}`;

it('REGISTRY/lock-recovery a dead owner on the same host and domain is recovered by --break-lock', async () => {
  const f = fixture();
  await staleLock(f.registry);
  const view = await openRegistry(f.registry, { hostname: () => 'host-a', pidAlive: () => false });
  await view.lock({ breakLock: true });
  expect(JSON.parse(readFileSync(f.registry + '.lock', 'utf8'))).toMatchObject({ pid: process.pid, hostname: 'host-a' });
  await view.unlock();
  expect(existsSync(f.registry + '.lock')).toBe(false);
});

it('REGISTRY/lock-recovery a live owner with matching host and domain is never broken', async () => {
  const f = fixture();
  const { record, text } = await staleLock(f.registry);
  const view = await openRegistry(f.registry, { hostname: () => 'host-a', pidAlive: pid => pid === deadPid });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3, message: locked(record) });
  expect(readFileSync(f.registry + '.lock', 'utf8')).toBe(text);
});

it('REGISTRY/lock-recovery a dead owner recorded on another host is never broken', async () => {
  const f = fixture();
  const { record, text } = await staleLock(f.registry, { hostname: 'host-b' });
  const view = await openRegistry(f.registry, { hostname: () => 'host-a', pidAlive: () => false });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3, message: locked(record) });
  expect(readFileSync(f.registry + '.lock', 'utf8')).toBe(text);
});

it('REGISTRY/lock-recovery a dead owner from a different process domain is never broken', async () => {
  const f = fixture();
  const own = await domain();
  const other = { ...own, bootId: own.bootId === '11111111-2222-3333-4444-555555555555'
    ? '66666666-7777-8888-9999-aaaaaaaaaaaa' : '11111111-2222-3333-4444-555555555555' };
  const { text } = await staleLock(f.registry, { processDomain: other });
  const view = await openRegistry(f.registry, { hostname: () => 'host-a', pidAlive: () => false });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3,
    message: expect.stringContaining('stale lock ownership cannot be proven safely') });
  expect(readFileSync(f.registry + '.lock', 'utf8')).toBe(text);
});

// The liveness probe itself: signalling a process this account may not signal fails
// with EPERM, which means the process exists. That must count as alive. The EPERM answer is
// injected into process.kill for that one pid, so the case runs on every platform and account
// (an elevated Windows runner or root may signal the real protected pid; audit 1.4.0).
const protectedPid = 900_003;
it('REGISTRY/lock-recovery an owner pid that exists but cannot be signalled (EPERM) is treated as alive', async () => {
  const f = fixture();
  const { record, text } = await staleLock(f.registry, { pid: protectedPid, hostname: hostname() });
  const real = process.kill.bind(process);
  const probes: number[] = [];
  const kill = vi.spyOn(process, 'kill').mockImplementation(((pid: number, signal?: string | number) => {
    if (pid !== protectedPid) return real(pid, signal);
    probes.push(pid);
    throw Object.assign(new Error('kill EPERM'), { code: 'EPERM', errno: -1, syscall: 'kill' });
  }) as typeof process.kill);
  try {
    const view = await openRegistry(f.registry);
    await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3, message: locked(record) });
  } finally { kill.mockRestore(); }
  // The real probe was asked (not an injected pidAlive), and its EPERM kept the lock.
  expect(probes).toContain(protectedPid);
  expect(readFileSync(f.registry + '.lock', 'utf8')).toBe(text);
});

it('REGISTRY/lock-recovery unlock never removes a lock file replaced after acquisition', async () => {
  const f = fixture();
  const view = await openRegistry(f.registry);
  await view.lock();
  const lockPath = f.registry + '.lock';
  // The replacement is what a competing acquisition writes: its own pid, start time and
  // fresh per-acquisition token, on the same host and process domain. Linux usually hands
  // the freed inode number (and, within one timestamp tick, the same birth time) to this new
  // file, so only the owner record tells it apart. A byte-identical copy of our own record,
  // token included, is by design indistinguishable from our own lock and is not a meaningful
  // scenario: only a party that can already read and rewrite the lock directory can produce
  // it, and that party can remove or forge any lock anyway.
  const ours = JSON.parse(readFileSync(lockPath, 'utf8')) as Record<string, unknown>;
  const replacement = JSON.stringify({ ...ours, pid: 900_002, startedAt: new Date().toISOString(), token: randomUUID() });
  unlinkSync(lockPath);
  writeFileSync(lockPath, replacement); // a different owner's record in a different file
  await expect(view.unlock()).rejects.toMatchObject({ code: 3, message: 'cannot release registry lock' });
  expect(readFileSync(lockPath, 'utf8')).toBe(replacement);
  expect(existsSync(f.registry)).toBe(true);
  unlinkSync(lockPath);
});

it('REGISTRY/lock-recovery a lock whose owner record changes after the quarantine rename is preserved', async () => {
  const f = fixture();
  const lockPath = f.registry + '.lock';
  await staleLock(f.registry);
  const competitor = JSON.stringify({ pid: 900_002, hostname: 'host-a', startedAt, processDomain: await domain() });
  const io = { ...fs, rename: (async (from: string, to: string) => {
    await fs.rename(from, to);
    if (String(from) === lockPath) await fs.writeFile(to, competitor); // same file, new owner
  }) as typeof fs.rename };
  const view = await openRegistry(f.registry, { fs: io, hostname: () => 'host-a', pidAlive: () => false });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3,
    message: expect.stringContaining('changed during recovery') });
  expect(readFileSync(lockPath, 'utf8')).toBe(competitor);
});

it('REGISTRY/lock-recovery an owner that becomes alive during the quarantine rename is preserved', async () => {
  const f = fixture();
  const lockPath = f.registry + '.lock';
  const { text } = await staleLock(f.registry);
  let renamed = false;
  const io = { ...fs, rename: (async (from: string, to: string) => {
    await fs.rename(from, to);
    if (String(from) === lockPath) renamed = true;
  }) as typeof fs.rename };
  const view = await openRegistry(f.registry, { fs: io, hostname: () => 'host-a', pidAlive: () => renamed });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3,
    message: expect.stringContaining('changed during recovery') });
  expect(renamed).toBe(true);
  expect(readFileSync(lockPath, 'utf8')).toBe(text);
});

it('REGISTRY/lock-recovery a lock preserved after its owner changed during recovery keeps one name, so a later --break-lock can recover it', async () => {
  const f = fixture();
  const lockPath = f.registry + '.lock';
  await staleLock(f.registry);
  const competitor = JSON.stringify({ pid: 900_002, hostname: 'host-a', startedAt, processDomain: await domain() });
  const io = { ...fs, rename: (async (from: string, to: string) => {
    await fs.rename(from, to);
    if (String(from) === lockPath) await fs.writeFile(to, competitor); // same file, new owner
  }) as typeof fs.rename };
  const view = await openRegistry(f.registry, { fs: io, hostname: () => 'host-a', pidAlive: () => false });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3,
    message: expect.stringContaining('changed during recovery') });
  // Preserved means: the new owner's record is at the lock path, under that one name. A second
  // name (the quarantine's) would make every later --break-lock refuse the lock as ambiguous.
  expect(readFileSync(lockPath, 'utf8')).toBe(competitor);
  expect(statSync(lockPath).nlink).toBe(1);
  expect(readdirSync(f.dir).filter(name => name.endsWith('.stale'))).toEqual([]);
  // Once the new owner is gone too, the preserved lock is recovered like any stale lock.
  const next = await openRegistry(f.registry, { hostname: () => 'host-a', pidAlive: () => false });
  await next.lock({ breakLock: true });
  await next.unlock();
  expect(existsSync(lockPath)).toBe(false);
});
