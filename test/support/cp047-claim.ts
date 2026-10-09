import { fork } from 'node:child_process';
import { closeSync, existsSync, openSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect } from 'vitest';
import { openRegistry } from '../../src/registry/index.js';
import { childEnvironment } from '../helpers/environment.js';
import { deadProductLock } from '../helpers/cp042-lock-process.js';
import { repo, scratch } from './cp041-controls.js';

function identity(path: string) {
  const { dev, ino } = statSync(path, { bigint: true });
  return { dev, ino };
}
async function refuseClaim(path: string) {
  const claim = path + '.lock.claim';
  const before = readFileSync(claim), originalIdentity = identity(claim);
  const registryBefore = readFileSync(path), registryIdentity = identity(path);
  for (const breakLock of [false, true]) {
    const view = await openRegistry(path);
    let failure: { code?: number; message?: string } | undefined;
    let acquired = false;
    try { await view.lock({ breakLock }); acquired = true; }
    catch (e) { failure = e as typeof failure; }
    finally { if (acquired) await view.unlock(); }
    expect(acquired, 'no acquisition succeeds').toBe(false);
    expect(failure?.code).toBe(3);
    expect(failure?.message).toBe(
      `registry acquisition in progress or ambiguous: ${claim}. Stop all writers, establish that the recorded process is gone in its namespace, then delete this .claim file (and any stale lock) offline before retrying.`);
    expect(readFileSync(claim).equals(before)).toBe(true);
    expect(identity(claim)).toEqual(originalIdentity);
    expect(readFileSync(path).equals(registryBefore)).toBe(true);
    expect(identity(path)).toEqual(registryIdentity);
    expect(existsSync(path + '.lock'), 'no product lock acquired').toBe(false);
  }
}
export async function crashClaimControl() {
  await childClaimControl('killed');
}
export async function ownershipClaimControls() {
  await childClaimControl('live');
  await childClaimControl('replaced');
  await ambiguousClaimControl();
}
async function childClaimControl(kind: 'killed' | 'live' | 'replaced') { await scratch(async dir => {
  const path = join(dir, 'registry.json'), claim = path + '.lock.claim';
  writeFileSync(path, JSON.stringify({ schema: 1, entries: [] }));
  const child = fork(join(repo, 'test/helpers/cp047-claim-child.mjs'), [path], {
    execArgv: [], env: childEnvironment(), windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const closed = new Promise<void>(done => child.once('close', () => done()));
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  try {
    await new Promise<void>((done, fail) => {
      child.once('error', () => fail(new Error('Claim child setup failed')));
      child.once('close', () => fail(new Error('Claim child closed before capture')));
      child.once('message', value => (value as { kind: string }).kind === 'claim-created' ? done() : fail(new Error('Claim window not reached')));
    });
    const before = readFileSync(claim);
    const originalIdentity = identity(claim);
    if (kind === 'killed') {
      child.kill('SIGKILL'); await closed;
      let dead = false; try { process.kill(child.pid!, 0); } catch (e) { dead = (e as NodeJS.ErrnoException).code === 'ESRCH'; }
      expect(dead, 'independent child is gone').toBe(true);
    } else {
      expect(() => process.kill(child.pid!, 0), 'independent claim creator remains alive').not.toThrow();
    }
    const displaced = claim + '.displaced';
    if (kind === 'replaced') {
      renameSync(claim, displaced);
      writeFileSync(claim, '{"owner":"ambiguous replacement"}', { flag: 'wx', mode: 0o600 });
      expect(identity(claim)).not.toEqual(originalIdentity);
    }
    await refuseClaim(path);
    const originalPath = kind === 'replaced' ? displaced : claim;
    expect(readFileSync(originalPath).equals(before)).toBe(true);
    expect(identity(originalPath)).toEqual(originalIdentity);
    if (kind !== 'killed') expect(() => process.kill(child.pid!, 0)).not.toThrow();
  } finally { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await closed; } }
}); }

export async function ambiguousClaimControl() {
  for (const record of ['{"pid":', JSON.stringify({
    pid: process.pid, hostname: 'unverified-owner', startedAt: '2026-10-04T00:00:00Z',
  })]) {
    await scratch(async dir => {
      const path = join(dir, 'registry.json');
      writeFileSync(path, JSON.stringify({ schema: 1, entries: [] }));
      writeFileSync(path + '.lock.claim', record, { flag: 'wx', mode: 0o600 });
      await refuseClaim(path);
    });
  }
}

export async function staleProductLockControl() { await scratch(async dir => {
  const path = join(dir, 'registry.json');
  writeFileSync(path, JSON.stringify({ schema: 1, entries: [] }));
  const registryBefore = readFileSync(path), registryIdentity = identity(path);
  const stale = await deadProductLock(path);
  const staleFd = openSync(path + '.lock', 'r');
  try {
    const staleIdentity = identity(path + '.lock');
    const view = await openRegistry(path);
    await view.lock({ breakLock: true });
    try {
      expect(JSON.parse(readFileSync(path + '.lock', 'utf8')).pid).toBe(process.pid);
      expect(readFileSync(path + '.lock').equals(stale.bytes)).toBe(false);
      expect(identity(path + '.lock')).not.toEqual(staleIdentity);
      expect(existsSync(path + '.lock.claim')).toBe(false);
      expect(readFileSync(path).equals(registryBefore)).toBe(true);
      expect(identity(path)).toEqual(registryIdentity);
    } finally { await view.unlock(); }
    expect(existsSync(path + '.lock')).toBe(false);
  } finally { closeSync(staleFd); }
}); }
