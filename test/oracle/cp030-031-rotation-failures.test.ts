import { fixtureTopology } from '../fixture/topology.mjs';
import { revealSecret } from '../helpers/secret-bytes.js';
import { childEnvironment } from '../helpers/environment.js';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { fork } from 'node:child_process';
import { resolve } from 'node:path';
import { hostname } from 'node:os';
import { expect, it, vi } from 'vitest';
import { Secret } from '../../src/secret.js';
import { LndError } from '../../src/errors.js';
import { render } from '../helpers/render-adversarial.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { register } from '../helpers/cp026-revoke-support.mjs';
import { safe } from '../helpers/cp027-revoke-support.js';
import { scenario, ids, probe, rows, stage, cli, copy, docker, oldId, type Context } from '../helpers/cp030-live-support.js';

type Fault = 'bake absent' | 'lost bake response' | 'rejected replacement' | 'verify timeout' |
  'delete fails' | 'false delete success' | 'stage permissions unavailable' | 'stage list unavailable' |
  'finish permissions unavailable' | 'finish list unavailable' | 'new baseline unavailable' |
  'old baseline unavailable' | 'old proof unavailable' | 'new proof unavailable' | 'stage save' | 'finish save';
async function injected(f: Context, fault: Fault, finish = false) {
  const command = await import('../../src/commands/rotate.js');
  const module = await import('../../src/lnd/index.js');
  const adapter = module.createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: readFileSync(f.cert),
    macaroon: new Secret(readFileSync(f.own)) });
  const calls: string[] = [], issued: string[] = [], output: string[] = [];
  let paused = false, deleted = false, checks = 0;
  const pause = () => {
    if (docker(['pause', 'lnd']).status !== 0) throw new FixtureInvalidError('Fixture pause unavailable'); paused = true;
  };
  const resume = () => {
    if (!paused) return;
    if (docker(['unpause', 'lnd']).status !== 0) throw new FixtureInvalidError('Fixture unpause unavailable'); paused = false;
  };
  const lnd = new Proxy(adapter, { get(target, key) {
    const value = Reflect.get(target, key, target);
    if (key === 'listMacaroonIds' && typeof value !== 'function') return async () => ({ root_key_ids: (await lnd.listMacaroonIds()).map(String) });
    if (typeof value !== 'function') return value;
    return async (...args: unknown[]) => {
      calls.push(String(key));
      if (key === 'checkMacaroon') checks++;
      const failRead = (key === 'listPermissions' && fault.includes('permissions unavailable')) ||
        (key === 'listMacaroonIds' && fault.includes('list unavailable')) ||
        (key === 'checkMacaroon' && ((fault === 'new baseline unavailable' && checks === 1) ||
          (fault === 'old baseline unavailable' && checks === 2) ||
          (fault === 'old proof unavailable' && deleted && checks === 3) ||
          (fault === 'new proof unavailable' && deleted && checks === 4)));
      const failMutation = (key === 'bakeMacaroon' && fault === 'bake absent') ||
        (key === 'deleteMacaroonId' && fault === 'delete fails');
      if (failRead || failMutation || (key === 'checkMacaroon' && fault === 'verify timeout' && issued.length > 0)) {
        pause();
        try { return await value.apply(target, args); } finally { resume(); }
      }
      if (key === 'deleteMacaroonId' && fault === 'false delete success') return { deleted: true };
      const result = await value.apply(target, args);
      if (key === 'deleteMacaroonId') deleted = true;
      if (key === 'bakeMacaroon') {
        const bytes = Buffer.from(revealSecret(result)); issued.push(register(bytes));
        if (fault === 'lost bake response') {
          // Drop a completed real response; independent lncli observes the created ID and authority.
          throw new LndError(4, 'transport', 'response lost after fixture issuance');
        }
        if (fault === 'rejected replacement') {
          // A second operator revokes N before verification; the actual LND proof rejects it.
          const removed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', String(args[1])]);
          if (removed.status !== 0 || JSON.parse(removed.stdout).deleted !== true)
            throw new FixtureInvalidError('Replacement fault setup failed');
        }
      }
      return result;
    };
  } });
  let registryWrites = 0;
  const fileSystem = { ...fs, rename: async (...args: Parameters<typeof fs.rename>) => {
    if (args[1] === f.registry) {
      registryWrites++;
      // Stage first persists the durable pending allocation; fail its final save.
      if ((fault === 'stage save' && registryWrites === 2) || fault === 'finish save') await fs.unlink(args[0]);
    }
    return fs.rename(...args);
  } };
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((text: unknown) => { output.push(String(text)); return true; }) as typeof process.stdout.write);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((text: unknown) => { output.push(String(text)); return true; }) as typeof process.stderr.write);
  let result: Awaited<ReturnType<typeof command.run>>;
  try {
    result = await command.run(['Alice', ...(finish ? ['--finish', '--yes'] : ['--out', f.out]),
      '--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', f.cert, '--macaroon', f.own],
    { lnd, fs: fileSystem, env: {}, clock: () => new Date() });
  } finally { stdout.mockRestore(); stderr.mockRestore(); resume(); }
  if (existsSync(f.out) && readFileSync(f.out).length) register(readFileSync(f.out));
  safe(output.join('') + render(result, 'text') + render(result, 'json'), [f.dir]);
  return { result, calls, issued };
}
function remoteProbe(f: Context, local: string, accepted: boolean, id: string) {
  const remote = `/tmp/macwarden-cp030-${process.pid}-${f.remotes.length}.macaroon`;
  f.remotes.push(remote); copy(local, remote); probe(remote, accepted ? 'accepted' : 'rejected', id);
}
it.each(['bake absent', 'lost bake response'] as const)(
  'CP-030/fi1-4-old-acceptance FI1 %s independently observes unchanged O and actual N state', async fault => scenario(async f => {
    const beforeIds = ids(), before = readFileSync(f.registry), { result, issued } = await injected(f, fault);
    expect(result.error).toMatchObject({ code: fault === 'bake absent' ? 4 : 7, step: 'S10' });
    const added = ids().filter(id => !beforeIds.includes(id)); expect(added).toHaveLength(fault === 'bake absent' ? 0 : 1);
    expect(rows(f)).toContainEqual(f.old); probe(f.oldRemote, 'accepted', oldId);
    if (added.length) {
      expect(rows(f)).toEqual([f.old, expect.objectContaining({ rootKeyId: added[0], label: 'Alice',
        permissions: f.old.permissions, grade: f.old.grade, replaces: oldId, status: 'active',
        verified: false, fingerprint: null, outPath: null })]);
      expect(result.error!.message).toContain(`macwarden revoke ${added[0]}`);
      expect(result.error!.message).not.toContain('--unregistered');
      remoteProbe(f, issued[0], true, added[0]);
    } else expect(readFileSync(f.registry).equals(before)).toBe(true);
  }), 120_000);
it.each(['rejected replacement', 'verify timeout'] as const)(
  'CP-030/fi1-4-registry-state FI2 %s independently probes issued N and preserves O', async fault => scenario(async f => {
    const beforeIds = ids(), { result, issued } = await injected(f, fault);
    expect(result.error).toMatchObject({ code: 7, step: 'S12' });
    const added = ids().filter(id => !beforeIds.includes(id)); expect(added).toHaveLength(fault === 'verify timeout' ? 1 : 0);
    const replacement = rows(f).find(row => row.replaces === oldId)!;
    expect(result.error!.message).toContain(`macwarden revoke ${replacement.rootKeyId}`);
    expect(rows(f)).toContainEqual(f.old);
    expect(replacement).toMatchObject({ status: 'active', verified: false, replaces: oldId });
    probe(f.oldRemote, 'accepted', oldId); remoteProbe(f, issued.at(-1)!, fault === 'verify timeout', String(replacement.rootKeyId));
  }), 120_000);
it('CP-030/fi1-4-registry-state FI4 real failed delete retains both credentials and exact retry', async () => scenario(async f => {
  const { next, remote } = stage(f), before = readFileSync(f.registry), { result } = await injected(f, 'delete fails', true);
  expect(result.error).toMatchObject({ code: 5, step: 'F10' });
  expect(result.error!.message).toContain('macwarden rotate Alice --finish');
  expect(readFileSync(f.registry).equals(before)).toBe(true); probe(f.oldRemote, 'accepted', oldId); probe(remote, 'accepted', String(next.rootKeyId));
}), 120_000);
it('CP-031/fi5-8-old-acceptance FI5 false success retains independently accepted O and unchanged registry', async () => scenario(async f => {
  const { next, remote } = stage(f), before = readFileSync(f.registry), { result } = await injected(f, 'false delete success', true);
  expect(result.error).toMatchObject({ code: 7, step: 'F11' }); expect(result.error!.message).toContain('macwarden inventory');
  expect(readFileSync(f.registry).equals(before)).toBe(true); probe(f.oldRemote, 'accepted', oldId); probe(remote, 'accepted', String(next.rootKeyId));
}), 120_000);
it.each(['stage permissions unavailable', 'stage list unavailable', 'finish permissions unavailable',
  'finish list unavailable', 'new baseline unavailable', 'old baseline unavailable', 'old proof unavailable', 'new proof unavailable'] as const)(
  'CP-031/fi5-8-old-acceptance FI6 %s observes authority after a real transport outage', async fault => scenario(async f => {
    const finish = !fault.startsWith('stage'), staged = finish ? stage(f) : null;
    const before = readFileSync(f.registry), { result, calls } = await injected(f, fault, finish);
    if (fault === 'old baseline unavailable') expect(calls.filter(call => call === 'deleteMacaroonId')).toEqual([]);
    expect(result.error).not.toBeNull();
    const deleted = fault === 'old proof unavailable' || fault === 'new proof unavailable';
    expect(result.error!.code).toBe(deleted ? 7 : 4);
    expect(readFileSync(f.registry).equals(before)).toBe(true);
    probe(f.oldRemote, deleted ? 'rejected' : 'accepted', oldId);
    if (staged) probe(staged.remote, 'accepted', String(staged.next.rootKeyId));
    expect(calls.filter(call => call === 'deleteMacaroonId').length).toBeLessThanOrEqual(1);
    if (deleted) expect(result.error!.message).toContain('macwarden inventory');
  }), 120_000);
it.each(['stage save', 'finish save'] as const)(
  'CP-031/fi5-8-state-recovery FI7 %s real rename failure preserves registry and exact recovery', async fault => scenario(async f => {
    const staged = fault === 'finish save' ? stage(f) : null, before = readFileSync(f.registry), beforeIds = ids();
    const { result, issued } = await injected(f, fault, !!staged);
    expect(result.error).toMatchObject({ code: 7, step: staged ? 'F12' : 'S13' });
    probe(f.oldRemote, staged ? 'rejected' : 'accepted', oldId);
    if (staged) {
      expect(readFileSync(f.registry).equals(before)).toBe(true);
      probe(staged.remote, 'accepted', String(staged.next.rootKeyId));
      expect(result.error!.message).toContain('macwarden rotate Alice --finish');
      const repaired = cli(f, 'rotate', ['Alice'], ['--finish', '--yes', '--json']);
      expect(repaired.status).toBe(0); expect(JSON.parse(repaired.stdout).result.repaired).toBe(true);
    } else {
      const added = ids().filter(id => !beforeIds.includes(id)); expect(added).toHaveLength(1);
      expect(rows(f)).toEqual([f.old, expect.objectContaining({ rootKeyId: added[0], label: 'Alice',
        permissions: f.old.permissions, grade: f.old.grade, replaces: oldId, status: 'active',
        verified: false, fingerprint: null, outPath: null })]);
      expect(result.error!.message).toContain(`macwarden revoke ${added[0]}`);
      expect(result.error!.message).not.toContain('--unregistered');
      expect(existsSync(f.out)).toBe(true); remoteProbe(f, issued[0], true, added[0]);
    }
  }), 120_000);

function unpause() {
  if (docker(['unpause', 'lnd']).status !== 0) throw new FixtureInvalidError('Fixture unpause unavailable');
}
it.each(['before delete', 'after delete'] as const)(
  'CP-031/fi5-8-state-recovery FI8 process killed %s against paused fixture inventories state and repairs', async point => scenario(async f => {
    const { next, remote } = stage(f), before = readFileSync(f.registry);
    const oldBytes = readFileSync(f.oldPath), newBytes = readFileSync(f.out);
    const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
    const child = fork(resolve('test/helpers/cp031-kill-child.mjs'), [f.registry, f.cert, f.own, point],
      { env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
    let paused = false, childClosed = false, output = '';
    child.stdout!.on('data', value => { output += value; }); child.stderr!.on('data', value => { output += value; });
    let timer: ReturnType<typeof setTimeout>;
    try {
      await new Promise<void>((done, reject) => {
        timer = setTimeout(() => reject(new Error('Kill-point coordination timed out')), 25_000);
        child.on('error', reject);
        child.on('message', (message: { kind: string }) => {
          try {
            if (message.kind === 'holding') {
              if (docker(['pause', 'lnd']).status !== 0) throw new FixtureInvalidError('Fixture pause unavailable');
              paused = true; child.send('continue');
            } else if (message.kind === 'blocked-call') child.kill('SIGKILL');
            else reject(new Error('Finish returned before the requested interruption'));
          } catch (error) { reject(error); }
        });
        child.on('close', () => {
          childClosed = true;
          if (paused) done(); else reject(new Error('Finish child ended before pause'));
        });
      });
    } finally {
      clearTimeout(timer!); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      if (paused) unpause();
    }
    safe(output, [f.dir]); expect(readFileSync(f.registry).equals(before)).toBe(true);
    const lock = `${f.registry}.lock`, staleLock = readFileSync(lock);
    const lockStat = lstatSync(lock);
    expect(lockStat.isFile()).toBe(true); expect(lockStat.isSymbolicLink()).toBe(false);
    expect(JSON.parse(staleLock.toString('utf8'))).toMatchObject({ pid: child.pid, hostname: hostname() });
    const assertStoppedWriters = () => {
      // Stage, inventory and refusal use synchronous CLI calls; the only
      // asynchronous scenario writer is this recorded, closed finish child.
      expect(childClosed).toBe(true); expect(child.connected).toBe(false);
      expect(child.signalCode).toBe('SIGKILL'); expect(child.pid).toBeGreaterThan(0);
      let gone = false;
      try { process.kill(child.pid!, 0); }
      catch (error) { gone = (error as NodeJS.ErrnoException).code === 'ESRCH'; }
      expect(gone, 'recorded finish child must be gone in the test process namespace').toBe(true);
    };
    const assertRetainedState = () => {
      const current = lstatSync(lock);
      expect(current.isFile()).toBe(true); expect(current.isSymbolicLink()).toBe(false);
      for (const key of ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs', 'birthtimeMs'] as const)
        expect(current[key]).toBe(lockStat[key]);
      expect(readFileSync(lock).equals(staleLock)).toBe(true);
      expect(readFileSync(f.registry).equals(before)).toBe(true);
      expect(readFileSync(f.oldPath).equals(oldBytes)).toBe(true);
      expect(readFileSync(f.out).equals(newBytes)).toBe(true);
    };
    assertStoppedWriters(); assertRetainedState();
    const deleted = point === 'after delete'; probe(f.oldRemote, deleted ? 'rejected' : 'accepted', oldId);
    probe(remote, 'accepted', String(next.rootKeyId));
    const retainedIds = ['0', '4294967342', String(next.rootKeyId), ...(!deleted ? [oldId] : [])].sort();
    expect(ids()).toEqual(retainedIds);
    const observed = cli(f, 'inventory', [], ['--json']); expect(observed.status).toBe(0);
    assertRetainedState(); expect(ids()).toEqual(retainedIds);
    const rootKeys = JSON.parse(observed.stdout).result.rootKeys as Array<{ rootKeyId: string; inLnd: boolean; flags: string[] }>;
    expect(rootKeys.find(row => row.rootKeyId === oldId)?.inLnd).toBe(!deleted);
    expect(rootKeys.find(row => row.rootKeyId === String(next.rootKeyId))?.inLnd).toBe(true);
    if (deleted) expect(rootKeys.find(row => row.rootKeyId === oldId)?.flags).toContain('missing-in-lnd');
    assertStoppedWriters(); assertRetainedState();
    const repaired = cli(f, 'rotate', ['Alice'], ['--finish', '--yes', '--break-lock', '--json']);
    expect(repaired.status).toBe(0);
    const result = JSON.parse(repaired.stdout).result;
    expect(result).toEqual({ stage: 'finished', old: expect.objectContaining({ ...f.old,
      status: 'revoked', revokedAt: expect.any(String), replacedBy: next.rootKeyId,
      revokeEvidence: deleted ? 'by-id-only' : 'rejected' }), new: next,
      evidence: deleted ? 'by-id-only' : 'rejected', repaired: deleted });
    expect(rows(f)).toEqual([result.old, next]);
    expect(existsSync(lock)).toBe(false);
    expect(ids()).toEqual(['0', '4294967342', String(next.rootKeyId)].sort());
    expect(readFileSync(f.oldPath).equals(oldBytes)).toBe(true);
    expect(readFileSync(f.out).equals(newBytes)).toBe(true);
    probe(f.oldRemote, 'rejected', oldId); probe(remote, 'accepted', String(next.rootKeyId));
  }), 120_000);
