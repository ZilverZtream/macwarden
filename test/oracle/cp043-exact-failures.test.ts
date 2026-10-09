import { fixtureTopology } from '../fixture/topology.mjs';
import { revealSecret } from '../helpers/secret-bytes.js';
import { existsSync, readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { expect, it, vi } from 'vitest';
import { Secret } from '../../src/secret.js';
import { LndError } from '../../src/errors.js';
import { render } from '../helpers/render-adversarial.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { register } from '../helpers/cp026-revoke-support.mjs';
import { safe } from '../helpers/cp027-revoke-support.js';
import { scenario, ids, probe, rows, stage, cli, copy, docker, oldId, type Context } from '../helpers/cp030-live-support.js';

const liveProofs: Array<{ id: string; branch: string; exit: number }> = [];

type Fault = 'lost delete response' | 'bake absent' | 'lost bake response' | 'rejected replacement' | 'verify timeout' |
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
      if (key === 'deleteMacaroonId') {
        deleted = true;
        if (fault === 'lost delete response') throw new LndError(4, 'transport', 'response lost after fixture deletion');
      }
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
it('CP-043/cli-adapter-live built inventory and rotation use actual adapter with independent lncli acceptance', async () => scenario(async f => {
  const inventory = cli(f, 'inventory', [], ['--json']); expect(inventory.status).toBe(0);
  const document = JSON.parse(inventory.stdout) as { result: { rootKeys: Array<{ rootKeyId: string }> } };
  expect(document.result.rootKeys.map(row => row.rootKeyId).sort()).toEqual(ids());
  const { next, remote } = stage(f);
  probe(f.oldRemote, 'accepted', oldId); probe(remote, 'accepted', String(next.rootKeyId));
  const finished = cli(f, 'rotate', ['Alice'], ['--finish', '--yes', '--json']); expect(finished.status).toBe(0);
  expect(ids()).not.toContain(oldId); probe(f.oldRemote, 'rejected', oldId); probe(remote, 'accepted', String(next.rootKeyId));
}), 120_000);
it('CP-043/cli-adapter-live built bake and revoke prove live permissions and acceptance independently', async () => scenario(async f => {
  const baked = cli(f, 'bake', ['--label', 'New', '--preset', 'invoice-only', '--out', f.out], ['--json']);
  expect(baked.status).toBe(0);
  const issued = rows(f).find(row => row.label === 'New')!;
  const remote = `/tmp/macwarden-cp043-${process.pid}-${f.remotes.length}.macaroon`;
  f.remotes.push(remote); copy(f.out, remote);
  const printed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'printmacaroon', `--macaroon_file=${remote}`]);
  expect(printed.status).toBe(0);
  expect(JSON.parse(printed.stdout)).toMatchObject({ root_key_id: issued.rootKeyId, permissions: issued.permissions });
  probe(remote, 'accepted', String(issued.rootKeyId)); probe(f.oldRemote, 'accepted', oldId);
  const revoked = cli(f, 'revoke', [String(issued.rootKeyId)], ['--yes', '--json']); expect(revoked.status).toBe(0);
  expect(ids()).not.toContain(String(issued.rootKeyId)); probe(remote, 'rejected', String(issued.rootKeyId)); probe(f.oldRemote, 'accepted', oldId);
}), 120_000);
it('CP-030/FI-4 completed lost DELETE response reconciles independently observed LND state without retry', async () => scenario(async f => {
  const { next, remote } = stage(f), { result, calls } = await injected(f, 'lost delete response', true);
  expect(result.error).toBeNull(); expect(calls.filter(call => call === 'deleteMacaroonId')).toHaveLength(1);
  expect(ids()).not.toContain(oldId); probe(f.oldRemote, 'rejected', oldId); probe(remote, 'accepted', String(next.rootKeyId));
  expect(rows(f).find(row => row.rootKeyId === oldId)).toMatchObject({ status: 'revoked', replacedBy: next.rootKeyId });
  liveProofs.push({ id: 'CP-030/FI-4', branch: 'lost delete response', exit: result.error?.code ?? 0 });
}), 120_000);
it.each(['bake absent', 'lost bake response'] as const)(
  'CP-030/FI-1 %s independently observes unchanged O and actual N state', async fault => scenario(async f => {
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
      const recovered = cli(f, 'revoke', [added[0]], ['--yes', '--json']); expect(recovered.status).toBe(0);
      expect(ids()).not.toContain(added[0]); remoteProbe(f, issued[0], false, added[0]);
      probe(f.oldRemote, 'accepted', oldId);
    } else expect(readFileSync(f.registry).equals(before)).toBe(true);
    liveProofs.push({ id: 'CP-030/FI-1', branch: fault, exit: result.error!.code });
  }), 120_000);
it.each(['rejected replacement', 'verify timeout'] as const)(
  'CP-030/FI-2 %s independently probes issued N and preserves O', async fault => scenario(async f => {
    const beforeIds = ids(), { result, issued } = await injected(f, fault);
    expect(result.error).toMatchObject({ code: 7, step: 'S12' });
    const added = ids().filter(id => !beforeIds.includes(id)); expect(added).toHaveLength(fault === 'verify timeout' ? 1 : 0);
    const replacement = rows(f).find(row => row.replaces === oldId)!;
    expect(result.error!.message).toContain(`macwarden revoke ${replacement.rootKeyId}`);
    expect(rows(f)).toContainEqual(f.old);
    expect(replacement).toMatchObject({ status: 'active', verified: false, replaces: oldId });
    probe(f.oldRemote, 'accepted', oldId); remoteProbe(f, issued.at(-1)!, fault === 'verify timeout', String(replacement.rootKeyId));
    liveProofs.push({ id: 'CP-030/FI-2', branch: fault, exit: result.error!.code });
  }), 120_000);
it('CP-030/FI-4 real failed delete retains both credentials and exact retry', async () => scenario(async f => {
  const { next, remote } = stage(f), before = readFileSync(f.registry), { result } = await injected(f, 'delete fails', true);
  expect(result.error).toMatchObject({ code: 5, step: 'F10' });
  expect(result.error!.message).toContain('macwarden rotate Alice --finish');
  expect(readFileSync(f.registry).equals(before)).toBe(true); probe(f.oldRemote, 'accepted', oldId); probe(remote, 'accepted', String(next.rootKeyId));
  liveProofs.push({ id: 'CP-030/FI-4', branch: 'delete fails', exit: result.error!.code });
}), 120_000);
it.each(['stage save', 'finish save'] as const)(
  'CP-031/FI-7 %s real rename failure preserves registry and exact recovery', async fault => scenario(async f => {
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
    liveProofs.push({ id: 'CP-031/FI-7', branch: fault, exit: result.error!.code });
  }), 120_000);

it('CP-043/missing-failure-cases-live independently aggregates executed exact FI outcomes after lncli acceptance and state probes', () => {
  expect(liveProofs.sort((a, b) => `${a.id}:${a.branch}`.localeCompare(`${b.id}:${b.branch}`))).toEqual([
    { id: 'CP-030/FI-1', branch: 'bake absent', exit: 4 },
    { id: 'CP-030/FI-1', branch: 'lost bake response', exit: 7 },
    { id: 'CP-030/FI-2', branch: 'rejected replacement', exit: 7 },
    { id: 'CP-030/FI-2', branch: 'verify timeout', exit: 7 },
    { id: 'CP-030/FI-4', branch: 'delete fails', exit: 5 },
    { id: 'CP-030/FI-4', branch: 'lost delete response', exit: 0 },
    { id: 'CP-031/FI-7', branch: 'finish save', exit: 7 },
    { id: 'CP-031/FI-7', branch: 'stage save', exit: 7 },
  ]);
});



