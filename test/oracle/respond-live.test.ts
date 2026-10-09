import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { expect, it } from 'vitest';
import { docker, ids, probe, scenario, FixtureInvalidError } from '../helpers/cp038-live.js';
import { register, type Entry } from '../helpers/cp038-online.js';
import { childEnvironment } from '../helpers/environment.js';

// Owner request 2026-10-08: incident response against the pinned regtest LND.
function cli(flags: string[], args: string[]) {
  return spawnSync(process.execPath, [resolve('dist/bin.js'), 'respond', ...args, ...flags, '--json'],
    { env: childEnvironment(), encoding: 'utf8', timeout: 60_000, windowsHide: true });
}

it('RESPOND/live stage then finish rotates two credentials, proves old rejected and new accepted, and leaves unknown IDs alone', async () => scenario(async f => {
  // A second labelled credential on its own root key ID, baked by lncli independently of macwarden.
  const bobId = '4294967400';
  const baked = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon', `--root_key_id=${bobId}`, ...f.old.permissions]);
  if (baked.status !== 0 || !/^(?:[0-9a-f]{2})+$/i.test(baked.stdout.trim())) throw new FixtureInvalidError('Fixture bake unavailable');
  const bobPath = register(Buffer.from(baked.stdout.trim(), 'hex'));
  const bob: Entry = { ...f.old, label: 'Bob', rootKeyId: bobId, outPath: bobPath,
    fingerprint: 'fp:' + createHash('sha256').update(readFileSync(bobPath)).digest('hex').slice(0, 16) };
  f.save([f.old, bob]);
  // f.next is baked in LND but absent from this registry: an unknown ID respond must never touch.
  const before = ids();
  expect(before).toEqual(expect.arrayContaining([f.old.rootKeyId, bobId, f.next.rootKeyId, '0']));

  const outDir = join(f.dir, 'respond');
  const staged = cli(f.flags, ['--out-dir', outDir, '--yes']);
  expect(staged.status, staged.stderr).toBe(0);
  const stage = JSON.parse(staged.stdout).result;
  expect(stage.items.map((item: { label: string; status: string }) => [item.label, item.status])).toEqual([['Alice', 'staged'], ['Bob', 'staged']]);
  expect(stage.unknown.rootKeyIds).toContain(f.next.rootKeyId);
  for (const label of ['Alice', 'Bob']) expect(probe(join(outDir, `${label}.macaroon`))).toBe('accepted');
  // Staging changes nothing for the old credentials.
  expect(probe(f.old.outPath!)).toBe('accepted');
  expect(probe(bobPath)).toBe('accepted');

  const finished = cli(f.flags, ['--finish', '--yes']);
  expect(finished.status, finished.stderr).toBe(0);
  const finish = JSON.parse(finished.stdout).result;
  for (const item of finish.items) expect(item).toMatchObject({ status: 'finished',
    proof: { oldRootKeyIdAbsent: true, oldCredential: 'rejected', newCredential: 'accepted', proven: true, strength: 'credential-rejected' } });
  expect(finish.unproven).toEqual([]);
  // Independent lncli evidence agrees with the proof report.
  expect(probe(f.old.outPath!)).toBe('rejected');
  expect(probe(bobPath)).toBe('rejected');
  for (const label of ['Alice', 'Bob']) expect(probe(join(outDir, `${label}.macaroon`))).toBe('accepted');
  const after = ids();
  expect(after).not.toContain(f.old.rootKeyId);
  expect(after).not.toContain(bobId);
  expect(after).toEqual(expect.arrayContaining(['0', f.next.rootKeyId]));
}), 180_000);
