import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fixtureTopology } from '../fixture/topology.mjs';
import { expect, it } from 'vitest';
import { docker, ids, probe, scenario, FixtureInvalidError } from '../helpers/cp038-live.js';
import { declare, type Entry } from '../helpers/cp038-online.js';
import { childEnvironment } from '../helpers/environment.js';

// Audit 2026-10-08 of 1.0.1 (docs/reviews/2026-10-08-audit-1.0.1.md) against the pinned regtest LND.
function cli(command: string, flags: string[], args: string[]) {
  return spawnSync(process.execPath, [resolve('dist/bin.js'), command, ...args, ...flags, '--json'],
    { env: childEnvironment(), encoding: 'utf8', timeout: 60_000, windowsHide: true });
}
/** Runs watch with the canary guard registered, as in the audit: LND then accepts the canary's checks. */
async function withWatch(flags: string[], work: () => Promise<void>): Promise<void> {
  const child = spawn(process.execPath, [resolve('dist/bin.js'), 'watch', ...flags,
    '--lnd-grpc', `localhost:${fixtureTopology().grpcPort}`, '--until', '120s', '--json'],
  { env: childEnvironment(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  child.stdout!.on('data', chunk => { stdout += String(chunk); });
  const exited = new Promise<number | null>(done => child.on('close', code => done(code)));
  try {
    await new Promise<void>((done, fail) => {
      const timer = setTimeout(() => fail(new FixtureInvalidError('watch did not register')), 20_000);
      const check = () => { if (/"status":"registered","canaries":1/.test(stdout)) { clearTimeout(timer); done(); } };
      child.stdout!.on('data', check);
      child.on('close', () => { clearTimeout(timer); fail(new FixtureInvalidError('watch exited before registering')); });
    });
    await work();
  } finally {
    child.kill('SIGINT');
    await exited;
  }
}
const rows = (registry: string) => (JSON.parse(readFileSync(registry, 'utf8')) as { entries: Entry[] }).entries;

it('MW102-01/live a canary whose registry caveats were cleared is never rotated into an accepted ordinary credential', async () => scenario(async f => {
  const decoy = join(f.dir, 'decoy.macaroon');
  declare(decoy);
  const baked = cli('bake', f.flags, ['--label', 'Decoy', '--canary', '--out', decoy]);
  expect(baked.status, baked.stderr).toBe(0);
  const decoyId = JSON.parse(baked.stdout).result.rootKeyId as string;
  const out = join(f.dir, 'decoy-next.macaroon');
  declare(out);
  const outDir = join(f.dir, 'respond');
  for (const name of ['Alice', 'Decoy']) declare(join(outDir, `${name}.macaroon`));
  let before: string[] = [];
  let tampered = Buffer.alloc(0);
  // As in the audit, watch runs with the canary guard registered, so LND accepts the canary's
  // permission check; then only the registry metadata is cleared, and only the file's caveat can
  // stop the rotation.
  await withWatch(f.flags, async () => {
    const entries = rows(f.registry);
    const canary = entries.find(entry => entry.rootKeyId === decoyId)!;
    expect(canary.caveats.some(caveat => caveat.type === 'lnd-custom')).toBe(true);
    canary.caveats = [];
    writeFileSync(f.registry, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
    before = ids();
    tampered = readFileSync(f.registry);
    for (const extra of [['--dry-run'], []]) {
      const rotated = cli('rotate', f.flags, ['Decoy', '--out', out, ...extra]);
      expect(rotated.status, rotated.stdout).toBe(3);
      expect(JSON.parse(rotated.stdout).error).toMatchObject({ code: 3, step: 'S4' });
    }
    expect(existsSync(out)).toBe(false);
    const responded = cli('respond', f.flags, ['--out-dir', outDir, '--yes']);
    expect(responded.status, responded.stdout).toBe(3);
    expect(JSON.parse(responded.stdout).error).toMatchObject({ code: 3, step: 'P5' });
    expect(existsSync(join(outDir, 'Alice.macaroon'))).toBe(false);
    expect(existsSync(join(outDir, 'Decoy.macaroon'))).toBe(false);
  });

  // Nothing was baked or deleted, and the registry is exactly as the tampering left it.
  expect(ids()).toEqual(before);
  expect(readFileSync(f.registry).equals(tampered)).toBe(true);
  // LND still refuses the canary itself (no watch runs), and the ordinary credential is untouched.
  const remote = `/tmp/mw102-decoy-${process.pid}.macaroon`;
  if (docker(['cp', decoy, 'lnd:' + remote]).status !== 0) throw new FixtureInvalidError('Fixture copy unavailable');
  try {
    const used = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', '--macaroonpath=' + remote, 'getinfo']);
    expect(used.status).not.toBe(0);
    expect(used.stderr).toContain('no middleware registered');
  } finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
  expect(probe(f.old.outPath!)).toBe('accepted');
}), 180_000);

it('MW102-02/live respond --finish after the old root key was deleted but the registry not saved repairs through F6 and proves the replacement', async () => scenario(async f => {
  const outDir = join(f.dir, 'respond');
  declare(join(outDir, 'Alice.macaroon'));
  const staged = cli('respond', f.flags, ['--out-dir', outDir, '--yes']);
  expect(staged.status, staged.stdout).toBe(0);
  const replacementId = JSON.parse(staged.stdout).result.items[0].replacementRootKeyId as string;
  // The deletion succeeded, then the process died before the registry was saved.
  const deleted = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', f.old.rootKeyId]);
  if (deleted.status !== 0) throw new FixtureInvalidError('Fixture deletion unavailable');
  expect(ids()).not.toContain(f.old.rootKeyId);
  expect(rows(f.registry).filter(entry => entry.status === 'active' && entry.label === 'Alice')).toHaveLength(2);

  const finished = cli('respond', f.flags, ['--finish', '--yes']);
  expect(finished.status, finished.stdout).toBe(0);
  const finish = JSON.parse(finished.stdout).result;
  expect(finish.items).toHaveLength(1);
  expect(finish.items[0]).toMatchObject({ action: 'finish', status: 'finished', replacementRootKeyId: replacementId,
    proof: { oldRootKeyIdAbsent: true, oldCredential: 'rejected', newCredential: 'accepted', proven: true } });
  expect(finish.unproven).toEqual([]);
  // Independent lncli evidence, and the registry records the revocation and the link.
  expect(probe(f.old.outPath!)).toBe('rejected');
  expect(probe(join(outDir, 'Alice.macaroon'))).toBe('accepted');
  const after = rows(f.registry);
  expect(after.find(entry => entry.rootKeyId === f.old.rootKeyId)).toMatchObject({ status: 'revoked', replacedBy: replacementId });
  expect(after.find(entry => entry.rootKeyId === replacementId)).toMatchObject({ status: 'active' });
  expect(ids()).toContain(replacementId);
}), 180_000);
