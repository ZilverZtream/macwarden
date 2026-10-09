import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from './environment.js';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect } from 'vitest';
import { cp024Compose } from '../fixture/cp024-fixture.mjs';
import { FixtureInvalidError } from './fixture-invalid.mjs';
import { classifyAcceptance, requirePinnedFixture } from './lnd-facts.mjs';
import { declare, directory, register, template, vector } from './cp026-revoke-support.mjs';
import { safe, type Envelope } from './cp027-revoke-support.js';
import { fixtureCopies, inside } from './fixture-copies.js';

// Helpers for the live rotation tests against the regtest fixture.
const repo = resolve(), oldId = '4294967341', ownId = '4294967342';
let serial = 0;
function docker(args: string[]) {
  return spawnSync('docker', [...cp024Compose, ...args], { cwd: repo, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const observed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (observed.error || observed.signal || observed.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(observed.stdout); } catch { throw new FixtureInvalidError('Fixture returned invalid JSON'); }
}
function ids(): string[] {
  const value = lncli(['listmacaroonids']).root_key_ids;
  if (!Array.isArray(value)) throw new FixtureInvalidError('Fixture ID state unavailable');
  return value.map(String).sort();
}
function bake(id: string, permissions: string[]) {
  const observed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon', `--root_key_id=${id}`, ...permissions]);
  if (observed.error || observed.signal || observed.status !== 0) throw new FixtureInvalidError('Fixture bake unavailable');
  const value = observed.stdout.trim();
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) throw new FixtureInvalidError('Fixture bake returned invalid credential text');
  return register(Buffer.from(value, 'hex'));
}
function copy(local: string, remote: string) {
  if (docker(['cp', local, `lnd:${remote}`]).status !== 0) throw new FixtureInvalidError('Fixture credential copy unavailable');
}
function probe(remote: string, expected: 'accepted' | 'rejected', id: string) {
  const observed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${remote}`, 'getinfo']);
  if (observed.error || observed.signal || observed.status === null) throw new FixtureInvalidError('Independent lncli probe unavailable');
  safe(observed.stdout + observed.stderr, []);
  expect(classifyAcceptance(observed)).toBe(expected);
  if (expected === 'rejected') expect(observed.stderr).toContain(`root key with id ${id} doesn't exist`);
}
async function fixtureCert() {
  const supplied = await fixtureCopies();
  const cert = join(supplied, 'tls.cert');
  if (!existsSync(cert)) throw new FixtureInvalidError('Harness fixture certificate copy unavailable');
  return cert;
}
type Context = { dir: string; registry: string; out: string; cert: string; own: string; oldPath: string;
  oldRemote: string; remotes: string[]; old: Record<string, unknown> };
async function scenario(work: (f: Context) => Promise<void>) {
  const cert = await fixtureCert(), info = lncli(['getinfo']);
  requirePinnedFixture(info, lncli(['listmacaroonids']));
  const baseline = ids(), root = directory('MACWARDEN_TEST_TMP');
  const dir = mkdtempSync(join(root, 'cp029-live-')), remotes: string[] = [];
  try {
    const reference = vector('preset-invoice-only');
    const oldPath = bake(oldId, reference.printed.permissions), own = bake(ownId, vector('default-admin').printed.permissions);
    const oldRemote = `/tmp/macwarden-cp029-${process.pid}-${serial++}.macaroon`;
    remotes.push(oldRemote); copy(oldPath, oldRemote);
    const printed = lncli(['printmacaroon', `--macaroon_file=${oldRemote}`]);
    expect(printed.root_key_id).toBe(oldId); expect(printed.permissions).toEqual(reference.printed.permissions);
    const old = { ...template, nodePubkey: info.identity_pubkey, label: 'Alice', rootKeyId: oldId,
      permissions: printed.permissions, grade: reference.expectedGrade, caveats: [], outPath: oldPath,
      fingerprint: 'fp:' + createHash('sha256').update(readFileSync(oldPath)).digest('hex').slice(0, 16) };
    const registry = join(dir, 'registry.json'), out = join(dir, 'replacement.macaroon'); declare(out);
    writeFileSync(registry, JSON.stringify({ schema: 1, entries: [old] }), { mode: 0o600 });
    probe(oldRemote, 'accepted', oldId);
    await work({ dir, registry, out, cert, own, oldPath, oldRemote, remotes, old });
  } finally { cleanup(baseline, remotes, dir, root); }
}
function cleanup(baseline: string[], remotes: string[], dir: string, root: string) {
  for (const id of ids().filter(id => !baseline.includes(id))) {
    if (id === '0') throw new FixtureInvalidError('Unsafe fixture cleanup');
    if (lncli(['deletemacaroonid', id]).deleted !== true) throw new FixtureInvalidError('Fixture cleanup failed');
  }
  for (const remote of remotes)
    if (docker(['exec', '-T', 'lnd', 'rm', '-f', remote]).status !== 0) throw new FixtureInvalidError('Fixture remote cleanup failed');
  if (!inside(root, dir) || resolve(root) === resolve(dir)) throw new Error('Unsafe scratch cleanup');
  rmSync(dir, { recursive: true, force: true });
  requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
}
function cli(f: Context, command: string, leading: string[], flags: string[],
  expectedLockRefusal?: { exitCode: 3; retainedLock: Buffer }) {
  const lock = `${f.registry}.lock`;
  const previousLock = command === 'inventory' && existsSync(lock) ? readFileSync(lock) : null;
  if (expectedLockRefusal) {
    expect(command).toBe('rotate'); expect(leading).toEqual(['Alice']);
    for (const flag of ['--finish', '--yes', '--break-lock', '--json']) expect(flags).toContain(flag);
    expect(readFileSync(lock).equals(expectedLockRefusal.retainedLock)).toBe(true);
  }
  const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
  const observed = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), command, ...leading,
    '--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', f.cert, '--macaroon', f.own, ...flags],
    { cwd: repo, env, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
  expect(observed.error).toBeUndefined();
  expect(observed.signal).toBeNull();
  if (existsSync(f.out) && readFileSync(f.out).length) register(readFileSync(f.out));
  safe(observed.stdout + observed.stderr, [f.dir]);
  if (expectedLockRefusal) {
    expect(observed.status).toBe(expectedLockRefusal.exitCode);
    expect(JSON.parse(observed.stdout)).toMatchObject({ schema: 1, command: 'rotate', ok: false,
      result: null, error: { code: expectedLockRefusal.exitCode, step: 'F9' } });
    expect(readFileSync(lock).equals(expectedLockRefusal.retainedLock)).toBe(true);
  } else if (previousLock) expect(readFileSync(lock).equals(previousLock)).toBe(true);
  else expect(existsSync(lock)).toBe(false);
  return observed;
}
function json(f: Context, command: string, leading: string[], flags: string[]): Envelope {
  const observed = cli(f, command, leading, [...flags, '--json']);
  expect(observed.status).toBe(0);
  if (command === 'rotate' && flags.includes('--finish') && !flags.includes('--dry-run')) {
    const staged = rows(f).find(row => row.replaces === oldId)!;
    for (const value of [oldId, String(staged.rootKeyId), String(staged.grade),
      String(staged.outPath), ...(staged.permissions as string[])]) expect(observed.stderr).toContain(value);
    expect(observed.stderr).toMatch(/old/i); expect(observed.stderr).toMatch(/new/i);
  } else if (command === 'rotate' && !flags.includes('--finish') && !flags.includes('--dry-run')) {
    // S4 requires the live issue plan; S9's caveats and finish plan are dry-run output.
    expect(observed.stderr.trimEnd().split(/\r?\n/)).toEqual([
      `stage Alice  old root key ID ${oldId}  ${String(f.old.grade)}`,
      `permissions  ${(f.old.permissions as string[]).join(' ')}`,
      'stage plan  allocate a fresh root key ID; bake, verify, write and record a replacement',
    ]);
    expect(observed.stderr).not.toMatch(/error|failed|warning/i);
    expect(observed.stderr).not.toContain(String.fromCharCode(27));
  } else expect(observed.stderr).toBe('');
  const result = JSON.parse(observed.stdout) as Envelope;
  expect(result).toMatchObject({ schema: 1, command, ok: true, error: null });
  return result;
}
function rows(f: Context): Array<Record<string, unknown>> { return JSON.parse(readFileSync(f.registry, 'utf8')).entries; }
function stage(f: Context) {
  const result = json(f, 'rotate', ['Alice'], ['--out', f.out]);
  const next = result.result!.new as Record<string, unknown>;
  expect(result.result!.stage).toBe('staged');
  expect(next).toMatchObject({ status: 'active', replaces: oldId, outPath: f.out });
  expect(rows(f)).toContainEqual(f.old);
  const remote = `/tmp/macwarden-cp029-${process.pid}-${serial++}.macaroon`;
  f.remotes.push(remote); copy(f.out, remote);
  probe(f.oldRemote, 'accepted', oldId); probe(remote, 'accepted', String(next.rootKeyId));
  return { next, remote };
}

export { scenario, ids, probe, rows, stage, cli, copy, docker, oldId };
export type { Context };
