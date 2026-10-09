import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { expect, it } from 'vitest';
import { render } from '../helpers/render-adversarial.js';
import { cp024Compose } from '../fixture/cp024-fixture.mjs';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { classifyAcceptance, requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { declare, directory, register, template, vector } from '../helpers/cp026-revoke-support.mjs';
import { safe, scope, type Envelope } from '../helpers/cp027-revoke-support.js';

// Runs against the shared regtest fixture (npm run fixture:up).
const repo = resolve(), oldId = '4294967341', ownId = '4294967342';
const tmp = () => {
  const path = join(directory('MACWARDEN_TEST_TMP'), 'cp029-rotate');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
};
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
function inside(parent: string, child: string) {
  const path = relative(resolve(parent), resolve(child));
  return path === '' || (!isAbsolute(path) && path !== '..' && !path.startsWith('..' + sep));
}
function fixtureCert() {
  const supplied = process.env.MACWARDEN_FIXTURE_DIR;
  if (!supplied || !isAbsolute(supplied) || !inside(repo, supplied))
    throw new FixtureInvalidError('MACWARDEN_FIXTURE_DIR must name fixture copies within this worktree');
  for (const root of [directory('MACWARDEN_TEST_TMP'), directory('MACWARDEN_SENTINEL_DIR')])
    if (inside(root, supplied) || inside(supplied, root)) throw new FixtureInvalidError('Fixture copies must have a separate root');
  const cert = join(supplied, 'tls.cert');
  if (!existsSync(cert)) throw new FixtureInvalidError('Harness fixture certificate copy unavailable');
  return cert;
}
type Context = { dir: string; registry: string; out: string; cert: string; own: string; oldPath: string;
  oldRemote: string; remotes: string[]; old: Record<string, unknown> };
async function scenario(work: (f: Context) => Promise<void>) {
  const cert = fixtureCert(), info = lncli(['getinfo']);
  requirePinnedFixture(info, lncli(['listmacaroonids']));
  const baseline = ids(), root = tmp();
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
  } finally {
    // Inspect the complete scenario scratch before cleanup removes its artifacts.
    try { safe('', [dir]); }
    finally { cleanup(baseline, remotes, dir, root); }
  }
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
function cli(f: Context, command: string, leading: string[], flags: string[]) {
  const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
  const observed = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), command, ...leading,
    '--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', f.cert, '--macaroon', f.own, ...flags],
    { cwd: repo, env, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
  expect(observed.error).toBeUndefined();
  if (existsSync(f.out) && readFileSync(f.out).length) register(readFileSync(f.out));
  safe(observed.stdout + observed.stderr, [f.dir]);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
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
  expect(result).toEqual({ schema: 1, command, ok: true, warnings: [], error: null, result: result.result });
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
it('CP-029/finish-live-state completed stage and finish reject only O and record its replacement', async () => scenario(async f => {
  const { next, remote } = stage(f), oldBytes = readFileSync(f.oldPath), newBytes = readFileSync(f.out);
  const result = json(f, 'rotate', ['Alice'], ['--finish', '--yes']);
  expect(result.result).toMatchObject({ stage: 'finished', evidence: 'rejected', repaired: false,
    old: { ...f.old, status: 'revoked', revokedAt: expect.any(String), revokeEvidence: 'rejected', replacedBy: next.rootKeyId }, new: next });
  expect(ids()).not.toContain(oldId); expect(ids()).toContain(String(next.rootKeyId));
  probe(f.oldRemote, 'rejected', oldId); probe(remote, 'accepted', String(next.rootKeyId));
  expect(rows(f)).toEqual([result.result!.old, next]);
  expect(readFileSync(f.oldPath).equals(oldBytes)).toBe(true); expect(readFileSync(f.out).equals(newBytes)).toBe(true);
  expect(render(result, 'text').trimEnd().endsWith(scope)).toBe(true);
}), 120_000);
it('CP-029/abandon-live-state live numeric revoke rejects N while O remains accepted and inventory has no pending replacement', async () => scenario(async f => {
  const { next, remote } = stage(f);
  json(f, 'revoke', [String(next.rootKeyId)], ['--yes']);
  expect(ids()).toContain(oldId); expect(ids()).not.toContain(String(next.rootKeyId));
  probe(remote, 'rejected', String(next.rootKeyId)); probe(f.oldRemote, 'accepted', oldId);
  expect(rows(f)).toContainEqual(f.old);
  expect(rows(f).find(row => row.rootKeyId === next.rootKeyId)).toMatchObject({ status: 'revoked', revokeEvidence: 'rejected' });
  const inventory = cli(f, 'inventory', [], []); expect(inventory.status).toBe(0);
  expect(inventory.stdout).toContain(oldId); expect(inventory.stdout).not.toContain('pending-replacement');
}), 120_000);
it('CP-029/finish-dry-run-unchanged stage and finish dry runs preserve live IDs registry and output bytes', async () => scenario(async f => {
  const beforeIds = ids(), before = readFileSync(f.registry), oldBytes = readFileSync(f.oldPath);
  const stagedPlan = json(f, 'rotate', ['Alice'], ['--out', f.out, '--dry-run']);
  expect(stagedPlan.result).toMatchObject({ dryRun: true, stage: 'stage', old: f.old });
  expect(ids()).toEqual(beforeIds); expect(readFileSync(f.registry).equals(before)).toBe(true); expect(existsSync(f.out)).toBe(false);
  const { next, remote } = stage(f), stagedIds = ids(), stagedBytes = readFileSync(f.registry), newBytes = readFileSync(f.out);
  const finishPlan = json(f, 'rotate', ['Alice'], ['--finish', '--dry-run']);
  expect(finishPlan.result).toMatchObject({ dryRun: true, stage: 'finish', old: f.old, grade: f.old.grade, permissions: f.old.permissions });
  expect(ids()).toEqual(stagedIds); expect(readFileSync(f.registry).equals(stagedBytes)).toBe(true);
  expect(readFileSync(f.oldPath).equals(oldBytes)).toBe(true); expect(readFileSync(f.out).equals(newBytes)).toBe(true);
  probe(f.oldRemote, 'accepted', oldId); probe(remote, 'accepted', String(next.rootKeyId));
}), 120_000);
it('CP-029/leak-check standing sentinel scan covers finish and abandon output and registry artifacts', () => {
  safe('', [tmp()]);
}, 60_000);
