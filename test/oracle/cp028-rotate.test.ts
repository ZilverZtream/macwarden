import { fixtureTopology } from '../fixture/topology.mjs';
import { revealSecret } from '../helpers/secret-bytes.js';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { expect, it, vi } from 'vitest';
import { Secret } from '../../src/secret.js';
import { render } from '../helpers/render-adversarial.js';
import { cp024Compose } from '../fixture/cp024-fixture.mjs';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { classifyAcceptance, requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { declare, directory, register, template, vector } from '../helpers/cp026-revoke-support.mjs';
import { fingerprint, oldId, safe, type Envelope } from '../helpers/cp028-rotate-support.js';

// Runs against the shared regtest fixture (npm run fixture:up).
const repo = resolve(), ownId = '4294967330', otherId = '4294967329';
const tmp = () => {
  const path = join(directory('MACWARDEN_TEST_TMP'), 'cp028-rotate');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
};
let serial = 0;
function docker(args: string[]) {
  return spawnSync('docker', [...cp024Compose, ...args], { cwd: repo, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout); } catch { throw new FixtureInvalidError('Fixture returned invalid JSON'); }
}
function ids(): string[] {
  const value = lncli(['listmacaroonids']).root_key_ids;
  if (!Array.isArray(value)) throw new FixtureInvalidError('Fixture root key state unavailable');
  return value.map(String).sort();
}
function remote() { return `/tmp/macwarden-cp028-${process.pid}-${serial++}.macaroon`; }
function copy(local: string, target: string) {
  if (docker(['cp', local, `lnd:${target}`]).status !== 0) throw new FixtureInvalidError('Fixture credential copy unavailable');
}
function bake(id: string, permissions: string[], expiry = false): string {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    `--root_key_id=${id}`, ...(expiry ? ['--timeout=3600'] : []), ...permissions]);
  if (result.error || result.signal || result.status !== 0) throw new FixtureInvalidError('Fixture bake unavailable');
  const value = result.stdout.trim();
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) throw new FixtureInvalidError('Fixture bake returned invalid credential text');
  return register(Buffer.from(value, 'hex'));
}
function printed(path: string) {
  return lncli(['printmacaroon', `--macaroon_file=${path}`]) as { root_key_id: string; permissions: string[]; caveats: string[] | null };
}
function probe(path: string) {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${path}`, 'getinfo']);
  if (result.error || result.signal || result.status === null) throw new FixtureInvalidError('Independent acceptance probe unavailable');
  expect(classifyAcceptance(result)).toBe('accepted'); safe(result.stdout + result.stderr, []);
}
async function scenario(work: (f: Context) => Promise<void>, expiry = false) {
  const info = lncli(['getinfo']); requirePinnedFixture(info, lncli(['listmacaroonids']));
  const baseline = ids(), dir = mkdtempSync(join(tmp(), 'cp028-live-'));
  const fixture = join(tmpdir(), 'macwarden-fixture'), cert = join(fixture, 'tls.cert');
  const remotes: string[] = [];
  try {
    if (!existsSync(cert) || !existsSync(join(fixture, 'admin.macaroon'))) throw new FixtureInvalidError('Harness fixture copies unavailable');
    declare(join(fixture, 'admin.macaroon')); register(readFileSync(join(fixture, 'admin.macaroon')));
    const reference = vector('preset-invoice-only');
    const oldPath = bake(oldId, reference.printed.permissions, expiry), oldRemote = remote(); remotes.push(oldRemote); copy(oldPath, oldRemote);
    const other = bake(otherId, reference.printed.permissions), otherRemote = remote(); remotes.push(otherRemote); copy(other, otherRemote);
    const own = bake(ownId, vector('default-admin').printed.permissions), oldPrinted = printed(oldRemote);
    expect(oldPrinted.root_key_id).toBe(oldId); expect(oldPrinted.permissions).toEqual(reference.printed.permissions);
    const old = { ...template, nodePubkey: info.identity_pubkey, label: 'Alice', rootKeyId: oldId,
      permissions: oldPrinted.permissions, grade: reference.expectedGrade,
      fingerprint: fingerprint(readFileSync(oldPath)), outPath: oldPath,
      caveats: (oldPrinted.caveats ?? []).map(condition => {
        if (!condition.startsWith('time-before ')) throw new FixtureInvalidError('Unexpected fixture caveat');
        return { type: 'time-before', value: condition.slice(12), requested: '1h' };
      }) };
    const registry = join(dir, 'registry.json'), out = join(dir, 'replacement.macaroon'); declare(out);
    writeFileSync(registry, JSON.stringify({ schema: 1, entries: [old] }), { mode: 0o600 });
    const f = { dir, registry, out, cert, own, oldPath, oldRemote, otherRemote, remotes, old, oldPrinted,
      clock: new Date(), calls: [] as string[], outputs: [] as string[] };
    probe(oldRemote); probe(otherRemote); await work(f);
  } finally {
    // Inspect the complete scenario scratch before cleanup removes its artifacts.
    try { safe('', [dir]); }
    finally { cleanup(baseline, remotes, dir); }
  }
}
function cleanup(baseline: string[], remotes: string[], dir: string) {
    for (const id of ids().filter(id => !baseline.includes(id))) {
      if (id === '0') throw new FixtureInvalidError('Unsafe fixture root-zero cleanup');
      if (lncli(['deletemacaroonid', id]).deleted !== true) throw new FixtureInvalidError('Fixture cleanup failed');
    }
    for (const path of remotes) if (docker(['exec', '-T', 'lnd', 'rm', '-f', path]).status !== 0)
      throw new FixtureInvalidError('Fixture remote cleanup failed');
    const target = resolve(dir), root = resolve(directory('MACWARDEN_TEST_TMP'));
    if (!target.startsWith(root + sep)) throw new Error('Unsafe scratch cleanup');
    rmSync(target, { recursive: true, force: true });
    requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
}
type Context = { dir: string; registry: string; out: string; cert: string; own: string;
  oldPath: string; oldRemote: string; otherRemote: string; remotes: string[];
  old: Record<string, unknown>; oldPrinted: ReturnType<typeof printed>; clock: Date; calls: string[]; outputs: string[] };
function args(f: Context, flags: string[]) {
  return ['Alice', '--out', f.out, '--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`,
    '--tls-cert', f.cert, '--macaroon', f.own, ...flags];
}
async function invoke(f: Context, flags: string[] = [], afterBake?: () => void): Promise<Envelope> {
  const commandPath = '../../src/commands/rotate.js', adapterPath = '../../src/lnd/index.js';
  const command = await import(/* @vite-ignore */ commandPath) as { run(args: string[], deps: unknown): Promise<Envelope> };
  const module = await import(/* @vite-ignore */ adapterPath);
  const adapter = module.createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: readFileSync(f.cert), macaroon: new Secret(readFileSync(f.own)) });
  const lnd = new Proxy(adapter, { get(target, key) {
    const value = Reflect.get(target, key, target);
    if (key === 'listMacaroonIds' && typeof value !== 'function') return async () => {
      f.calls.push('listMacaroonIds'); return { root_key_ids: (await target.listMacaroonIds()).map(String) };
    };
    if (typeof value !== 'function') return value;
    return async (...values: unknown[]) => {
      if (key === 'checkMacaroon') register(Buffer.from(revealSecret((values[0] as Secret))));
      f.calls.push(String(key)); const result = await value.apply(target, values);
      if (key === 'bakeMacaroon') { register(Buffer.from(revealSecret(result))); afterBake?.(); }
      return result;
    };
  } });
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((value: unknown) => { f.outputs.push(String(value)); return true; }) as typeof process.stdout.write);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((value: unknown) => { f.outputs.push(String(value)); return true; }) as typeof process.stderr.write);
  let result: Envelope;
  try { result = await command.run(args(f, flags), { lnd, fs: { ...fs }, env: {}, clock: () => f.clock }); }
  finally { stdout.mockRestore(); stderr.mockRestore(); }
  if (existsSync(f.out) && readFileSync(f.out).length) register(readFileSync(f.out));
  safe(f.outputs.join('') + render(result, 'text') + render(result, 'json'), [f.dir]);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
  expect(f.calls).not.toContain('deleteMacaroonId'); return result;
}
function cli(f: Context, command: string, flags: string[]) {
  const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
  const commandArgs = command === 'rotate' ? args(f, flags) : ['--registry', f.registry,
    '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', f.cert, '--macaroon', f.own, ...flags];
  const result = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), command, ...commandArgs],
    { cwd: repo, env, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
  expect(result.error).toBeUndefined();
  if (existsSync(f.out) && readFileSync(f.out).length) register(readFileSync(f.out));
  safe(result.stdout + result.stderr, [f.dir]); return result;
}
function rows(f: Context): Array<Record<string, unknown>> { return JSON.parse(readFileSync(f.registry, 'utf8')).entries; }
function verifyStage(f: Context, result: Envelope, before: Buffer, beforeIds: string[]) {
  expect(result).toMatchObject({ schema: 1, command: 'rotate', ok: true, error: null });
  const next = result.result!.new as Record<string, unknown>;
  expect(result.result).toEqual({ stage: 'staged', old: f.old, new: next });
  expect(typeof next.rootKeyId).toBe('string'); expect(beforeIds).not.toContain(next.rootKeyId);
  expect(ids()).toEqual([...beforeIds, String(next.rootKeyId)].sort());
  expect(rows(f)).toEqual([f.old, next]); expect(next).toMatchObject({ replaces: oldId,
    label: 'Alice', permissions: f.oldPrinted.permissions, grade: 'RECEIVE', status: 'active', verified: true, outPath: f.out });
  expect(readFileSync(f.oldPath).equals(before)).toBe(true);
  const nextRemote = remote(); f.remotes.push(nextRemote); copy(f.out, nextRemote);
  probe(f.oldRemote); probe(nextRemote); probe(f.otherRemote);
  expect(printed(f.oldRemote)).toEqual(f.oldPrinted);
  const newPrinted = printed(nextRemote);
  expect(newPrinted.root_key_id).toBe(next.rootKeyId);
  expect(newPrinted.permissions.slice().sort()).toEqual(f.oldPrinted.permissions.slice().sort());
  expect(next.fingerprint).toBe(fingerprint(readFileSync(f.out)));
  return { next, newPrinted };
}
it.each(['run', 'CLI'])('CP-028/stage-live-acceptance %s leaves both credentials accepted and inventory pending', async mode => scenario(async f => {
  const before = readFileSync(f.oldPath), beforeIds = ids();
  let result: Envelope;
  if (mode === 'run') result = await invoke(f);
  else {
    const command = cli(f, 'rotate', ['--json']); expect(command.status).toBe(0);
    // S4 requires the live issue plan; S9's caveats and finish plan are dry-run output.
    expect(command.stderr.trimEnd().split(/\r?\n/)).toEqual([
      `stage Alice  old root key ID ${oldId}  ${String(f.old.grade)}`,
      `permissions  ${f.oldPrinted.permissions.join(' ')}`,
      'stage plan  allocate a fresh root key ID; bake, verify, write and record a replacement',
    ]);
    expect(command.stderr).not.toMatch(/error|failed|warning/i);
    expect(command.stderr).not.toContain(String.fromCharCode(27));
    result = JSON.parse(command.stdout);
  }
  const { next } = verifyStage(f, result, before, beforeIds);
  const inventory = cli(f, 'inventory', []); expect(inventory.status).toBe(0);
  for (const value of [oldId, String(next.rootKeyId), 'rotation staged', 'replacement']) expect(inventory.stdout).toContain(value);
  const saved = readFileSync(f.registry), second = await invoke(f);
  expect(second.error).toMatchObject({ code: 2, step: 'S3' });
  for (const value of [oldId, String(next.rootKeyId), 'macwarden rotate Alice --finish', `macwarden revoke ${next.rootKeyId}`, f.out]) expect(second.error!.message).toContain(value);
  expect(readFileSync(f.registry).equals(saved)).toBe(true); expect(ids()).toEqual([...beforeIds, String(next.rootKeyId)].sort());
  probe(f.oldRemote);
}), 120_000);
it.each([false, true])('CP-028/stage-permission-equality expiry=%s uses independently decoded permissions and renews requested duration', async expiry => scenario(async f => {
  const before = readFileSync(f.oldPath), beforeIds = ids();
  const { next, newPrinted } = verifyStage(f, await invoke(f), before, beforeIds);
  if (expiry) {
    const value = new Date(Math.floor((f.clock.getTime() + 3_600_000) / 1000) * 1000).toISOString().replace('.000Z', 'Z');
    expect(next.caveats).toEqual([{ type: 'time-before', value, requested: '1h' }]);
    expect(newPrinted.caveats).toEqual([`time-before ${value}`]);
  } else { expect(newPrinted.caveats ?? []).toEqual([]); expect(next.caveats).toEqual([]); }
}, expiry), 120_000);
it('CP-028/stage-dry-run-unchanged live IDs registry bytes and output remain unchanged without mutations', async () => scenario(async f => {
  const beforeIds = ids(), before = readFileSync(f.registry), old = readFileSync(f.oldPath);
  const result = await invoke(f, ['--dry-run', '--json']);
  expect(result.error).toBeNull(); expect(result.result).toMatchObject({ dryRun: true, stage: 'stage', old: f.old,
    permissions: f.oldPrinted.permissions, grade: 'RECEIVE' });
  expect(f.calls).toEqual(['getInfo', 'listPermissions', 'listMacaroonIds', 'checkMacaroon']);
  expect(ids()).toEqual(beforeIds); expect(readFileSync(f.registry).equals(before)).toBe(true);
  expect(readFileSync(f.oldPath).equals(old)).toBe(true); expect(existsSync(f.out)).toBe(false);
  probe(f.oldRemote); probe(f.otherRemote);
}), 120_000);
it('CP-028/stage-live-acceptance real pause after bake keeps old valid and records uncertain N by its ID', async () => scenario(async f => {
  const before = readFileSync(f.oldPath), beforeIds = ids(); let paused = false, result: Envelope;
  try {
    result = await invoke(f, [], () => {
      if (docker(['pause', 'lnd']).status !== 0) throw new FixtureInvalidError('Fixture pause unavailable'); paused = true;
    });
  } finally { if (paused) unpause(); }
  expect(result!.error).toMatchObject({ code: 7, step: 'S12' });
  const added = ids().filter(id => !beforeIds.includes(id)); expect(added).toHaveLength(1);
  expect(result!.error!.message).toContain(`macwarden revoke ${added[0]}`);
  expect(result!.error!.message).not.toContain('macwarden revoke Alice');
  expect(rows(f)).toContainEqual(f.old);
  expect(rows(f).find(row => row.rootKeyId === added[0])).toMatchObject({ status: 'active', verified: false, outPath: null, replaces: oldId });
  expect(existsSync(f.out)).toBe(false); expect(readFileSync(f.oldPath).equals(before)).toBe(true);
  probe(f.oldRemote); probe(f.otherRemote);
}), 120_000);
function unpause() {
  if (docker(['unpause', 'lnd']).status !== 0) throw new FixtureInvalidError('Fixture unpause failed');
}
it('CP-028/leak-check standing scan covers all declared products and registry artifacts', () => {
  safe('', [tmp()]);
}, 60_000);
