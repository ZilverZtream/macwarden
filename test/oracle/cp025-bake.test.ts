import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from "../helpers/leak-check.js";
import { cp024Compose } from '../fixture/cp024-fixture.mjs';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { declare, directory, register } from '../helpers/cp025-bake-support.mjs';
import { contend } from '../helpers/cp025-contention.js';

const repo = resolve();
const outerTmp = () => directory('MACWARDEN_TEST_TMP');
const temp = () => {
  const path = join(outerTmp(), 'cp025-bake');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
};
const sentinels = () => directory('MACWARDEN_SENTINEL_DIR');
function docker(args: string[]) {
  return spawnSync('docker', [...cp024Compose, ...args], { cwd: repo,
    encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function ids(): string[] {
  const observed = lncli(['listmacaroonids']).root_key_ids;
  if (!Array.isArray(observed)) throw new FixtureInvalidError('Fixture IDs unavailable');
  return observed.map(String);
}
function guard() {
  const info = lncli(['getinfo']), before = lncli(['listmacaroonids']);
  requirePinnedFixture(info, before);
  let facts;
  try { facts = JSON.parse(readFileSync(join(repo, 'test/oracle/facts/observations.json'), 'utf8')); }
  catch { throw new FixtureInvalidError('CP-015 prerequisite facts unavailable'); }
  if (facts.fixture?.network !== 'regtest' || !facts.fixture.version?.startsWith('0.21.4-beta') ||
    JSON.stringify(facts.fixture.baselineRootKeyIds) !== '["0"]' ||
    facts.fixtureBasics?.snapshotMatches !== true || facts.fixtureBasics.bakedLocation !== 'lnd' ||
    facts.emptyPermissionCheck?.corruptRejectedByOrdinaryRpc !== true)
    throw new FixtureInvalidError('CP-015 prerequisite facts invalid');
  const cert = join(tmpdir(), 'macwarden-fixture/tls.cert');
  const own = join(tmpdir(), 'macwarden-fixture/admin.macaroon');
  if (!existsSync(cert) || !existsSync(own)) throw new FixtureInvalidError('Workspace fixture copies unavailable');
  declare(own);
  return { info, before: (before.root_key_ids as string[]).map(String), cert,
    own: register(readFileSync(own)) };
}
type Context = ReturnType<typeof guard> & { dir: string; registry: string; remote: string[]; outputs: string[] };
let serial = 0;
async function scenario(work: (f: Context) => Promise<void>) {
  const baseline = guard();
  const dir = mkdtempSync(join(temp(), 'cp025-live-'));
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, '{"schema":1,"entries":[]}', { mode: 0o600 });
  const f: Context = { ...baseline, dir, registry, remote: [], outputs: [] };
  try { await work(f); }
  finally {
    // Inspect the complete scenario scratch before cleanup removes its artifacts.
    try { safe('', [dir]); }
    finally { cleanup(f); }
  }
}
function cleanup(f: Context) {
  // Only IDs absent from this guarded baseline belong to this isolated run.
  for (const id of ids().filter(id => !f.before.includes(id))) {
    if (id === '0') throw new FixtureInvalidError('Refusing fixture root-zero cleanup');
    if (lncli(['deletemacaroonid', id]).deleted !== true)
      throw new FixtureInvalidError('Fixture issued ID cleanup failed');
  }
  if (f.remote.length && docker(['exec', '-T', 'lnd', 'rm', '-f', ...f.remote]).status !== 0)
    throw new FixtureInvalidError('Fixture temporary credential cleanup failed');
  rmSync(f.dir, { recursive: true, force: true });
  requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
}
function safe(output: string, paths: string[]) {
  expect(findLeaks({ root: repo, sentinels: join(repo, 'test/sentinels.json'),
    sentinelDir: sentinels(), testTmp: outerTmp(), commandOutput: output, paths })).toBeNull();
}
function inspectAndProbe(f: Context, out: string): Record<string, unknown> {
  const source = register(readFileSync(out));
  const remote = `/tmp/macwarden-cp025-${process.pid}-${serial++}.macaroon`;
  f.remote.push(remote);
  if (docker(['cp', source, `lnd:${remote}`]).status !== 0)
    throw new FixtureInvalidError('Fixture credential copy unavailable');
  const printed = lncli(['printmacaroon', `--macaroon_file=${remote}`]);
  const probe = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${remote}`, 'getinfo']);
  if (probe.error) throw new FixtureInvalidError('Independent lncli acceptance probe unavailable');
  // Authorization is established by lncli, independently of bake's own check.
  expect(probe.status, 'independent lncli GetInfo accepts the written credential').toBe(0);
  safe(probe.stdout + probe.stderr, [f.dir]);
  expect(printed.permissions).toEqual(JSON.parse(readFileSync(
    join(repo, 'test/vectors/preset-invoice-only.printmacaroon.json'), 'utf8')).permissions);
  return printed;
}
function fresh(id: string, before: string[]) {
  expect(id).toMatch(/^[1-9][0-9]*$/);
  expect(before).not.toContain(id);
  expect(BigInt(id) >= 4294967296n && BigInt(id) <= 9223372036854775807n).toBe(true);
}
function cli(f: Context, label: string, filename: string) {
  const out = join(f.dir, filename); declare(out); f.outputs.push(out);
  const env = childEnvironment(); delete env.NODE_OPTIONS; delete env.NODE_DEBUG;
  const result = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'bake', '--label', label,
    '--preset', 'invoice-only', '--out', out, '--registry', f.registry,
    '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', f.cert, '--macaroon', f.own, '--json'],
  { cwd: repo, env, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
  expect(result.error).toBeUndefined();
  if (existsSync(out)) register(readFileSync(out));
  safe(result.stdout + result.stderr, [f.dir]);
  return { ...result, out };
}

it('CP-025/concurrent-one-new-id concurrent fixture children add exactly one live ID and lncli accepts only winner output',
  async () => scenario(async f => {
    const before = ids();
    const rows = await contend(f.dir, { cert: f.cert, own: f.own });
    expect(rows.map(row => row.code).sort()).toEqual([0, 3]);
    const winner = rows.findIndex(row => row.code === 0), loser = 1 - winner;
    expect(rows[loser].calls).toEqual([]);
    expect(rows[winner].calls.filter(call => call === 'bakeMacaroon')).toHaveLength(1);
    const out = join(f.dir, `child-${winner}.macaroon`);
    expect(existsSync(join(f.dir, `child-${loser}.macaroon`))).toBe(false);
    const printed = inspectAndProbe(f, out), id = String(printed.root_key_id);
    fresh(id, before);
    expect(ids().filter(id => !before.includes(id))).toEqual([id]);
    const entries = JSON.parse(readFileSync(f.registry, 'utf8')).entries;
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ rootKeyId: id, outPath: out, verified: true, status: 'active' });
    expect(JSON.parse(rows[winner].stdout).result.rootKeyId).toBe(id);
    expect(JSON.parse(rows[loser].stdout).error).toMatchObject({ code: 3, step: 'B6' });
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    safe(rows.map(row => row.stdout + row.stderr).join(''), [f.dir]);
  }), 60_000);

it('CP-025/repeated-distinct-ids consecutive fixture bakes yield two fresh range-valid IDs confirmed by lncli',
  async () => scenario(async f => {
    const before = ids();
    const template = JSON.parse(readFileSync(join(repo, 'test/registry-fixtures/registry.json'), 'utf8')).entries[1];
    const prior = [{ ...template, nodePubkey: f.info.identity_pubkey, rootKeyId: '4294967296' },
      { ...template, rootKeyId: '4294967297' }];
    writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: prior }), { mode: 0o600 });
    const forbidden = [...before, ...prior.map((entry: {rootKeyId:string}) => entry.rootKeyId)];
    const first = cli(f, 'Alice', 'first.macaroon');
    expect(first.status).toBe(0);
    const firstPrinted = inspectAndProbe(f, first.out), firstId = String(firstPrinted.root_key_id);
    fresh(firstId, forbidden);
    expect(ids().filter(id => !before.includes(id))).toEqual([firstId]);
    const second = cli(f, 'Bob', 'second.macaroon');
    expect(second.status).toBe(0);
    const secondPrinted = inspectAndProbe(f, second.out), secondId = String(secondPrinted.root_key_id);
    fresh(secondId, [...forbidden, firstId]);
    expect(new Set([firstId, secondId]).size).toBe(2);
    expect(ids().filter(id => !before.includes(id)).sort()).toEqual([firstId, secondId].sort());
    expect(JSON.parse(first.stdout).result.rootKeyId).toBe(firstId);
    expect(JSON.parse(second.stdout).result.rootKeyId).toBe(secondId);
    const entries = JSON.parse(readFileSync(f.registry, 'utf8')).entries;
    expect(entries.slice(0, 2)).toEqual(prior);
    expect(entries.slice(2).map((entry: {rootKeyId:string}) => entry.rootKeyId)).toEqual([firstId, secondId]);
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
  }), 60_000);

it('CP-025/leak-check standing leak checker scans temporary outputs and registries with declared products excluded', () => {
  safe('', [temp()]);
});
