import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as fs from 'node:fs/promises';
import { expect, it } from 'vitest';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { requirePinnedFixture, registerFixtureSentinel } from '../helpers/lnd-facts.mjs';
import { findLeaks } from "../helpers/leak-check.js";

const repo = resolve();
const fixtureDir = join(tmpdir(), 'macwarden-fixture');
const cert = join(fixtureDir, 'tls.cert');
const own = join(fixtureDir, 'admin.macaroon');
const compose = fixtureTopology().composeArgs;
const pubkeyFromInfo = (info: Record<string, unknown>) => String(info.identity_pubkey);
const vectorManifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: Array<{ name: string; fingerprint: string; expectedGrade: string }> };
const readVector = vectorManifest.vectors.find(item => item.name === 'default-readonly');
if (!readVector) throw new Error('Missing default-readonly vector metadata');

function docker(args: string[]) {
  return spawnSync('docker', [...compose, ...args],
    { cwd: repo, encoding: 'utf8', timeout: 30_000, maxBuffer: 2_000_000 });
}

function lncli(command: string, args: string[] = []): Record<string, unknown> {
  const run = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', command, ...args]);
  if (run.status !== 0) throw new FixtureInvalidError(`Fixture ${command} unavailable`);
  try { return JSON.parse(run.stdout) as Record<string, unknown>; }
  catch { throw new FixtureInvalidError(`Fixture ${command} returned invalid JSON`); }
}

function baseline() {
  const info = lncli('getinfo');
  const ids = lncli('listmacaroonids');
  requirePinnedFixture(info, ids);
  return { info, ids: (ids.root_key_ids as Array<string | number>).map(String) };
}

function currentIds(): string[] {
  return (lncli('listmacaroonids').root_key_ids as Array<string | number>).map(String)
    .sort((a, b) => BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0);
}

async function temp<T>(work: (dir: string) => T | Promise<T>): Promise<T> {
  const base = process.env.MACWARDEN_TEST_TMP;
  if (!base) throw new FixtureInvalidError('MACWARDEN_TEST_TMP is required');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(base, 'cp019-oracle-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function inventory(registryPath: string, json = true) {
  const env = childEnvironment();
  delete env.NODE_DEBUG;
  delete env.NODE_OPTIONS;
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inventory',
    ...(json ? ['--json'] : []), '--lnd-rest', `localhost:${fixtureTopology().restPort}`,
    '--tls-cert', cert, '--macaroon', own, '--registry', registryPath],
  { cwd: repo, env, encoding: 'utf8', timeout: 15_000, maxBuffer: 2_000_000 });
  expect(run.error).toBeUndefined();
  return run;
}

function document(output: string) {
  return JSON.parse(output) as { schema: number; command: string; ok: boolean;
    result: { node: { pubkey: string; alias: string; network: string; version: string };
      rootKeys: Array<{ rootKeyId: string; inLnd: boolean; flags: string[];
        verify: string; entry: Record<string, unknown> | null }> } | null;
    error: { code: number } | null };
}

it('CP-019/fresh-node-live independent lncli IDs match rows and own default root key', () => temp(dir => {
  const { info, ids } = baseline();
  const registry = join(dir, 'absent.json');
  const json = inventory(registry);
  expect(json.status).toBe(0);
  expect(json.stderr).toBe('');
  const actual = document(json.stdout);
  expect(actual.error).toBeNull();
  expect(actual.result?.node).toEqual({ pubkey: pubkeyFromInfo(info), alias: info.alias,
    network: 'regtest', version: info.version });
  expect(actual.result?.rootKeys.map(row => row.rootKeyId)).toEqual(ids);
  // 1.0.1: macwarden's own credential is recognised as such, never as unknown.
  const zero = actual.result?.rootKeys.find(row => row.rootKeyId === '0')?.flags;
  expect(zero).toEqual(expect.arrayContaining(['default-root-key', 'own-credential']));
  expect(zero).not.toContain('unknown');
  const text = inventory(registry, false);
  expect(text.status).toBe(0);
  expect(text.stdout).toContain('default root key: cannot be individually revoked');
  expect(existsSync(registry)).toBe(false);
  expect(existsSync(`${registry}.lock`)).toBe(false);
  expect(currentIds()).toEqual(ids);
}));

it('CP-019/unknown-and-missing-live independently baked ID and absent active entry preserve LND state', () => temp(dir => {
  const { info, ids: before } = baseline();
  const unknownId = '9007199254740993';
  const missingId = '18446744073709551615';
  const remote = `/tmp/macwarden-cp019-${process.pid}.macaroon`;
  const baked = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    'bakemacaroon', `--root_key_id=${unknownId}`, `--save_to=${remote}`, 'info:read']);
  if (baked.status !== 0) throw new FixtureInvalidError('Fixture could not bake unknown root key ID');
  let cleaned: boolean;
  try {
    const sentinelDir = process.env.MACWARDEN_SENTINEL_DIR;
    if (!sentinelDir) throw new FixtureInvalidError('MACWARDEN_SENTINEL_DIR is required');
    const sentinel = registerFixtureSentinel(own, 'cp019-own.macaroon', sentinelDir);
    const unknown = join(sentinelDir, 'cp019-unknown.macaroon');
    if (docker(['cp', `lnd:${remote}`, unknown]).status !== 0)
      throw new FixtureInvalidError('Fixture could not register baked sentinel');
    const observed = currentIds();
    expect(observed).toContain(unknownId);
    expect(observed).not.toContain(missingId);
    const registry = join(dir, 'registry.json');
    writeFileSync(registry, JSON.stringify({ schema: 1, entries: [{
      nodePubkey: pubkeyFromInfo(info), label: 'absent', rootKeyId: missingId,
      permissions: ['info:read'], caveats: [], grade: readVector.expectedGrade,
      fingerprint: readVector.fingerprint, outPath: null,
      createdAt: '2026-10-02T09:00:00Z', verified: false, status: 'active',
      revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null,
    }] }), { mode: 0o600 });
    const bytes = readFileSync(registry);
    const mtime = statSync(registry).mtimeMs;
    const first = inventory(registry);
    const second = inventory(registry);
    expect(first.status).toBe(0);
    expect(second.status).toBe(0);
    const firstResult = document(first.stdout).result;
    expect(firstResult).toEqual(document(second.stdout).result);
    expect(firstResult?.rootKeys.map(row => row.rootKeyId)).toEqual(
      [...observed, missingId].sort((a, b) => BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0));
    expect(firstResult?.rootKeys.find(row => row.rootKeyId === unknownId)).toMatchObject({
      inLnd: true, flags: ['unknown'], entry: null, verify: 'not-checked' });
    expect(firstResult?.rootKeys.find(row => row.rootKeyId === missingId)).toMatchObject({
      inLnd: false, flags: ['missing-in-lnd'], verify: 'not-checked' });
    expect(readFileSync(registry).equals(bytes)).toBe(true);
    expect(statSync(registry).mtimeMs).toBe(mtime);
    expect(existsSync(`${registry}.lock`)).toBe(false);
    expect(currentIds()).toEqual(observed);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: first.stdout + first.stderr + second.stdout + second.stderr,
      paths: [dir], testTmp: dir, root: repo })).toBeNull();
    expect(readFileSync(sentinel).length).toBeGreaterThan(0);
  } finally {
    const removed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
      'deletemacaroonid', unknownId]);
    docker(['exec', '-T', 'lnd', 'rm', '-f', remote]);
    cleaned = removed.status === 0 && currentIds().join(',') === before.join(',');
  }
  if (!cleaned) throw new FixtureInvalidError('Fixture unknown-ID cleanup failed');
}));

it('CP-019/leak-check registered sentinel stays out of inventory output and registry', () => temp(async dir => {
  const sentinelDir = process.env.MACWARDEN_SENTINEL_DIR;
  if (!sentinelDir) throw new FixtureInvalidError('MACWARDEN_SENTINEL_DIR is required');
  const source = join(repo, 'test/vectors/default-readonly.macaroon');
  const registered = registerFixtureSentinel(source, 'cp019-offline-own.macaroon', sentinelDir);
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }), { mode: 0o600 });
  const bytes = readFileSync(registered);
  const forms = [bytes.toString('utf8'), bytes.toString('latin1'), bytes.toString('hex'),
    bytes.toString('hex').toUpperCase(), bytes.toString('base64'),
    bytes.toString('base64url'), bytes.toString('base64').replace(/=+$/, ''),
    bytes.toString('base64url').replace(/=+$/, '')];
  const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as {
    methods: Record<string, string[]> };

  const command = await import('../../src/commands/inventory.js') as unknown as {
    run: (args: string[], deps: unknown) => Promise<unknown> };
  const result = await command.run(['--lnd-rest', '127.0.0.1:1',
    '--tls-cert', join(repo, 'test/fixture/wrong-tls.cert'),
    '--macaroon', registered, '--registry', registry], {
      lnd: {
        getInfo: async () => ({ pubkey: '02' + 'ab'.repeat(32), alias: 'alice',
          network: 'regtest', version: '0.21.4-beta' }),
        listPermissions: async () => snapshot.methods,
        listMacaroonIds: async () => [0n],
      }, fs, env: {}, clock: () => new Date('2026-10-04T00:00:00Z'),
    });
  expect(result).toMatchObject({ ok: true, error: null });
  const { render } = await import('../helpers/render-adversarial.js');
  const output = render(result as Parameters<typeof render>[0], 'json') +
    render(result as Parameters<typeof render>[0], 'text');
  for (const form of forms) expect(output.includes(form)).toBe(false);
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    commandOutput: output, paths: [dir], testTmp: dir, root: repo })).toBeNull();
}));
