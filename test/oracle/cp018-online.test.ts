import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { findLeaks } from "../helpers/leak-check.js";

const repo = resolve();
const fixture = join(tmpdir(), 'macwarden-fixture');
const cert = join(fixture, 'tls.cert');
const macaroon = join(fixture, 'admin.macaroon');
const wrongCert = join(repo, 'test/fixture/wrong-tls.cert');
const testTmp = resolve(process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp'));
const sentinelDir = resolve(process.env.MACWARDEN_SENTINEL_DIR || join(testTmp, 'sentinels'));
const compose = fixtureTopology().composeArgs;

function registryArgs(args: string[]): string[] {
  const root = process.env.MACWARDEN_TEST_TMP;
  if (!root) throw new FixtureInvalidError('MACWARDEN_TEST_TMP is required');
  let path: string;
  do { path = join(resolve(root), `cp018-registry-${randomUUID()}.json`); }
  while (existsSync(path));
  return ['--registry', path, ...args];
}

function lncli(command: string) {
  const result = spawnSync('docker', [...compose, 'exec', '-T', 'lnd', 'lncli',
    '--network=regtest', command], { cwd: repo, encoding: 'utf8', timeout: 30_000 });
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture ${command} unavailable`);
  try { return JSON.parse(result.stdout) as Record<string, unknown>; }
  catch { throw new FixtureInvalidError(`Fixture ${command} returned invalid JSON`); }
}

function docker(args: string[]) {
  return spawnSync('docker', [...compose, ...args],
    { cwd: repo, encoding: 'utf8', timeout: 30_000, maxBuffer: 2_000_000 });
}

function pinnedIds(): string[] {
  const info = lncli('getinfo');
  const ids = lncli('listmacaroonids');
  requirePinnedFixture(info, ids);
  return (ids.root_key_ids as Array<string | number>).map(String);
}

function invoke(args: string[], extraEnv: Record<string, string> = {}, nodeArgs: string[] = []) {
  const env = childEnvironment({ ...extraEnv  });
  delete env.NODE_DEBUG;
  if (!extraEnv.NODE_OPTIONS) delete env.NODE_OPTIONS;
  const flags = [...args];
  if (!flags.includes('--lnd-rest')) flags.push('--lnd-rest', `localhost:${fixtureTopology().restPort}`);
  if (!flags.includes('--tls-cert')) flags.push('--tls-cert', cert);
  if (!flags.includes('--macaroon')) flags.push('--macaroon', macaroon);
  const run = spawnSync(process.execPath, [...nodeArgs, join(repo, 'dist/bin.js'), 'inventory', ...registryArgs(flags)],
  { cwd: repo, env, encoding: 'utf8', timeout: 15_000, maxBuffer: 2_000_000 });
  expect(run.error).toBeUndefined();
  return run;
}

function document(stdout: string) {
  let parsed: unknown;
  try { parsed = JSON.parse(stdout); }
  catch { throw new Error('Expected one JSON envelope'); }
  return parsed as {
    schema: number; command: string; ok: boolean; warnings: Array<{ code?: string } | string>;
    result: { rootKeys: Array<{ rootKeyId: string; inLnd: boolean; entry: unknown }> } | null;
    error: { code: number; step: string | null; message: string } | null;
  };
}

function assertNoCredential(output: string, bytes: Buffer) {
  const forms = [bytes.toString('hex'), bytes.toString('hex').toUpperCase(),
    bytes.toString('base64'), bytes.toString('base64url'),
    bytes.toString('base64').replace(/=+$/, ''), bytes.toString('latin1')];
  for (const form of forms) expect(output.includes(form)).toBe(false);
}

it('CP-018/ids-live provisional ID rows equal independent live lncli ListMacaroonIDs', () => {
  const expected = pinnedIds();
  const run = invoke(['--json']);
  expect(run.status).toBe(0);
  expect(run.stderr).toBe('');
  const result = document(run.stdout);
  expect(result.error).toBeNull();
  expect(result.result?.rootKeys.map(row => row.rootKeyId)).toEqual(expected);
  expect(result.result?.rootKeys.every(row => row.inLnd && row.entry === null)).toBe(true);
  expect(result.result?.rootKeys.find(row => row.rootKeyId === '0')).toBeDefined();
  assertNoCredential(run.stdout + run.stderr, readFileSync(macaroon));
});

it('CP-018/B5 own root key zero warns in text and JSON while inventory succeeds', () => {
  pinnedIds();
  const text = invoke([]);
  expect(text.status).toBe(0);
  expect(text.stderr).toMatch(/warning: own-root-key-0:/);
  const json = invoke(['--json']);
  expect(json.status).toBe(0);
  expect(json.stderr).toBe('');
  expect(document(json.stdout).warnings.some(warning =>
    typeof warning === 'string' ? warning === 'own-root-key-0' : warning.code === 'own-root-key-0')).toBe(true);
});

it('CP-018/B6 bundled permissions equal pinned live ListPermissions without drift', () => {
  pinnedIds();
  const run = invoke(['--json']);
  expect(run.status).toBe(0);
  expect(document(run.stdout).warnings.some(warning =>
    typeof warning === 'string' ? warning === 'snapshot-drift' : warning.code === 'snapshot-drift')).toBe(false);
});

it('CP-018/B9 a live uint64 ID above Number.MAX_SAFE_INTEGER stays exact in provisional rows', () => {
  const baseline = pinnedIds();
  const id = '9007199254740993';
  const remote = `/tmp/macwarden-cp018-${process.pid}-large.macaroon`;
  const baked = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    `--root_key_id=${id}`, `--save_to=${remote}`,
    'uri:/lnrpc.Lightning/GetInfo', 'uri:/lnrpc.Lightning/ListPermissions',
    'uri:/lnrpc.Lightning/ListMacaroonIDs']);
  if (baked.status !== 0) throw new FixtureInvalidError('Fixture could not bake large root key ID');
  let cleaned: boolean;
  try {
    mkdirSync(sentinelDir, { recursive: true, mode: 0o700 });
    const registered = join(sentinelDir, 'cp018-large.macaroon');
    if (docker(['cp', `lnd:${remote}`, registered]).status !== 0)
      throw new FixtureInvalidError('Fixture could not register large-ID sentinel');
    const independent = lncli('listmacaroonids').root_key_ids as Array<string | number>;
    const expected = independent.map(String).sort((a, b) =>
      BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0);
    expect(expected).toContain(id);
    const json = invoke(['--json']);
    expect(json.status).toBe(0);
    const rows = document(json.stdout).result?.rootKeys;
    expect(rows?.map(row => row.rootKeyId)).toEqual(expected);
    expect(rows?.every(row => row.inLnd && row.entry === null)).toBe(true);
    expect(json.stdout.includes(id)).toBe(true);
    const text = invoke([]);
    expect(text.status).toBe(0);
    expect(text.stdout).toContain(id);
    const ownUri = invoke(['--json', '--macaroon', registered]);
    expect(ownUri.status).toBe(0);
    expect(document(ownUri.stdout).result?.rootKeys.map(row => row.rootKeyId)).toEqual(expected);
    assertNoCredential(json.stdout + json.stderr + text.stdout + text.stderr,
      readFileSync(registered));
    assertNoCredential(ownUri.stdout + ownUri.stderr, readFileSync(registered));
  } finally {
    const deleted = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
      'deletemacaroonid', id]);
    docker(['exec', '-T', 'lnd', 'rm', '-f', remote]);
    cleaned = deleted.status === 0 && pinnedIds().join(',') === baseline.join(',');
  }
  if (!cleaned) throw new FixtureInvalidError('Fixture large-ID cleanup failed');
});

it('CP-018/failure-state-live wrong TLS and unreachable endpoint leave live root key IDs unchanged', () => {
  const before = pinnedIds();
  const bytes = readFileSync(macaroon);
  for (const json of [false, true]) {
    for (const failure of ['tls', 'port']) {
      const args = [...(json ? ['--json'] : []),
        '--lnd-rest', failure === 'port' ? '127.0.0.1:1' : `localhost:${fixtureTopology().restPort}`,
        '--tls-cert', failure === 'tls' ? wrongCert : cert];
      const run = invoke(args);
      expect(run.status, `${failure} json=${json}`).toBe(4);
      if (json) {
        expect(run.stderr).toBe('');
        expect(document(run.stdout).error).toMatchObject({ code: 4 });
      }
      assertNoCredential(run.stdout + run.stderr, bytes);
      expect(pinnedIds()).toEqual(before);
    }
  }
});

it('CP-018/B10 wrong TLS certificate and unreachable fixture port exit four in both output modes', () => {
  pinnedIds();
  const bytes = readFileSync(macaroon);
  for (const json of [false, true]) {
    for (const flags of [
      ['--tls-cert', wrongCert], ['--lnd-rest', '127.0.0.1:1'],
    ]) {
      const run = invoke([...(json ? ['--json'] : []), ...flags]);
      expect(run.status).toBe(4);
      if (json) expect(document(run.stdout).error).toMatchObject({ code: 4 });
      assertNoCredential(run.stdout + run.stderr, bytes);
    }
  }
});

it('CP-018/B7 a decodable foreign-node credential reaches LND auth refusal without changing IDs', () => {
  const before = pinnedIds();
  const foreign = join(repo, 'test/vectors/default-readonly.macaroon');
  const bytes = readFileSync(foreign);
  for (const json of [false, true]) {
    const run = invoke([...(json ? ['--json'] : []), '--macaroon', foreign]);
    expect(run.status).toBe(4);
    if (json) expect(document(run.stdout).error).toMatchObject({ code: 4 });
    assertNoCredential(run.stdout + run.stderr, bytes);
    expect(pinnedIds()).toEqual(before);
  }
});

it('CP-018/B8 unexpected mid-request crash exits internal without stack or inventory advice', () => {
  pinnedIds();
  const bytes = readFileSync(macaroon);
  const preload = pathToFileURL(join(repo, 'test/preloads/cp018-crash.mjs')).href;
  const run = invoke(['--json'], {
    NODE_OPTIONS: '',
    MACWARDEN_CRASH_MARKER: bytes.toString('hex'),
  }, ['--import', preload]);
  expect(run.status).toBe(8);
  expect(run.stderr).toBe('');
  const error = document(run.stdout).error;
  expect(error).toMatchObject({ code: 8, step: 'internal' });
  expect(error?.message).not.toMatch(/run.*inventory/i);
  expect(run.stdout).not.toMatch(/^\s+at /m);
  assertNoCredential(run.stdout, bytes);
});

it('CP-018/leak-check mid-request crash exits internal and registered sentinel does not leak', () => {
  pinnedIds();
  mkdirSync(sentinelDir, { recursive: true, mode: 0o700 });
  const registered = join(sentinelDir, 'cp018-own.macaroon');
  copyFileSync(macaroon, registered);
  const bytes = readFileSync(registered);
  const preload = pathToFileURL(join(repo, 'test/preloads/cp018-crash.mjs')).href;
  for (const json of [false, true]) {
    const run = invoke(json ? ['--json'] : [], {
      NODE_OPTIONS: '',
      MACWARDEN_CRASH_MARKER: bytes.toString('hex'),
    }, ['--import', preload]);
    expect(run.status).toBe(8);
    if (json) {
      expect(run.stderr).toBe('');
      expect(document(run.stdout).error).toMatchObject({ code: 8, step: 'internal' });
      expect(document(run.stdout).error?.message).not.toMatch(/run.*inventory/i);
    } else {
      expect(run.stderr).toContain('internal');
      expect(run.stderr).not.toMatch(/run.*inventory/i);
    }
    const output = run.stdout + run.stderr;
    expect(output).not.toMatch(/^\s+at /m);
    assertNoCredential(output, bytes);
  }
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    paths: [testTmp], testTmp, root: repo })).toBeNull();
});
