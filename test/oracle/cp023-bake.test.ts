import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync,
  readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from "../helpers/leak-check.js";
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { requirePinnedFixture } from '../helpers/lnd-facts.mjs';

const repo = resolve();
const fixture = join(tmpdir(), 'macwarden-fixture');
const cert = join(fixture, 'tls.cert');
const own = join(fixture, 'admin.macaroon');
const compose = fixtureTopology().composeArgs;

function temp(): string {
  if (!process.env.MACWARDEN_TEST_TMP) throw new FixtureInvalidError('MACWARDEN_TEST_TMP is required');
  const path = resolve(process.env.MACWARDEN_TEST_TMP);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}

function sentinels(): string {
  if (!process.env.MACWARDEN_SENTINEL_DIR)
    throw new FixtureInvalidError('MACWARDEN_SENTINEL_DIR is required');
  const path = resolve(process.env.MACWARDEN_SENTINEL_DIR);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}

function lncli(command: string): Record<string, unknown> {
  const run = spawnSync('docker', [...compose, 'exec', '-T', 'lnd', 'lncli',
    '--network=regtest', command], { cwd: repo, encoding: 'utf8', timeout: 30_000 });
  if (run.status !== 0) throw new FixtureInvalidError(`Fixture ${command} unavailable`);
  try { return JSON.parse(run.stdout) as Record<string, unknown>; }
  catch { throw new FixtureInvalidError(`Fixture ${command} returned invalid JSON`); }
}

function pinnedIds(): string[] {
  const info = lncli('getinfo');
  const ids = lncli('listmacaroonids');
  requirePinnedFixture(info, ids);
  let cp015: { fixture?: { network?: string; version?: string; baselineRootKeyIds?: string[] };
    fixtureBasics?: { snapshotMatches?: boolean } };
  try { cp015 = JSON.parse(readFileSync(join(repo, 'test/oracle/facts/observations.json'), 'utf8')); }
  catch { throw new FixtureInvalidError('CP-015 prerequisite observations unavailable'); }
  if (cp015.fixture?.network !== 'regtest' ||
      !cp015.fixture.version?.startsWith('0.21.4-beta') ||
      JSON.stringify(cp015.fixture.baselineRootKeyIds) !== '["0"]' ||
      cp015.fixtureBasics?.snapshotMatches !== true)
    throw new FixtureInvalidError('CP-015 prerequisite observations invalid');
  if (!existsSync(cert) || !existsSync(own))
    throw new FixtureInvalidError('Fixture credential copy unavailable');
  return (ids.root_key_ids as Array<string | number>).map(String);
}

function registeredOwn(): string {
  const target = join(sentinels(), 'cp023-live-own.macaroon');
  copyFileSync(own, target);
  appendFileSync(join(temp(), 'declared-out.txt'), `${target}\n`);
  return target;
}

function invoke(args: string[], registry: string, out: string, macaroon: string) {
  const env = childEnvironment();
  delete env.NODE_DEBUG;
  delete env.NODE_OPTIONS;
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'bake',
    '--registry', registry, '--out', out, '--lnd-rest', `localhost:${fixtureTopology().restPort}`,
    '--tls-cert', cert, '--macaroon', macaroon, ...args],
  { cwd: repo, env, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
  expect(run.error).toBeUndefined();
  return run;
}

function document(stdout: string) {
  let parsed: unknown;
  try { parsed = JSON.parse(stdout); }
  catch { throw new Error('Expected exactly one bake JSON envelope'); }
  return parsed as { schema: number; command: string; ok: boolean;
    result: { dryRun: boolean; label: string; permissions: string[];
      grade: string; caveats: unknown[] } | null;
    error: { code: number; step: string } | null;
    warnings: Array<string | { code: string }> };
}

function assertNoCredential(output: string, bytes: Buffer): void {
  for (const form of [bytes.toString('utf8'), bytes.toString('latin1'),
    bytes.toString('hex'), bytes.toString('hex').toUpperCase(), bytes.toString('base64'),
    bytes.toString('base64url'), bytes.toString('base64').replace(/=+$/, ''),
    bytes.toString('base64url').replace(/=+$/, '')]) {
    if (form) expect(output).not.toContain(form);
  }
}

function state(registry: string, out: string) {
  return {
    ids: pinnedIds(),
    registry: existsSync(registry) ? readFileSync(registry) : null,
    registryMtime: existsSync(registry) ? statSync(registry).mtimeMs : null,
    out: existsSync(out) ? readFileSync(out) : null,
    outMtime: existsSync(out) ? statSync(out).mtimeMs : null,
    lock: existsSync(`${registry}.lock`) ? readFileSync(`${registry}.lock`) : null,
  };
}

function unchanged(before: ReturnType<typeof state>, after: ReturnType<typeof state>) {
  expect(after.ids).toEqual(before.ids);
  expect(after.registry?.equals(before.registry || Buffer.alloc(0)) ?? null)
    .toBe(before.registry === null ? null : true);
  expect(after.registryMtime).toBe(before.registryMtime);
  expect(after.out?.equals(before.out || Buffer.alloc(0)) ?? null)
    .toBe(before.out === null ? null : true);
  expect(after.outMtime).toBe(before.outMtime);
  expect(after.lock?.equals(before.lock || Buffer.alloc(0)) ?? null)
    .toBe(before.lock === null ? null : true);
}

it.each(['text', 'json'] as const)(
  'CP-023/dry-run-unchanged %s plan leaves live IDs, registry bytes and mtime, out and lock unchanged',
  mode => {
  pinnedIds();
  const dir = mkdtempSync(join(temp(), 'cp023-live-dry-'));
  try {
    const registry = join(dir, 'registry.json');
    const out = join(dir, 'candidate.macaroon');
    const macaroon = registeredOwn();
    writeFileSync(registry, '{"schema":1,"entries":[]}');
    const before = state(registry, out);
    const run = invoke(['--label', 'Alice', '--preset', 'invoice-only', '--dry-run',
      ...(mode === 'json' ? ['--json'] : [])], registry, out, macaroon);
    expect(run.status).toBe(0);
    if (mode === 'json') {
      expect(run.stderr).toBe('');
      expect(document(run.stdout)).toMatchObject({ schema: 1, command: 'bake', ok: true,
        result: { dryRun: true, label: 'Alice', grade: 'RECEIVE',
          permissions: ['info:read', 'invoices:read', 'invoices:write'], caveats: [] }, error: null });
    } else {
      for (const expected of ['Alice', 'RECEIVE', 'info:read', 'invoices:write',
        'root key ID: allocated at bake time']) expect(run.stdout).toContain(expected);
    }
    unchanged(before, state(registry, out));
    assertNoCredential(run.stdout + run.stderr, readFileSync(macaroon));
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 60_000);

it.each(['request', 'held lock', 'existing out'] as const)(
  'CP-023/refusals-unchanged %s leaves independent live state untouched', kind => {
  pinnedIds();
  const dir = mkdtempSync(join(temp(), 'cp023-live-refusal-'));
  try {
    const registry = join(dir, 'registry.json');
    const out = join(dir, 'candidate.macaroon');
    const macaroon = registeredOwn();
    writeFileSync(registry, '{"schema":1,"entries":[]}');
    if (kind === 'held lock') writeFileSync(`${registry}.lock`,
      JSON.stringify({ pid: 12345, hostname: 'other-host', startedAt: '2026-10-04T00:00:00Z' }));
    if (kind === 'existing out') writeFileSync(out, 'existing operator file');
    const before = state(registry, out);
    const run = invoke(kind === 'request' ? ['--label', 'Alice', '--permissions', 'loop:write', '--json'] :
      ['--label', 'Alice', '--preset', 'invoice-only', '--json'], registry, out, macaroon);
    const code = kind === 'request' ? 2 : 3;
    const step = kind === 'request' ? 'B3' : kind === 'held lock' ? 'B6' : 'B4';
    expect(run.status).toBe(code);
    expect(run.stderr).toBe('');
    expect(document(run.stdout).error).toMatchObject({ code, step });
    unchanged(before, state(registry, out));
    assertNoCredential(run.stdout + run.stderr, readFileSync(macaroon));
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 60_000);

it('CP-023/leak-check live OWN sentinel is absent from temporary output and registry', () => {
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: sentinels(),
    paths: [temp()], testTmp: temp(), root: repo })).toBeNull();
});
