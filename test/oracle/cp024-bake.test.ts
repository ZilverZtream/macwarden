import { fixtureTopology } from '../fixture/topology.mjs';
import { revealSecret } from '../helpers/secret-bytes.js';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync,
  rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { Secret } from '../../src/secret.js';
import { render } from '../helpers/render-adversarial.js';
import { findLeaks } from "../helpers/leak-check.js";
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { registerFixtureSentinel, requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { probeHtlcInterceptor } from '../helpers/cp024-htlc-probe.mjs';
import { cp024Compose } from '../fixture/cp024-fixture.mjs';

type Envelope = { schema: number; command: string; ok: boolean; warnings: Array<string | {code:string;message?:string}>;
  result: Record<string, unknown> | null;
  error: { code: number; step: string; message: string } | null };
type Adapter = {
  getInfo(): Promise<unknown>; listPermissions(): Promise<unknown>;
  listMacaroonIds(): Promise<bigint[]>;
  bakeMacaroon(perms: string[], id: bigint): Promise<Secret>;
  checkMacaroon(mac: Secret, perms: string[]): Promise<unknown>;
};
const repo = resolve();
function temp(): string {
  const value = process.env.MACWARDEN_TEST_TMP;
  if (!value) throw new FixtureInvalidError('MACWARDEN_TEST_TMP is required');
  const path = resolve(value); mkdirSync(path, { recursive: true, mode: 0o700 }); return path;
}
function sentinels(): string {
  const value = process.env.MACWARDEN_SENTINEL_DIR;
  if (!value) throw new FixtureInvalidError('MACWARDEN_SENTINEL_DIR is required');
  const path = resolve(value); mkdirSync(path, { recursive: true, mode: 0o700 }); return path;
}
const cert = () => join(tmpdir(), 'macwarden-fixture', 'tls.cert');
const own = () => join(tmpdir(), 'macwarden-fixture', 'admin.macaroon');
function declare(path: string) { appendFileSync(join(temp(), 'declared-out.txt'), `${path}\n`); }
function docker(args: string[]) {
  return spawnSync('docker', [...cp024Compose, ...args], { cwd: repo, encoding: 'utf8',
    timeout: 20_000, maxBuffer: 2_000_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function ids(): string[] {
  return (lncli(['listmacaroonids']).root_key_ids as Array<string | number>).map(String);
}
function guard() {
  const info = lncli(['getinfo']), before = lncli(['listmacaroonids']);
  requirePinnedFixture(info, before);
  let cp015: { fixture?: { network?: string; version?: string; baselineRootKeyIds?: string[] };
    fixtureBasics?: { snapshotMatches?: boolean; bakedLocation?: string };
    emptyPermissionCheck?: { corruptRejectedByOrdinaryRpc?: boolean } };
  try { cp015 = JSON.parse(readFileSync(join(repo, 'test/oracle/facts/observations.json'), 'utf8')); }
  catch { throw new FixtureInvalidError('CP-015 prerequisite facts unavailable'); }
  if (cp015.fixture?.network !== 'regtest' || !cp015.fixture.version?.startsWith('0.21.4-beta') ||
      JSON.stringify(cp015.fixture.baselineRootKeyIds) !== '["0"]' ||
      cp015.fixtureBasics?.snapshotMatches !== true || cp015.fixtureBasics.bakedLocation !== 'lnd' ||
      cp015.emptyPermissionCheck?.corruptRejectedByOrdinaryRpc !== true)
    throw new FixtureInvalidError('CP-015 prerequisite facts invalid');
  if (!existsSync(cert()) || !existsSync(own())) throw new FixtureInvalidError('Workspace fixture copies unavailable');
  declare(own());
  // Register the copied fixture OWN credential before any command sees it.
  const path = join(sentinels(), 'cp024-live-own.macaroon'); copyFileSync(own(), path); declare(path);
  return { info, before: (before.root_key_ids as string[]).map(String), own: path };
}
let serial = 0;
function register(source: string): string {
  const path = registerFixtureSentinel(source, `cp024-live-${serial++}.macaroon`, sentinels());
  declare(path); return path;
}
function copyToContainer(source: string, remote: string) {
  if (docker(['cp', source, `lnd:${remote}`]).status !== 0)
    throw new FixtureInvalidError('Fixture credential copy unavailable');
}
function probe(remote: string, command: string[]) {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    `--macaroonpath=${remote}`, ...command]);
  if (result.error) throw new FixtureInvalidError('Independent acceptance probe unavailable');
  if (result.status === 0) return 'accepted';
  if (/permission denied|permission\b.*(?:denied|not allowed)|not authorized/i.test(result.stderr)) return 'permission-denied';
  if (/time-before|expired|not yet valid/i.test(result.stderr)) return 'time-rejected';
  return 'unexpected';
}
function safe(output: string, paths: string[] = []) {
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: sentinels(),
    commandOutput: output, paths, testTmp: temp(), root: repo })).toBeNull();
  expect(output).not.toMatch(/^\s+at\s+.*:\d+/m);
}
async function scenario(work: (f: { dir: string; out: string; registry: string;
  remote: string; own: string; before: string[]; info: Record<string, unknown> }) => Promise<void>) {
  const baseline = guard();
  const dir = mkdtempSync(join(temp(), 'cp024-live-'));
  const out = join(dir, 'candidate.macaroon'), registry = join(dir, 'registry.json');
  declare(out); writeFileSync(registry, '{"schema":1,"entries":[]}', { mode: 0o600 });
  const remote = `/tmp/macwarden-cp024-${process.pid}-${serial++}.macaroon`;
  try { await work({ dir, out, registry, remote, ...baseline }); }
  finally { cleanup(baseline.before, remote, dir); }
}
function cleanup(baselineIds: string[], remote: string, dir: string) {
    // Independent live IDs catch even a lost response, so cleanup never relies
    // on the command's registry or result. This session owns the fixture.
    for (const id of ids().filter(id => !baselineIds.includes(id))) {
      if (id === '0') throw new FixtureInvalidError('Refusing fixture root-zero cleanup');
      if (lncli(['deletemacaroonid', id]).deleted !== true)
        throw new FixtureInvalidError('Fixture issued ID cleanup failed');
    }
    docker(['exec', '-T', 'lnd', 'rm', '-f', remote]);
    rmSync(dir, { recursive: true, force: true });
    requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
}
function cli(f: { out: string; registry: string; own: string }, flags: string[]) {
  const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
  const result = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'bake', '--label', 'Alice',
    '--out', f.out, '--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`,
    '--tls-cert', cert(), '--macaroon', f.own, ...flags],
  { cwd: repo, env, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
  expect(result.error).toBeUndefined();
  if (existsSync(f.out) && statSync(f.out).size > 0) register(f.out);
  safe(result.stdout + result.stderr, [dirname(f.registry)]);
  return result;
}
const presets = {
  'read-only': { grade: 'READ', forbidden: ['listmacaroonids'] },
  'invoice-only': { grade: 'RECEIVE', forbidden: ['listpayments'] },
  'pay-only': { grade: 'SPEND', forbidden: ['listinvoices'] },
};

it.each(Object.keys(presets) as Array<keyof typeof presets>)(
  'CP-024/bake-ids-and-preset-authority %s live ID and permitted/forbidden lncli RPCs',
  async preset => scenario(async f => {
    const command = cli(f, ['--preset', preset, '--json']);
    expect(command.status).toBe(0); expect(command.stderr).toBe('');
    const envelope = JSON.parse(command.stdout) as Envelope;
    expect(envelope).toMatchObject({ schema: 1, command: 'bake', ok: true, error: null });
    const entry = envelope.result!;
    expect(typeof entry.rootKeyId).toBe('string');
    expect(entry.rootKeyId).toMatch(/^[1-9][0-9]*$/);
    expect(f.before).not.toContain(entry.rootKeyId);
    expect(ids().filter(id => !f.before.includes(id))).toEqual([entry.rootKeyId]);
    const registered = register(f.out); copyToContainer(registered, f.remote);
    expect(probe(f.remote, ['getinfo'])).toBe('accepted');
    expect(probe(f.remote, presets[preset].forbidden)).toBe('permission-denied');
    const printed = lncli(['printmacaroon', `--macaroon_file=${f.remote}`]);
    const reference = JSON.parse(readFileSync(join(repo, `test/vectors/preset-${preset}.printmacaroon.json`), 'utf8'));
    expect((printed.permissions as string[]).slice().sort()).toEqual(reference.permissions.slice().sort());
    if (preset === 'pay-only') {
      expect(probe(f.remote, ['updatechanpolicy', '--base_fee_msat=1', '--fee_rate=0.000001',
        '--time_lock_delta=40'])).toBe('permission-denied');
      expect(await probeHtlcInterceptor(cert(), registered)).toBe('permission-denied');
    }
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
  }), 60_000);

it('CP-024/bake-output-printmacaroon live lncli reports final ID, requested authority and appended expiry',
  async () => scenario(async f => {
    const result = cli(f, ['--preset', 'invoice-only', '--expires', '90d', '--json']);
    expect(result.status).toBe(0); expect(result.stderr).toBe('');
    const envelope = JSON.parse(result.stdout) as Envelope;
    const entry = envelope.result!;
    const registered = register(f.out); copyToContainer(registered, f.remote);
    const printed = lncli(['printmacaroon', `--macaroon_file=${f.remote}`]);
    expect(printed.root_key_id).toBe(entry.rootKeyId);
    expect(printed.permissions).toEqual(['info:read', 'invoices:read', 'invoices:write']);
    const expiry = (entry.caveats as Array<{ type: string; value: string; requested: string }>)[0];
    expect(expiry).toMatchObject({ type: 'time-before', requested: '90d' });
    expect(expiry.value).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    expect(printed.caveats).toEqual([`time-before ${expiry.value}`]);
    expect(probe(f.remote, ['getinfo'])).toBe('accepted');
    const fp = `fp:${createHash('sha256').update(readFileSync(f.out)).digest('hex').slice(0, 16)}`;
    expect(entry).toMatchObject({ nodePubkey: f.info.identity_pubkey, label: 'Alice',
      fingerprint: fp, grade: 'RECEIVE', outPath: f.out, verified: true, status: 'active',
      revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null });
    expect(JSON.parse(readFileSync(f.registry, 'utf8')).entries).toEqual([entry]);
    if (process.platform !== 'win32') {
      expect(statSync(f.out).mode & 0o777).toBe(0o600);
      expect(statSync(f.registry).mode & 0o777).toBe(0o600);
      expect(statSync(f.dir).mode & 0o777).toBe(0o700);
    }
    const inspected = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', f.out, '--json'],
      { cwd: repo, encoding: 'utf8', timeout: 10_000 });
    expect(inspected.status).toBe(0);
    safe(inspected.stdout + inspected.stderr);
    const inspection = JSON.parse(inspected.stdout).result;
    expect(inspection.fingerprint).toBe(fp);
    expect(inspection.caveats).toContainEqual(expect.objectContaining({ type: 'time-before', value: expiry.value }));
  }), 60_000);

it('CP-024/bake-expiry-rejected clock two days back with one-day expiry fails B14 and lncli independently rejects final bytes',
  async () => scenario(async f => {

    const { createLndAdapter } = await import('../../src/lnd/index.js') as {
      createLndAdapter: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => Adapter;
    };
    const adapter = createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: readFileSync(cert()),
      macaroon: new Secret(readFileSync(f.own)) });
    let captured: string | undefined;
    const deps = { fs: { ...fs }, env: {} as Record<string, string>,
      clock: () => new Date(Date.now() - 2 * 86400_000),
      lnd: new Proxy(adapter, { get(target, key) {
        if (key === 'listMacaroonIds') return () => adapter.listMacaroonIds();
        if (key !== 'checkMacaroon') {
          const value = Reflect.get(target, key, target);
          return typeof value === 'function' ? value.bind(target) : value;
        }
        return async (mac: Secret, requested: string[]) => {
        const path = join(sentinels(), `cp024-expired-${serial++}.macaroon`);
        writeFileSync(path, Buffer.from(revealSecret(mac)), { mode: 0o600 }); declare(path); captured = path;
        // Observation only: the real pinned adapter still checks the final bytes.
        return adapter.checkMacaroon(mac, requested);
        };
      } }) };

    const command = await import('../../src/commands/bake/index.js') as {
      run: (args: string[], deps: unknown) => Promise<Envelope>;
    };
    const result = await command.run(['--label', 'Alice', '--preset', 'invoice-only', '--expires', '1d',
      '--out', f.out, '--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`,
      '--tls-cert', cert(), '--macaroon', f.own, '--json'], deps);
    expect(result.error).toMatchObject({ code: 7, step: 'B14' });
    expect(captured).toBeDefined(); copyToContainer(captured!, f.remote);
    const printed = lncli(['printmacaroon', `--macaroon_file=${f.remote}`]);
    const condition = (printed.caveats as string[]).at(-1)!;
    expect(condition.startsWith('time-before ')).toBe(true);
    expect(Date.parse(condition.slice('time-before '.length))).toBeLessThan(Date.now());
    expect(probe(f.remote, ['getinfo'])).toBe('time-rejected');
    expect(existsSync(f.out)).toBe(false);
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    const entry = JSON.parse(readFileSync(f.registry, 'utf8')).entries[0];
    expect(entry).toMatchObject({ rootKeyId: printed.root_key_id, status: 'active', verified: false, outPath: null });
    const allocated = String(printed.root_key_id);
    expect(ids().filter(id => !f.before.includes(id))).toEqual([allocated]);
    const recovery = result.error!.message.match(/macwarden revoke ([1-9][0-9]*)( --unregistered)?([^;\n]*)/);
    expect(recovery?.[1]).toBe(allocated);
    expect(recovery?.[2]).toBeUndefined(); // The pending entry is present in this registry.
    const flags = ['--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`,
      '--tls-cert', cert(), '--macaroon', f.own];
    for (let index = 0; index < flags.length; index += 2) {
      expect(recovery?.[3]).toContain(flags[index]);
      expect(recovery?.[3]).toContain(flags[index + 1]);
    }
    // Exercise the prescribed numeric target with the same connection and
    // registry, rather than merely accepting a recovery-shaped message.
    const recovered = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'revoke', allocated,
      ...flags, '--yes', '--json'], { cwd: repo, env: childEnvironment(), encoding: 'utf8',
        timeout: 20_000, maxBuffer: 2_000_000 });
    expect(recovered.error).toBeUndefined(); expect(recovered.status).toBe(0);
    const document = JSON.parse(recovered.stdout) as Envelope;
    expect(document).toMatchObject({ schema: 1, command: 'revoke', ok: true, error: null,
      result: { rootKeyId: allocated, evidence: 'by-id-only', entry: { status: 'revoked' } } });
    expect(ids()).toEqual(f.before);
    expect(JSON.parse(readFileSync(f.registry, 'utf8')).entries).toEqual([document.result!.entry]);
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    safe(recovered.stdout + recovered.stderr, [f.dir]);
    safe(render(result, 'text') + render(result, 'json'), [f.dir]);
  }), 60_000);

it('CP-024/leak-check registered live credentials are absent from output, registry and undeclared temporary files', () => {
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: sentinels(),
    paths: [temp()], testTmp: temp(), root: repo })).toBeNull();
});
