import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { classifyAcceptance, registerFixtureSentinel, requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { findLeaks } from "../helpers/leak-check.js";
import { render } from '../helpers/render-adversarial.js';

const repo = resolve();
const compose = fixtureTopology().composeArgs;
const fixtureDir = join(tmpdir(), 'macwarden-fixture');
const cert = join(fixtureDir, 'tls.cert');
const admin = join(fixtureDir, 'admin.macaroon');
const remotePrefix = `/tmp/macwarden-cp020-${process.pid}`;
const ids = ['20031', '20022'];
const ownId = '20023';
const freshId = '20032';
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: Array<{ name: string; expectedGrade: string }> };
const readGrade = manifest.vectors.find(item => item.name === 'default-readonly')?.expectedGrade;
if (!readGrade) throw new Error('Missing pinned read grade');

function docker(args: string[]) {
  return spawnSync('docker', [...compose, ...args],
    { cwd: repo, encoding: 'utf8', timeout: 30_000, maxBuffer: 2_000_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout) as Record<string, unknown>; }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function rootIds(): string[] {
  return (lncli(['listmacaroonids']).root_key_ids as Array<string | number>).map(String)
    .sort((a, b) => BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0);
}
function baseline() {
  const info = lncli(['getinfo']);
  const state = lncli(['listmacaroonids']);
  requirePinnedFixture(info, state);
  return String(info.identity_pubkey);
}
async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  const base = process.env.MACWARDEN_TEST_TMP;
  if (!base) throw new FixtureInvalidError('MACWARDEN_TEST_TMP is required');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(base, 'cp020-oracle-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function sentinel(name: string, remote: string, dir: string): string {
  const copied = join(dir, `${name}.macaroon`);
  if (docker(['cp', `lnd:${remote}`, copied]).status !== 0)
    throw new FixtureInvalidError('Fixture credential copy failed');
  const registered = registerFixtureSentinel(copied, `cp020-${name}.macaroon`);
  rmSync(copied);
  const base = process.env.MACWARDEN_TEST_TMP;
  if (!base) throw new FixtureInvalidError('MACWARDEN_TEST_TMP is required');
  writeFileSync(join(base, 'declared-out.txt'), `${copied}\n${registered}\n`, { flag: 'a' });
  return registered;
}
function bake(id: string, name: string, dir: string, permissions = ['info:read']): {
  remote: string; local: string; permissions: string[] } {
  const remote = `${remotePrefix}-${name}.macaroon`;
  const run = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    `--root_key_id=${id}`, `--save_to=${remote}`, ...permissions]);
  if (run.status !== 0) throw new FixtureInvalidError('Fixture bake unavailable');
  const printed = lncli(['printmacaroon', `--macaroon_file=${remote}`]);
  if (String(printed.root_key_id) !== id || !Array.isArray(printed.permissions) ||
      printed.permissions.length === 0) throw new FixtureInvalidError('Fixture printed macaroon facts invalid');
  return { remote, local: sentinel(name, remote, dir), permissions: printed.permissions as string[] };
}
function registry(dir: string, pubkey: string, entries: Array<{ id: string; path: string; permissions: string[] }>) {
  const path = join(dir, 'registry.json');
  writeFileSync(path, JSON.stringify({ schema: 1, entries: entries.map(item => ({
    nodePubkey: pubkey, label: `registered${item.id}`, rootKeyId: item.id,
    permissions: item.permissions, caveats: [], grade: readGrade,
    fingerprint: `fp:${createHash('sha256').update(readFileSync(item.path)).digest('hex').slice(0, 16)}`,
    outPath: item.path, createdAt: '2026-10-02T09:00:00Z', verified: true,
    status: 'active', revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null,
  })) }), { mode: 0o600 });
  return path;
}
function inventory(path: string, own = admin, json = true) {
  const env = childEnvironment();
  delete env.NODE_DEBUG;
  delete env.NODE_OPTIONS;
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inventory', '--verify',
    ...(json ? ['--json'] : []), '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', cert,
    '--macaroon', own, '--registry', path],
  { cwd: repo, env, encoding: 'utf8', timeout: 15_000, maxBuffer: 2_000_000 });
  expect(run.error).toBeUndefined();
  return run;
}
function document(stdout: string) {
  return JSON.parse(stdout) as { ok: boolean; error: { code: number } | null;
    result: { rootKeys: Array<{ rootKeyId: string; verify: string; flags: string[] }> } | null };
}
function row(output: ReturnType<typeof document>, id: string) {
  const found = output.result?.rootKeys.find(item => item.rootKeyId === id);
  expect(found, `row ${id}`).toBeDefined();
  return found!;
}
function probe(remote: string) {
  return classifyAcceptance(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    `--macaroonpath=${remote}`, 'getinfo']));
}
function ordinary(remote: string) {
  const run = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    `--macaroonpath=${remote}`, 'getinfo']);
  return { accepted: run.status === 0,
    category: run.status === 0 ? 'accepted' : /signature mismatch/i.test(run.stderr) ?
      'signature-mismatch' : /root key with id [0-9]+ doesn't exist/i.test(run.stderr) ?
        'root-key-missing' : 'other' };
}
function sanitizedError(json: Record<string, unknown>) {
  const message = typeof json.message === 'string' ? json.message : '';
  const rootMissing = /root key with id ([0-9]+) doesn't exist/i.exec(message);
  if (rootMissing) return { category: 'root-key-missing', text: rootMissing[0] };
  if (/signature mismatch/i.test(message)) return { category: 'signature-mismatch', text: 'signature mismatch' };
  if (!message) return { category: 'none', text: null };
  return { category: 'other', text: '[sanitized]' };
}
async function rest(path: string, method: string, body?: Record<string, unknown>) {
  const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return await new Promise<{ status: number; json: Record<string, unknown> }>((done, fail) => {
    const call = request({ hostname: 'localhost', port: fixtureTopology().restPort, path, method, ca: readFileSync(cert),
      headers: { 'Grpc-Metadata-macaroon': readFileSync(admin).toString('hex'),
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}) } }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        try { done({ status: response.statusCode || 0,
          json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { fail(new FixtureInvalidError('Fixture REST response invalid JSON')); }
      });
    });
    call.on('error', () => fail(new FixtureInvalidError('Fixture REST request failed')));
    if (data) call.write(data);
    call.end();
  });
}
async function check(local: string, permissions: string[]) {
  const wire = permissions.map(permission => {
    const at = permission.indexOf(':');
    return { entity: permission.slice(0, at), action: permission.slice(at + 1) };
  });
  const response = await rest('/v1/macaroon/checkpermissions', 'POST',
    { macaroon: readFileSync(local).toString('base64'), permissions: wire });
  return { status: response.status, code: response.json.code ?? null,
    valid: response.json.valid ?? null, ...sanitizedError(response.json) };
}
function assertReadOnly(path: string, beforeIds: string[], bytes: Buffer, mtime: number) {
  expect(rootIds()).toEqual(beforeIds);
  expect(readFileSync(path).equals(bytes)).toBe(true);
  expect(statSync(path).mtimeMs).toBe(mtime);
  expect(existsSync(`${path}.lock`)).toBe(false);
}
function cleanup(roots: string[], remotes: string[]) {
  for (const id of roots) {
    const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', id]);
    if (result.status !== 0) throw new FixtureInvalidError('Fixture root key cleanup failed');
  }
  for (const remote of remotes) docker(['exec', '-T', 'lnd', 'rm', '-f', remote]);
  if (rootIds().join(',') !== '0') throw new FixtureInvalidError('Fixture root key cleanup incomplete');
}
async function regenerate(dir: string): Promise<'REST ChangePassword after isolated unlocker restart'> {
  const base = readFileSync(join(repo, 'test/fixture/docker-compose.yml'), 'utf8');
  const service = /\n {2}lnd:\r?\n([\s\S]*?)(?=\nvolumes:)/.exec(base)?.[1];
  const commands = / {4}command:\r?\n((?: {6}- [^\r\n]+\r?\n)+)/.exec(service || '')?.[1]
    .split(/\r?\n/).filter(Boolean).map(line => line.replace(/^ {6}- /, ''));
  if (!commands?.includes('--noseedbackup')) throw new FixtureInvalidError('Fixture unlocker setup invalid');
  const override = join(dir, 'unlocker-compose.yml');
  writeFileSync(override, `services:\n  lnd:\n    command:\n${commands.filter(arg => arg !== '--noseedbackup')
    .map(arg => `      - ${arg}`).join('\n')}\n`);
  const composeOverride = (args: string[]) => spawnSync('docker', [...fixtureTopology().composeArgs, '-f', override, ...args],
  { cwd: repo, encoding: 'utf8', timeout: 60_000, maxBuffer: 2_000_000 });
  if (docker(['stop', 'lnd']).status !== 0 ||
      composeOverride(['up', '-d', '--no-deps', '--force-recreate', 'lnd']).status !== 0)
    throw new FixtureInvalidError('Fixture unlocker restart failed');
  const password = randomBytes(24);
  const body = Buffer.from(JSON.stringify({ current_password: '',
    new_password: password.toString('base64'), new_macaroon_root_key: true }));
  let changed = false;
  for (let attempt = 0; attempt < 20 && !changed; attempt++) {
    changed = await new Promise<boolean>(done => {
      const req = request({ hostname: 'localhost', port: fixtureTopology().restPort, path: '/v1/changepassword',
        method: 'POST', ca: readFileSync(cert), headers: {
          'Grpc-Metadata-macaroon': readFileSync(admin).toString('hex'),
          'Content-Type': 'application/json', 'Content-Length': body.length } }, response => {
        response.resume();
        response.on('end', () => done(response.statusCode === 200));
      });
      req.on('error', () => done(false));
      req.write(body);
      req.end();
    });
    if (!changed) await new Promise(done => setTimeout(done, 500));
  }
  if (!changed) throw new FixtureInvalidError('Fixture ChangePassword unavailable');
  for (let attempt = 0; attempt < 20; attempt++) {
    const fresh = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'getinfo']);
    if (fresh.status === 0) break;
    if (attempt === 19) throw new FixtureInvalidError('Fixture did not return after regeneration');
    await new Promise(done => setTimeout(done, 500));
  }
  if (docker(['cp', 'lnd:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon', admin]).status !== 0)
    throw new FixtureInvalidError('Regenerated admin credential unavailable');
  chmodSync(admin, 0o600);
  const method = 'REST ChangePassword after isolated unlocker restart' as const;
  const baseTmp = process.env.MACWARDEN_TEST_TMP;
  if (baseTmp) writeFileSync(join(baseTmp, 'cp020-regeneration-method.json'), JSON.stringify({ method }) + '\n');
  return method;
}

it('CP-020/read-only-live inventory preserves independent root IDs and registry bytes on each call', () => temp(async dir => {
  const pubkey = baseline();
  const baked = bake(ids[0], 'readonly', dir);
  try {
    expect(probe(baked.remote)).toBe('accepted');
    const path = registry(dir, pubkey, [{ id: ids[0], path: baked.local, permissions: baked.permissions }]);
    const bytes = readFileSync(path), mtime = statSync(path).mtimeMs, roots = rootIds();
    for (let index = 0; index < 2; index++) {
      const run = inventory(path);
      expect(run.status).toBe(0);
      expect(row(document(run.stdout), ids[0]).verify).toBe('accepted');
      assertReadOnly(path, roots, bytes, mtime);
    }
  } finally { cleanup([ids[0]], [baked.remote]); }
}), 30_000);

it('CP-020/acceptance-live independent lncli acceptance agrees before and after regeneration', () => temp(async dir => {
  const pubkey = baseline();
  const baked = ids.map((id, index) => bake(id, `acceptance${index}`, dir));
  const zeroRemote = `${remotePrefix}-zero.macaroon`;
  if (docker(['exec', '-T', 'lnd', 'cp',
    '/root/.lnd/data/chain/bitcoin/regtest/readonly.macaroon', zeroRemote]).status !== 0)
    throw new FixtureInvalidError('Fixture root-zero target copy failed');
  const zeroPrinted = lncli(['printmacaroon', `--macaroon_file=${zeroRemote}`]);
  if (String(zeroPrinted.root_key_id) !== '0' || !Array.isArray(zeroPrinted.permissions) ||
      zeroPrinted.permissions.length === 0)
    throw new FixtureInvalidError('Fixture root-zero permissions invalid');
  const zero = { remote: zeroRemote, local: sentinel('zero', zeroRemote, dir),
    permissions: zeroPrinted.permissions as string[] };
  const remotes = [...baked.map(item => item.remote), zeroRemote];
  let own: string | null = null;
  let fresh: ReturnType<typeof bake> | null = null;
  try {
    const path = registry(dir, pubkey, [{ id: '0', path: zero.local,
      permissions: zero.permissions }, ...baked.map((item, index) =>
      ({ id: ids[index], path: item.local, permissions: item.permissions }))]);
    const bytes = readFileSync(path), mtime = statSync(path).mtimeMs;
    const beforeIds = rootIds();
    expect(beforeIds).toContain('0');
    for (const id of ids) expect(beforeIds).toContain(id);
    const beforeDirect = {
      zero: { check: await check(zero.local, zero.permissions), ordinary: ordinary(zero.remote) },
      nonzero: { check: await check(baked[0].local, baked[0].permissions),
        ordinary: ordinary(baked[0].remote) },
    };
    for (const target of [beforeDirect.zero, beforeDirect.nonzero]) {
      expect(target.check).toMatchObject({ status: 200, valid: true });
      expect(target.ordinary.accepted).toBe(true);
    }
    for (const item of baked) expect(probe(item.remote)).toBe('accepted');
    const before = inventory(path);
    expect(before.status).toBe(0);
    for (const id of ['0', ...ids]) expect(row(document(before.stdout), id).verify).toBe('accepted');
    assertReadOnly(path, beforeIds, bytes, mtime);
    expect(await regenerate(dir)).toBe('REST ChangePassword after isolated unlocker restart');
    const freshOwn = await rest('/v1/getinfo', 'GET');
    expect(freshOwn.status).toBe(200);
    const ownBaked = bake(ownId, 'own-after-regeneration', dir,
      ['info:read', 'macaroon:read']);
    own = ownBaked.local;
    remotes.push(ownBaked.remote);
    expect(probe(ownBaked.remote)).toBe('accepted');
    fresh = bake(freshId, 'fresh-after-regeneration', dir);
    remotes.push(fresh.remote);
    const afterIds = rootIds();
    for (const id of ['0', ...ids, ownId, freshId]) expect(afterIds).toContain(id);
    const afterDirect = {
      zero: { check: await check(zero.local, zero.permissions), ordinary: ordinary(zero.remote) },
      nonzero: { check: await check(baked[0].local, baked[0].permissions),
        ordinary: ordinary(baked[0].remote) },
      fresh: { check: await check(fresh.local, fresh.permissions), ordinary: ordinary(fresh.remote) },
    };
    for (const target of [afterDirect.zero, afterDirect.nonzero]) {
      expect(target.check).toMatchObject({ status: 400, valid: null,
        category: 'signature-mismatch', text: 'signature mismatch' });
      expect(target.ordinary.accepted).toBe(false);
    }
    expect(afterDirect.fresh.check).toMatchObject({ status: 200, valid: true });
    expect(afterDirect.fresh.ordinary.accepted).toBe(true);
    for (const item of baked) expect(ordinary(item.remote).accepted).toBe(false);
    const after = inventory(path, own);
    expect(after.status).toBe(0);
    for (const id of ['0', ...ids]) {
      expect(row(document(after.stdout), id).verify).toBe('rejected');
      expect(row(document(after.stdout), id).flags).toContain('rejected');
    }
    assertReadOnly(path, afterIds, bytes, mtime);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'),
      sentinelDir: process.env.MACWARDEN_SENTINEL_DIR,
      commandOutput: before.stdout + before.stderr + after.stdout + after.stderr,
      paths: [dir], testTmp: dir, root: repo })).toBeNull();
  } finally { cleanup([...ids, ...(own ? [ownId] : []), ...(fresh ? [freshId] : [])], remotes); }
}), 120_000);

it('CP-020/leak-check registered eligible file stays out of both rendered output modes and temporary files', () => temp(async dir => {
  const sentinelDir = process.env.MACWARDEN_SENTINEL_DIR;
  if (!sentinelDir) throw new FixtureInvalidError('MACWARDEN_SENTINEL_DIR is required');
  const source = join(repo, 'test/vectors/default-readonly.macaroon');
  const target = registerFixtureSentinel(source, 'cp020-leak-offline.macaroon', sentinelDir);
  const fingerprint = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8'))
    .vectors.find((item: { name: string }) => item.name === 'default-readonly').fingerprint;
  const pubkey = '02' + 'ab'.repeat(32);
  const path = join(dir, 'registry.json');
  writeFileSync(path, JSON.stringify({ schema: 1, entries: [{ nodePubkey: pubkey,
    label: 'leak', rootKeyId: '9', permissions: ['info:read'], caveats: [], grade: readGrade,
    fingerprint, outPath: target, createdAt: '2026-10-02T09:00:00Z', verified: true,
    status: 'active', revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null }] }),
  { mode: 0o600 });
  const command = await import('../../src/commands/inventory.js') as unknown as {
    run: (args: string[], deps: unknown) => Promise<Parameters<typeof render>[0]> };
  const lnd = { getInfo: async () => ({ pubkey, alias: 'alice',
    network: 'regtest', version: '0.21.4-beta' }),
    listPermissions: async () => ({}),
    listMacaroonIds: async () => [0n, 9n],
    checkMacaroon: async () => ({ valid: true }) };
  const result = await command.run(['--verify', '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', join(repo, 'test/fixture/wrong-tls.cert'),
    '--macaroon', source, '--registry', path], { lnd, fs, env: {},
      clock: () => new Date('2026-10-04T00:00:00Z') });
  expect(result).toMatchObject({ ok: true, error: null });
  const output = render(result, 'json') + render(result, 'text');
  expect(output).not.toContain('Grpc-Metadata-macaroon');
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    commandOutput: output, paths: [dir], testTmp: dir, root: repo })).toBeNull();
}));
