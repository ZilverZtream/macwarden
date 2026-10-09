import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { request } from 'node:https';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { Secret } from '../../src/secret.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { classifyAcceptance, registerFixtureSentinel, requirePinnedFixture } from '../helpers/lnd-facts.mjs';

type Adapter = {
  getInfo(): Promise<{ pubkey: string; alias: string; network: string; version: string }>;
  listMacaroonIds(): Promise<bigint[]>;
  listPermissions(): Promise<Record<string, string[]>>;
  checkMacaroon(mac: Secret, perms: string[]): Promise<
    { valid: true } | { valid: false; reason: 'root-key-missing' | 'other'; message: string }>;
};
const repo = resolve();
const tmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const sentinelDir = process.env.MACWARDEN_SENTINEL_DIR || join(tmp, 'sentinels');
process.env.MACWARDEN_TEST_TMP = tmp;
process.env.MACWARDEN_SENTINEL_DIR = sentinelDir;
const compose = fixtureTopology().composeArgs;
const remote = (name: string) => `/tmp/macwarden-cp016-${process.pid}-${name}.macaroon`;

function docker(args: string[], binary = false) {
  return spawnSync('docker', [...compose, ...args], { cwd: repo,
    encoding: binary ? null : 'utf8', timeout: 30_000, maxBuffer: 4_000_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout as string); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function fixtureBytes(name: 'tls.cert' | 'admin.macaroon'): Buffer {
  const path = name === 'tls.cert' ? '/root/.lnd/tls.cert' :
    '/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon';
  const result = docker(['exec', '-T', 'lnd', 'cat', path], true);
  if (result.status !== 0) throw new FixtureInvalidError('Fixture credential unavailable');
  return result.stdout as unknown as Buffer;
}
async function adapter(cert = fixtureBytes('tls.cert')): Promise<Adapter> {

  const module = await import('../../src/lnd/index.js') as {
    createLndAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => Adapter;
  };
  expect(typeof module.createLndAdapter).toBe('function');
  return module.createLndAdapter!({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: cert,
    macaroon: new Secret(fixtureBytes('admin.macaroon')) });
}
function pinned() {
  const info = lncli(['getinfo']);
  const ids = lncli(['listmacaroonids']);
  requirePinnedFixture(info, ids);
  return { info, ids };
}
function bake(name: string, id: string, flags: string[] = []) {
  const path = remote(name);
  const input = flags.length ? `${path}.unconstrained` : path;
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    `--root_key_id=${id}`, `--save_to=${input}`, 'info:read']);
  if (result.status !== 0) throw new FixtureInvalidError('Fixture bake unavailable');
  if (flags.length) {
    try {
      const constrained = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
        'constrainmacaroon', ...flags, input, path]);
      if (constrained.status !== 0) throw new FixtureInvalidError('Fixture constraint unavailable');
    } finally { docker(['exec', '-T', 'lnd', 'rm', '-f', input]); }
  }
  mkdirSync(tmp, { recursive: true });
  mkdirSync(sentinelDir, { recursive: true });
  const local = join(tmp, `cp016-${name}.macaroon`);
  if (docker(['cp', `lnd:${path}`, local]).status !== 0)
    throw new FixtureInvalidError('Fixture credential copy unavailable');
  const registered = registerFixtureSentinel(local, `cp016-${name}.macaroon`, sentinelDir);
  rmSync(local, { force: true });
  appendFileSync(join(tmp, 'declared-out.txt'), `${registered}\n`);
  return { remotePath: path, localPath: registered };
}
function probe(path: string) {
  return classifyAcceptance(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    `--macaroonpath=${path}`, 'getinfo']));
}
async function rawIds(): Promise<unknown> {
  const ca = fixtureBytes('tls.cert'), own = fixtureBytes('admin.macaroon');
  return await new Promise((done, fail) => {
    const call = request({ hostname: 'localhost', port: fixtureTopology().restPort, path: '/v1/macaroon/ids',
      ca, headers: { 'Grpc-Metadata-macaroon': own.toString('hex') } }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        try { done(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { fail(new FixtureInvalidError('Fixture REST IDs returned invalid JSON')); }
      });
    });
    call.on('error', fail);
    call.end();
  });
}

it('CP-016/read-endpoints-live read operations match independent pinned lncli and REST facts', async () => {
  const { info } = pinned();
  const maxId = '18446744073709551615';
  try {
    bake('max', maxId);
    const ids = lncli(['listmacaroonids']);
    const value = await adapter();
    const liveInfo = await value.getInfo();
    expect(liveInfo).toEqual({ pubkey: info.identity_pubkey, alias: info.alias,
      network: (info.chains as { network: string }[])[0].network, version: info.version });
    expect((await value.listMacaroonIds()).map(String)).toEqual(ids.root_key_ids);
    expect((ids.root_key_ids as string[])).toContain(maxId);
    const rest = await rawIds() as { root_key_ids?: unknown[] };
    const observed = JSON.parse(readFileSync(join(repo, 'test/oracle/facts/observations.json'), 'utf8')) as {
      rootKeyIdsType: { types: string[] } };
    expect(Array.isArray(rest.root_key_ids)).toBe(true);
    const rawValues = rest.root_key_ids!;
    expect(rawValues.map(item => typeof item)).toEqual(observed.rootKeyIdsType.types);
    const methods = lncli(['listpermissions']).method_permissions as
      Record<string, { permissions?: { entity: string; action: string }[] }>;
    const expected = Object.fromEntries(Object.entries(methods).map(([name, entry]) =>
      [name, (entry.permissions || []).map(item => `${item.entity}:${item.action}`)]));
    expect(await value.listPermissions()).toEqual(expected);
  } finally {
    docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', maxId]);
  }
}, 60_000);

it('CP-016/verify-live valid, deleted and expired credentials follow independent lncli probes', async () => {
  pinned();
  try {
    const live = bake('live', '16016');
    const deleted = bake('deleted', '16017');
    const expired = bake('expired', '16018', ['--timeout=1']);
    const value = await adapter();
    const checks = [live, deleted, expired];
    for (const item of checks) {
      const printed = lncli(['printmacaroon', `--macaroon_file=${item.remotePath}`]);
      expect(printed.permissions).toEqual(['info:read']);
    }
    const caveats = lncli(['printmacaroon', `--macaroon_file=${expired.remotePath}`]).caveats;
    expect(caveats).toEqual([expect.stringMatching(/^time-before /)]);
    const expiry = Date.parse((caveats as string[])[0].slice('time-before '.length));
    expect(Number.isFinite(expiry)).toBe(true);
    expect(probe(live.remotePath)).toBe('accepted');
    expect((await value.checkMacaroon(new Secret(readFileSync(live.localPath)), ['info:read'])).valid).toBe(true);
    const deletion = lncli(['deletemacaroonid', '16017']);
    expect(deletion.deleted).toBe(true);
    expect(probe(deleted.remotePath)).toBe('rejected');
    const missing = await value.checkMacaroon(new Secret(readFileSync(deleted.localPath)), ['info:read']);
    expect(missing).toMatchObject({ valid: false as const, reason: 'root-key-missing' });
    const fixtureNow = () => {
      const clock = docker(['exec', '-T', 'lnd', 'date', '+%s']);
      if (clock.status !== 0 || !/^\d+\s*$/.test(clock.stdout as string))
        throw new FixtureInvalidError('Fixture clock unavailable');
      return Number(clock.stdout) * 1000;
    };
    await new Promise(done => setTimeout(done, Math.max(0, expiry + 1000 - fixtureNow())));
    expect(fixtureNow()).toBeGreaterThan(expiry);
    const expiration = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
      `--macaroonpath=${expired.remotePath}`, 'getinfo']);
    expect(expiration.error).toBeUndefined();
    expect(expiration.signal).toBeNull();
    expect(expiration.status).not.toBeNull();
    expect(expiration.status).not.toBe(0);
    expect(classifyAcceptance(expiration)).toBe('error');
    expect(expiration.stderr).toMatch(/macaroon.*(?:expired|time-before)|(?:expired|time-before).*macaroon/i);
    const overdue = await value.checkMacaroon(new Secret(readFileSync(expired.localPath)), ['info:read']);
    expect(overdue).toMatchObject({ valid: false as const, reason: 'expired' as const });
  } finally {
    for (const id of ['16016', '16017', '16018'])
      docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', id]);
  }
}, 90_000);

it('CP-016/tls-live wrong trust anchor is rejected without changing LND state', async () => {
  const before = pinned().ids.root_key_ids;
  const wrong = readFileSync(join(repo, 'test/fixture/cp016-wrong-ca.crt'));
  const value = await adapter(wrong);
  let failed = false;
  try { await value.getInfo(); } catch { failed = true; }
  expect(failed).toBe(true);
  expect(lncli(['listmacaroonids']).root_key_ids).toEqual(before);
}, 60_000);
