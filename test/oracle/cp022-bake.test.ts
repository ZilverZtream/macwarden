import { fixtureTopology } from '../fixture/topology.mjs';
import { revealSecret } from '../helpers/secret-bytes.js';
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from "../helpers/leak-check.js";
import { Secret } from '../../src/secret.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { classifyAcceptance, requirePinnedFixture } from '../helpers/lnd-facts.mjs';

const repo = resolve();
const tmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const sentinelDir = process.env.MACWARDEN_SENTINEL_DIR || join(tmp, 'sentinels');
process.env.MACWARDEN_TEST_TMP = tmp;
process.env.MACWARDEN_SENTINEL_DIR = sentinelDir;
const compose = fixtureTopology().composeArgs;
const ids = ['4294967331', '4294967332'];
const responseId = '4294967333';
const remote = (name: string) => `/tmp/macwarden-cp022-${process.pid}-${name}.macaroon`;

function docker(args: string[], binary = false) {
  return spawnSync('docker', [...compose, ...args], { cwd: repo,
    encoding: binary ? null : 'utf8', timeout: 30_000, maxBuffer: 4_000_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const run = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (run.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(run.stdout as string); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function fixtureBytes(name: 'tls.cert' | 'admin.macaroon'): Buffer {
  const path = name === 'tls.cert' ? '/root/.lnd/tls.cert' :
    '/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon';
  const run = docker(['exec', '-T', 'lnd', 'cat', path], true);
  if (run.status !== 0) throw new FixtureInvalidError('Fixture credential unavailable');
  return run.stdout as unknown as Buffer;
}
function pinned() {
  const info = lncli(['getinfo']);
  const before = lncli(['listmacaroonids']);
  requirePinnedFixture(info, before);
  const cp015 = JSON.parse(readFileSync(join(repo, 'test/oracle/facts/observations.json'), 'utf8')) as {
    fixture: { network: string; version: string; baselineRootKeyIds: string[] };
    bakeEdgeFacts: { maxRootKeyId: string; maxProbe: string };
  };
  if (cp015.fixture.network !== 'regtest' || !cp015.fixture.version.startsWith('0.21.4-beta') ||
      cp015.fixture.baselineRootKeyIds.join(',') !== '0' ||
      cp015.bakeEdgeFacts.maxRootKeyId !== '18446744073709551615' ||
      cp015.bakeEdgeFacts.maxProbe !== 'accepted') {
    throw new FixtureInvalidError('CP-015 pinned bake facts unavailable');
  }
}
async function adapter() {

  const module = await import('../../src/lnd/index.js') as {
    createLndAdapter: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => {
      bakeMacaroon(perms: string[], id: bigint): Promise<Secret> };
  };
  return module.createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: fixtureBytes('tls.cert'),
    macaroon: new Secret(fixtureBytes('admin.macaroon')) });
}
async function bake(id: string, name: string) {
  pinned();
  const secret = await (await adapter()).bakeMacaroon(['info:read'], BigInt(id));
  expect(secret).toBeInstanceOf(Secret);
  mkdirSync(sentinelDir, { recursive: true, mode: 0o700 });
  mkdirSync(tmp, { recursive: true });
  const local = join(sentinelDir, `cp022-${name}.macaroon`);
  writeFileSync(local, Buffer.from(revealSecret(secret)), { mode: 0o600 });
  appendFileSync(join(tmp, 'declared-out.txt'), `${local}\n`);
  const path = remote(name);
  if (docker(['cp', local, `lnd:${path}`]).status !== 0)
    throw new FixtureInvalidError('Fixture probe credential copy unavailable');
  return { secret, path };
}
function cleanup(id: string) {
  docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', id]);
}
async function independentRestResponse(id: string): Promise<Secret> {
  const body = Buffer.from(JSON.stringify({ permissions: [{ entity: 'info', action: 'read' }],
    root_key_id: id }));
  const json = await new Promise<{ status: number; macaroon?: unknown }>((done, fail) => {
    const call = request({ hostname: 'localhost', port: fixtureTopology().restPort, method: 'POST', path: '/v1/macaroon',
      ca: fixtureBytes('tls.cert'), headers: {
        'Grpc-Metadata-macaroon': fixtureBytes('admin.macaroon').toString('hex'),
        'Content-Type': 'application/json', 'Content-Length': body.length,
      } }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        try { done({ status: response.statusCode || 0,
          ...JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { fail(new FixtureInvalidError('Fixture bake REST response is not JSON')); }
      });
    });
    call.on('error', fail);
    call.end(body);
  });
  expect(json.status).toBe(200);
  expect(typeof json.macaroon).toBe('string');
  expect(json.macaroon as string).toMatch(/^[0-9a-f]+$/i);
  return new Secret(Buffer.from(json.macaroon as string, 'hex'));
}

it('CP-022/bake-id-listed-and-accepted adapter ID appears in live LND and lncli accepts its credential', async () => {
  const id = ids[0];
  try {
    const result = await bake(id, 'accepted');
    expect((lncli(['listmacaroonids']).root_key_ids as string[])).toContain(id);
    const probe = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
      `--macaroonpath=${result.path}`, 'getinfo']);
    expect(classifyAcceptance(probe)).toBe('accepted');
  } finally { cleanup(id); }
}, 60_000);

it('CP-022/bake-id-printmacaroon live lncli reports chosen ID and requested permission', async () => {
  const id = ids[1];
  try {
    pinned();
    try {
      const raw = await independentRestResponse(responseId);
      const { decodeMacaroon } = await import('../../src/decode/index.js');
      expect(decodeMacaroon(raw).rootKeyId).toBe(BigInt(responseId));
    } finally { cleanup(responseId); }
    const result = await bake(id, 'printed');
    const printed = lncli(['printmacaroon', `--macaroon_file=${result.path}`]);
    expect(printed.root_key_id).toBe(id);
    expect(printed.permissions).toEqual(['info:read']);
    const { decodeMacaroon } = await import('../../src/decode/index.js');
    expect(decodeMacaroon(result.secret).rootKeyId).toBe(BigInt(id));
  } finally { cleanup(id); }
}, 60_000);

it('CP-022/leak-check baked fixture credentials do not appear in owned temporary output', () => {
  const leak = findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    paths: [tmp], testTmp: tmp, root: repo });
  expect(leak).toBeNull();
});
