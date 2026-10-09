import { fixtureTopology } from '../fixture/topology.mjs';
import { revealSecret } from '../helpers/secret-bytes.js';
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { beforeAll, expect, it } from 'vitest';
import { Secret } from '../../src/secret.js';
import { findLeaks } from "../helpers/leak-check.js";
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { registerFixtureSentinel, requirePinnedFixture } from '../helpers/lnd-facts.mjs';

type Facts = { rootKeyId: bigint; permissions: string[]; caveats: { type: string; value: string }[] };
type Boundary = { decodeMacaroon(mac: Secret): Facts;
  addFirstPartyCaveat(mac: Secret, condition: string): Secret };
const repo = resolve();
const suppliedTmp = process.env.MACWARDEN_TEST_TMP;
const suppliedSentinels = process.env.MACWARDEN_SENTINEL_DIR;
if (!suppliedTmp || !suppliedSentinels) throw new FixtureInvalidError('Scoped test tmp and sentinel directories required');
const outerTmp = resolve(suppliedTmp), sentinelDir = resolve(suppliedSentinels);
const tmp = join(outerTmp, 'cp021-time-before');
const declarations = join(outerTmp, 'declared-out.txt');
const compose = fixtureTopology().composeArgs;
const remote = (part: string) => `/tmp/macwarden-cp021-${process.pid}-${part}.macaroon`;

const boundary = async (): Promise<Boundary> => import('../../src/decode/index.js') as Promise<Boundary>;

function docker(args: string[]) {
  return spawnSync('docker', [...compose, ...args], { cwd: repo,
    encoding: 'utf8', maxBuffer: 4_000_000, timeout: 30_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function guard(): void {
  requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
  let evidence: {
    fixture?: { network?: string; version?: string; baselineRootKeyIds?: string[] };
    fixtureBasics?: { snapshotMatches?: boolean; bakedLocation?: string };
    emptyPermissionCheck?: { corruptRejectedByOrdinaryRpc?: boolean } };
  try { evidence = JSON.parse(readFileSync(join(repo, 'test/oracle/facts/observations.json'), 'utf8')); }
  catch { throw new FixtureInvalidError('CP-015 committed prerequisite facts are unavailable'); }
  if (evidence.fixture?.network !== 'regtest' ||
    !evidence.fixture?.version?.startsWith('0.21.4-beta') ||
    JSON.stringify(evidence.fixture?.baselineRootKeyIds) !== '["0"]' ||
    evidence.fixtureBasics?.snapshotMatches !== true ||
    evidence.fixtureBasics?.bakedLocation !== 'lnd' ||
    evidence.emptyPermissionCheck?.corruptRejectedByOrdinaryRpc !== true) {
    throw new FixtureInvalidError('CP-015 committed prerequisite facts are unavailable');
  }
}
function checked(result: ReturnType<typeof docker>, label: string): void {
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture ${label} unavailable`);
}
function bake(name: string, id: string): { local: string; source: string } {
  const source = remote(name);
  checked(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    `--root_key_id=${id}`, `--save_to=${source}`, '--timeout=3600', 'info:read']), 'bake');
  const local = join(tmp, `cp021-${name}-source.macaroon`);
  appendFileSync(declarations, `${local}\n`);
  checked(docker(['cp', `lnd:${source}`, local]), 'credential copy');
  const registered = registerFixtureSentinel(local, `cp021-${name}-source.macaroon`, sentinelDir);
  appendFileSync(declarations, `${registered}\n`);
  rmSync(local, { force: true });
  return { local: registered, source };
}
function attenuate(api: Boundary, source: string, name: string, condition: string): { local: string; remotePath: string } {
  const secret = api.addFirstPartyCaveat(new Secret(readFileSync(source)), condition);
  expect(secret).toBeInstanceOf(Secret);
  const local = join(sentinelDir, `cp021-${name}.macaroon`);
  writeFileSync(local, Buffer.from(revealSecret(secret)));
  appendFileSync(declarations, `${local}\n`);
  const remotePath = remote(name);
  checked(docker(['cp', local, `lnd:${remotePath}`]), 'attenuated credential copy');
  return { local, remotePath };
}
function printed(path: string): { root_key_id: string; permissions: string[]; caveats: string[] | null } {
  return lncli(['printmacaroon', `--macaroon_file=${path}`]) as ReturnType<typeof printed>;
}
function probe(path: string): 'accepted' | 'time-rejected' | 'unexpected' {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    `--macaroonpath=${path}`, 'getinfo']);
  if (result.status === 0) return 'accepted';
  if (typeof result.stderr === 'string' && /time-before|expired|not yet valid/i.test(result.stderr))
    return 'time-rejected';
  return 'unexpected';
}
function clean(paths: string[], id: string) {
  for (const path of paths) docker(['exec', '-T', 'lnd', 'rm', '-f', path]);
  docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', id]);
}

beforeAll(() => { guard(); mkdirSync(tmp, { recursive: true }); mkdirSync(sentinelDir, { recursive: true }); }, 30_000);

it('CP-021/time-before-printmacaroon live lncli sees the appended condition after original caveats', async () => {
  const id = '21021';
  const paths = [remote('printed-source'), remote('printed-added')];
  try {
    const source = bake('printed-source', id);
    const original = printed(source.source);
    const condition = 'time-before 2030-01-01T00:00:00Z';
    const final = attenuate(await boundary(), source.local, 'printed-added', condition);
    const observed = printed(final.remotePath);
    expect(original.caveats?.length).toBe(1);
    expect(original.caveats?.[0]).toMatch(/^time-before /);
    expect(observed.caveats).toEqual([...(original.caveats || []), condition]);
    expect(observed.root_key_id).toBe(original.root_key_id);
    expect(observed.permissions).toEqual(original.permissions);
    const facts = (await boundary()).decodeMacaroon(new Secret(readFileSync(final.local)));
    expect(facts.rootKeyId.toString()).toBe(observed.root_key_id);
    expect(facts.permissions).toEqual(observed.permissions);
    expect(facts.caveats.map(item => `${item.type} ${item.value}`)).toEqual(observed.caveats);
  } finally { clean(paths, id); }
}, 60_000);

it('CP-021/time-before-acceptance independent lncli accepts future and rejects past attenuation', async () => {
  const id = '21022';
  const paths = [remote('accept-source'), remote('accept-future'), remote('accept-past')];
  try {
    const source = bake('accept-source', id);
    expect(probe(source.source)).toBe('accepted');
    const api = await boundary();
    const future = attenuate(api, source.local, 'accept-future',
      `time-before ${new Date(Date.now() + 600_000).toISOString().replace(/\.\d{3}Z$/, 'Z')}`);
    const past = attenuate(api, source.local, 'accept-past',
      `time-before ${new Date(Date.now() - 600_000).toISOString().replace(/\.\d{3}Z$/, 'Z')}`);
    expect(probe(future.remotePath)).toBe('accepted');
    expect(probe(past.remotePath)).toBe('time-rejected');
  } finally { clean(paths, id); }
}, 60_000);

it('CP-021/leak-check registered credentials do not appear in output or undeclared temporary files', async () => {
  const id = '21023';
  const paths = [remote('leak-source'), remote('leak-added')];
  try {
    const source = bake('leak-source', id);
    const final = attenuate(await boundary(), source.local, 'leak-added',
      'time-before 2030-01-01T00:00:00Z');
    const found = findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      paths: [tmp], testTmp: outerTmp, root: repo });
    expect(found).toBeNull();
    expect(printed(final.remotePath).caveats?.at(-1)).toBe('time-before 2030-01-01T00:00:00Z');
  } finally { clean(paths, id); }
}, 60_000);
