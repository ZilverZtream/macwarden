import { expectDocumentValid, expectWatchEventValid } from '../helpers/output-schema.js';
import { fixtureTopology } from '../fixture/topology.mjs';
import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { beforeAll, expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';
import { findLeaks } from '../helpers/leak-check.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { registerFixtureSentinel, requirePinnedFixture } from '../helpers/lnd-facts.mjs';

// Owner request 2026-10-07: `macwarden watch` against the pinned regtest LND with
// rpcmiddleware.enable (test/fixture/docker-compose.yml). Proves attribution, canary
// denial within the same call, clean unregistration and usage-based recommendation.
const repo = resolve();
const suppliedTmp = process.env.MACWARDEN_TEST_TMP;
const suppliedSentinels = process.env.MACWARDEN_SENTINEL_DIR;
if (!suppliedTmp || !suppliedSentinels) throw new FixtureInvalidError('Scoped test tmp and sentinel directories required');
const outerTmp = resolve(suppliedTmp), sentinelDir = resolve(suppliedSentinels);
const tmp = join(outerTmp, 'watch-live');
const declarations = join(outerTmp, 'declared-out.txt');
const topology = fixtureTopology();
const compose = topology.composeArgs;
const remote = (part: string) => `/tmp/macwarden-watch-${process.pid}-${part}.macaroon`;
const registry = join(tmp, 'registry.json');
let flags: string[] = [];

function docker(args: string[]) {
  return spawnSync('docker', [...compose, ...args], { cwd: repo, encoding: 'utf8', maxBuffer: 4_000_000, timeout: 30_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout); } catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function declare(path: string): string { appendFileSync(declarations, `${path}\n`); return path; }
function cli(command: string, args: string[]) {
  return spawnSync(process.execPath, [resolve('dist/bin.js'), command, ...args, ...flags, '--json'],
    { env: childEnvironment(), encoding: 'utf8', timeout: 30_000, windowsHide: true });
}
/** Runs a call inside the container with a credential written by macwarden. */
function call(local: string, name: string, method: string[]) {
  const target = remote(name);
  if (docker(['cp', local, `lnd:${target}`]).status !== 0) throw new FixtureInvalidError('Fixture credential copy unavailable');
  return docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${target}`, ...method]);
}
function startWatch(seconds: number) {
  const child = spawn(process.execPath, [resolve('dist/bin.js'), 'watch', ...flags,
    '--lnd-grpc', `localhost:${topology.grpcPort}`, '--until', `${seconds}s`, '--json'],
  { env: childEnvironment(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  child.stdout!.on('data', chunk => { stdout += String(chunk); });
  let stderr = '';
  child.stderr!.on('data', chunk => { stderr += String(chunk); });
  const registered = new Promise<void>((done, fail) => {
    const timer = setTimeout(() => fail(new Error(`watch did not register: ${stdout} ${stderr}`)), 20_000);
    child.on('close', () => { clearTimeout(timer); if (!stdout.includes('"status":"registered"')) fail(new Error(`watch exited: ${stdout} ${stderr}`)); });
    child.stdout!.on('data', () => { if (stdout.includes('"status":"registered"')) { clearTimeout(timer); done(); } });
  });
  const exited = new Promise<number | null>(done => child.on('close', code => done(code)));
  return { registered, exited, lines: () => stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line) as Record<string, unknown>) };
}

beforeAll(() => {
  requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true }); mkdirSync(sentinelDir, { recursive: true });
  const cert = declare(join(tmp, 'tls.cert'));
  if (docker(['cp', 'lnd:/root/.lnd/tls.cert', cert]).status !== 0) throw new FixtureInvalidError('Fixture certificate unavailable');
  const adminCopy = join(tmp, 'admin-source.macaroon');
  if (docker(['cp', 'lnd:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon', adminCopy]).status !== 0)
    throw new FixtureInvalidError('Fixture admin macaroon unavailable');
  const own = declare(registerFixtureSentinel(adminCopy, 'watch-own-admin.macaroon', sentinelDir));
  rmSync(adminCopy, { force: true });
  flags = ['--lnd-rest', `localhost:${topology.restPort}`, '--tls-cert', cert, '--macaroon', own, '--registry', registry];
}, 60_000);

it('WATCH/live attribution, canary denial in the same call, clean unregistration and recommendation', async () => {
  const app = declare(join(sentinelDir, 'watch-app.macaroon'));
  const decoy = declare(join(sentinelDir, 'watch-decoy.macaroon'));
  const ids: string[] = [];
  try {
    const baked = cli('bake', ['--label', 'watched-app', '--preset', 'read-only', '--out', app]);
    expect(baked.status, baked.stderr).toBe(0);
    ids.push(JSON.parse(baked.stdout).result.rootKeyId);
    const canary = cli('bake', ['--label', 'decoy', '--canary', '--out', decoy]);
    expect(canary.status, canary.stderr).toBe(0);
    ids.push(JSON.parse(canary.stdout).result.rootKeyId);
    const caveatName = JSON.parse(readFileSync(`${registry}.canary.json`, 'utf8')).caveatName as string;

    // Without a watcher LND itself refuses the canary: fail closed.
    const unguarded = call(decoy, 'decoy-a', ['getinfo']);
    expect(unguarded.status).not.toBe(0);
    expect(unguarded.stderr).toContain(`cannot accept macaroon with custom caveat '${caveatName}', no middleware registered`);

    const watch = startWatch(20);
    await watch.registered;
    for (let i = 0; i < 2; i++) expect(call(app, `app-${i}`, ['getinfo']).status).toBe(0);
    const guarded = call(decoy, 'decoy-b', ['getinfo']);
    expect(guarded.status).not.toBe(0);
    expect(guarded.stderr).toContain('permission denied');
    expect(await watch.exited).toBe(0);
    const events = watch.lines();
    const appRoot = ids[0], decoyRoot = ids[1];
    const appCalls = events.filter(event => event.event === 'call' && event.rootKeyId === appRoot);
    expect(appCalls.map(event => [event.method, event.label])).toEqual([
      ['/lnrpc.Lightning/GetInfo', 'watched-app'], ['/lnrpc.Lightning/GetInfo', 'watched-app']]);
    // Both calls carried different lncli timeout caveats but one credential identity.
    expect(new Set(appCalls.map(event => event.credential)).size).toBe(1);
    const alerts = events.filter(event => event.event === 'canary');
    expect(alerts).toEqual([expect.objectContaining({ method: '/lnrpc.Lightning/GetInfo', rootKeyId: decoyRoot, label: 'decoy', denied: true })]);
    const summary = events.at(-1)!;
    expect(summary).toMatchObject({ ok: true, command: 'watch', result: expect.objectContaining({ canaryAlerts: 1 }) });
    // Every real event line and the final document match the published watch schemas.
    for (const event of events.slice(0, -1)) expectWatchEventValid(JSON.stringify(event));
    expectDocumentValid(summary as { command: string });

    // After exit both middlewares are unregistered: normal calls work and the canary is
    // again refused by LND itself (no middleware registered for its caveat).
    expect(lncli(['getinfo'])).toHaveProperty('identity_pubkey');
    expect(call(decoy, 'decoy-c', ['getinfo']).stderr).toContain('no middleware registered');

    const recommended = cli('recommend', ['watched-app']);
    expect(recommended.status, recommended.stderr).toBe(0);
    expect(JSON.parse(recommended.stdout).result).toMatchObject({ recommended: ['info:read'],
      recommendedUris: ['uri:/lnrpc.Lightning/GetInfo'] });
    expectDocumentValid(JSON.parse(recommended.stdout));
    // The access review from real LND data, the triggered canary's uses included, matches the schema.
    const review = JSON.parse(cli('inventory', ['--report', 'json']).stdout);
    expectDocumentValid(review);
    expect(review.result.report.review.credentials.find((item: { rootKeyId: string }) => item.rootKeyId === decoyRoot).canary)
      .toMatchObject({ uses: 1 });
    const inventory = JSON.parse(cli('inventory', []).stdout);
    // The real output, usage data included, must match the published inventory schema.
    expectDocumentValid(inventory);
    const row = inventory.result.rootKeys.find((item: { rootKeyId: string }) => item.rootKeyId === appRoot);
    expect(row.usage).toMatchObject({ calls: 2, methods: ['/lnrpc.Lightning/GetInfo'] });

    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir, paths: [tmp],
      testTmp: outerTmp, root: repo, commandOutput: JSON.stringify(events) + recommended.stdout })).toBeNull();
  } finally {
    for (const id of ids) docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', id]);
    for (const name of ['decoy-a', 'decoy-b', 'decoy-c', 'app-0', 'app-1']) docker(['exec', '-T', 'lnd', 'rm', '-f', remote(name)]);
  }
}, 120_000);
