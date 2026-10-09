import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, copyFileSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { join, resolve } from 'node:path';
import { beforeAll, expect, it } from 'vitest';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { registerFixtureSentinel, requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { findLeaks } from "../helpers/leak-check.js";

// No production imports: expected authority comes from the literal manifest,
// IDs from pinned lncli printmacaroon, and fingerprints from installed bytes.
const repo = resolve();
const compose = fixtureTopology().composeArgs;
const adminRemote = '/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon';
const manifest = JSON.parse(readFileSync(join(repo, 'test/fixtures-cp033-apps.json'), 'utf8')) as {
  apps: Array<{ label: string; preset: string; grade: string; permissions: string[] }>;
  installedFile: string; expectedRootKeyZeroFindings: number;
};
type App = typeof manifest.apps[number] & { rootKeyId: string; fingerprint: string; outPath: string;
  installedPath: string; remote: string; accepted: boolean };
let dir: string, cert: string, session: string, registry: string;
const apps: App[] = [];
let inventory: { rootKeys: Array<{ rootKeyId: string; verify: string }> };
let scan: { findings: Array<{ path: string; fingerprint: string; grade: string; rootKeyId?: string }>;
  skipped: unknown[]; summary: { ignored: number; dropped: number } };
const trace: Array<Record<string, unknown>> = [];
const oldChecks: Array<{ name: string; rejected: boolean }> = [];
// Pinned LND's ordinary RPC authentication failures use both documented forms.
const signatureRejection = /signature mismatch|verification failed/i;
function docker(args: string[], input?: string) {
  return spawnSync('docker', [...compose, ...args], { cwd: repo, input, encoding: 'utf8',
    timeout: 30_000, maxBuffer: 2_000_000 });
}
function checked(run: ReturnType<typeof docker>, operation: string) {
  if (run.status !== 0) throw new FixtureInvalidError(`Fixture ${operation} failed`);
  trace.push({ operation, exit: run.status });
  return run;
}
function lncli(args: string[]) {
  const run = checked(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]), args[0]);
  return JSON.parse(run.stdout) as Record<string, unknown>;
}
function remote(name: string) { return `/tmp/macwarden-cp033-${process.pid}-${name}.macaroon`; }
function declare(path: string) { appendFileSync(join(process.env.MACWARDEN_TEST_TMP!, 'declared-out.txt'), `${path}\n`); }
function register(path: string, name: string) {
  declare(path);
  const sentinel = registerFixtureSentinel(path, `cp033-${name}.macaroon`);
  declare(sentinel);
}
function copyRemote(path: string, local: string, name: string) {
  checked(docker(['cp', `lnd:${path}`, local]), 'copy fixture credential by path');
  register(local, name);
  return local;
}
function bakeSession(id: string, name: string) {
  const path = remote(name);
  const ids = (lncli(['listmacaroonids']).root_key_ids as unknown[]).map(String);
  if (id === '0' || ids.includes(id)) throw new FixtureInvalidError('Session ID collision');
  checked(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    `--root_key_id=${id}`, '--timeout=3600', `--save_to=${path}`,
    'macaroon:generate', 'macaroon:read', 'macaroon:write', 'info:read']), 'bake session');
  const printed = lncli(['printmacaroon', `--macaroon_file=${path}`]);
  expect(printed.root_key_id).toBe(id);
  return { remote: path, local: copyRemote(path, join(dir, `${name}.macaroon`), name) };
}
function probe(path: string) {
  return docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${path}`, 'getinfo']);
}
async function rest(path: string, body?: Record<string, unknown>) {
  const data = body ? Buffer.from(JSON.stringify(body)) : undefined;
  return await new Promise<{ status: number; json: Record<string, unknown> }>((done, fail) => {
    const call = request({ hostname: 'localhost', port: fixtureTopology().restPort, path, method: body ? 'POST' : 'GET',
      ca: readFileSync(cert), signal: AbortSignal.timeout(10_000),
      headers: data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {} }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        try { done({ status: response.statusCode || 0, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { fail(new FixtureInvalidError('Unlocker response invalid JSON')); }
      });
    });
    call.on('error', () => fail(new FixtureInvalidError('Unlocker request failed')));
    if (data) call.write(data);
    call.end();
  });
}
async function regenerate() {
  const base = readFileSync(join(repo, 'test/fixture/docker-compose.yml'), 'utf8');
  const service = /\n {2}lnd:\r?\n([\s\S]*?)(?=\nvolumes:)/.exec(base)?.[1];
  const commands = / {4}command:\r?\n((?: {6}- [^\r\n]+\r?\n)+)/.exec(service || '')?.[1]
    .split(/\r?\n/).filter(Boolean).map(line => line.replace(/^ {6}- /, ''));
  if (!commands?.includes('--noseedbackup')) throw new FixtureInvalidError('Fixture startup recipe unavailable');
  const override = join(dir, 'unlocker.yml');
  writeFileSync(override, `services:\n  lnd:\n    command:\n${commands.filter(arg => arg !== '--noseedbackup').map(arg => `      - ${arg}`).join('\n')}\n`);
  checked(docker(['stop', 'lnd']), 'operator stops disposable LND');
  checked(spawnSync('docker', [...compose, '-f', override, 'up', '-d', '--no-deps', '--force-recreate', 'lnd'],
    { cwd: repo, encoding: 'utf8', timeout: 60_000 }), 'operator starts unlocker');
  const password = randomBytes(24);
  const cli = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'changepassword',
    '--new_mac_root_key', `--save_to=${remote('regenerated-admin')}`],
  `\n${password.toString('base64url')}\n${password.toString('base64url')}\n`);
  const nonTty = cli.status !== 0 && /tty|terminal|ioctl/i.test(cli.stderr);
  trace.push({ operation: 'operator lncli changepassword', exit: cli.status, nonTty });
  if (cli.status !== 0 && !nonTty) throw new FixtureInvalidError('Password CLI failed outside known non-TTY limit');
  if (nonTty) {
    let locked = false;
    for (let attempt = 0; attempt < 20; attempt++) {
      try { const state = await rest('/v1/state'); locked = state.status === 200 && state.json.state === 'LOCKED'; }
      catch { /* Readiness may lag container restart. */ }
      if (locked) break;
      await new Promise(done => setTimeout(done, 500));
    }
    if (!locked) throw new FixtureInvalidError('Unlocker did not become locked');
    // Oracle emulates the operator once; macwarden never sends this mutation.
    const changed = await rest('/v1/changepassword', { current_password: '',
      new_password: password.toString('base64'), new_macaroon_root_key: true });
    trace.push({ operation: 'operator REST fallback for non-TTY CLI', status: changed.status });
    if (changed.status !== 200) throw new FixtureInvalidError('Operator root regeneration failed');
  }
  let ready = false;
  for (let attempt = 0; attempt < 20; attempt++) {
    const run = probe(adminRemote);
    if (run.status === 0) {
      const info = JSON.parse(run.stdout);
      if (info.chains?.[0]?.network !== 'regtest' || !info.version?.startsWith('0.21.4-beta'))
        throw new FixtureInvalidError('Regenerated fixture identity invalid');
      ready = true; break;
    }
    await new Promise(done => setTimeout(done, 500));
  }
  if (!ready) throw new FixtureInvalidError('Current operator authority did not become ready');
  trace.push({ operation: 'current operator authority ready', exit: 0 });
}
function cli(command: string, args: string[], online = true) {
  const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), command, ...args,
    ...(online ? ['--registry', registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', cert, '--macaroon', session] : []), '--json'],
  { cwd: repo, env, encoding: 'utf8', timeout: 30_000, maxBuffer: 2_000_000 });
  // Never give assertion reporters raw credential-bearing output.
  if (run.status !== 0) throw new Error(`Guide ${command} exited ${run.status}`);
  trace.push({ operation: `macwarden ${command}`, exit: run.status });
  const outIndex = args.indexOf('--out');
  if (outIndex >= 0 && existsSync(args[outIndex + 1])) register(args[outIndex + 1], args[args.indexOf('--label') + 1]);
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: process.env.MACWARDEN_SENTINEL_DIR,
    commandOutput: run.stdout + run.stderr, paths: [], testTmp: process.env.MACWARDEN_TEST_TMP, root: repo })).toBeNull();
  const envelope = JSON.parse(run.stdout);
  expect(envelope.ok).toBe(true);
  return envelope.result;
}
beforeAll(async () => {
  if (!process.env.MACWARDEN_TEST_TMP || !process.env.MACWARDEN_SENTINEL_DIR)
    throw new FixtureInvalidError('Scoped test tmp and sentinel directories required');
  dir = join(resolve(process.env.MACWARDEN_TEST_TMP), 'cp033-guide'); mkdirSync(dir, { recursive: true, mode: 0o700 });
  cert = join(dir, 'tls.cert'); registry = join(dir, 'registry.json');
  const info = lncli(['getinfo']); const roots = lncli(['listmacaroonids']);
  requirePinnedFixture(info, roots);
  trace.push({ operation: 'pinned fresh fixture', version: info.version, network: 'regtest', baselineRootKeyIds: roots.root_key_ids });
  checked(docker(['cp', 'lnd:/root/.lnd/tls.cert', cert]), 'copy fixture certificate');
  trace.push({ operation: 'maintenance window; three simulated apps paused', apps: manifest.apps.map(app => app.label) });
  const oldDefault = remote('old-default'); checked(docker(['exec', '-T', 'lnd', 'cp', adminRemote, oldDefault]), 'preserve old fixture default');
  const oldDefaultLocal = copyRemote(oldDefault, join(dir, 'old-default.macaroon'), 'old-default');
  expect(lncli(['printmacaroon', `--macaroon_file=${oldDefault}`]).root_key_id).toBe('0');
  for (const app of manifest.apps) {
    const config = join(dir, 'apps', app.label, 'config'); mkdirSync(config, { recursive: true, mode: 0o700 });
    const installed = join(config, manifest.installedFile); copyFileSync(oldDefaultLocal, installed); declare(installed);
  }
  trace.push({ operation: 'independent initial app config manifest', apps: manifest.apps.map(app => ({ label: app.label, rootKeyId: '0' })) });
  const oldSession = bakeSession('33001', 'old-session');
  const oldApp = remote('old-app');
  checked(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon', '--root_key_id=33002',
    `--save_to=${oldApp}`, 'info:read']), 'bake pre-rotation app');
  const oldAppLocal = copyRemote(oldApp, join(dir, 'old-app.macaroon'), 'old-app');
  for (const path of [oldDefault, oldSession.remote, oldApp]) expect(probe(path).status === 0).toBe(true);
  await regenerate();
  // force-recreate discards container /tmp. Restore the preserved old bytes,
  // then prove their identity before interpreting an ordinary RPC failure.
  for (const [name, local, path, id] of [
    ['old-default', oldDefaultLocal, oldDefault, '0'],
    ['old-session', oldSession.local, oldSession.remote, '33001'],
    ['old-app', oldAppLocal, oldApp, '33002'],
  ]) {
    checked(docker(['cp', local, `lnd:${path}`]), 'restore pre-rotation credential after container recreation');
    const digest = createHash('sha256').update(readFileSync(local)).digest('hex');
    const remoteDigest = checked(docker(['exec', '-T', 'lnd', 'sha256sum', path]), 'fingerprint restored credential').stdout.split(/\s/)[0];
    expect(remoteDigest).toBe(digest);
    expect(lncli(['printmacaroon', `--macaroon_file=${path}`]).root_key_id).toBe(id);
    trace.push({ operation: 'restored old credential identity', name, rootKeyId: id, fingerprint: `fp:${digest.slice(0, 16)}` });
  }
  for (const [name, path] of [['old-default', oldDefault], ['old-session', oldSession.remote], ['old-app', oldApp]]) {
    const run = probe(path);
    // Keep only exit/category evidence: an unknown failure is not proof of rejection.
    trace.push({ operation: 'pre-rotation credential probe', name, exit: run.status,
      category: run.status === 0 ? 'accepted' : signatureRejection.test(run.stderr) ? 'signature-rejected' :
        /root key with id [0-9]+ doesn't exist/i.test(run.stderr) ? 'root-key-missing' : 'unclassified-error' });
    oldChecks.push({ name, rejected: run.status !== 0 && (signatureRejection.test(run.stderr) ||
      /root key with id [0-9]+ doesn't exist/i.test(run.stderr)) });
  }
  session = bakeSession('33003', 'fresh-session').local;
  cli('inventory', []);
  for (const app of manifest.apps) {
    const outPath = join(dir, `${app.label}.macaroon`); declare(outPath);
    cli('bake', ['--label', app.label, '--preset', app.preset, '--expires', '90d', '--out', outPath]);
    register(outPath, app.label);
    const path = remote(app.label); checked(docker(['cp', outPath, `lnd:${path}`]), 'copy replacement for independent probe');
    const printed = lncli(['printmacaroon', `--macaroon_file=${path}`]);
    expect((printed.permissions as string[]).slice().sort()).toEqual(app.permissions.slice().sort());
    const config = join(dir, 'apps', app.label, 'config'); mkdirSync(config, { recursive: true, mode: 0o700 });
    const installedPath = join(config, manifest.installedFile);
    const fingerprint = `fp:${createHash('sha256').update(readFileSync(outPath)).digest('hex').slice(0, 16)}`;
    apps.push({ ...app, rootKeyId: String(printed.root_key_id), fingerprint, outPath, installedPath, remote: path, accepted: false });
  }
  // Finish every bake before distributing any replacement, as the guide orders.
  for (const app of apps) {
    copyFileSync(app.outPath, app.installedPath); declare(app.installedPath);
    expect(`fp:${createHash('sha256').update(readFileSync(app.installedPath)).digest('hex').slice(0, 16)}`).toBe(app.fingerprint);
    checked(docker(['cp', app.installedPath, `lnd:${app.remote}`]), 'installed credential for app-side probe');
    app.accepted = probe(app.remote).status === 0;
  }
  // Prepared from planted files and lncli facts before invoking either boundary.
  writeFileSync(join(dir, 'installed-manifest.json'), JSON.stringify(apps, null, 2));
  trace.push({ operation: 'distributed distinct replacements; apps reconnected', apps: apps.map(app => app.label) });
  inventory = cli('inventory', ['--verify']);
  scan = cli('scan', apps.map(app => join(dir, 'apps', app.label, 'config')), false);
  expect(lncli(['deletemacaroonid', '33003']).deleted).toBe(true);
  trace.push({ operation: 'operator revokes session', rootKeyId: '33003', deleted: true });
  // Sentinel retains the test credential for the standing leak checker.
  unlinkSync(session);
  trace.push({ operation: 'local session cleanup', removed: true });
  writeFileSync(join(dir, 'walkthrough.json'), JSON.stringify({ guide: 'docs/replacing-default-macaroons.md',
    trace, oldChecks, apps, scope: 'three app config directories only' }, null, 2));
}, 180_000);

it('CP-033/guide-regtest-walkthrough operator regeneration precedes fresh session and three independently accepted app credentials', () => {
  expect(oldChecks).toEqual(['old-default', 'old-session', 'old-app'].map(name => ({ name, rejected: true })));
  expect(apps).toHaveLength(3);
  expect(apps.every(app => /^[1-9][0-9]*$/.test(app.rootKeyId) && app.accepted)).toBe(true);
  expect(new Set(apps.map(app => app.rootKeyId)).size).toBe(3);
  expect(apps.some(app => app.rootKeyId === '33003')).toBe(false);
  const entries = JSON.parse(readFileSync(registry, 'utf8')).entries;
  expect(entries).toHaveLength(3);
  for (const app of apps) {
    const entry = entries.find((entry: { label: string }) => entry.label === app.label);
    expect(entry).toMatchObject({
      label: app.label, rootKeyId: app.rootKeyId, fingerprint: app.fingerprint, outPath: app.outPath,
      grade: app.grade, status: 'active', verified: true });
    expect(entry.permissions.slice().sort()).toEqual(app.permissions.slice().sort());
    expect(inventory.rootKeys.find(row => row.rootKeyId === app.rootKeyId)?.verify).toBe('accepted');
    expect(probe(app.remote).status === 0).toBe(true); // Session cleanup leaves app IDs valid.
  }
});
it('CP-033/guide-app-config-scan independent installed manifest agrees with final inventory and complete covered config findings', () => {
  expect(scan.skipped).toEqual([]);
  expect(scan.summary.ignored).toBe(0); expect(scan.summary.dropped).toBe(0);
  const portable = (path: string) => path.replaceAll('\\', '/');
  expect(scan.findings.map(finding => ({ path: portable(finding.path), fingerprint: finding.fingerprint, grade: finding.grade }))
    .sort((a, b) => a.path.localeCompare(b.path))).toEqual(apps.map(app => ({ path: app.installedPath,
      fingerprint: app.fingerprint, grade: app.grade })).map(app => ({ ...app, path: portable(app.path) })).sort((a, b) => a.path.localeCompare(b.path)));
  expect(apps.filter(app => app.rootKeyId === '0')).toHaveLength(manifest.expectedRootKeyZeroFindings);
  for (const app of apps) expect(inventory.rootKeys.find(row => row.rootKeyId === app.rootKeyId)?.verify).toBe('accepted');
});
it('CP-033/leak-check walkthrough output and undeclared temporary files contain no credential encoding', () => {
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: process.env.MACWARDEN_SENTINEL_DIR,
    paths: [dir], testTmp: process.env.MACWARDEN_TEST_TMP, root: repo })).toBeNull();
});
