import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { beforeAll, expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';
import { findLeaks } from '../helpers/leak-check.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { registerFixtureSentinel, requirePinnedFixture } from '../helpers/lnd-facts.mjs';

// Owner request 2026-10-07: offline attenuation against the pinned regtest LND.
const repo = resolve();
const suppliedTmp = process.env.MACWARDEN_TEST_TMP;
const suppliedSentinels = process.env.MACWARDEN_SENTINEL_DIR;
if (!suppliedTmp || !suppliedSentinels) throw new FixtureInvalidError('Scoped test tmp and sentinel directories required');
const outerTmp = resolve(suppliedTmp), sentinelDir = resolve(suppliedSentinels);
const tmp = join(outerTmp, 'attenuate-live');
const declarations = join(outerTmp, 'declared-out.txt');
const compose = fixtureTopology().composeArgs;
const remote = (part: string) => `/tmp/macwarden-attenuate-${process.pid}-${part}.macaroon`;

function docker(args: string[]) {
  return spawnSync('docker', [...compose, ...args], { cwd: repo, encoding: 'utf8', maxBuffer: 4_000_000, timeout: 30_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout); } catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function checked(result: ReturnType<typeof docker>, label: string): void {
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture ${label} unavailable`);
}
function declare(path: string): string { appendFileSync(declarations, `${path}\n`); return path; }
function copyOut(source: string, name: string): string {
  const local = declare(join(tmp, `${name}.macaroon`));
  checked(docker(['cp', `lnd:${source}`, local]), 'credential copy');
  const registered = declare(registerFixtureSentinel(local, `attenuate-${name}.macaroon`, sentinelDir));
  rmSync(local, { force: true });
  return registered;
}
function bake(name: string, id: string): { local: string; source: string } {
  const source = remote(name);
  checked(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    `--root_key_id=${id}`, `--save_to=${source}`, 'info:read']), 'bake');
  return { local: copyOut(source, name), source };
}
function cli(args: string[]) {
  return spawnSync(process.execPath, [resolve('dist/bin.js'), 'attenuate', ...args, '--json'],
    { env: childEnvironment(), encoding: 'utf8', timeout: 20_000, windowsHide: true });
}
function attenuated(source: string, name: string, flags: string[]): { local: string; remotePath: string; stdout: string } {
  const local = declare(join(sentinelDir, `attenuate-${name}.macaroon`));
  const run = cli([source, '--out', local, ...flags]);
  expect(run.status, run.stderr).toBe(0);
  const remotePath = remote(name);
  checked(docker(['cp', local, `lnd:${remotePath}`]), 'attenuated credential copy');
  return { local, remotePath, stdout: run.stdout };
}
function probe(path: string): 'accepted' | 'ip-rejected' | 'range-rejected' | 'unexpected' {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${path}`, 'getinfo']);
  if (result.status === 0) return 'accepted';
  // LND's IP lock checkers name the violated constraint; any other failure is unexpected.
  if (typeof result.stderr === 'string' && /locked to different IP address/i.test(result.stderr)) return 'ip-rejected';
  if (typeof result.stderr === 'string' && /locked to different IP range/i.test(result.stderr)) return 'range-rejected';
  return 'unexpected';
}
function clean(paths: string[], id: string): void {
  for (const path of paths) docker(['exec', '-T', 'lnd', 'rm', '-f', path]);
  docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', id]);
}

beforeAll(() => {
  requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
  mkdirSync(tmp, { recursive: true }); mkdirSync(sentinelDir, { recursive: true });
}, 30_000);

it('ATTENUATE/live-constrainmacaroon ipaddr output is byte-identical to lncli constrainmacaroon', async () => {
  const id = '51001', paths = [remote('cm-source'), remote('cm-lncli'), remote('cm-ours')];
  try {
    const source = bake('cm-source', id);
    checked(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'constrainmacaroon',
      '--ip_address=127.0.0.1', source.source, remote('cm-lncli')]), 'constrainmacaroon');
    const reference = copyOut(remote('cm-lncli'), 'cm-lncli');
    const ours = attenuated(source.local, 'cm-ours', ['--ip', '127.0.0.1']);
    expect(readFileSync(ours.local).equals(readFileSync(reference))).toBe(true);
  } finally { clean(paths, id); }
}, 60_000);

it('ATTENUATE/live-acceptance lncli accepts matching IP, range and future expiry and rejects a non-matching IP and range', async () => {
  const id = '51002', paths = [remote('acc-source'), remote('acc-ip'), remote('acc-range'), remote('acc-wrong'), remote('acc-range-wrong'), remote('acc-time')];
  try {
    const source = bake('acc-source', id);
    expect(probe(source.source)).toBe('accepted');
    // lncli inside the container reaches LND over loopback, so LND sees 127.0.0.1.
    expect(probe(attenuated(source.local, 'acc-ip', ['--ip', '127.0.0.1']).remotePath)).toBe('accepted');
    expect(probe(attenuated(source.local, 'acc-range', ['--ip-range', '127.0.0.0/8']).remotePath)).toBe('accepted');
    expect(probe(attenuated(source.local, 'acc-wrong', ['--ip', '203.0.113.9']).remotePath)).toBe('ip-rejected');
    // Proves LND enforces iprange rather than ignoring it: a range that excludes loopback is refused.
    expect(probe(attenuated(source.local, 'acc-range-wrong', ['--ip-range', '203.0.113.0/24']).remotePath)).toBe('range-rejected');
    const timed = attenuated(source.local, 'acc-time', ['--expires', '10m']);
    expect(probe(timed.remotePath)).toBe('accepted');
    const printed = lncli(['printmacaroon', `--macaroon_file=${timed.remotePath}`]) as { root_key_id: string; caveats: string[] };
    expect(printed.root_key_id).toBe(id);
    expect(printed.caveats.at(-1)).toMatch(/^time-before \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  } finally { clean(paths, id); }
}, 60_000);

it('ATTENUATE/live-shared-root-key revoking the root key ID rejects the parent and the attenuated copy', async () => {
  const id = '51003', paths = [remote('rv-source'), remote('rv-child')];
  try {
    const source = bake('rv-source', id);
    const child = attenuated(source.local, 'rv-child', ['--expires', '1h']);
    expect(JSON.parse(child.stdout).warnings.map((item: { code?: string } | string) => typeof item === 'string' ? item : item.code))
      .toContain('shared-root-key');
    expect(probe(child.remotePath)).toBe('accepted');
    checked(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', id]), 'deletemacaroonid');
    // Same revocation evidence as the CP-030 live probes: LND reports the deleted root key ID itself.
    for (const path of [source.source, child.remotePath]) {
      const rejected = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${path}`, 'getinfo']);
      expect(rejected.status).not.toBe(0);
      expect(rejected.stderr).toContain(`root key with id ${id} doesn't exist`);
    }
  } finally { clean(paths, id); }
}, 60_000);

it('ATTENUATE/leak-check registered credentials do not appear in command output or undeclared files', async () => {
  const id = '51004', paths = [remote('leak-source'), remote('leak-child')];
  try {
    const source = bake('leak-source', id);
    const child = attenuated(source.local, 'leak-child', ['--expires', '1h', '--ip', '127.0.0.1']);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir, paths: [tmp],
      testTmp: outerTmp, root: repo, commandOutput: child.stdout })).toBeNull();
  } finally { clean(paths, id); }
}, 60_000);
