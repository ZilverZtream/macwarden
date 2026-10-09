import { fixtureTopology } from '../fixture/topology.mjs';
import { expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { findLeaks } from "../helpers/leak-check.js";

const repo = resolve();
const compose = fixtureTopology().composeArgs;
const fixtureDir = join(tmpdir(), 'macwarden-fixture');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
const sentinelDir = process.env.MACWARDEN_SENTINEL_DIR || join(testTmp, 'sentinels');
const observation = join(testTmp, 'cp004-fixture-observation.json');
function docker(args: string[]) {
  return spawnSync('docker', [...compose, ...args], { cwd: repo, encoding: 'utf8', maxBuffer: 16_000_000, timeout: 30_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const p = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (p.status !== 0) throw new Error(`lncli ${args[0]} failed`);
  try { return JSON.parse(p.stdout); } catch { throw new Error(`lncli ${args[0]} returned invalid JSON`); }
}
function state() {
  const info = lncli(['getinfo']);
  if ((info.chains as { network: string }[] | undefined)?.[0]?.network !== 'regtest'
    || typeof info.version !== 'string' || !info.version.startsWith('0.21.4-beta')) {
    throw new FixtureInvalidError('Fixture must be LND 0.21.4-beta on regtest');
  }
  return info;
}
function observe(facts: Record<string, unknown>) {
  mkdirSync(testTmp, { recursive: true });
  const previous = existsSync(observation) ? JSON.parse(readFileSync(observation, 'utf8')) as Record<string, unknown> : {};
  writeFileSync(observation, JSON.stringify({ ...previous, ...facts }, null, 2) + '\n');
}
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { name: string; file: string }[];
};

  it('CP-004/fixture-pinned getinfo and ListPermissions match the committed snapshot', () => {
    const info = state();
    const live = lncli(['listpermissions']);
    const raw = live.method_permissions as Record<string, { permissions?: { entity: string; action: string }[] }>;
    const methods = Object.fromEntries(Object.entries(raw).map(([name, value]) => [name, (value.permissions || []).map(p => `${p.entity}:${p.action}`)]));
    const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as { methods: Record<string, string[]> };
    expect(JSON.stringify(methods) === JSON.stringify(snapshot.methods)).toBe(true);
    observe({ network: 'regtest', lndVersion: info.version, methodCount: Object.keys(methods).length });
  });
  it('CP-004/printmacaroon-live every stored decode equals pinned lncli output', () => {
    state();
    let count = 0;
    for (const vector of manifest.vectors) {
      const remote = `/tmp/macwarden-oracle-${process.pid}-${vector.file}`;
      const copied = docker(['cp', join(repo, 'test/vectors', vector.file), `lnd:${remote}`]);
      if (copied.status !== 0) throw new Error(`Could not transfer ${vector.name} to fixture`);
      let printed;
      try { printed = lncli([`printmacaroon`, `--macaroon_file=${remote}`]); }
      finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
      const stored = JSON.parse(readFileSync(join(repo, 'test/vectors', `${vector.name}.printmacaroon.json`), 'utf8'));
      expect(JSON.stringify(printed) === JSON.stringify(stored), vector.name).toBe(true);
      count++;
    }
    observe({ verifiedVectorCount: count });
  }, 120_000);
  it('CP-004/baked-location-lnd newly baked macaroon has location lnd', () => {
    state();
    const remote = `/tmp/macwarden-oracle-${process.pid}-baked.macaroon`;
    const baked = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon', '--root_key_id=4294967296', `--save_to=${remote}`, 'info:read']);
    if (baked.status !== 0) throw new Error('Pinned LND bake failed');
    try {
      const printed = lncli(['printmacaroon', `--macaroon_file=${remote}`]);
      expect(printed.location).toBe('lnd');
      observe({ bakedLocation: printed.location, bakedRootKeyId: printed.root_key_id });
      mkdirSync(sentinelDir, { recursive: true });
      const registered = docker(['cp', `lnd:${remote}`, join(sentinelDir, 'cp004-baked.macaroon')]);
      if (registered.status !== 0) throw new Error('Could not register runtime credential sentinel');
    } finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
  });
  it('CP-004/leak-check registers the fixture credential and finds no temp leak', () => {
    state();
    mkdirSync(sentinelDir, { recursive: true });
    copyFileSync(join(fixtureDir, 'admin.macaroon'), join(sentinelDir, 'fixture-admin.macaroon'));
    const leak = findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      paths: [testTmp], testTmp, root: repo });
    expect(leak).toBeNull();
    observe({ fixtureAdminSentinelRegistered: true, leakCheck: 'clear' });
  });
