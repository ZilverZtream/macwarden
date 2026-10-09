import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { createFixture } from '../fixture/fixture.mjs';
import { fixtureTopology } from '../fixture/topology.mjs';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { findLeaks } from '../helpers/leak-check.js';
import { FULL_CONTROL_TIMEOUT_MS, fullControl } from '../harness/cp050-full.js';

it('CP-050/selection-and-evidence-ground-truth actual full validation retains complete evidence and rejects incomplete or changed inputs', () => {
  fullControl('complete');
  fullControl('changed-candidate');
  fullControl('selective-as-full');
  fullControl('metadata-leak');
}, 4 * FULL_CONTROL_TIMEOUT_MS + 60_000);

it('CP-050/fixture-shard-isolation two fresh pinned owners isolate mutations and teardown', async () => {
  const scratch = process.env.MACWARDEN_TEST_TMP;
  const sentinels = process.env.MACWARDEN_SENTINEL_DIR;
  if (!scratch || !sentinels) throw new FixtureInvalidError('Private fixture scratch and sentinels are required');
  const owners = ['3', '4'].map(shard => {
    const topology = fixtureTopology({ MACWARDEN_FIXTURE_SHARD: shard });
    const lifecycle: Array<{ command: string; exit: number | null }> = [];
    const fixture = createFixture({ env: { MACWARDEN_FIXTURE_SHARD: shard }, tempBase: join(scratch, `control-${shard}`),
      docker: (args, options) => {
        const result = spawnSync('docker', [...topology.composeArgs, ...args], { ...options,
          encoding: options.encoding === null ? null : 'utf8', env: childEnvironment() });
        // Record lifecycle only. Credential-producing commands remain private.
        if (args[0] === 'up' || args[0] === 'down') lifecycle.push({ command: args.join(' '), exit: result.status });
        return result;
      } });
    const run = (args: string[]) => {
      const result = spawnSync('docker', [...topology.composeArgs, ...args], { encoding: 'utf8',
        env: childEnvironment(), timeout: 30_000, maxBuffer: 2_000_000 });
      if (result.error || result.status !== 0) throw new FixtureInvalidError('Isolated regtest command unavailable');
      return result.stdout;
    };
    const cli = (args: string[]) => JSON.parse(run(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args])) as Record<string, unknown>;
    return { shard, topology, fixture, lifecycle, run, cli };
  });
  try {
    await Promise.all(owners.map(owner => owner.fixture.up()));
    for (const owner of owners) {
      const info = owner.cli(['getinfo']) as { chains?: { network: string }[]; version?: string };
      expect(info.chains?.[0]?.network).toBe('regtest');
      expect(info.version?.startsWith('0.21.4-beta')).toBe(true);
      expect(owner.cli(['listmacaroonids']).root_key_ids).toEqual(['0']);
    }
    const credentials = owners.map((owner, index) => {
      const id = String(500050 + index);
      const value = owner.run(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon', `--root_key_id=${id}`, 'info:read']).trim();
      if (!/^(?:[0-9a-f]{2})+$/i.test(value)) throw new FixtureInvalidError('Fixture bake response invalid');
      const path = join(sentinels, `cp050-owner-${owner.shard}.macaroon`);
      writeFileSync(path, Buffer.from(value, 'hex'), { mode: 0o600 });
      const remote = '/tmp/cp050-acceptance.macaroon';
      owner.run(['cp', path, `lnd:${remote}`]);
      return { id, remote };
    });
    owners.forEach((owner, index) => {
      const ids = owner.cli(['listmacaroonids']).root_key_ids as string[];
      expect(ids).toContain(credentials[index]!.id);
      expect(ids).not.toContain(credentials[1 - index]!.id);
    });
    await owners[0]!.fixture.down();
    const info = owners[1]!.cli([`--macaroonpath=${credentials[1]!.remote}`, 'getinfo']) as { chains?: { network: string }[] };
    expect(info.chains?.[0]?.network).toBe('regtest');
  } finally {
    const outcomes = await Promise.allSettled(owners.map(owner => owner.fixture.down()));
    for (const owner of owners) {
      const path = join(scratch, `cp050-lifecycle-${owner.shard}.json`);
      writeFileSync(path, JSON.stringify({ project: owner.topology.project, restPort: owner.topology.restPort,
        grpcPort: owner.topology.grpcPort, commands: owner.lifecycle }));
      writeFileSync(`${path}.sha256`, createHash('sha256').update(readFileSync(path)).digest('hex'));
    }
    expect(outcomes.every(outcome => outcome.status === 'fulfilled'), 'Every fixture owner must tear down').toBe(true);
  }
});

it('CP-050/leak-check independent nonempty sentinels cover retained selection output and shard scratch', () => {
  expect(findLeaks({ root: process.cwd(), sentinels: 'test/sentinels.json',
    sentinelDir: process.env.MACWARDEN_SENTINEL_DIR, testTmp: process.env.MACWARDEN_TEST_TMP,
    paths: [process.env.MACWARDEN_TEST_TMP!], commandOutput: '' })).toBeNull();
});
