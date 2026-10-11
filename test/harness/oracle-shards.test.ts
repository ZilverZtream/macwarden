import { execFileSync, spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { assignShards, listOracleFiles, readDurations } from '../../scripts/oracle-shards.mjs';
import { lndOwners } from '../../scripts/full-validation.mjs';
import { fixtureTopology } from '../fixture/topology.mjs';

const oracleFiles = readdirSync('test/oracle').filter(name => name.endsWith('.test.ts')).map(name => `test/oracle/${name}`);

it('TOOLING-PERF/oracle-shards full validation plan gives every oracle file exactly one fixture owner', () => {
  const plan = assignShards(oracleFiles, readDurations('.'), lndOwners.length);
  expect(plan).toHaveLength(lndOwners.length);
  const planned = plan.flatMap(shard => shard.files);
  expect(planned.sort()).toEqual([...oracleFiles].sort());
  for (const shard of plan) expect(shard.files.length).toBeGreaterThan(0);
  // CP-050/fixture-shard-isolation starts owners 3 and 4 itself; no runner shard may hold them.
  expect(lndOwners).not.toContain('3');
  expect(lndOwners).not.toContain('4');
  expect(new Set(lndOwners).size).toBe(lndOwners.length);
  for (const owner of lndOwners) expect(() => fixtureTopology({ MACWARDEN_FIXTURE_SHARD: owner })).not.toThrow();
});

it('TOOLING-PERF/oracle-shards greedy assignment is deterministic, drops empty shards and weighs unknown files by default', () => {
  const durations = { defaultSeconds: 10, files: { 'test/oracle/a.test.ts': 100, 'test/oracle/b.test.ts': 60, 'test/oracle/c.test.ts': 50 } };
  const plan = assignShards(['test/oracle/c.test.ts', 'test/oracle/new.test.ts', 'test/oracle/a.test.ts', 'test/oracle/b.test.ts'], durations, 2);
  // a (100) | b (60) + c (50) = 110; the unmapped file (10) goes to the least-loaded shard, a's.
  expect(plan).toEqual([
    { files: ['test/oracle/a.test.ts', 'test/oracle/new.test.ts'], seconds: 110 },
    { files: ['test/oracle/b.test.ts', 'test/oracle/c.test.ts'], seconds: 110 },
  ]);
  expect(assignShards(['test/oracle/a.test.ts'], durations, 6)).toHaveLength(1);
  expect(() => assignShards(['test/oracle/a.test.ts', 'test/oracle/a.test.ts'], durations, 2)).toThrow(/duplicate/);
  expect(() => assignShards(['test/oracle/a.test.ts'], durations, 0)).toThrow(/shard count/);
});

it('TOOLING-PERF/oracle-shards every shard Compose override publishes the topology ports on loopback only', () => {
  for (const shard of ['1', '2', '3', '4', '5', '6', '7', '8']) {
    const topology = fixtureTopology({ MACWARDEN_FIXTURE_SHARD: shard });
    const ports = [...readFileSync(`test/fixture/shard-${shard}.yml`, 'utf8').matchAll(/^\s*- (.+)$/gm)].map(match => match[1]!.trim());
    expect(ports).toEqual([`127.0.0.1:${topology.restPort}:8080`, `127.0.0.1:${topology.grpcPort}:10009`]);
  }
});

it('TOOLING-PERF/oracle-shards the checked-in duration map names only existing oracle files', () => {
  const durations = readDurations('.');
  expect(durations.defaultSeconds).toBeGreaterThan(0);
  for (const [file, seconds] of Object.entries(durations.files)) {
    expect(oracleFiles, file).toContain(file);
    expect(seconds).toBeGreaterThanOrEqual(0);
  }
});

it('TOOLING-PERF/oracle-shards the CI matrix quarters cover every oracle file exactly once', () => {
  const quarters = [1, 2, 3, 4].map(index => execFileSync(process.execPath, ['scripts/oracle-shards.mjs', '--files', `${index}/4`], { encoding: 'utf8' })
    .split('\n').filter(Boolean));
  for (const files of quarters) expect(files.length).toBeGreaterThan(0);
  const listed = quarters.flat();
  expect(new Set(listed).size).toBe(listed.length);
  expect(listed.sort()).toEqual([...oracleFiles].sort());
  expect(listOracleFiles('.')).toEqual([...oracleFiles].sort());
  for (const bad of [['--files', '5/4'], ['--files', '0/4'], ['--files', '1/0'], ['--files'], ['--files', '1/4', 'x']]) {
    expect(spawnSync(process.execPath, ['scripts/oracle-shards.mjs', ...bad], { encoding: 'utf8' }).status, bad.join(' ')).toBe(2);
  }
});
