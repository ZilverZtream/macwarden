import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';

/** Fixed loopback listeners and Compose ownership; caller input never becomes a port or project name. */
export function fixtureTopology(env = process.env) {
  const shard = env.MACWARDEN_FIXTURE_SHARD;
  const base = ['compose', '-f', 'test/fixture/docker-compose.yml', '-f', 'test/fixture/cp024-compose.yml'];
  if (shard === undefined) return { composeArgs: base, restPort: 18080, grpcPort: 18009, project: undefined };
  if (shard.length !== 1 || !/^[1-8]$/.test(shard)) throw new FixtureInvalidError('Fixture shard must be one of 1 to 8');
  const index = Number(shard);
  const project = `macwarden-shard-${shard}`;
  return { composeArgs: ['compose', '-p', project, ...base.slice(1), '-f', `test/fixture/shard-${shard}.yml`],
    restPort: 18080 + index * 100, grpcPort: 18009 + index * 100, project };
}
