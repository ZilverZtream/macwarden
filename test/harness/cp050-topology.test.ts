import { expect, it } from 'vitest';
import { EventEmitter } from 'node:events';
import { fixtureTopology } from '../fixture/topology.mjs';
import { createFixture } from '../fixture/fixture.mjs';
import { createPrivateDirectory } from '../../scripts/private-scratch.mjs';
import { childEnvironment } from '../helpers/environment.js';

it('CP-050/B3 fixed isolated fixture owners use distinct projects and loopback ports', () => {
  const fixtures = ['1', '2', '3', '4', '5', '6', '7', '8'].map(shard => fixtureTopology({ MACWARDEN_FIXTURE_SHARD: shard }));
  expect(new Set(fixtures.map(f => f.project)).size).toBe(8);
  expect(new Set(fixtures.map(f => f.restPort)).size).toBe(8);
  expect(new Set(fixtures.map(f => f.grpcPort)).size).toBe(8);
  // No owner's REST port is another owner's gRPC port, or the unsharded fixture's.
  expect(new Set([...fixtures, fixtureTopology({})].flatMap(f => [f.restPort, f.grpcPort])).size).toBe(18);
  expect(fixtureTopology({}).restPort).toBe(18080);
  expect(fixtureTopology({}).grpcPort).toBe(18009);
  expect(fixtureTopology({}).composeArgs).not.toContain('-p');
});
it.each([
  { network: 'mainnet', version: '0.21.4-beta' },
  { network: 'regtest', version: '0.20.0-beta' },
])('CP-050/B3 shard controller refuses wrong pinned state %j before credential copies', async info => {
  const root = await createPrivateDirectory(process.env.MACWARDEN_TEST_TMP!, 'cp050-invalid-');
  const calls: string[] = [];
  const fixture = createFixture({ env: { MACWARDEN_FIXTURE_SHARD: '1' }, tempBase: root,
    docker: args => { calls.push(args[0]!); return { status: 0, stdout: Buffer.alloc(0) }; },
    httpsRequest: (_options, receive) => {
      const req = new EventEmitter() as EventEmitter & { end(): void };
      req.end = () => {
        const response = new EventEmitter() as EventEmitter & { statusCode: number };
        response.statusCode = 200; receive(response);
        response.emit('data', Buffer.from(JSON.stringify({ chains: [{ network: info.network }], version: info.version })));
        response.emit('end');
      };
      return req;
    },
  });
  await expect(fixture.up()).rejects.toMatchObject({ name: 'FixtureInvalidError' });
  expect(calls).not.toContain('cp');
  expect(calls.filter(call => call === 'down')).toHaveLength(2);
});
it.each(['up', 'down'])('CP-050/B3 unavailable shard %s is INVALID and still tears down its owner', async failure => {
  const root = await createPrivateDirectory(process.env.MACWARDEN_TEST_TMP!, 'cp050-unavailable-');
  const calls: string[] = [];
  const fixture = createFixture({ env: { MACWARDEN_FIXTURE_SHARD: '1' }, tempBase: root,
    docker: args => { calls.push(args[0]!); return { status: args[0] === failure ? 1 : 0, stdout: '' }; } });
  await expect(fixture.up()).rejects.toMatchObject({ name: 'FixtureInvalidError' });
  expect(calls).toEqual(failure === 'up' ? ['down', 'up', 'down'] : ['down', 'down']);
});
it.each(['', '0', '9', '01', '-p injected', '../1', '1\n'])('CP-050/B3 invalid fixture identity %j is refused before Docker', value => {
  expect(() => fixtureTopology({ MACWARDEN_FIXTURE_SHARD: value })).toThrow(/Fixture shard/);
});
it('CP-050/B3 fixture identity propagates to subprocesses', () => {
  const previous = process.env.MACWARDEN_FIXTURE_SHARD;
  try {
    process.env.MACWARDEN_FIXTURE_SHARD = '2';
    expect(childEnvironment().MACWARDEN_FIXTURE_SHARD).toBe('2');
  } finally {
    if (previous === undefined) delete process.env.MACWARDEN_FIXTURE_SHARD;
    else process.env.MACWARDEN_FIXTURE_SHARD = previous;
  }
});
