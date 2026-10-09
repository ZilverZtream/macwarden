import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';

type Result = { grade: string; reasons: string[]; warnings: string[]; unassessed: string[] };
const repo = resolve();
const vectors = join(repo, 'test/vectors');

const grader = (): Promise<{ grade: (permissions: string[]) => Result }> => import('../../src/grade/index.js');
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; expectedGrade: string }[];
};
const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as {
  lndVersion: string; methods: Record<string, string[]>;
};
const docker = (args: string[]) => spawnSync('docker', [...fixtureTopology().composeArgs, ...args],
  { cwd: repo, encoding: 'utf8', maxBuffer: 16_000_000, timeout: 30_000 });
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function state(): Record<string, unknown> {
  const info = lncli(['getinfo']);
  const ids = lncli(['listmacaroonids']).root_key_ids;
  if ((info.chains as { network: string }[] | undefined)?.[0]?.network !== 'regtest'
    || typeof info.version !== 'string' || !info.version.startsWith('0.21.4-beta')
    || !Array.isArray(ids) || ids.some(id => String(id) !== '0')) {
    throw new FixtureInvalidError('Fixture must be fresh LND 0.21.4-beta on regtest');
  }
  return info;
}

it('CP-007/snapshot-live committed methods and LND version equal pinned fixture', () => {
  const info = state();
  const live = lncli(['listpermissions']);
  const raw = live.method_permissions as Record<string, { permissions?: { entity: string; action: string }[] }>;
  const methods = Object.fromEntries(Object.entries(raw).map(([name, value]) =>
    [name, (value.permissions || []).map(permission => `${permission.entity}:${permission.action}`)]));
  expect((info.version as string).startsWith(snapshot.lndVersion)).toBe(true);
  expect(methods).toEqual(snapshot.methods);
});

it('CP-007/default-files-live fixture default credentials grade ADMIN, READ and RECEIVE', async () => {
  state();
  const { grade } = await grader();
  for (const [name, expected] of [['admin', 'ADMIN'], ['readonly', 'READ'], ['invoice', 'RECEIVE']]) {
    const path = `/root/.lnd/data/chain/bitcoin/regtest/${name}.macaroon`;
    const live = lncli(['printmacaroon', `--macaroon_file=${path}`]);
    expect(grade(live.permissions as string[]).grade, name).toBe(expected);
  }
});

it('CP-007/manifest-grades every stored printmacaroon set matches hand assigned grade', async () => {
  const { grade } = await grader();
  for (const vector of manifest.vectors) {
    const stored = JSON.parse(readFileSync(join(vectors, `${vector.name}.printmacaroon.json`), 'utf8')) as {
      permissions: string[];
    };
    expect(grade(stored.permissions).grade, vector.name).toBe(vector.expectedGrade);
  }
});
