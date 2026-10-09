import { fixtureTopology } from '../fixture/topology.mjs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { Secret } from '../../src/secret.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';

type Facts = { rootKeyId: bigint; permissions: string[]; caveats: { type: string; value: string }[] };
const repo = resolve();
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { name: string; file: string; canonicalLength: number; fingerprint: string }[];
};

const decoder = (): Promise<{ decodeMacaroon: (secret: Secret) => Facts }> => import('../../src/decode/index.js');
const docker = (args: string[]) => spawnSync('docker', [...fixtureTopology().composeArgs, ...args],
  { cwd: repo, encoding: 'utf8', maxBuffer: 16_000_000, timeout: 30_000 });
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function state(): void {
  const info = lncli(['getinfo']);
  const ids = lncli(['listmacaroonids']).root_key_ids;
  if ((info.chains as { network: string }[] | undefined)?.[0]?.network !== 'regtest'
    || typeof info.version !== 'string' || !info.version.startsWith('0.21.4-beta')
    || !Array.isArray(ids) || ids.some(id => String(id) !== '0')) {
    throw new FixtureInvalidError('Fixture must be fresh LND 0.21.4-beta on regtest');
  }
}
function sameCaveats(facts: Facts, stored: string[] | null): boolean {
  return facts.caveats.length === (stored?.length || 0) && facts.caveats.every((caveat, index) =>
    caveat.type === 'third-party' ? caveat.value === 'fixture-location'
      : (caveat.type === 'unknown' ? caveat.value : `${caveat.type} ${caveat.value}`) === stored?.[index]);
}

it('CP-005/printmacaroon-live decoded facts match live pinned LND', async () => {
  state();
  const implementation = await decoder();
  for (const entry of manifest.vectors) {
    const remote = `/tmp/macwarden-cp005-${process.pid}-${entry.file}`;
    const copied = docker(['cp', join(repo, 'test/vectors', entry.file), `lnd:${remote}`]);
    if (copied.status !== 0) throw new FixtureInvalidError(`Fixture could not receive ${entry.name}`);
    let live: Record<string, unknown>;
    try { live = lncli(['printmacaroon', `--macaroon_file=${remote}`]); }
    finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
    const facts = implementation.decodeMacaroon(new Secret(readFileSync(join(repo, 'test/vectors', entry.file))));
    expect(facts.rootKeyId.toString() === live.root_key_id, entry.name).toBe(true);
    expect(JSON.stringify(facts.permissions) === JSON.stringify(live.permissions), entry.name).toBe(true);
    expect(sameCaveats(facts, live.caveats as string[] | null), entry.name).toBe(true);
  }
}, 120_000);

it('CP-005/fingerprint-manifest decoder fingerprints match independent vector hashes', async () => {
  const implementation = await decoder();
  for (const entry of manifest.vectors) {
    const value = readFileSync(join(repo, 'test/vectors', entry.file));
    const digest = `fp:${createHash('sha256').update(value.subarray(0, entry.canonicalLength)).digest('hex').slice(0, 16)}`;
    const facts = implementation.decodeMacaroon(new Secret(value)) as Facts & { fingerprint: string };
    expect(facts.fingerprint === entry.fingerprint && digest === entry.fingerprint, entry.name).toBe(true);
  }
});
