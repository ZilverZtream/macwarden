import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { findLeaks } from "../helpers/leak-check.js";
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';

type Print = { root_key_id: string; permissions: string[]; caveats: string[] | null };
type Caveat = { type: string; value: string; expired?: boolean };
type Result = { rootKeyId: string; permissions: string[]; caveats: Caveat[];
  fingerprint: string; grade: string };
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const tempRoot = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
const sentinelRoot = process.env.MACWARDEN_SENTINEL_DIR || join(tempRoot, 'sentinels');
const vectorManifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; file: string; fingerprint: string; expectedGrade: string }[] };
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(JSON.parse(
  readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8')));
const docker = (args: string[]) => spawnSync('docker',
  [...fixtureTopology().composeArgs, ...args],
  { cwd: repo, encoding: 'utf8', timeout: 30_000, maxBuffer: 8_000_000 });

function lncli(args: string[]): Record<string, unknown> {
  const run = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (run.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(run.stdout) as Record<string, unknown>; }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function freshRegtest(): void {
  const info = lncli(['getinfo']);
  const ids = lncli(['listmacaroonids']).root_key_ids;
  if ((info.chains as { network: string }[] | undefined)?.[0]?.network !== 'regtest'
    || typeof info.version !== 'string' || !info.version.startsWith('0.21.4-beta')
    || !Array.isArray(ids) || ids.some(id => String(id) !== '0'))
    throw new FixtureInvalidError('Fixture must be fresh LND 0.21.4-beta on regtest');
}
function printStored(name: string): Print {
  return JSON.parse(readFileSync(join(vectors, `${name}.printmacaroon.json`), 'utf8')) as Print;
}
function inspect(path: string): { raw: string; result: Result } {
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', path, '--json'],
    { cwd: repo, encoding: 'utf8', timeout: 10_000, maxBuffer: 1_000_000 });
  expect(run.status).toBe(0);
  let document: unknown;
  try { document = JSON.parse(run.stdout) as unknown; }
  catch { throw new Error('inspect did not emit one JSON document'); }
  expect(validate(document), 'inspect schema validation').toBe(true);
  expect(run.stderr).toBe('');
  const envelope = document as { ok: boolean; result: Result };
  expect(envelope.ok).toBe(true);
  return { raw: run.stdout + run.stderr, result: envelope.result };
}

it('CP-037/inspect-live-regression third-party and first-party facts match stored and live lncli', () => {
  freshRegtest();
  mkdirSync(tempRoot, { recursive: true });
  mkdirSync(sentinelRoot, { recursive: true });
  const owned = mkdtempSync(join(tempRoot, 'cp037-oracle-'));
  try {
    for (const name of ['third-party', 'ipaddr', 'default-readonly']) {
      const entry = vectorManifest.vectors.find(item => item.name === name);
      expect(entry, `vector ${name} is absent`).toBeDefined();
      const path = join(vectors, entry!.file);
      const remote = `/tmp/macwarden-cp037-${process.pid}-${entry!.file}`;
      if (docker(['cp', path, `lnd:${remote}`]).status !== 0)
        throw new FixtureInvalidError(`Fixture could not receive ${name}`);
      let live: Print;
      try { live = lncli(['printmacaroon', `--macaroon_file=${remote}`]) as Print; }
      finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
      const stored = printStored(name);
      expect(live.root_key_id, name).toBe(stored.root_key_id);
      expect(live.permissions, name).toEqual(stored.permissions);
      expect(live.caveats, name).toEqual(stored.caveats);
      const actual = inspect(path);
      expect(actual.result.rootKeyId, name).toBe(live.root_key_id);
      expect(actual.result.permissions, name).toEqual(live.permissions);
      expect(actual.result.fingerprint, name).toBe(entry!.fingerprint);
      expect(actual.result.grade, name).toBe(entry!.expectedGrade);
      expect(actual.result.caveats, name).toHaveLength(live.caveats?.length ?? 0);
      for (const [index, caveat] of actual.result.caveats.entries()) {
        if (name === 'third-party' && caveat.type === 'third-party') {
          // SPEC: output uses the location; lncli prints the raw caveat ID.
          expect(caveat.value).toBe('fixture-location');
          expect(caveat).not.toHaveProperty('expired');
        } else {
          const observed = caveat.type === 'unknown' ? caveat.value
            : `${caveat.type} ${caveat.value}`;
          expect(observed, `${name} caveat ${index}`).toBe(live.caveats?.[index]);
        }
      }
      if (name === 'third-party')
        expect(actual.result.caveats.map(caveat => caveat.type)).toContain('third-party');
      writeFileSync(join(sentinelRoot, `cp037-${name}.macaroon`), readFileSync(path));
      const capture = join(owned, `${name}.txt`);
      writeFileSync(capture, actual.raw);
      expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'),
        sentinelDir: sentinelRoot, commandOutput: actual.raw,
        paths: [capture], testTmp: tempRoot, root: repo }), `${name} inspect leaked`).toBeNull();
    }
  } finally { rmSync(owned, { recursive: true, force: true }); }
}, 120_000);
