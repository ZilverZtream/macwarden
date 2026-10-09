import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { findLeaks } from "../helpers/leak-check.js";

type Result = { rootKeyId: string; permissions: string[]; caveats: { type: string; value: string }[];
  fingerprint: string; grade: string };
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; file: string; fingerprint: string; canonicalLength: number; expectedGrade: string }[] };
const schema = JSON.parse(readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8'));
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(schema);
const docker = (args: string[]) => spawnSync('docker', [...fixtureTopology().composeArgs, ...args],
  { cwd: repo, encoding: 'utf8', maxBuffer: 16_000_000, timeout: 30_000 });
function lncli(args: string[]): Record<string, unknown> {
  const run = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (run.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(run.stdout); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function state(): void {
  const info = lncli(['getinfo']);
  const ids = lncli(['listmacaroonids']).root_key_ids;
  if ((info.chains as { network: string }[] | undefined)?.[0]?.network !== 'regtest'
    || typeof info.version !== 'string' || !info.version.startsWith('0.21.4-beta')
    || !Array.isArray(ids) || ids.some(id => String(id) !== '0'))
    throw new FixtureInvalidError('Fixture must be fresh LND 0.21.4-beta on regtest');
}
function inspect(path: string): { raw: string; result: Result } {
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', path, '--json'],
    { cwd: repo, encoding: 'utf8', timeout: 10_000, maxBuffer: 1_000_000 });
  expect(run.status).toBe(0);
  let parsed: unknown;
  try { parsed = JSON.parse(run.stdout); } catch { throw new Error('inspect did not emit one JSON document'); }
  expect(validate(parsed), 'inspect schema validation').toBe(true);
  expect(run.stderr).toBe('');
  const envelope = parsed as { ok: boolean; result: Result };
  expect(envelope.ok).toBe(true);
  return { raw: run.stdout, result: envelope.result };
}
function sameCaveats(actual: Result['caveats'], expected: string[] | null): boolean {
  return actual.length === (expected?.length || 0) && actual.every((caveat, index) =>
    caveat.type === 'third-party' ? caveat.value === 'fixture-location'
      : (caveat.type === 'unknown' ? caveat.value : `${caveat.type} ${caveat.value}`) === expected?.[index]);
}

it('CP-008/inspect-printmacaroon-live inspect facts match pinned lncli output', () => {
  state();
  for (const entry of manifest.vectors) {
    const remote = `/tmp/macwarden-cp008-${process.pid}-${entry.file}`;
    const copied = docker(['cp', join(vectors, entry.file), `lnd:${remote}`]);
    if (copied.status !== 0) throw new FixtureInvalidError(`Fixture could not receive ${entry.name}`);
    let live: Record<string, unknown>;
    try { live = lncli(['printmacaroon', `--macaroon_file=${remote}`]); }
    finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
    const actual = inspect(join(vectors, entry.file)).result;
    expect(actual.rootKeyId === live.root_key_id, entry.name).toBe(true);
    expect(JSON.stringify(actual.permissions) === JSON.stringify(live.permissions), entry.name).toBe(true);
    expect(sameCaveats(actual.caveats, live.caveats as string[] | null), entry.name).toBe(true);
  }
}, 120_000);

it('CP-008/inspect-fingerprint-manifest inspect hashes and grades match independent manifest', () => {
  for (const entry of manifest.vectors) {
    const bytes = readFileSync(join(vectors, entry.file));
    const digest = `fp:${createHash('sha256').update(bytes.subarray(0, entry.canonicalLength)).digest('hex').slice(0, 16)}`;
    const actual = inspect(join(vectors, entry.file)).result;
    expect(actual.fingerprint === entry.fingerprint && actual.fingerprint === digest, entry.name).toBe(true);
    expect(actual.grade === entry.expectedGrade, entry.name).toBe(true);
  }
});

it('CP-036/portable-inspect-live repaired path and unsafe literal agree with pinned lncli for committed vectors', () => {
  state();
  for (const entry of manifest.vectors) {
    const path = join(vectors, entry.file);
    const bytes = readFileSync(path);
    const remote = `/tmp/macwarden-cp036-${process.pid}-${entry.file}`;
    if (docker(['cp', path, `lnd:${remote}`]).status !== 0)
      throw new FixtureInvalidError(`Fixture could not receive ${entry.name}`);
    let live: Record<string, unknown>;
    try { live = lncli(['printmacaroon', `--macaroon_file=${remote}`]); }
    finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
    const fromFile = inspect(path).result;
    for (const literal of [bytes.toString('hex'), bytes.toString('base64'),
      `lndconnect://h:10009?macaroon=${bytes.toString('base64url')}`]) {
      const refused = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', literal, '--json'],
        { cwd: repo, encoding: 'utf8', timeout: 10_000 });
      expect(refused.status, entry.name).toBe(2);
      expect(refused.stdout + refused.stderr, entry.name).not.toContain(literal);
      const run = spawnSync(process.execPath,
        [join(repo, 'dist/bin.js'), 'inspect', literal, '--unsafe-arg', '--json'],
        { cwd: repo, encoding: 'utf8', timeout: 10_000 });
      expect(run.status, entry.name).toBe(0);
      const doc = JSON.parse(run.stdout) as { warnings: string[]; result: Result };
      expect(doc.warnings, entry.name).toContain('unsafe-arg');
      expect(doc.result, entry.name).toEqual(fromFile);
      expect(run.stdout + run.stderr, entry.name).not.toContain(literal);
    }
    expect(fromFile.rootKeyId, entry.name).toBe(live.root_key_id);
    expect(fromFile.permissions, entry.name).toEqual(live.permissions);
    expect(sameCaveats(fromFile.caveats, live.caveats as string[] | null), entry.name).toBe(true);
  }
}, 300_000);

it('CP-008/leak-check inspect output and owned temp artifacts contain no sentinel', () => {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp008-leak-'));
  try {
    const sentinelDir = join(dir, 'sentinels');
    mkdirSync(sentinelDir);
    const sentinel = readFileSync(join(vectors, 'default-invoice.macaroon'));
    writeFileSync(join(sentinelDir, 'invoice.macaroon'), sentinel);
    const run = spawnSync(process.execPath,
      [join(repo, 'dist/bin.js'), 'inspect', join(vectors, 'default-invoice.macaroon'), '--json'],
      { cwd: repo, encoding: 'utf8', timeout: 10_000 });
    expect(run.status).toBe(0);
    const captured = join(dir, 'captured.txt');
    writeFileSync(captured, `${run.stdout}${run.stderr}`);
    const leak = findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: `${run.stdout}${run.stderr}`, paths: [captured], testTmp, root: repo });
    expect(leak).toBeNull();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
