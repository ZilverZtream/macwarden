import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';

type Caveat = { type: string; value: string; expired?: boolean };
type Facts = { rootKeyId: bigint; location: string | null; permissions: string[];
  caveats: Caveat[]; fingerprint: string };
type Result = { rootKeyId: string; location: string | null; permissions: string[];
  caveats: Caveat[]; fingerprint: string; grade: string };
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; file: string; purpose: string; fingerprint: string;
    expectedGrade: string }[] };
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(JSON.parse(
  readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8')));

it('CP-037/C-third-party-oracle decoder and inspect retain stored first-party facts and location', async () => {
  const entry = manifest.vectors.find(vector => vector.name === 'third-party');
  expect(entry, 'third-party vector must remain in the manifest').toBeDefined();
  const oracle = JSON.parse(readFileSync(join(vectors, 'third-party.printmacaroon.json'), 'utf8')) as {
    root_key_id: string; location: string | null; permissions: string[]; caveats: string[] | null };
  const expectedLocation = entry!.purpose.match(/^third-party caveat at (.+)$/)?.[1];
  expect(expectedLocation, 'manifest must state the third-party location').toBeTruthy();
  const file = join(vectors, entry!.file);

  const { decodeMacaroon } = await import('../src/decode/index.js') as {
    decodeMacaroon: (secret: Secret) => Facts };
  const facts = decodeMacaroon(new Secret(readFileSync(file)));
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', file, '--json'],
    { cwd: repo, encoding: 'utf8', timeout: 10_000, maxBuffer: 1_000_000 });
  expect(run.status, 'inspect exit code').toBe(0);
  expect(run.stderr, 'inspect JSON stderr').toBe('');
  let document: unknown;
  try { document = JSON.parse(run.stdout) as unknown; }
  catch { throw new Error('inspect did not emit one JSON document'); }
  expect(validate(document), 'inspect schema validation').toBe(true);
  const envelope = document as { ok: boolean; error: unknown; result: Result };
  expect(envelope.ok).toBe(true);
  expect(envelope.error).toBeNull();
  expect(facts.rootKeyId.toString()).toBe(oracle.root_key_id);
  expect(envelope.result.rootKeyId).toBe(oracle.root_key_id);
  expect(facts.location).toBe(oracle.location);
  expect(envelope.result.location).toBe(oracle.location);
  expect(facts.permissions).toEqual(oracle.permissions);
  expect(envelope.result.permissions).toEqual(oracle.permissions);
  expect(facts.fingerprint).toBe(entry!.fingerprint);
  expect(envelope.result.fingerprint).toBe(entry!.fingerprint);
  expect(envelope.result.grade).toBe(entry!.expectedGrade);
  // SPEC compares first-party strings with lncli; its third-party ID is not the output location.
  expect(oracle.caveats).toHaveLength(1);
  expect(facts.caveats).toHaveLength(oracle.caveats!.length);
  expect(envelope.result.caveats).toHaveLength(oracle.caveats!.length);
  for (const [index, caveat] of facts.caveats.entries()) {
    if (caveat.type === 'third-party') {
      expect(caveat.value).toBe(expectedLocation);
      expect(caveat).not.toHaveProperty('expired');
      continue;
    }
    const comparable = caveat.type === 'unknown' ? caveat.value : `${caveat.type} ${caveat.value}`;
    expect(comparable, `first-party caveat ${index}`).toBe(oracle.caveats![index]);
  }
  expect(facts.caveats.map(caveat => caveat.type)).toContain('third-party');
  expect(envelope.result.caveats).toEqual(facts.caveats);
  expect(expectedLocation).not.toBe(oracle.caveats![0]);
});
