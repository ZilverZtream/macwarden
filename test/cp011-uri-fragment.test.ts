import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { captureMain } from './support/capture.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const vectorRoot = join(repo, 'test/vectors');
const readonly = () => readFileSync(join(vectorRoot, 'default-readonly.macaroon'));
const reference = (JSON.parse(readFileSync(join(vectorRoot, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[];
}).vectors.find(entry => entry.name === 'default-readonly');
if (!reference) throw new Error('readonly reference vector missing');

const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false });
const inspectSchema = ajv.compile(JSON.parse(readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8')));
const scanSchema = ajv.compile(JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));

async function cli(args: string[]) {
  const { main } = await import('../src/cli.js');
  return captureMain(main, args);
}

function document(run: Awaited<ReturnType<typeof cli>>, command: 'inspect' | 'scan') {
  let value: unknown;
  try { value = JSON.parse(run.stdout); }
  catch { throw new Error(`${command} did not return one JSON document`); }
  expect(run.stderr === '').toBe(true);
  expect((command === 'inspect' ? inspectSchema : scanSchema)(value)).toBe(true);
  return value as {
    command: string;
    ok: boolean;
    error: { code: number; step: string | null } | null;
    result: {
      fingerprint?: string;
      grade?: string;
      findings?: { kind: string; fingerprint: string; grade: string | null }[];
      summary?: { dropped: number; findings: number };
    } | null;
  };
}

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp011-uri-fragment-'));
  try { return await work(dir); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}

function uriWithFragmentQuery() {
  return `lndconnect://h:10009/#?macaroon=${readonly().toString('base64url')}`;
}

function uriWithActualQuery() {
  return `lndconnect://h:10009/?macaroon=${readonly().toString('base64url')}#fragment`;
}

it('CP-011/B13 inspect refuses a macaroon parameter inside a URI fragment', async () => {
  const uri = uriWithFragmentQuery();
  const run = await cli(['inspect', uri, '--unsafe-arg', '--json']);
  expect(run.code).toBe(3);
  const result = document(run, 'inspect');
  expect(result.command).toBe('inspect');
  expect(result.ok).toBe(false);
  expect(result.error?.code).toBe(3);
  expect(result.error?.step).toBe('input-form');
  expect((run.stdout + run.stderr).includes(uri)).toBe(false);
});

it('CP-011/B13 scan drops a URI whose macaroon parameter is only in a fragment', async () => temp(async dir => {
  const uri = uriWithFragmentQuery();
  const path = join(dir, 'fragment.env');
  writeFileSync(path, uri);
  const run = await cli(['scan', path, '--json']);
  expect(run.code).toBe(0);
  const result = document(run, 'scan');
  expect(result.command).toBe('scan');
  expect(result.ok).toBe(true);
  expect(result.error).toBeNull();
  // The URI is not accepted as lndconnect; since RR-01 the credential in its fragment is still
  // reported on its own instead of being hidden by the URI that failed.
  expect(result.result?.findings?.map(finding => finding.kind)).toEqual(['macaroon-base64']);
  expect(result.result?.summary?.findings).toBe(1);
  expect(result.result?.summary?.dropped).toBe(1);
  expect((run.stdout + run.stderr).includes(uri)).toBe(false);
}));

it('CP-011/B13 inspect accepts an actual macaroon query before a URI fragment', async () => {
  const uri = uriWithActualQuery();
  const run = await cli(['inspect', uri, '--unsafe-arg', '--json']);
  expect(run.code).toBe(0);
  const result = document(run, 'inspect');
  expect(result.command).toBe('inspect');
  expect(result.ok).toBe(true);
  expect(result.error).toBeNull();
  expect(result.result?.fingerprint).toBe(reference.fingerprint);
  expect(result.result?.grade).toBe(reference.expectedGrade);
  expect((run.stdout + run.stderr).includes(uri)).toBe(false);
});

it('CP-011/B13 scan accepts an actual macaroon query before a URI fragment', async () => temp(async dir => {
  const uri = uriWithActualQuery();
  const path = join(dir, 'query.env');
  writeFileSync(path, uri);
  const run = await cli(['scan', path, '--json']);
  expect(run.code).toBe(0);
  const result = document(run, 'scan');
  expect(result.command).toBe('scan');
  expect(result.ok).toBe(true);
  expect(result.error).toBeNull();
  expect(result.result?.findings?.length).toBe(1);
  expect(result.result?.findings?.[0].kind).toBe('lndconnect');
  expect(result.result?.findings?.[0].fingerprint).toBe(reference.fingerprint);
  expect(result.result?.findings?.[0].grade).toBe(reference.expectedGrade);
  expect(result.result?.summary?.findings).toBe(1);
  expect(result.result?.summary?.dropped).toBe(0);
  expect((run.stdout + run.stderr).includes(uri)).toBe(false);
}));
