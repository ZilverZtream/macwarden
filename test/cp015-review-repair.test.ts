import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';
import { permissionTextVector } from './helpers/cp015-audit-vectors.mjs';
import { checkLiveReference, ReferenceConflictError, registerFixtureSentinel } from './helpers/lnd-facts.mjs';
import { captureMain } from './support/capture.js';

const root = process.cwd();
const tmp = process.env.MACWARDEN_TEST_TMP || join(root, 'test/.tmp');
const sentinels = process.env.MACWARDEN_SENTINEL_DIR || join(root, 'test/.sentinels/cp015-review-repair');
process.env.MACWARDEN_TEST_TMP = tmp;
process.env.MACWARDEN_SENTINEL_DIR = sentinels;

const permissionCases = [
  { field: 'entity', entity: '\uFEFFinfo', action: 'read', warning: 'unassessed-permission' },
  { field: 'action', entity: 'info', action: '\uFEFFread', warning: 'unassessed-permission' },
  { field: 'uri-action', entity: 'uri', action: '\uFEFF/lnrpc.Lightning/GetInfo', warning: 'unassessed-permission' },
];

// Hand-made identifier mutations prove parsing and offline grading, not LND acceptance.
async function withPermissionVector<T>(field: string, entity: string, action: string,
  work: (path: string) => Promise<T>): Promise<T> {
  mkdirSync(tmp, { recursive: true });
  const runtimeRoot = join(root, 'test/.runtime/cp015-review-repair');
  const nested = (path: string, parent: string) => resolve(path) === resolve(parent) ||
    resolve(path).startsWith(`${resolve(parent)}${sep}`);
  if ([tmp, sentinels].some(path => nested(runtimeRoot, path) || nested(path, runtimeRoot)))
    throw new Error('Audit fixture runtime must be separate from output and sentinels');
  mkdirSync(runtimeRoot, { recursive: true });
  const dir = mkdtempSync(join(runtimeRoot, 'cp015-bom-'));
  if (!nested(dir, runtimeRoot)) throw new Error('Unexpected audit runtime directory');
  try {
    const source = join(dir, 'structural.macaroon');
    writeFileSync(source, permissionTextVector(root, entity, action));
    const path = registerFixtureSentinel(source, `cp015-bom-${field}.macaroon`, sentinels);
    unlinkSync(source);
    appendFileSync(join(tmp, 'declared-out.txt'), `${path}\n`);
    return await work(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

it.each(permissionCases)('CP-015/B8 leading U+FEFF in permission $field stays exact and UNASSESSED through inspect', async ({ field, entity, action, warning }) =>
  withPermissionVector(field, entity, action, async path => {

    const { decodeMacaroon } = await import('../src/decode/index.js') as {
      decodeMacaroon: (secret: Secret) => { permissions: string[] };
    };

    const { run } = await import('../src/commands/inspect.js') as {
      run: (args: string[], deps: { stdin: Readable; fs: typeof fs; clock: () => Date }) => Promise<{
        ok: boolean; result: { permissions: string[]; grade: string; unassessed: string[]; warnings: string[] } | null;
      }>;
    };
    const expected = `${entity}:${action}`;
    const facts = decodeMacaroon(new Secret(readFileSync(path)));
    expect.soft(facts.permissions, 'decoder preserves original protobuf text').toEqual([expected]);
    const output = await run([path, '--json'], { stdin: Readable.from([]), fs,
      clock: () => new Date('2030-01-01T00:00:00Z') });
    expect(output.ok).toBe(true);
    expect.soft(output.result?.permissions, 'inspect preserves original protobuf text').toEqual([expected]);
    expect.soft(output.result?.grade, 'unknown BOM permission fails closed').toBe('UNASSESSED');
    expect.soft(output.result?.unassessed).toEqual([expected]);
    expect.soft(output.result?.warnings).toContain(warning);
  }));

it.each(permissionCases)('CP-015/B8 leading U+FEFF in permission $field stays exact and UNASSESSED through scan and fails every threshold', async ({ field, entity, action, warning }) =>
  withPermissionVector(field, entity, action, async path => {

    const { main } = await import('../src/cli.js') as {
      main: (args: string[]) => Promise<number>;
    };
    const expected = `${entity}:${action}`;
    const before = readFileSync(path);
    const modified = statSync(path).mtimeMs;
    for (const threshold of ['SPEND', 'ADMIN', 'OPERATE', 'RECEIVE', 'READ']) {
      const output = await captureMain(main, ['scan', path, '--json', '--fail-on', threshold]);
      expect(output.stderr).toBe('');
      expect(output.exitCalls).toBe(0);
      const value = JSON.parse(output.stdout) as {
        command: string; ok: boolean; error: unknown;
        result: { findings: { kind: string; permissions: string[]; grade: string;
          unassessed: string[]; warnings: string[] }[];
          summary: { findings: number; byGrade: Record<string, number> };
          failOn: { threshold: string; count: number } };
      };
      expect(value).toMatchObject({ command: 'scan', ok: true, error: null });
      expect(value.result.findings).toHaveLength(1);
      const finding = value.result.findings[0];
      expect(finding.kind).toBe('macaroon-file');
      expect.soft(finding.permissions, `${threshold}: original protobuf text`).toEqual([expected]);
      expect.soft(finding.grade, `${threshold}: unknown permission fails closed`).toBe('UNASSESSED');
      expect.soft(finding.unassessed, threshold).toEqual([expected]);
      expect.soft(finding.warnings, threshold).toContain(warning);
      expect.soft(value.result.summary.byGrade.UNASSESSED, threshold).toBe(1);
      expect.soft(value.result.failOn, threshold).toEqual({ threshold, count: 1 });
      expect.soft(output.code, `${threshold}: UNASSESSED fails every threshold`).toBe(1);
    }
    expect(readFileSync(path).equals(before), 'offline scan preserves credential contents').toBe(true);
    expect(statSync(path).mtimeMs, 'offline scan preserves credential mtime').toBe(modified);
  }));

it.each([
  { name: 'BakeMacaroon InvalidArgument code 3', kind: 'bake-rest-error',
    fact: { invalidStatus: 400, invalidCode: 3 }, statement: 'docs/architecture.md#verified-lnd-behaviour',
    reference: 'BakeMacaroon REST /v1/macaroon', observed: 'code 3' },
  { name: 'host HTTP 403', kind: 'rest-caveat-address',
    fact: { hostRestStatus: 403, containerRestExit: 0 }, statement: 'docs/spec.md#output',
    reference: 'host and container REST /v1/getinfo', observed: 'host HTTP 403' },
  { name: 'container exit 1', kind: 'rest-caveat-address',
    fact: { hostRestStatus: 200, containerRestExit: 1 }, statement: 'docs/architecture.md#assumptions-to-confirm',
    reference: 'host and container REST /v1/getinfo', observed: 'container exit 1' },
  { name: 'host HTTP 403 and container exit 1', kind: 'rest-caveat-address',
    fact: { hostRestStatus: 403, containerRestExit: 1 }, statement: 'docs/spec.md#output',
    reference: 'host and container REST /v1/getinfo', observed: 'host HTTP 403; container exit 1' },
])('CP-015/B13 live checker blocks settlement for $name and emits both references', ({ kind, fact, statement, reference, observed }) => {
  const reports: { settled: boolean; conflict: string | null }[] = [];
  let thrown: unknown;
  try { checkLiveReference(kind, fact, comparison => reports.push(comparison)); }
  catch (error) { thrown = error; }
  expect(thrown).toBeInstanceOf(ReferenceConflictError);
  expect(reports).toHaveLength(1);
  expect(reports[0].settled).toBe(false);
  expect(reports[0].conflict).toContain('REFERENCE_CONFLICT');
  expect(reports[0].conflict).toContain(statement);
  expect(reports[0].conflict).toContain(reference);
  expect(reports[0].conflict).toContain(observed);
  expect((thrown as Error).message).toBe(reports[0].conflict);
});

it('CP-015/B13 live checker settles matching pinned bake and REST address observations', () => {
  expect(checkLiveReference('bake-rest-error', { invalidStatus: 500, invalidCode: 2 }))
    .toEqual({ settled: true, conflict: null });
  expect(checkLiveReference('rest-caveat-address', { hostRestStatus: 200, containerRestExit: 0 }))
    .toEqual({ settled: true, conflict: null });
});
