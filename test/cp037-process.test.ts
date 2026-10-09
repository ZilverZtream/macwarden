import { childEnvironment } from './helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';

const repo = resolve();
const input = join(repo, 'test', 'sentinels', 'sentinel.macaroon');
const sentinel = readFileSync(input);
const fingerprint = (JSON.parse(readFileSync(join(repo, 'test', 'sentinels', 'manifest.json'), 'utf8')) as {
  fingerprint: string;
}).fingerprint;
const schema = JSON.parse(readFileSync(join(repo, 'schemas', 'output', 'inspect.schema.json'), 'utf8'));
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(schema);
const preload = pathToFileURL(join(repo, 'test', 'preloads', 'cp037-process-event.mjs')).href;
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;

type Run = { status: number | null; stdout: string; stderr: string; error?: Error; traceMethod?: string };

function noCredential(output: string): void {
  for (const value of [sentinel.toString('utf8'), sentinel.toString('latin1'), sentinel.toString('hex'),
    sentinel.toString('hex').toUpperCase(), sentinel.toString('base64'),
    sentinel.toString('base64url')]) expect(output).not.toContain(value);
}

function run(json: boolean, event?: 'exception' | 'rejection' | 'warning'): Run {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp037-process-'));
  const trace = join(dir, 'read-entered.txt');
  try {
    const child = spawnSync(process.execPath,
      [join(repo, 'dist', 'bin.js'), 'inspect', input, ...(json ? ['--json'] : [])], {
        cwd: repo,
        encoding: 'utf8',
        timeout: 8_000,
        env: childEnvironment({...(event ? {
            NODE_OPTIONS: `--import=${preload}`,
            MACWARDEN_CP037_INPUT: input,
            MACWARDEN_CP037_TRACE: trace,
            MACWARDEN_CP037_EVENT: event,
            MACWARDEN_CP037_MARKER: 'cp037-process-event-' + 'cafe'.repeat(16),
          } : {})}),
      });
    expect(child.error).toBeUndefined();
    const traceMethod = event ? readFileSync(trace, 'utf8').trim() : undefined;
    if (event) expect(traceMethod).toMatch(/^fs(?:\/promises)?\./);
    return { ...child, traceMethod };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

function document(output: string): Record<string, unknown> {
  const value: unknown = JSON.parse(output);
  expect(validate(value), JSON.stringify(validate.errors)).toBe(true);
  return value as Record<string, unknown>;
}

it('CP-037/A2-sticky-crash an exception or rejection during inspect keeps exit 8 and one safe error', () => {
  for (const event of ['exception', 'rejection'] as const) for (const json of [false, true]) {
    const actual = run(json, event);
    expect(actual.status, `${event} json=${json} via ${actual.traceMethod}`).toBe(8);
    noCredential(actual.stdout + actual.stderr);
    expect(actual.stdout + actual.stderr).not.toContain('cp037-process-event-');
    expect(actual.stdout + actual.stderr).not.toContain(input);
    expect(actual.stdout + actual.stderr).not.toContain('sentinel.macaroon');
    expect(actual.stdout + actual.stderr).not.toMatch(/^\s+at /m);
    if (json) {
      expect(actual.stderr).toBe('');
      const failure = document(actual.stdout);
      expect(failure).toEqual({
        schema: 1, command: 'inspect', ok: false, warnings: [], result: null,
        error: { code: 8, step: 'internal', message: expect.any(String) },
      });
      expect((failure.error as { message: string }).message.length).toBeGreaterThan(0);
      expect(actual.stdout).not.toContain(fingerprint);
    } else {
      expect(actual.stdout).toBe('');
      expect(actual.stderr).toMatch(/^error: internal[^\r\n]*\r?\n$/);
    }
  }
}, 40_000);

it('CP-037/A2-harmless-warning a Node warning during inspect preserves success and never echoes it', () => {
  for (const json of [false, true]) {
    const baseline = run(json);
    const actual = run(json, 'warning');
    expect(baseline.status).toBe(0);
    expect(actual.status).toBe(0);
    expect(actual.stdout).toBe(baseline.stdout);
    expect(actual.stderr).toBe(baseline.stderr);
    expect(actual.stdout).toContain(fingerprint);
    noCredential(actual.stdout + actual.stderr);
    expect(actual.stdout + actual.stderr).not.toContain('cp037-process-event-');
    if (json) {
      expect(actual.stderr).toBe('');
      expect(document(actual.stdout)).toMatchObject({ command: 'inspect', ok: true, error: null });
    }
  }
}, 40_000);

it('CP-037/C-crash-and-success-coverage the valid global sentinel succeeds and a mid-command crash is sticky', () => {
  const success = run(true);
  expect(success.status).toBe(0);
  expect(document(success.stdout)).toMatchObject({ command: 'inspect', ok: true, error: null,
    result: { fingerprint } });
  expect(success.stdout).toContain(fingerprint);
  noCredential(success.stdout + success.stderr);

  const crash = run(true, 'exception');
  expect(crash.traceMethod).toMatch(/^fs(?:\/promises)?\./);
  expect(crash.status).toBe(8);
  expect(document(crash.stdout)).toMatchObject({ command: 'inspect', ok: false, result: null,
    error: { code: 8, step: 'internal' } });
  noCredential(crash.stdout + crash.stderr);
}, 20_000);
