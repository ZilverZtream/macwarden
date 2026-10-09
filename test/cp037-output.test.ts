import { render } from './helpers/render-adversarial.js';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';

const repo = resolve();
const sentinel = () => readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false });
const schemaFor = (command: 'inspect' | 'scan') => ajv.compile(JSON.parse(
  readFileSync(join(repo, `schemas/output/${command}.schema.json`), 'utf8')));

vi.mock('../src/commands/handlers.js', () => ({ handlers: {
  poisoned: async () => ({ code: 0, warnings: [], result: { nested: { raw: sentinel() } } }),
} }));

import { main } from '../src/cli.js';

it('CP-037/A9-nonplain-output renderer refuses every non-plain nested value before writing', async () => {
  await import('../src/output/index.js');
  const bytes = sentinel();
  const values = [bytes, new Uint8Array(bytes), new Date(), new Map([['a', 'b']])];
  for (const value of values) {
    const envelope = { schema: 1 as const, command: 'inspect', ok: true, warnings: [],
      result: { nested: [value] }, error: null };
    for (const mode of ['json', 'text'] as const) {
      expect(() => render(envelope, mode), `${value.constructor.name} ${mode}`).toThrow();
    }
  }
  for (const command of ['inspect', 'scan'] as const) {
    const plain = { schema: 1 as const, command, ok: false, warnings: [], result: null,
      error: { code: 8, step: 'internal', message: 'internal error' } };
    const doc = JSON.parse(render(plain, 'json'));
    expect(doc).toEqual(plain);
    expect(schemaFor(command)(doc)).toBe(true);
  }
});

it('CP-037/A9-nonplain-output process error path emits one safe internal document', async () => {
  const observed = await captureMain(main, ['poisoned', '--json']);
  expect(observed.code).toBe(8);
  expect(observed.stderr).toBe('');
  const doc = JSON.parse(observed.stdout) as { ok: boolean; result: unknown;
    error: { code: number; step: string; message: string } };
  expect(doc.ok).toBe(false);
  expect(doc.result).toBeNull();
  expect(doc.error).toMatchObject({ code: 8, step: 'internal' });
  expect(observed.stdout.includes(sentinel().toString('hex'))).toBe(false);
  expect(observed.stdout.includes(sentinel().toString('base64'))).toBe(false);
});

it('CP-037/C-crash-and-success-coverage global sentinel succeeds through inspect with one leak-free document', async () => {
  const { spawnSync } = await import('node:child_process');
  const path = join(repo, 'test/sentinels/sentinel.macaroon');
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', path, '--json'],
    { cwd: repo, encoding: 'utf8', timeout: 10_000 });
  expect(run.status).toBe(0);
  expect(run.stderr).toBe('');
  const document = JSON.parse(run.stdout) as { ok: boolean; result: { fingerprint: string } };
  expect(document.ok).toBe(true);
  const expected = JSON.parse(readFileSync(join(repo, 'test/sentinels/manifest.json'), 'utf8')) as {
    fingerprint: string };
  expect(document.result.fingerprint).toBe(expected.fingerprint);
  expect(schemaFor('inspect')(document)).toBe(true);
  const bytes = sentinel();
  for (const encoded of [bytes.toString('hex'), bytes.toString('base64'), bytes.toString('base64url')]) {
    expect(run.stdout.includes(encoded)).toBe(false);
  }
});
