import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import Ajv from 'ajv';
import { expect, it } from 'vitest';
import { renderChunks, type OutputResult } from '../src/output/index.js';
import { neverOpenedLines } from '../src/output/scan-formats.js';
import { scan } from '../src/scan/index.js';
import { scratch, vector } from './support/cp039-audit.js';

// Files whose names look like wallet secrets are never opened (SAFE-02). A CI gate must show
// which files it did not check: SARIF lists them as notifications, GitHub output as warnings.

function tree(dir: string): void {
  const admin = vector('default-admin').bytes.toString('hex');
  mkdirSync(join(dir, 'prisma'));
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'prisma', 'seed.ts'), `export const m = '${admin}';\n`);
  writeFileSync(join(dir, 'src', 'password-reset.ts'), `const m = '${admin}';\n`);
  writeFileSync(join(dir, 'src', 'app.ts'), 'const ok = 1;\n');
}

async function render(dir: string, format: 'sarif' | 'github'): Promise<string> {
  const result = await scan([dir]);
  return [...renderChunks({ command: 'scan', ok: true, warnings: [], error: null, result,
    display: { format, scanRoot: dir, toolVersion: '9.8.7' } } as OutputResult, 'text')].join('');
}

it('SARIF lists never-opened files as tool execution notifications with their locations', async () => scratch(async dir => {
  tree(dir);
  const log = JSON.parse(await render(dir, 'sarif')) as { runs: { results: unknown[]; invocations: {
    toolExecutionNotifications?: { level: string; message: { text: string }; locations?: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] }[] };
  const schema = JSON.parse(readFileSync(join(resolve(), 'test/vendor/sarif-schema-2.1.0.json'), 'utf8')) as Record<string, unknown>;
  const { id, $schema: _ignored, ...rest } = schema;
  void _ignored;
  const validate = new (Ajv as unknown as typeof import('ajv').default)({ strict: false, validateFormats: false, allErrors: true })
    .compile({ $id: id as string, ...rest });
  expect(validate(log), JSON.stringify(validate.errors)).toBe(true);
  expect(log.runs[0].results).toEqual([]);
  const notes = log.runs[0].invocations[0].toolExecutionNotifications ?? [];
  expect(notes.map(note => note.locations?.[0].physicalLocation.artifactLocation.uri)).toEqual(['prisma/seed.ts', 'src/password-reset.ts']);
  for (const note of notes) {
    expect(note.level).toBe('warning');
    expect(note.message.text).toMatch(/not opened/);
  }
}));

it('GitHub output warns about each never-opened file', async () => scratch(async dir => {
  tree(dir);
  const text = await render(dir, 'github');
  const warnings = text.split('\n').filter(line => line.startsWith('::warning '));
  expect(warnings).toHaveLength(2);
  expect(warnings[0]).toMatch(/^::warning file=prisma\/seed\.ts,title=macwarden never-open::/);
  expect(warnings[1]).toMatch(/^::warning file=src\/password-reset\.ts,title=macwarden never-open::/);
}));

it('text lines name every never-opened file, escaped like other output', () => {
  const lines = [...neverOpenedLines({ skipped: [{ path: 'a/seed.ts', reason: 'never-open' }, { path: 'b.bin', reason: 'binary' },
    { path: 'c/‮password', reason: 'never-open' }] }, text => text.replace(/‮/g, '\\u202e'))];
  expect(lines).toEqual([
    'never-opened  a/seed.ts  (name matches a protected pattern; not scanned)\n',
    'never-opened  c/\\u202epassword  (name matches a protected pattern; not scanned)\n',
  ]);
});
