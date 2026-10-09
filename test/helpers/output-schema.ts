import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect } from 'vitest';
import { render, type OutputResult } from '../../src/output/index.js';

// Validates the --json document a command result renders to against the published
// schemas/output/<command>.schema.json, so every test that drives a command also proves
// that the real output matches the documented shape.
const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false, allErrors: true });
const compiled = new Map<string, ReturnType<typeof ajv.compile>>();

function validator(command: string) {
  let validate = compiled.get(command);
  if (!validate) {
    validate = ajv.compile(JSON.parse(readFileSync(join(resolve(), 'schemas/output', `${command}.schema.json`), 'utf8')));
    compiled.set(command, validate);
  }
  return validate;
}

export function expectSchemaValid(result: unknown): void {
  const document = JSON.parse(render(result as OutputResult, 'json')) as { command: string | null };
  const validate = validator(document.command ?? 'macwarden');
  expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
}

/** Validates an already-parsed --json document, such as a child process's stdout. */
export function expectDocumentValid(document: { command: string | null }): void {
  const validate = validator(document.command ?? 'macwarden');
  expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
}

/** Validates one `watch --json` event line (an NDJSON line before the final document). */
export function expectWatchEventValid(line: string): void {
  const validate = validator('watch-event');
  const document = JSON.parse(line) as unknown;
  expect(validate(document), `${line} ${JSON.stringify(validate.errors)}`).toBe(true);
}
