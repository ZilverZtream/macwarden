import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { afterEach, expect, it, vi } from 'vitest';
import { run } from '../src/commands/attenuate.js';

// Audit 1.4.0 (spec.md A5): attenuate decodes the child it built and refuses, with exit 8 at
// step internal and no file written, unless the child is the input plus exactly the requested
// caveats. The caveat appender is replaced here so that it adds something else.
const tamper = vi.hoisted(() => ({ condition: null as ((condition: string) => string) | null }));
vi.mock('../src/decode/index.js', async importOriginal => {
  const original = await importOriginal<typeof import('../src/decode/index.js')>();
  return { ...original,
    addFirstPartyCaveat: (mac: Parameters<typeof original.addFirstPartyCaveat>[0], condition: string) =>
      original.addFirstPartyCaveat(mac, tamper.condition ? tamper.condition(condition) : condition) };
});

const dirs: string[] = [];
afterEach(() => { tamper.condition = null; for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function out(): string {
  const root = process.env.MACWARDEN_TEST_TMP!;
  mkdirSync(root, { recursive: true });
  const dir = mkdtempSync(join(root, 'tests-audit-attenuate-'));
  dirs.push(dir);
  return join(dir, 'child.macaroon');
}
const deps = () => ({ stdin: Object.assign(Readable.from([]), { isTTY: true }), fs, env: {}, clock: () => new Date('2026-10-04T00:00:00Z') });
const input = resolve('test/vectors/default-readonly.macaroon');

it.each([
  ['a different caveat', (condition: string) => `${condition}0`],
  ['an IP caveat instead of the expiry', () => 'ipaddr 192.0.2.1'],
])('TESTS-AUDIT/attenuate a child carrying %s is refused with exit 8 at internal and nothing is written', async (_kind, change) => {
  tamper.condition = change;
  const path = out();
  const result = await run([input, '--out', path, '--expires', '1d'], deps());
  expect(result.error).toEqual({ code: 8, step: 'internal', message: 'attenuated macaroon does not equal the input plus the requested caveats' });
  expect(result.result).toBeNull();
  expect(existsSync(path)).toBe(false);
});

it('TESTS-AUDIT/attenuate the unchanged appender passes the self-check', async () => {
  const result = await run([input, '--out', out(), '--expires', '1d', '--dry-run'], deps());
  expect(result.error).toBeNull();
});
