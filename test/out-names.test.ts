import { existsSync, mkdtempSync, readdirSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { outputNameProblem } from '../src/protected-path.js';
import { root } from './helpers/cp038-online.js';

// RO-2: Node opens the literal \\?\ object while Win32 tools open the normalised name, so
// an output name that Windows normalises or maps to a device must be refused before any
// write: trailing dot or space, a reserved device name, ':' (alternate data stream).
it.each([
  'C:\\out\\app.macaroon.', 'C:\\out\\app.macaroon ', 'C:\\out\\app.macaroon. .', 'C:\\out.\\app.macaroon', 'C:\\out \\app.macaroon',
  'C:\\out\\NUL', 'C:\\out\\nul.macaroon', 'C:\\out\\Con', 'C:\\out\\CON .txt', 'C:\\out\\prn.x', 'C:\\out\\AUX', 'C:\\out\\com1',
  'C:\\out\\COM9.macaroon', 'C:\\out\\lpt1', 'C:\\out\\LPT\u00b9.macaroon', 'C:\\out\\conin$', 'C:\\out\\CONOUT$.txt', 'C:\\NUL\\app.macaroon',
  'C:\\out\\notes.txt:app.macaroon', 'C:\\out\\notes.txt::$DATA', 'C:\\out\\a<b', 'C:\\out\\a|b', 'C:\\out\\a?b', 'C:\\out\\a*b',
  'C:\\out\\a\u0001b', '\\\\.\\C:\\out\\app.macaroon', '\\\\?\\C:\\out\\app.macaroon.', '\\\\server\\share\\app.macaroon ',
])('RO-2/windows-names refuses %j on Windows and accepts it elsewhere', path => {
  expect(outputNameProblem(path, 'win32')).toEqual(expect.any(String));
  expect(outputNameProblem(path, 'linux')).toBeNull();
  expect(outputNameProblem(path, 'darwin')).toBeNull();
});

it.each([
  'C:\\out\\app.macaroon', 'C:\\out\\.macaroon', 'C:\\out\\a..macaroon', 'C:\\out\\console.macaroon', 'C:\\out\\nul_x.macaroon',
  'C:\\out\\com10', 'C:\\out\\lpt', 'C:\\out\\CON-1.macaroon', 'C:\\out\\x.CON', 'C:\\out\\dir.d\\app.macaroon',
  '\\\\?\\C:\\out\\app.macaroon', '\\\\server\\share\\app.macaroon', 'relative\\app.macaroon', 'C:/out/app.macaroon',
])('RO-2/windows-names accepts the ordinary name %j', path => {
  expect(outputNameProblem(path, 'win32')).toBeNull();
});

// The commands refuse before creating anything, whatever else the invocation would do.
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
afterEach(() => { Object.defineProperty(process, 'platform', platform); });

it('RO-2/windows-names attenuate and inventory --report refuse a normalised name before any write', async () => {
  const dir = mkdtempSync(join(root('MACWARDEN_TEST_TMP'), 'out-names-'));
  Object.defineProperty(process, 'platform', { ...platform, value: 'win32' });
  const { run: attenuate } = await import('../src/commands/attenuate.js');
  for (const name of ['child.macaroon.', 'child.macaroon ', 'NUL', 'COM1.macaroon']) {
    const result = await attenuate([join('test', 'vectors', 'default-readonly.macaroon'), '--out', join(dir, name), '--expires', '1h'],
      { stdin: process.stdin, fs, env: {}, clock: () => new Date() });
    expect(result.error).toMatchObject({ code: 3, step: 'A3' });
    expect(result.error!.message).toMatch(/^output path refused: /);
  }
  const { run: inventory } = await import('../src/commands/inventory.js');
  const report = await inventory(['--report', 'json', '--out', join(dir, 'review.json.'), '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', 'missing.cert', '--macaroon', 'missing.macaroon'], { fs, env: {}, clock: () => new Date() } as never);
  expect(report.error).toMatchObject({ code: 3, step: 'N7' });
  expect(report.error!.message).toMatch(/^report path refused: /);
  expect(readdirSync(dir)).toEqual([]);
});

it('RO-2/windows-names bake and rotate refuse a normalised name before any LND call', async () => {
  const { fixture } = await import('./helpers/cp038-online.js');
  const { run: bake } = await import('../src/commands/bake/index.js');
  const { run: rotate } = await import('../src/commands/rotate.js');
  Object.defineProperty(process, 'platform', { ...platform, value: 'win32' });
  const f = fixture();
  const baked = await bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', `${f.out}.`, ...f.flags], f.deps);
  expect(baked.error).toMatchObject({ code: 3, step: 'B4' });
  const rotated = await rotate(['Alice', '--out', join(f.dir, 'AUX.macaroon'), ...f.flags], f.deps);
  expect(rotated.error).toMatchObject({ code: 3, step: 'S5' });
  expect(f.lnd.calls).toEqual([]);
  expect(existsSync(`${f.out}.`)).toBe(false); expect(existsSync(join(f.dir, 'AUX.macaroon'))).toBe(false);
});
