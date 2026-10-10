import { mkdtempSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { run as inspect } from '../src/commands/inspect.js';
import { run as scan } from '../src/commands/scan.js';
import { SUPPORTED_NODE, supportedNode, unsafeNodeFlags } from '../src/environment.js';
import { captureMain } from './support/capture.js';

// Audit 1.2.1: Node flags on the command line are the counterpart of NODE_OPTIONS; watch's
// HTTP/2 client depends on the Node releases package.json names; inspect and scan decode
// credentials a heap snapshot or profile would hold.
it('CLI/runtime node flags are refused before any command runs', async () => {
  const flagged = await captureMain(main, ['inspect', resolve('test/vectors/default-readonly.macaroon'), '--json'], { execArgv: ['--inspect=0'] });
  expect(flagged.code).toBe(2);
  expect(JSON.parse(flagged.stdout)).toMatchObject({ command: 'inspect', ok: false, error: { code: 2, message: expect.stringContaining('node flags') } });
  expect(unsafeNodeFlags([])).toBe(false);
  expect(unsafeNodeFlags(['--heapsnapshot-signal=SIGUSR2'])).toBe(true);
  for (const flag of ['--inspect', '--inspect-brk=9229', '--cpu-prof', '--heap-prof', '--report-on-signal', '--trace-tls', '--tls-keylog=k', '--prof'])
    expect(unsafeNodeFlags([flag]), flag).toBe(true);
  for (const flag of ['--max-old-space-size=4096', '--experimental-transform-types', '--no-warnings', '--enable-source-maps'])
    expect(unsafeNodeFlags([flag]), flag).toBe(false);
});

it('CLI/runtime watch refuses a Node version outside the engines ranges; every other command does not check', async () => {
  for (const [version, ok] of [['22.23.2', true], ['22.23.1', false], ['22.30.0', true], ['23.9.0', false], ['24.18.1', true], ['24.17.9', false],
    ['24.20.0', true], ['25.0.0', false], ['26.5.1', true], ['26.5.0', false], ['27.0.0', true], ['garbage', false]] as const)
    expect(supportedNode(version), version).toBe(ok);
  const refused = await captureMain(main, ['watch', '--json'], { nodeVersion: '22.23.1' });
  expect(refused.code).toBe(2);
  expect(JSON.parse(refused.stdout)).toMatchObject({ command: 'watch', ok: false, error: { code: 2, message: expect.stringContaining(SUPPORTED_NODE) } });
  // inspect runs on the same version: only watch depends on the fixed releases.
  const other = await captureMain(main, ['inspect', resolve('test/vectors/default-readonly.macaroon'), '--json'], { nodeVersion: '22.23.1' });
  expect(other.code).toBe(0);
});

it('CLI/runtime inspect and scan refuse unsafe Node diagnostic settings like every online command', async () => {
  const dir = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP || tmpdir(), 'cli-runtime-'));
  writeFileSync(join(dir, 'app.env'), 'NOTHING=here\n');
  const stdin = Object.assign(Readable.from([]), { isTTY: false });
  const inspected = await inspect([resolve('test/vectors/default-readonly.macaroon')], { stdin, fs, clock: () => new Date(), env: { NODE_OPTIONS: '--inspect' } });
  expect(inspected).toMatchObject({ ok: false, error: { code: 2, message: 'unsafe Node diagnostic settings' } });
  const scanned = await scan([dir], { fs, env: { NODE_DEBUG: 'tls' } });
  expect(scanned).toMatchObject({ ok: false, error: { code: 2, message: 'unsafe Node diagnostic settings' } });
  expect((await scan([dir], { fs, env: { NODE_DEBUG: 'fs' } })).ok).toBe(true);
});
