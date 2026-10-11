// Pre-1.4 audit, CLI section: how the built CLI process ends after an interrupted respond, a
// second signal while a command is blocked, and an uncaught exception in a command that never
// resumes. The command handler is replaced by a synthetic stand-in (test/helpers/cli-audit-child.mjs).
import { fork, spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from './helpers/environment.js';
import { expectDocumentValid } from './helpers/output-schema.js';

const repo = resolve();
const bin = join(repo, 'dist/bin.js');
const child = join(repo, 'test/helpers/cli-audit-child.mjs');
// How long the process may stay alive after its result: the flush and exit take milliseconds.
const EXIT_WITHIN_MS = 3_000;

function start(scenario: string, args: string[], ipc: boolean) {
  const root = process.env.MACWARDEN_TEST_TMP ?? join(repo, 'test/.tmp');
  mkdirSync(root, { recursive: true });
  const home = mkdtempSync(join(root, 'cli-audit-home-'));
  const env = childEnvironment({ HOME: home, USERPROFILE: home, APPDATA: join(home, 'Roaming'), LOCALAPPDATA: join(home, 'Local'),
    XDG_CONFIG_HOME: join(home, '.config'), MACWARDEN_CLI_AUDIT_SCENARIO: scenario });
  // An IPC channel keeps the child's event loop alive, so a run that must drain it is spawned without one.
  const proc = ipc ? fork(child, [bin, ...args], { cwd: home, execArgv: [], stdio: ['ignore', 'pipe', 'pipe', 'ipc'], env })
    : spawn(process.execPath, [child, bin, ...args], { cwd: home, stdio: ['ignore', 'pipe', 'pipe'], env });
  const output = { stdout: '', stderr: '' };
  proc.stdout!.on('data', chunk => { output.stdout += chunk; });
  proc.stderr!.on('data', chunk => { output.stderr += chunk; });
  const exited = new Promise<number | null>(done => proc.on('exit', code => done(code)));
  const stalled = ipc ? new Promise<void>((done, fail) => {
    proc.on('message', (message: { kind?: string }) => { if (message?.kind === 'stalled') done(); });
    void exited.then(code => fail(new Error(`child exited ${code} before stalling: ${output.stdout}${output.stderr}`)));
  }) : Promise.resolve();
  const within = (ms: number) => Promise.race([exited, new Promise<'alive'>(done => setTimeout(() => done('alive'), ms))]);
  return { proc, output, exited, stalled, within };
}

it('CLI-AUDIT/respond-exit an interrupted respond batch leaving a call pending exits 6 at once with its result', async () => {
  const run = start('respond-interrupted', ['respond', '--out-dir', 'out', '--yes', '--json'], true);
  try {
    await run.stalled;
    run.proc.send({ kind: 'signal', signal: 'SIGINT' });
    expect(await run.within(EXIT_WITHIN_MS), 'process still alive after the respond result').toBe(6);
    expect(JSON.parse(run.output.stdout)).toMatchObject({ command: 'respond', ok: true, error: null,
      warnings: [expect.objectContaining({ code: 'interrupted' })] });
  } finally { if (run.proc.exitCode === null) run.proc.kill(); }
});

it('CLI-AUDIT/second-signal-exit a command blocked past the first signal exits 6 on the second with one result', async () => {
  const run = start('blocked', ['inventory', '--json'], true);
  try {
    await run.stalled;
    run.proc.send({ kind: 'signal', signal: 'SIGINT' });
    run.proc.send({ kind: 'signal', signal: 'SIGTERM' });
    expect(await run.within(EXIT_WITHIN_MS), 'process still alive after two signals').toBe(6);
    expect(run.output.stdout.trim().split('\n')).toHaveLength(1);
    expect(JSON.parse(run.output.stdout)).toMatchObject({ command: 'inventory', ok: false,
      error: { code: 6, step: 'cancelled', message: 'interrupted' } });
  } finally { if (run.proc.exitCode === null) run.proc.kill(); }
});

it.each([['--json'], [null]] as const)(
  'CLI-AUDIT/never-resumes-exit an uncaught exception in a command that never resumes exits 8 with the internal error (%s)',
  async flag => {
    const run = start('uncaught', ['inspect', 'x', ...(flag ? [flag] : [])], false);
    try {
      expect(await run.within(EXIT_WITHIN_MS * 3)).toBe(8);
      if (flag) {
        expect(run.output.stdout.trim().split('\n')).toHaveLength(1);
        expect(JSON.parse(run.output.stdout)).toMatchObject({ command: 'inspect', ok: false, error: { code: 8, step: 'internal' } });
      } else {
        expect(run.output.stdout).toBe('');
        expect(run.output.stderr).toMatch(/^error: internal/m);
        expect(run.output.stderr).not.toContain('synthetic failure');
      }
    } finally { if (run.proc.exitCode === null) run.proc.kill(); }
  });

it('CLI-AUDIT/version-json-exit the built CLI prints the version as one JSON document with --json and bare without', () => {
  const version = (JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8')) as { version: string }).version;
  const env = childEnvironment();
  for (const args of [['--version', '--json'], ['--json', '--version']]) {
    const json = spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', env });
    expect(json.status).toBe(0);
    expect(json.stderr).toBe('');
    const document = JSON.parse(json.stdout) as { command: null };
    expect(document).toEqual({ schema: 1, command: null, ok: true, warnings: [], result: { version }, error: null });
    expectDocumentValid(document);
  }
  const text = spawnSync(process.execPath, [bin, '--version'], { encoding: 'utf8', env });
  expect(text.status).toBe(0);
  expect(text.stdout.trim()).toBe(version);
});
