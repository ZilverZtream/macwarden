import { fork } from 'node:child_process';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from './helpers/environment.js';

const repo = resolve();
const bin = join(repo, 'dist/bin.js');
const child = join(repo, 'test/support/stalled-lstat-child.mjs');

// 1.2.1 (audit F15 follow-up): Node cannot cancel a pending fs call. After an interrupt abandons
// an lstat that never returns, the exit-6 result is printed and the process ends with code 6
// at once, not when (if ever) the stalled mount answers.
it('CLI/interrupt-exit scan --agent-configs stalled on a hung mount exits 6 promptly after SIGINT', async () => {
  const root = process.env.MACWARDEN_TEST_TMP ?? join(repo, 'test/.tmp');
  mkdirSync(root, { recursive: true });
  const home = mkdtempSync(join(root, 'stalled-home-'));
  const project = mkdtempSync(join(root, 'stalled-project-'));
  const proc = fork(child, [bin, 'scan', '--agent-configs', '--json'], { cwd: project, execArgv: [],
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    env: childEnvironment({ HOME: home, USERPROFILE: home, APPDATA: join(home, 'Roaming'), LOCALAPPDATA: join(home, 'Local'),
      XDG_CONFIG_HOME: join(home, '.config'), MACWARDEN_STALL_PATH: home }) });
  let stdout = '';
  proc.stdout!.on('data', chunk => { stdout += chunk; });
  proc.stderr!.resume();
  const exited = new Promise<number | null>(done => proc.on('exit', code => done(code)));
  try {
    await new Promise<void>((done, fail) => {
      proc.on('message', (message: { kind?: string }) => { if (message?.kind === 'stalled') done(); });
      exited.then(code => fail(new Error(`child exited ${code} before stalling`)));
    });
    const signalled = Date.now();
    proc.send({ kind: 'signal', signal: 'SIGINT' });
    const code = await Promise.race([exited, new Promise<'alive'>(done => setTimeout(() => done('alive'), 2_000))]);
    expect(code, 'process still alive 2 s after the interrupt result').toBe(6);
    expect(Date.now() - signalled).toBeLessThan(2_000);
    expect(JSON.parse(stdout)).toMatchObject({ command: 'scan', ok: false, error: { code: 6, step: 'cancelled' } });
  } finally { if (proc.exitCode === null) proc.kill(); }
});
