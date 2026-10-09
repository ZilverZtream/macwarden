import { childEnvironment } from '../helpers/environment.js';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { scenario, ids, docker, probe } from '../helpers/cp038-live.js';
import { safe } from '../helpers/cp027-revoke-support.js';

// Child startup errors may include source lines or request details. Report only
// fixed diagnostic categories and validated envelope fields, never raw output.
function childDiagnostic(stdout: string, stderr: string): string {
  const categories = ['ERR_MODULE_NOT_FOUND', 'ERR_UNKNOWN_FILE_EXTENSION', 'ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX',
    'SyntaxError', 'TypeError', 'ReferenceError'] as const;
  const category = categories.find(value => stderr.includes(value)) ?? (stderr ? 'unclassified-stderr' : 'none');
  let commandCode: number | null = null, step = 'unavailable';
  try {
    const document = JSON.parse(stdout) as { error?: { code?: unknown; step?: unknown } | null } | null;
    const code = document?.error?.code, stage = document?.error?.step;
    if (typeof code === 'number' && Number.isInteger(code) && code >= 2 && code <= 8) commandCode = code;
    if (typeof stage === 'string' && /^(?:S(?:[1-9]|1[0-3])|F(?:[1-9]|1[0-2])|internal)$/.test(stage)) step = stage;
  } catch { /* Invalid output is diagnosed without reflecting its contents. */ }
  return `stderr-category=${category}; command-code=${commandCode}; command-step=${step}; stdout-chars=${stdout.length}; stderr-chars=${stderr.length}`;
}

it('CP-042/signal-cleanup-live real paused verification plus signal retains pending state and executable recovery', async () => {
  await scenario(async f => {
    const loader = pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href;
    const child = spawn(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import', loader,
      resolve('test/helpers/cp038-live-child.mjs'), f.out, ...f.flags], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      env: childEnvironment({ NODE_OPTIONS: '', NODE_DEBUG: ''  }) });
    let stdout = '', stderr = '', allocated = '', paused = false, verificationRequested = false, watchdogExpired = false;
    child.stdout!.on('data', value => { stdout += String(value); });
    child.stderr!.on('data', value => { stderr += String(value); });
    const watchdog = setTimeout(() => { watchdogExpired = true; child.kill(); }, 15000);
    try {
      const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((done, fail) => {
        child.once('error', fail);
        child.on('message', value => {
          const message = value as { kind: string; id?: string };
          if (message.kind === 'baked') {
            allocated = message.id!;
            if (docker(['pause', 'lnd']).status !== 0) { fail(new Error('Fixture pause unavailable')); return; }
            paused = true; child.send({ kind: 'continue' });
          } else if (message.kind === 'verify-request') {
            verificationRequested = true;
            if (process.platform === 'win32') child.send({ kind: 'signal', signal: 'SIGTERM' });
            else child.kill('SIGTERM');
          }
        });
        // close follows exit and the draining of both captured output streams.
        child.once('close', (code, signal) => done({ code, signal }));
      });
      safe(stdout + stderr, [f.dir]);
      const diagnostic = `child-code=${result.code}; child-signal=${result.signal}; verify-request=${verificationRequested}; watchdog-expired=${watchdogExpired}; ${childDiagnostic(stdout, stderr)}`;
      expect(paused, diagnostic).toBe(true); expect(allocated).toMatch(/^[1-9][0-9]*$/);
      docker(['unpause', 'lnd']); paused = false;
      expect(ids()).toContain(allocated); expect(probe(f.old.outPath!)).toBe('accepted');
      expect(result, diagnostic).toEqual({ code: 7, signal: null });
      expect(existsSync(f.registry + '.lock')).toBe(false); expect(existsSync(f.out)).toBe(false);
      const stored = JSON.parse(readFileSync(f.registry, 'utf8')) as { entries: Array<{ rootKeyId: string; verified: boolean; replaces: string }> };
      expect(stored.entries.find(row => row.rootKeyId === allocated)).toMatchObject({ verified: false, replaces: f.old.rootKeyId });
      const document = JSON.parse(stdout) as { error: { message: string } };
      const recovery = document.error.message.match(/macwarden revoke ([1-9][0-9]*)( --unregistered)?/);
      expect(recovery?.[1]).toBe(allocated);
      const repaired = spawnSync(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import', loader,
        resolve('test/helpers/cp038-cli-child.mjs'), 'revoke', allocated, ...(recovery?.[2] ? ['--unregistered'] : []),
        '--yes', ...f.flags, '--json'], { encoding: 'utf8', timeout: 20000, env: childEnvironment({ NODE_OPTIONS: '', NODE_DEBUG: ''  }) });
      expect(repaired.error).toBeUndefined(); expect(repaired.status).toBe(0);
      expect(ids()).not.toContain(allocated); expect(probe(f.old.outPath!)).toBe('accepted');
    } finally {
      clearTimeout(watchdog); if (paused) docker(['unpause', 'lnd']);
      if (child.exitCode === null && child.signalCode === null) child.kill();
    }
  });
}, 60000);
