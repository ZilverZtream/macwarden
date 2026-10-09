import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { fixture } from './helpers/cp038-online.js';
import { childEnvironment } from './helpers/environment.js';

// Faulty Deps establish the pre-mutation wait. POSIX sends an OS signal;
// Windows injects the Node signal event because child.kill force-terminates.
it.each(['bake', 'stage', 'revoke', 'finish'] as const)('CP-042/B6-pre-mutation-interruption %s pre-mutation signal reports cancellation and cleans owned files', async mode => {
  const f = fixture(), marker = join(f.dir, 'signal-state.json');
  const child = spawn(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
    pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, resolve('test/helpers/cp042-signal-child.mjs'), mode, 'before', marker],
    { env: childEnvironment(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let stdout = '', reached = false;
  child.stdout!.on('data', value => { stdout += String(value); }); child.stderr!.resume();
  const timer = setTimeout(() => child.kill(), 7000);
  try {
    const code = await new Promise<number | null>((done, fail) => {
      child.once('error', fail); child.on('message', value => {
        if ((value as { kind?: string }).kind !== 'boundary') return;
        reached = true; if (process.platform === 'win32') child.send({ kind: 'signal', signal: 'SIGTERM' }); else child.kill('SIGTERM');
      }); child.once('close', done);
    });
    expect(reached).toBe(true); expect(code).toBe(6);
    expect(JSON.parse(stdout)).toMatchObject({ ok: false, error: { code: 6, step: 'cancelled', message: 'interrupted' } });
    const state = JSON.parse(readFileSync(marker, 'utf8')) as { registry: string; out: string; ids: string[]; oldId: string };
    expect(state.ids).toContain(state.oldId); expect(existsSync(state.registry + '.lock')).toBe(false);
    if (mode === 'bake' || mode === 'stage') expect(existsSync(state.out)).toBe(false);
  } finally { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill(); }
}, 10_000);
