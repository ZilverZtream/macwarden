import { childEnvironment } from './helpers/environment.js';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { fixture } from './helpers/cp038-online.js';

const cancellationCases = (['bake', 'stage', 'revoke', 'finish'] as const).flatMap(mode =>
  (['SIGINT', 'SIGTERM', 'SIGHUP'] as const).flatMap(signal => (['before', 'after'] as const).map(point => [mode, signal, point] as const)));
it.each(cancellationCases)('CP-038/A5-cancellation %s %s %s observable mutation boundary cleans up and reports recovery', async (mode, signal, point) => {
  const f = fixture(), marker = join(f.dir, 'boundary.json');
  const child = spawn(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
    pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, resolve('test/helpers/cp038-signal-child.mjs'), mode, point, marker],
    { stdio: ['ignore', 'pipe', 'pipe', 'ipc'], env: childEnvironment({ NODE_OPTIONS: '', NODE_DEBUG: ''  }) });
  let stdout = '', stderr = '', at = 0, cancellationMs = 0;
  child.stdout!.on('data', chunk => { stdout += String(chunk); });
  child.stderr!.on('data', chunk => { stderr += String(chunk); });
  const watchdog = setTimeout(() => child.kill(), 7000);
  try {
    const actual = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((done, fail) => {
      child.once('error', fail);
      child.on('message', value => {
        if ((value as { kind?: string }).kind !== 'boundary') return;
        at = performance.now();
        if (process.platform === 'win32') child.send({ kind: 'signal', signal });
        else child.kill(signal);
      });
      child.once('exit', (code, signal) => {
        cancellationMs = performance.now() - at;
        done({ code, signal });
      });
    });
    expect(at, 'child must reach an observable boundary').not.toBe(0);
    const state = JSON.parse(readFileSync(marker, 'utf8')) as { registry: string; out: string; id: string; ids: string[]; oldId: string };
    expect(existsSync(state.registry + '.lock')).toBe(false);
    if (mode === 'stage' || mode === 'bake') expect(existsSync(state.out)).toBe(false);
    if (point === 'after') expect(actual).toEqual({ code: 7, signal: null });
    else { expect(actual.signal).toBeNull(); expect(actual.code).not.toBe(0); }
    expect(cancellationMs).toBeLessThan(3000);
    const document = JSON.parse(stdout) as { error: { code: number; message: string } };
    if (point === 'after') { expect(document.error.code).toBe(7); expect(document.error.message).toContain('macwarden'); }
    if ((mode === 'stage' || mode === 'bake') && point === 'after') {
      const stored = JSON.parse(readFileSync(state.registry, 'utf8')) as { entries: Array<{ rootKeyId: string; verified: boolean }> };
      expect(stored.entries.find(row => row.rootKeyId === state.id)).toMatchObject({ verified: false });
      if (mode === 'stage') expect(state.ids).toContain(state.oldId);
    }
    expect(stderr).not.toContain('paused operation deadline');
  } finally { clearTimeout(watchdog); if (child.exitCode === null && child.signalCode === null) child.kill(); }
}, 10000);

it('CP-038/B12-dispatch real bin keeps sticky internal failure and one JSON document after mutation', () => {
  const actual = spawnSync(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
    pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, '--import',
    pathToFileURL(resolve('test/helpers/cp038-bin-preload.mjs')).href, resolve('src/bin.ts')],
    { encoding: 'utf8', timeout: 10000, env: childEnvironment({ NODE_OPTIONS: '', NODE_DEBUG: ''  }) });
  expect(actual.error).toBeUndefined(); expect(actual.status).toBe(8); expect(actual.stderr).toBe('');
  const document = JSON.parse(actual.stdout) as { error: { message: string } };
  expect(document).toMatchObject({ command: 'bake', ok: false, result: null, error: { code: 8, step: 'internal' } });
  expect(document.error.message).toContain('macwarden inventory'); expect(actual.stdout).not.toContain('private process-event detail');
});
