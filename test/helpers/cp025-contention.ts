import { childEnvironment } from './environment.js';
import { fork } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export async function contend(dir: string, live?: { cert: string; own: string }) {
  const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
  const children = ['Alice', 'Bob'].map((label, index) => fork(resolve('test/helpers/cp025-bake-child.mjs'),
    [dir, label, `child-${index}.macaroon`, ...(live ? ['live', live.cert, live.own] : [])],
    { cwd: resolve(), env, execArgv: ['--experimental-transform-types', '--disable-warning=ExperimentalWarning',
      '--import', pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href],
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'] }));
  const rows = children.map(() => ({ code: null as number | null, stdout: '', stderr: '', calls: [] as string[] }));
  let timer: ReturnType<typeof setTimeout>;
  try {
    await new Promise<void>((resolve, reject) => {
      let ready = 0, holder = -1, exits = 0;
      timer = setTimeout(() => reject(new Error('CP-025 child coordination timed out')), 20_000);
      children.forEach((child, index) => {
        child.stdout!.on('data', data => { rows[index].stdout += data; });
        child.stderr!.on('data', data => { rows[index].stderr += data; });
        child.on('error', reject);
        child.on('message', (message: { kind: string; calls?: string[] }) => {
          if (message.kind === 'ready' && ++ready === 2) children.forEach(child => child.send('go'));
          if (message.kind === 'holding') {
            if (holder !== -1) { reject(new Error('Both bakes reached LND while one held the lock')); return; }
            holder = index;
            if (rows[1 - index].code !== null) child.send('release');
          }
          if (message.kind === 'calls') rows[index].calls = message.calls!;
        });
        child.on('close', code => {
          rows[index].code = code;
          if (holder !== -1 && holder !== index && children[holder].connected) children[holder].send('release');
          if (++exits === 2) resolve();
        });
      });
    });
    return rows;
  } finally {
    clearTimeout(timer!);
    children.forEach(child => { if (child.exitCode === null) child.kill(); });
  }
}
