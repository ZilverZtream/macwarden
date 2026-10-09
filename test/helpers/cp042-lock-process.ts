import { openRegistry } from '../../src/registry/index.js';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { childEnvironment } from './environment.js';

export async function deadProductLock(path: string) {
  const child = spawn(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
    pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, resolve('test/helpers/cp042-lock-owner.mjs'), path],
    { env: childEnvironment(), windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const closed = new Promise<void>((done, fail) => { child.once('error', fail); child.once('close', () => done()); });
  const timer = setTimeout(() => child.kill('SIGKILL'), 7000);
  try {
    await new Promise<void>((done, fail) => {
      child.once('error', fail); child.once('close', () => fail(new Error('Product lock owner ended before coordination')));
      child.on('message', value => {
        const message = value as { kind?: string; category?: string };
        if (message.kind === 'locked') done();
        else if (message.kind === 'failed') fail(new Error('Product lock setup failed: ' + message.category));
      });
    });
    const bytes = readFileSync(path + '.lock');
    expect(JSON.parse(bytes.toString('utf8')).pid).toBe(child.pid);
    child.kill('SIGKILL'); await closed;
    let dead = false; try { process.kill(child.pid!, 0); } catch (error) { dead = (error as NodeJS.ErrnoException).code === 'ESRCH'; }
    expect(dead, 'product-created owner is independently gone').toBe(true);
    expect(readFileSync(path + '.lock').equals(bytes)).toBe(true);
    return { bytes, pid: child.pid! };
  } finally { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
}

export async function liveProductLock(path: string) {
  const view = await openRegistry(path);
  await view.lock();
  const bytes = readFileSync(path + '.lock');
  const owner = JSON.parse(bytes.toString('utf8'));
  expect(owner.pid).toBe(process.pid);
  process.kill(owner.pid, 0);
  return { view, bytes, owner };
}
