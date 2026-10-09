import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';

const { attempts, stop } = vi.hoisted(() => {
  const attempts: string[] = [];
  return { attempts, stop: (name: string) => function blocked() {
    attempts.push(name);
    throw new Error('offline network attempt');
  } };
});
for (const name of ['fetch', 'WebSocket', 'EventSource']) vi.stubGlobal(name, stop(name));
vi.mock('node:https', async importOriginal => {
  const original = await importOriginal<typeof import('node:https')>();
  return { ...original, request: stop('https'), get: stop('https'),
    default: { ...original, request: stop('https'), get: stop('https') } };
});
vi.mock('node:http', async importOriginal => {
  const original = await importOriginal<typeof import('node:http')>();
  return { ...original, request: stop('http'), get: stop('http'),
    default: { ...original, request: stop('http'), get: stop('http') } };
});
vi.mock('node:net', async importOriginal => {
  const original = await importOriginal<typeof import('node:net')>();
  return { ...original, connect: stop('net'), createConnection: stop('net'),
    default: { ...original, connect: stop('net'), createConnection: stop('net') } };
});
vi.mock('node:dns', async importOriginal => {
  const original = await importOriginal<typeof import('node:dns')>();
  return { ...original, lookup: stop('dns'), resolve: stop('dns'),
    default: { ...original, lookup: stop('dns'), resolve: stop('dns') } };
});

const repo = resolve();
const tmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
process.env.MACWARDEN_TEST_TMP = tmp;
it('ATTENUATE/offline attenuate makes no network attempt with network globals and transports trapped', async () => {
  mkdirSync(tmp, { recursive: true });
  const dir = mkdtempSync(join(tmp, 'attenuate-offline-'));
  const path = join(dir, 'fixture.macaroon');
  writeFileSync(path, readFileSync(join(repo, 'test/vectors/default-readonly.macaroon')));
  const before = { bytes: readFileSync(path), mtime: statSync(path).mtimeMs };
  try {
    const module = await import('../src/cli.js');
    const run = await captureMain(module.main, ['attenuate', path, '--out', join(dir, 'child.macaroon'),
      '--expires', '1h', '--ip', '127.0.0.1', '--json']);
    expect(run.code).toBe(0);
    expect(JSON.parse(run.stdout)).toMatchObject({ command: 'attenuate', ok: true, error: null });
    expect(attempts).toEqual([]);
    expect(readFileSync(path).equals(before.bytes)).toBe(true);
    expect(statSync(path).mtimeMs).toBe(before.mtime);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
