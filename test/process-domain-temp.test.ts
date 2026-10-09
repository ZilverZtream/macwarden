import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';

// The query's process is replaced so the test sees the exact environment it receives.
const calls: { env: Record<string, string | undefined> }[] = [];
vi.mock('node:child_process', () => ({
  execFile: (_file: string, _args: string[], options: { env: Record<string, string | undefined> },
    callback: (error: Error | null, stdout: string, stderr: string) => void) => {
    calls.push({ env: options.env });
    callback(null, JSON.stringify({ platform: 'win32', bootId: '36fab8a9-2ae9-11f0-b7c7-8a889eea68a4', siloId: 'host' }), '');
  },
}));

const saved = { platform: process.platform, TEMP: process.env.TEMP, TMP: process.env.TMP, SystemRoot: process.env.SystemRoot };
afterEach(() => {
  Object.defineProperty(process, 'platform', { value: saved.platform });
  for (const name of ['TEMP', 'TMP', 'SystemRoot'] as const) {
    if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name];
  }
  calls.length = 0;
  vi.resetModules();
});

// The query refuses a SystemRoot that is not absolute for the host's node:path.
const ROOT = process.platform === 'win32' ? 'C:\\Windows' : '/windows';

async function query(env: { TEMP?: string; TMP?: string }) {
  Object.defineProperty(process, 'platform', { value: 'win32' });
  process.env.SystemRoot = ROOT;
  delete process.env.TEMP; delete process.env.TMP;
  Object.assign(process.env, env);
  const { ownProcessDomain } = await import('../src/registry/process-domain.js');
  expect(await ownProcessDomain()).toMatchObject({ platform: 'win32', siloId: 'host' });
  expect(calls).toHaveLength(1);
  return calls[0].env;
}

it('PROCESS-DOMAIN/temp-fallback a service environment without TEMP or TMP gets the system Temp folder', async () => {
  const env = await query({});
  // node:path joins with the host separator; on Windows this is exactly C:\Windows\Temp.
  expect(env).toMatchObject({ TEMP: join(ROOT, 'Temp'), TMP: join(ROOT, 'Temp') });
  if (saved.platform === 'win32') expect(env.TEMP).toBe('C:\\Windows\\Temp');
});

it('PROCESS-DOMAIN/temp-fallback an existing TEMP or TMP is passed through and fills the other', async () => {
  expect(await query({ TEMP: 'D:\\svc\\temp' })).toMatchObject({ TEMP: 'D:\\svc\\temp', TMP: 'D:\\svc\\temp' });
  vi.resetModules(); calls.length = 0;
  expect(await query({ TMP: 'E:\\t' })).toMatchObject({ TEMP: 'E:\\t', TMP: 'E:\\t' });
});
