import * as fs from 'node:fs/promises';
import { expect, it } from 'vitest';
import { Cancelled, withCancellation } from '../src/cancellation.js';
import { run } from '../src/commands/scan.js';
import { discoverAgentConfigs } from '../src/scan/agent-configs.js';

const environment = () => ({ platform: 'linux' as NodeJS.Platform, home: '/stalled/home', cwd: '/stalled/project', env: {} });

/** An lstat that never settles until released, as on a stalled mount. */
function stalledLstat() {
  let release: () => void = () => {};
  let calls = 0;
  const lstat = (() => {
    calls++;
    return new Promise((_resolve, reject) => { release = () => reject(Object.assign(new Error('gone'), { code: 'ENOENT' })); });
  }) as unknown as typeof fs.lstat;
  return { lstat, release: () => release(), calls: () => calls };
}

it('F15/discovery a pending agent-config lstat is released by an abort and rejects with Cancelled, not absent', async () => {
  const stalled = stalledLstat();
  const controller = new AbortController();
  const pending = withCancellation(controller.signal, () =>
    discoverAgentConfigs([{ client: 'cursor', path: '/stalled/home/.cursor/mcp.json' }, { client: 'dotenv', path: '/stalled/project/.env' }],
      path => stalled.lstat(path)));
  let settled = false;
  pending.then(() => { settled = true; }, () => { settled = true; });
  await new Promise(resolve => setImmediate(resolve));
  expect(settled).toBe(false);
  controller.abort();
  await expect(pending).rejects.toBeInstanceOf(Cancelled);
  // No further candidate is probed after the interrupt.
  expect(stalled.calls()).toBe(1);
  stalled.release();
});

it('F15/scan --agent-configs stalled on discovery exits 6 cancelled on abort', async () => {
  const stalled = stalledLstat();
  const controller = new AbortController();
  const pending = withCancellation(controller.signal, () =>
    run(['--agent-configs'], { fs: { ...fs, lstat: stalled.lstat }, agentEnvironment: environment }));
  await new Promise(resolve => setImmediate(resolve));
  controller.abort();
  const output = await pending;
  expect(output).toMatchObject({ command: 'scan', ok: false, result: null, error: { code: 6, step: 'cancelled', message: 'interrupted' } });
  stalled.release();
});

it('F15/discovery without an interrupt still records failing lstats as absent', async () => {
  const controller = new AbortController();
  const result = await withCancellation(controller.signal, () =>
    discoverAgentConfigs([{ client: 'dotenv', path: '/missing/.env' }],
      () => Promise.reject(Object.assign(new Error('missing'), { code: 'ENOENT' }))));
  expect(result).toEqual({ found: [], absent: [{ client: 'dotenv', path: '/missing/.env' }] });
});
