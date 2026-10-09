import { spawn as nodeSpawn, type spawn as Spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { ALERT_CLEANUP_MS, ALERT_KILL_MS, runAlertCommand } from '../src/watch/alert.js';
import { prepare, startedPids, stopDuringAlert } from './helpers/watch-alert-shutdown.js';

const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };

// Windows has no catchable SIGTERM: terminating the timed-out command first orphaned its
// children, so taskkill /T could no longer find them. The tree must be killed while the
// command still runs. Only the alert executable is replaced; taskkill is the product's own.
it('WATCH/alert-tree-windows a timed-out alert command dies with its detached child', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mw-alert-tree-'));
  const pids = join(dir, 'pids.txt');
  const script = join(dir, 'hang.cjs');
  writeFileSync(script, `
const { spawn } = require('child_process'); const fs = require('fs');
const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore', detached: true });
fs.writeFileSync(${JSON.stringify(pids)}, process.pid + ' ' + child.pid);
process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);
`);
  const spawn = ((command: string, args: string[], options: object) => /taskkill\.exe$/i.test(command)
    ? nodeSpawn(command, args, options) : nodeSpawn(process.execPath, [script], options)) as unknown as typeof Spawn;
  let command = 0, grandchild = 0;
  try {
    await expect(runAlertCommand('C:\\alert\\page.exe', { event: 'canary', time: 't', method: '/a/B', rootKeyId: '1',
      credential: 'id:0000000000000000', label: null, denied: true }, spawn, 'win32')).rejects.toThrow();
    [command, grandchild] = readFileSync(pids, 'utf8').split(' ').map(Number);
    // taskkill runs asynchronously; give it a moment to finish.
    for (let n = 0; n < 50 && (alive(command) || alive(grandchild)); n++) await new Promise(resolve => setTimeout(resolve, 100));
    expect(alive(command)).toBe(false);
    expect(alive(grandchild)).toBe(false);
  } finally {
    for (const pid of [command, grandchild]) if (pid && alive(pid)) try { process.kill(pid); } catch { /* gone */ }
    rmSync(dir, { recursive: true, force: true });
  }
}, 40_000);

// Audit MW102-05: at shutdown an alert waiting behind the running one must never start, the
// running command's whole tree must be gone when watch returns (taskkill awaited, so the CLI's
// exit watchdog cannot cut it short), and watch must return within its alert budget.
it('WATCH/alert-shutdown at shutdown the waiting alert never starts and the running tree is gone when watch returns', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mw-alert-shutdown-'));
  const starts = join(dir, 'starts.txt');
  const kids = join(dir, 'kids.txt');
  const script = join(dir, 'hang.cjs');
  writeFileSync(script, `
const { spawn } = require('child_process'); const fs = require('fs');
const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore', detached: true });
fs.appendFileSync(${JSON.stringify(kids)}, child.pid + ' ');
fs.appendFileSync(${JSON.stringify(starts)}, process.pid + ' ');
process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);
`);
  // A real .exe path for --alert-command validation; the spawn runs the script instead.
  const exe = join(dir, 'alert.exe');
  writeFileSync(exe, 'replaced by the test spawn');
  const spawn = ((command: string, args: string[], options: object) => /taskkill\.exe$/i.test(command)
    ? nodeSpawn(command, args, options) : nodeSpawn(process.execPath, [script], options)) as unknown as typeof Spawn;
  const pids: number[] = [];
  try {
    const args = [...prepare(dir), '--alert-command', exe];
    const { result, elapsed } = await stopDuringAlert(args, starts, {
      alert: (command, event, signal) => runAlertCommand(command, event, spawn, 'win32', signal) });
    pids.push(...startedPids(starts), ...startedPids(kids));
    expect(result).toMatchObject({ ok: true, result: { canaryAlerts: 2, alertFailures: 2 } });
    // Exactly one alert command ever started.
    expect(startedPids(starts)).toHaveLength(1);
    expect(startedPids(kids)).toHaveLength(1);
    // Gone at the moment watch returned: no polling.
    for (const pid of pids) expect(alive(pid), `pid ${pid}`).toBe(false);
    expect(elapsed).toBeLessThan(ALERT_KILL_MS + ALERT_CLEANUP_MS + 1_000);
    await new Promise(resolve => setTimeout(resolve, 500));
    expect(startedPids(starts)).toHaveLength(1);
  } finally {
    for (const pid of pids) if (pid && alive(pid)) try { process.kill(pid); } catch { /* gone */ }
    rmSync(dir, { recursive: true, force: true });
  }
}, 40_000);
