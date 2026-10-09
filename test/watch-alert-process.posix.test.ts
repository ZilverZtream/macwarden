import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import type { WatchEvent } from '../src/output/index.js';
import { ALERT_CLEANUP_MS, ALERT_KILL_MS, reapAlertGroups, runAlertCommand } from '../src/watch/alert.js';
import { prepare, startedPids, stopDuringAlert } from './helpers/watch-alert-shutdown.js';

// POSIX variant (process groups, /proc). Selected by the platform policy in
// scripts/platform-variants.mjs; the Windows counterpart is test/watch-alert-tree.windows.test.ts.
const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
let dir: string;
beforeAll(() => { mkdirSync(tmpRoot, { recursive: true }); dir = mkdtempSync(join(tmpRoot, 'watch-alert-process-')); });
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });

const canary: WatchEvent = { event: 'canary', time: '2026-10-08T12:00:00.000Z', method: '/lnrpc.Lightning/GetInfo',
  rootKeyId: '4294967342', credential: 'id:0123456789abcdef', label: 'decoy', denied: true };

it('WATCH/alert-leftover a real alert command that backgrounds a child and exits leaves no process behind', async () => {
  const script = join(dir, 'notify-and-return.sh');
  const marker = join(dir, 'leftover.pid');
  // The common "notify and return" shape: start a background job, exit 0 at once.
  writeFileSync(script, `#!/bin/sh\nsleep 3601 &\necho $! > '${marker}'\nexit 0\n`);
  chmodSync(script, 0o755);
  await runAlertCommand(script, canary);
  const leftover = Number(readFileSync(marker, 'utf8').trim());
  const dead = () => { try { return readFileSync(`/proc/${leftover}/stat`, 'utf8').split(') ')[1]?.[0] === 'Z'; } catch { return true; } };
  expect(dead()).toBe(false);
  // Gone after the grace period: the group got SIGKILL.
  for (let i = 0; i < 40 && !dead(); i++) await new Promise(resolve => setTimeout(resolve, 100));
  expect(dead()).toBe(true);
}, 30_000);

it('WATCH/alert-leftover reapAlertGroups kills leftovers at once when watch stops', async () => {
  const script = join(dir, 'notify-and-return-2.sh');
  const marker = join(dir, 'leftover-2.pid');
  writeFileSync(script, `#!/bin/sh\nsleep 3602 &\necho $! > '${marker}'\nexit 0\n`);
  chmodSync(script, 0o755);
  await runAlertCommand(script, canary);
  reapAlertGroups();
  const leftover = Number(readFileSync(marker, 'utf8').trim());
  const dead = () => { try { return readFileSync(`/proc/${leftover}/stat`, 'utf8').split(') ')[1]?.[0] === 'Z'; } catch { return true; } };
  // Well before the 1 s grace: the reap killed it, not the timer.
  for (let i = 0; i < 5 && !dead(); i++) await new Promise(resolve => setTimeout(resolve, 50));
  expect(dead()).toBe(true);
}, 30_000);

it('WATCH/alert-kill a real alert command that traps SIGTERM is killed by SIGKILL in its process group', async () => {
  const script = join(dir, 'stubborn-alert.sh');
  const marker = join(dir, 'grandchild.pid');
  // Ignores SIGTERM and starts a grandchild that would outlive a plain child kill.
  writeFileSync(script, `#!/bin/sh\ntrap '' TERM\nsleep 600 &\necho $! > '${marker}'\nwhile :; do sleep 1; done\n`);
  chmodSync(script, 0o755);
  const started = performance.now();
  await expect(runAlertCommand(script, canary)).rejects.toThrow('alert command timed out');
  const elapsed = performance.now() - started;
  expect(elapsed).toBeGreaterThanOrEqual(ALERT_KILL_MS - 500);
  expect(elapsed).toBeLessThan(ALERT_KILL_MS + 3_000);
  // The grandchild was in the same process group and is gone too.
  const grandchild = Number(readFileSync(marker, 'utf8').trim());
  // Killed means gone, or a zombie (dead, waiting for its new parent to reap it).
  const dead = () => { try { return readFileSync(`/proc/${grandchild}/stat`, 'utf8').split(') ')[1]?.[0] === 'Z'; } catch { return true; } };
  for (let i = 0; i < 30 && !dead(); i++) await new Promise(resolve => setTimeout(resolve, 100));
  expect(dead()).toBe(true);
}, 30_000);

// Audit MW102-05: at shutdown an alert waiting behind the running one must never start, the
// running command's process group must be gone when watch returns, and watch must return
// within its alert budget. The real watch command runs the real alert executable.
it('WATCH/alert-shutdown at shutdown the waiting alert never starts and the running group is gone when watch returns', async () => {
  const sub = mkdtempSync(join(dir, 'shutdown-'));
  const starts = join(sub, 'starts.txt');
  const kids = join(sub, 'kids.txt');
  const script = join(sub, 'alert');
  // Ignores SIGTERM, starts a background job, never exits on its own.
  writeFileSync(script, `#!/bin/sh\ntrap '' TERM\nsleep 3603 &\necho $! >> '${kids}'\necho $$ >> '${starts}'\nwhile :; do sleep 1; done\n`);
  chmodSync(script, 0o755);
  const { result, elapsed } = await stopDuringAlert([...prepare(sub), '--alert-command', script], starts);
  const pids = [...startedPids(starts), ...startedPids(kids)];
  // Killed means gone, or a zombie (dead, waiting for its new parent to reap it).
  const dead = (pid: number) => { try { return readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ')[1]?.[0] === 'Z'; } catch { return true; } };
  expect(result).toMatchObject({ ok: true, result: { canaryAlerts: 2, alertFailures: 2 } });
  expect(startedPids(starts)).toHaveLength(1);
  expect(startedPids(kids)).toHaveLength(1);
  // watch has sent SIGKILL to the alert's process group before returning; the kernel completes
  // the exit asynchronously, so a killed process can still show in /proc for a moment. Each must
  // be gone (or a zombie) within 2 s of watch returning.
  for (const pid of pids) {
    const until = performance.now() + 2_000;
    while (!dead(pid) && performance.now() < until) await new Promise(resolve => setTimeout(resolve, 20));
    expect(dead(pid), `pid ${pid}`).toBe(true);
  }
  expect(elapsed).toBeLessThan(ALERT_KILL_MS + ALERT_CLEANUP_MS + 1_000);
  await new Promise(resolve => setTimeout(resolve, 500));
  expect(startedPids(starts)).toHaveLength(1);
}, 40_000);
