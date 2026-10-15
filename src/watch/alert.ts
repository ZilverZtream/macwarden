// Runs the operator's --alert-command for a canary event: a fixed absolute executable,
// no shell, no arguments, a minimal environment, the event JSON on stdin and a timeout.
// The event holds no credential material: method, root key ID, fingerprint and label.
//
// The command may misbehave: it can ignore SIGTERM, be stopped, or start children that
// outlive it. It runs in its own process group on POSIX; the group gets SIGTERM after
// ALERT_TIMEOUT_MS and SIGKILL after ALERT_KILL_MS, and the run settles at ALERT_KILL_MS
// whatever the processes do. One stuck command therefore delays the next alert by at most
// ALERT_KILL_MS (alerts run one at a time). Its output is not read (no buffer to grow).
//
// Children that outlive the command: an attacker holding a canary decides how often alerts
// run, so leftovers would accumulate. On POSIX the whole group gets SIGKILL ALERT_GRACE_MS
// after the command exits, and every group still alive is killed when watch stops
// (reapAlertGroups). A child that calls setsid() itself leaves the group and is out of reach.
// On Windows there are no process groups: a timed-out command's process tree is killed with
// System32 taskkill /T /F, but children of a command that has already exited cannot be found
// by tree and are not killed. Alert commands on Windows must not leave background processes.
//
// Shutdown (audit MW102-05): watch stops the alert runner, which cancels a command still
// running at its deadline through the AbortSignal: the group gets SIGKILL (POSIX) or the tree
// is killed with taskkill (Windows), and the run settles once that is done. Every taskkill is
// tracked until it exits (each bounded by TASKKILL_MS): watch waits for them before it returns
// and the CLI arms its forced-exit deadline only after they finished (alertCleanupDone), since
// ending this process ends the command itself and orphans the children taskkill must find.
// spawn is used rather than execFile: execFile does not pass `detached` through, so it
// cannot create the process group.
import { spawn as nodeSpawn } from 'node:child_process';
import type { WatchEvent } from '../output/index.js';

export const ALERT_TIMEOUT_MS = 10_000;
export const ALERT_KILL_MS = 12_000;
export const ALERT_GRACE_MS = 1_000;
/** How long watch's shutdown waits for process-tree kills to finish before it returns. */
export const ALERT_CLEANUP_MS = 1_000;
/** A taskkill that has not exited by then is abandoned (and killed). */
const TASKKILL_MS = 10_000;

// Process groups of alert commands that may still have members (POSIX).
const liveGroups = new Set<number>();
const killGroup = (pid: number) => {
  // Probe first (audit 1.2.1): once every member exited, the kernel may hand the group ID to an
  // unrelated process; an empty group answers ESRCH and is left alone.
  try { process.kill(-pid, 0); process.kill(-pid, 'SIGKILL'); } catch { /* group already empty */ }
  liveGroups.delete(pid);
};

/** Kills every alert process group still alive; called when watch stops. */
export function reapAlertGroups(): void {
  for (const pid of [...liveGroups]) killGroup(pid);
}

// Windows process-tree kills (taskkill) that have not finished yet.
const treeKills = new Set<Promise<void>>();

/** Kills a Windows process tree with System32 taskkill: absolute path, no shell, bounded. */
function killTree(pid: number, spawn: Spawn): Promise<void> {
  const root = process.env.SystemRoot;
  if (!root || !/^[A-Za-z]:[\\/]/.test(root)) return Promise.resolve();
  let killer: ReturnType<Spawn>;
  try {
    killer = spawn(`${root}\\System32\\taskkill.exe`, ['/T', '/F', '/PID', String(pid)],
      { shell: false, windowsHide: true, stdio: 'ignore' });
  } catch { return Promise.resolve(); /* best effort */ }
  const done: Promise<void> = new Promise<void>(resolve => {
    const finish = () => { clearTimeout(timer); treeKills.delete(done); resolve(); };
    const timer = setTimeout(() => { try { killer.kill(); } catch { /* gone */ } finish(); }, TASKKILL_MS);
    timer.unref?.();
    killer.once('exit', finish);
    killer.once('error', finish);
  });
  treeKills.add(done);
  return done;
}

/** Resolves once every process-tree kill started so far has finished, or after `ms`. */
export async function alertCleanupDone(ms = TASKKILL_MS): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let expired = false;
  const deadline = new Promise<void>(resolve => { timer = setTimeout(() => { expired = true; resolve(); }, ms); });
  try {
    while (treeKills.size && !expired) await Promise.race([Promise.all([...treeKills]), deadline]);
  } finally { clearTimeout(timer); }
}

type Spawn = typeof nodeSpawn;

/**
 * Runs the alert command once. Aborting `signal` cancels it: the process group (POSIX) or
 * tree (Windows) is killed at once, and the run settles with an error after that finished.
 */
export function runAlertCommand(command: string, event: WatchEvent, spawn: Spawn = nodeSpawn,
  platform: NodeJS.Platform = process.platform, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const env: NodeJS.ProcessEnv = {};
    for (const name of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'HOME', 'USERPROFILE', 'TEMP', 'TMP', 'TMPDIR'])
      if (process.env[name] !== undefined) env[name] = process.env[name];
    const group = platform !== 'win32';
    let settled = false;
    // Filled in after spawn; settle may run before (a synchronous spawn failure).
    const timers: { term?: ReturnType<typeof setTimeout>; kill?: ReturnType<typeof setTimeout> } = {};
    let cancel = () => settle(new Error('alert command cancelled'));
    const onAbort = () => cancel();
    const settle = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timers.term);
      clearTimeout(timers.kill);
      signal?.removeEventListener('abort', onAbort);
      if (error) reject(error); else resolve();
    };
    if (signal?.aborted) { settle(new Error('alert command cancelled')); return; }
    signal?.addEventListener('abort', onAbort, { once: true });
    let child: ReturnType<Spawn>;
    try {
      child = spawn(command, [], { shell: false, windowsHide: true, env, detached: group, stdio: ['pipe', 'ignore', 'ignore'] });
    } catch { settle(new Error('alert command failed')); return; }
    child.once('error', () => settle(new Error('alert command failed')));
    if (group && child.pid) liveGroups.add(child.pid);
    child.once('exit', code => {
      // Leftover members of the group get a short grace, then SIGKILL (POSIX). An empty group
      // (the usual case) is forgotten at once (audit 1.3.2): kept for the grace, its ID could
      // be handed to a new group leader in that second and the timer would kill that group.
      if (group && child.pid) {
        const pid = child.pid;
        let members = true;
        try { process.kill(-pid, 0); } catch (error) { members = (error as NodeJS.ErrnoException).code !== 'ESRCH'; }
        if (members) setTimeout(() => killGroup(pid), ALERT_GRACE_MS).unref();
        else liveGroups.delete(pid);
      }
      settle(code === 0 ? undefined : new Error('alert command failed'));
    });
    /** Signals the command's group (POSIX) or kills its tree (Windows); resolves when that is done. */
    const kill = (name: NodeJS.Signals): Promise<void> => {
      // A negative PID addresses the process group created by detached: true.
      try {
        if (group && child.pid) process.kill(-child.pid, name);
        // Windows has no catchable SIGTERM: terminating the command first would orphan its
        // children before the tree could be found. Kill the whole tree while the command lives.
        else if (platform === 'win32' && child.pid) return killTree(child.pid, spawn);
        else child.kill(name);
      } catch { try { child.kill(name); } catch { /* already gone */ } }
      return Promise.resolve();
    };
    // Cancelled (watch is stopping): kill now; the run settles once the tree kill is done.
    cancel = () => { void kill('SIGKILL').then(() => settle(new Error('alert command cancelled'))); };
    timers.term = setTimeout(() => { void kill('SIGTERM'); }, ALERT_TIMEOUT_MS);
    timers.kill = setTimeout(() => { void kill('SIGKILL'); settle(new Error('alert command timed out')); }, ALERT_KILL_MS);
    child.stdin?.on('error', () => undefined);
    child.stdin?.end(`${JSON.stringify({ schema: 1, ...event })}\n`);
  });
}
