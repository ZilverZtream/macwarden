#!/usr/bin/env node
import { main, completionStatus, flushStandardStreams, interruptedCompletion } from './cli.js';
import { alertCleanupDone } from './watch/alert.js';

// watch runs unattended (systemd, CI). If its output can no longer be delivered (a pipe
// that is never read), a write already handed to the operating system cannot be
// cancelled: on Windows every write to an inherited pipe is synchronous, and a normal exit
// waits for the blocked writer. So once watch has finished, a short unref'd deadline
// terminates the process if it is still alive. With a reader that reads, the process exits
// on its own before the deadline with its real status; when the deadline fires, the
// non-zero exit (1 on Windows, SIGKILL on POSIX) reports that output was not delivered.
// Other commands are not affected: their output is waited for in full.
// The deadline is armed only after every alert process-tree kill (Windows taskkill) has
// finished, each bounded: ending this process first would end the alert command itself and
// orphan the children taskkill has yet to find (audit MW102-05).
const WATCH_EXIT_GRACE_MS = 3_000;

const status = await main(process.argv.slice(2), { execArgv: process.execArgv, nodeVersion: process.versions.node });
process.exitCode = completionStatus(status);
// An interrupt can abandon a file system call that never returns (lstat on a stalled mount):
// Node cannot cancel it, and the pending request would hold the process open after the exit-6/7
// result was printed. The command has already released its locks and removed unwritten output,
// so once that result has reached stdout and stderr the process ends with its code (1.2.1).
// Every other exit is left to Node as before.
if (interruptedCompletion() && process.argv[2] !== 'watch') {
  await flushStandardStreams();
  process.exit(completionStatus(status));
}
if (process.argv[2] === 'watch') {
  await alertCleanupDone();
  setTimeout(() => process.kill(process.pid, 'SIGKILL'), WATCH_EXIT_GRACE_MS).unref();
}
