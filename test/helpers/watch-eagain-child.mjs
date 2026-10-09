// Child for WATCH/output-eagain. It imports the CLI module first, exactly like production
// (bin -> cli), which touches process.stdout and so switches a pipe on stdout to
// non-blocking mode on Linux. A burst of ordinary lines then fills the pipe while the
// parent is not reading; later a canary alert (priority line) must still arrive once the
// parent reads again. The old output queue treated the resulting EAGAIN as a closed reader
// and silently dropped everything after it.
import '../../src/cli.js';
import { stdoutEvents } from '../../src/commands/watch.js';

const events = stdoutEvents();
const line = `${JSON.stringify({ event: 'call', pad: 'x'.repeat(200) })}\n`;
for (let i = 0; i < 2000; i++) events.emit(line, false);
await new Promise(resolve => setTimeout(resolve, 1500));
events.emit(`${JSON.stringify({ event: 'canary', label: 'CANARY-ALERT-MARKER' })}\n`, true);
const drained = await events.drainOutput(10_000);
process.stderr.write(`dropped ${events.dropped()} drained ${drained}\n`);
