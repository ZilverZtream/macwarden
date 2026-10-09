// Child for WATCH/unread-exit. It runs the real binary entry point (bin -> cli -> handler) as
// `watch --json`, with only the network part of the watch handler replaced: the handler
// writes a burst of event lines into a stdout pipe that the parent never reads, finishes
// the way watch does (bounded drain, then close), and returns. The process must exit with
// that status within a bounded time instead of waiting forever for the reader.
import { handlers } from '../../src/commands/handlers.js';
import { stdoutEvents } from '../../src/commands/watch.js';

handlers.watch = async () => {
  const events = stdoutEvents();
  const line = `${JSON.stringify({ event: 'call', pad: 'x'.repeat(400) })}\n`;
  for (let i = 0; i < 5000; i++) events.emit(line, i % 50 === 0);
  if (await events.drainOutput(500) === false) events.closeOutput();
  process.stderr.write(`handler done dropped ${events.dropped()}\n`);
  return { schema: 1, command: 'watch', ok: true, warnings: [], error: null,
    result: { node: 'n', startedAt: 's', endedAt: 'e', calls: 0, errors: 0, credentials: 0, canaryAlerts: 0, canaryUses: 0,
      reconnects: 0, canaries: 0, usageFile: 'u', droppedUsageRecords: 0, alertFailures: 0, droppedEvents: 0, droppedAttributions: 0 } };
};
await import('../../src/bin.js');
