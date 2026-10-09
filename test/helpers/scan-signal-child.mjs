// Runs the built CLI's main() in this process so a parent can deliver an interrupt
// portably: POSIX parents may send a real signal; on Windows child.kill terminates the
// process outright, so the parent asks over IPC and this child emits the signal event.
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const { main, completionStatus } = await import(pathToFileURL(resolve('dist/cli.js')).href);
process.on('message', message => {
  if (message && typeof message === 'object' && message.kind === 'signal') process.emit(message.signal, message.signal);
});
process.send?.({ kind: 'ready' });
const status = await main(process.argv.slice(2));
process.exitCode = completionStatus(status);
process.disconnect?.();
