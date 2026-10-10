// Runs the built CLI (argv[2]) with the remaining arguments while every lstat under the directory
// named by MACWARDEN_STALL_PATH never answers, as on a stalled mount: the pending call keeps the
// event loop alive the way a libuv request on a hung mount does. The parent drives signals over IPC
// (Windows has no SIGINT for a child process).
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { pathToFileURL } from 'node:url';

const stalled = process.env.MACWARDEN_STALL_PATH;
const real = fs.promises.lstat;
fs.promises.lstat = (path, ...rest) => stalled && String(path).startsWith(stalled)
  ? new Promise(() => { setTimeout(() => {}, 120_000); process.send?.({ kind: 'stalled' }); })
  : real(path, ...rest);
syncBuiltinESMExports();
process.on('message', message => { if (message?.kind === 'signal') process.emit(message.signal); });
const [bin, ...args] = process.argv.slice(2);
process.argv = [process.argv[0], bin, ...args];
await import(pathToFileURL(bin).href);
