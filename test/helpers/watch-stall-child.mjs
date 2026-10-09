// Child for WATCH/output-stall: registers a read-only middleware with a fake LND and
// emits one event line per intercept through the production event output of
// `macwarden watch` (stdoutEvents). The parent never reads this process's stdout, so the
// pipe fills up; intercept feedback must keep flowing regardless.
import { readFileSync } from 'node:fs';
import { macaroonId } from '../../src/decode/index.js';
import { registerMiddleware } from '../../src/lnd/index.js';
import { renderWatchEvent } from '../../src/output/index.js';
import { Secret } from '../../src/secret.js';
import { stdoutEvents } from '../../src/commands/watch.js';

const [port, caPath, ownPath] = process.argv.slice(2);
const events = stdoutEvents();
registerMiddleware({ host: '127.0.0.1', port: Number(port), tlsCert: readFileSync(caPath), macaroon: new Secret(readFileSync(ownPath)) },
  { name: 'macwarden-watch', readOnly: true }, call => {
    // The caller macaroon is valid only while this handler runs (as in watch itself).
    const identity = macaroonId(call.macaroon);
    queueMicrotask(() => {
      const line = renderWatchEvent({ event: 'call', time: new Date().toISOString(), method: call.method,
        rootKeyId: identity.rootKeyId.toString(), credential: identity.id, label: null }, 'text');
      // Pad each line so the pipe fills and the 1 MiB queue overflows within the run.
      events.emit(`${line.trimEnd()} ${'.'.repeat(2000)}\n`);
    });
    return '';
  }, () => process.stderr.write('registered\n'));
process.on('message', () => { process.stderr.write(`dropped ${events.dropped()}\n`); });
