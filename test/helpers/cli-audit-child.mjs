// Runs the built bin.js (argv[2]) with the remaining arguments after replacing one command handler
// with a synthetic stand-in named by MACWARDEN_CLI_AUDIT_SCENARIO. The parent drives signals over
// IPC (Windows has no SIGINT for a child process); 'stalled' tells it the handler is waiting.
//   respond-interrupted: respond waits for a signal, leaves a ref'd timer behind (an abandoned
//     file system call) and returns its own interrupted-batch result, exit 6.
//   blocked: inventory never returns (a call that does not observe the interrupt).
//   uncaught: inspect throws from a timer callback and its promise never settles.
import { pathToFileURL } from 'node:url';

const [bin, ...args] = process.argv.slice(2);
const dist = new URL('./', pathToFileURL(bin));
const { handlers } = await import(new URL('commands/handlers.js', dist).href);
const scenario = process.env.MACWARDEN_CLI_AUDIT_SCENARIO;
const stalled = () => process.send?.({ kind: 'stalled' });

if (scenario === 'respond-interrupted') {
  handlers.respond = () => new Promise(resolve => {
    process.once('SIGINT', () => {
      setTimeout(() => {}, 120_000);
      resolve({ schema: 1, command: 'respond', ok: true, exitCode: 6, error: null,
        warnings: [{ code: 'interrupted', message: 'interrupted: credentials marked not-run were not changed; rerun the same command to continue' }],
        result: { mode: 'stage', dryRun: false, node: { pubkey: `02${'ab'.repeat(32)}`, alias: 'n', network: 'regtest' },
          rootKey0: { present: true, ownOnRootKey0: false, guidance: [] }, own: { rootKeyId: '4294967296' },
          unknown: { rootKeyIds: [], guidance: '' }, revokedButPresent: { rootKeyIds: [], guidance: '' },
          bakingRisk: { rootKeyIds: [], guidance: [] }, outDir: null, items: [], unproven: [] } });
    });
    stalled();
  });
} else if (scenario === 'blocked') {
  handlers.inventory = () => new Promise(() => { setInterval(() => {}, 1_000); stalled(); });
} else if (scenario === 'uncaught') {
  handlers.inspect = () => new Promise(() => { setTimeout(() => { throw new Error('synthetic failure'); }, 10); });
} else throw new Error(`unknown scenario ${scenario}`);

// An IPC channel keeps the event loop alive, so the uncaught scenario runs without one.
if (process.send) process.on('message', message => { if (message?.kind === 'signal') process.emit(message.signal); });
process.argv = [process.argv[0], bin, ...args];
await import(pathToFileURL(bin).href);
