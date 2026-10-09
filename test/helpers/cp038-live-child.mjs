import { readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { Secret } from '../../src/secret.js';
import { createLndAdapter } from '../../src/lnd/index.js';
import { handlers } from '../../src/commands/handlers.js';
import { run } from '../../src/commands/rotate.js';
import { main } from '../../src/cli.js';
const flags = process.argv.slice(3);
const value = name => flags[flags.indexOf(name) + 1];
const lnd = createLndAdapter({ restUrl: 'https://' + value('--lnd-rest'), tlsCert: readFileSync(value('--tls-cert')),
  macaroon: new Secret(readFileSync(value('--macaroon'))) });
const realBake = lnd.bakeMacaroon.bind(lnd), realCheck = lnd.checkMacaroon.bind(lnd);
let continueBake, baked = false;
process.on('message', message => {
  if (message?.kind === 'continue') continueBake?.();
  if (message?.kind === 'signal') process.emit(message.signal);
});
lnd.bakeMacaroon = async (permissions, id) => {
  const result = await realBake(permissions, id);
  const wait = new Promise(resolve => { continueBake = resolve; });
  baked = true;
  process.send?.({ kind: 'baked', id: String(id) });
  await wait; return result;
};
// Rotation stage also checks the old credential (S8) before baking; only the
// post-bake verification of the new credential is the faulted request.
lnd.checkMacaroon = (...args) => { if (baked) process.send?.({ kind: 'verify-request' }); return realCheck(...args); };
/** @type {import('../../src/commands/rotate.js').Deps} */
const deps = { lnd, fs, env: {}, clock: () => new Date() };
handlers.rotate = args => run(args, deps);
process.exitCode = await main(['rotate', 'Alice', '--out', process.argv[2], ...flags, '--json']);
process.disconnect?.();
