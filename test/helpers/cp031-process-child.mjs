import { resolve } from 'node:path';
import { writeFileSync } from 'node:fs';
import { fixture, pubkey } from './cp025-bake-support.mjs';
import { Secret } from '../../src/secret.js';
import { handlers } from '../../src/commands/handlers.js';
import { main } from '../../src/cli.js';

const [, , dir, mode] = process.argv;
const marker = 'credential-safe-process-event-marker';
const f = fixture(resolve(dir), Secret);
writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [] }));
// Inject Deps through the existing command-map boundary, as cli-internal.test.ts does.
// main owns the active handler and its process-event/result lifecycle throughout the call.
if (mode === 'read-only') {
  f.lnd.getInfo = async () => {
    process.emit('uncaughtException', new Error(marker));
    return { alias: 'fixture', version: '0.21.4-beta', pubkey: pubkey, network: 'regtest' };
  };
  const command = await import('../../src/commands/inventory.js');
  handlers.inventory = args => command.run(args, f.deps);
  process.exitCode = await main(['inventory', ...f.args.slice(f.args.indexOf('--registry')), '--json']);
} else {
  const bake = f.lnd.bakeMacaroon;
  f.lnd.bakeMacaroon = async (...args) => {
    const result = await bake(...args);
    process.emit('uncaughtException', new Error(marker));
    return result;
  };
  const command = await import('../../src/commands/bake/index.js');
  handlers.bake = args => command.run(args, f.deps);
  process.exitCode = await main(['bake', ...f.args, '--json']);
}
