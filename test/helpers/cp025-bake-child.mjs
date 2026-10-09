import { fixtureTopology } from '../fixture/topology.mjs';
import { revealSecret } from '../../src/secret-capability.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fixture, register } from './cp025-bake-support.mjs';
import { Secret } from '../../src/secret.js';
import { run } from '../../src/commands/bake/index.js';
import { render } from '../../src/output/index.js';

const [, , dir, label, filename, mode = 'unit', cert, own] = process.argv;
const f = fixture(resolve(dir), Secret, label, filename);
let adapter = f.lnd;
if (mode === 'live') {
  const { createLndAdapter } = await import('../../src/lnd/index.js');
  adapter = createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: readFileSync(cert),
    macaroon: new Secret(readFileSync(own)) });
  f.args.splice(f.args.indexOf('--lnd-rest') + 1, 1, `localhost:${fixtureTopology().restPort}`);
  f.args.splice(f.args.indexOf('--tls-cert') + 1, 1, cert);
  f.args.splice(f.args.indexOf('--macaroon') + 1, 1, own);
}
// IPC holds the winner inside its first adapter call until the loser exits.
// No timing guess, production hook, or mock of the registry/lock boundary.
const messages = new Map();
const queued = new Set();
process.on('message', message => {
  const resolve = messages.get(message);
  if (resolve) { messages.delete(message); resolve(); } else queued.add(message);
});
function wait(message) {
  if (queued.delete(message)) return Promise.resolve();
  return new Promise(resolve => messages.set(message, resolve));
}
const calls = [];
f.deps.lnd = new Proxy(adapter, { get(target, key) {
  const value = Reflect.get(target, key, target);
  // Match the transport/normalized spellings used by the existing bake oracles.
  if (key === 'listMacaroonIds' && typeof value !== 'function') return async () => {
    calls.push(String(key));
    return ((await target.listMacaroonIds()).map(String)).map(BigInt);
  };
  if (typeof value !== 'function') return value;
  return async (...args) => {
    calls.push(String(key));
    if (key === 'getInfo') { process.send({ kind: 'holding' }); await wait('release'); }
    const result = await value.apply(target, args);
    if (key === 'bakeMacaroon') register(Buffer.from(revealSecret(result)));
    return result;
  };
} });
process.send({ kind: 'ready' });
await wait('go');
try {
  const result = await run([...f.args, '--json'], f.deps);
  process.stdout.write(render(result, 'json'));
  process.send({ kind: 'calls', calls });
  process.exitCode = result.error?.code ?? 0;
} catch {
  process.stderr.write('CP-025 child harness failed\n'); process.exitCode = 99;
} finally { process.disconnect(); }
