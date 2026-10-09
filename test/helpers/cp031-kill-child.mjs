import { fixtureTopology } from '../fixture/topology.mjs';
import { readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { Secret } from '../../dist/secret.js';
import { createLndAdapter } from '../../dist/lnd/index.js';
import { run } from '../../dist/commands/rotate.js';

const [, , registry, cert, own, point] = process.argv;
const adapter = createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: readFileSync(cert),
  macaroon: new Secret(readFileSync(own)) });
let deleted = false, release;
process.on('message', message => { if (message === 'continue') release?.(); });
const lnd = new Proxy(adapter, { get(target, key) {
  const value = Reflect.get(target, key, target);
  if (key === 'listMacaroonIds' && typeof value !== 'function') return async () => ({ root_key_ids: (await lnd.listMacaroonIds()).map(String) });
  if (typeof value !== 'function') return value;
  return async (...args) => {
    if ((point === 'before delete' && key === 'deleteMacaroonId') ||
        (point === 'after delete' && deleted && key === 'listMacaroonIds')) {
      await new Promise(resolve => { release = resolve; process.send({ kind: 'holding' }); });
      process.send({ kind: 'blocked-call' });
    }
    const result = await value.apply(target, args);
    if (key === 'deleteMacaroonId') deleted = true;
    return result;
  };
} });
try {
  const result = await run(['Alice', '--finish', '--yes', '--registry', registry,
    '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', cert, '--macaroon', own],
  { lnd, fs: { ...fs }, env: {}, clock: () => new Date() });
  process.send({ kind: 'returned', code: result.error?.code ?? 0 });
  process.exitCode = result.error?.code ?? 0;
} catch {
  process.send({ kind: 'harness-error' }); process.exitCode = 99;
} finally { process.disconnect(); }
