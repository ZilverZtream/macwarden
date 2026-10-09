import * as fs from 'node:fs/promises';
import { openRegistry } from '../../dist/registry/index.js';
const path = process.argv[2];
const deps = { ...fs, open: async (...args) => {
  const handle = await fs.open(...args);
  if (String(args[0]) === path + '.lock.claim') {
    process.on('message', () => {});
    process.send({ kind: 'claim-created' });
    await new Promise(() => {});
  }
  return handle;
} };
try { const view = await openRegistry(path, { fs: deps }); await view.lock(); process.send({ kind: 'unexpected-acquisition' }); }
catch { process.send({ kind: 'failed' }); }
