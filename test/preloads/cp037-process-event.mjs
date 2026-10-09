import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const target = resolve(process.env.MACWARDEN_CP037_INPUT);
const trace = process.env.MACWARDEN_CP037_TRACE;
const mode = process.env.MACWARDEN_CP037_EVENT;
const marker = process.env.MACWARDEN_CP037_MARKER;
let injected = false;

function pathOf(value) {
  return value instanceof URL ? fileURLToPath(value) : String(value);
}

function isTarget(path) {
  return path instanceof URL || typeof path === 'string' ? resolve(pathOf(path)) === target : false;
}

async function inject(method) {
  injected = true;
  fs.writeFileSync(trace, `${method}\n`);
  if (mode === 'exception') setImmediate(() => { throw new Error(marker); });
  else if (mode === 'rejection') setImmediate(() => { void Promise.reject(new Error(marker)); });
  else if (mode === 'warning') setImmediate(() => { process.emitWarning(new Error(marker)); });
  else throw new Error('unknown CP-037 event');
  await new Promise(done => setTimeout(done, 80));
}

for (const method of ['readFile', 'open']) {
  const original = fsPromises[method];
  fsPromises[method] = async function readWithProcessEvent(path, ...options) {
    if (!injected && isTarget(path)) await inject(`fs/promises.${method}`);
    return original.call(this, path, ...options);
  };
}

syncBuiltinESMExports();
