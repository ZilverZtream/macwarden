// Disposable regtest Core Lightning node for the rune comparison tests (1.2.0).
//
//   node test/fixture/cln-fixture.mjs up      start bitcoind and lightningd, wait until getinfo answers
//   node test/fixture/cln-fixture.mjs down    stop the node and remove its containers and volumes
//   node test/fixture/cln-fixture.mjs status  print the node's version and network
//
// The image is pinned by digest (test/fixture/cln-compose.yml). `up` refuses any node that is not
// Core Lightning v26.06.8 on regtest and brings it down again. No port is published: commands run
// inside the container with `docker compose exec`, so the fixture cannot reach or be reached from
// a real node, and it never collides with the LND fixture shards. Every rune it creates is
// disposable and has authority only on this node.
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const CLN_VERSION = 'v26.06.8';
export const PROJECT = 'macwarden-cln-fixture';
const compose = join(dirname(fileURLToPath(import.meta.url)), 'cln-compose.yml');
const STARTUP_LIMIT_MS = 180_000;

function docker(args, input) {
  return spawnSync('docker', ['compose', '-f', compose, '-p', PROJECT, ...args],
    { encoding: 'utf8', input, timeout: 120_000, maxBuffer: 64 * 1024 * 1024 });
}

/**
 * Runs `lightning-cli -k <method> key=value…` on the fixture node. Arguments are passed as an
 * array (no shell). Returns the parsed JSON result, or { error } with Core Lightning's error object.
 */
export function cli(method, params = {}) {
  const args = Object.entries(params).map(([key, value]) => `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}`);
  const run = docker(['exec', '-T', 'lightningd', 'lightning-cli', '--network=regtest', '-J', '-k', method, ...args]);
  if (run.error) throw run.error;
  const text = (run.stdout ?? '').trim();
  let parsed;
  try { parsed = JSON.parse(text); }
  catch { return { error: { message: `${text}\n${run.stderr ?? ''}`.trim(), code: null } }; }
  return run.status === 0 ? parsed : { error: parsed };
}

/** The fixture's identity, or null when it does not answer. */
export function status() {
  const info = cli('getinfo');
  if (info.error) return null;
  return { version: info.version, network: info.network };
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function up() {
  const started = docker(['up', '-d']);
  if (started.status !== 0) throw new Error(`docker compose up failed: ${started.stderr}`);
  const deadline = Date.now() + STARTUP_LIMIT_MS;
  for (;;) {
    const identity = status();
    if (identity) {
      if (identity.version !== CLN_VERSION || identity.network !== 'regtest') {
        down();
        throw new Error(`refusing fixture: expected Core Lightning ${CLN_VERSION} on regtest, got ${identity.version} on ${identity.network}`);
      }
      return identity;
    }
    if (Date.now() > deadline) throw new Error('Core Lightning fixture did not answer getinfo in time');
    sleep(1000);
  }
}

export function down() {
  const stopped = docker(['down', '-v', '--remove-orphans']);
  if (stopped.status !== 0) throw new Error(`docker compose down failed: ${stopped.stderr}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const command = process.argv[2];
  if (command === 'up') process.stdout.write(`${JSON.stringify(up())}\n`);
  else if (command === 'down') down();
  else if (command === 'status') process.stdout.write(`${JSON.stringify(status())}\n`);
  else { process.stderr.write('usage: node test/fixture/cln-fixture.mjs up|down|status\n'); process.exitCode = 2; }
}
