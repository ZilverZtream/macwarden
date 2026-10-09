import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { open, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { fixture, register, root, vector, type Fixture, type Entry } from './cp038-online.js';
import { fixtureCopies } from './fixture-copies.js';

export class FixtureInvalidError extends Error {
  constructor(message: string) { super(message); this.name = 'FixtureInvalidError'; }
}
const compose = fixtureTopology().composeArgs;
export function docker(args: string[]) {
  return spawnSync('docker', [...compose, ...args], { encoding: 'utf8', timeout: 20000, maxBuffer: 2_000_000 });
}
export function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.error || result.status !== 0) throw new FixtureInvalidError('Fixture lncli command unavailable');
  try { return JSON.parse(result.stdout) as Record<string, unknown>; }
  catch { throw new FixtureInvalidError('Fixture returned invalid JSON'); }
}
export function ids(): string[] {
  const value = lncli(['listmacaroonids']).root_key_ids;
  if (!Array.isArray(value)) throw new FixtureInvalidError('Fixture IDs unavailable');
  return value.map(String).sort();
}
function liveBake(id: string, permissions: string[]): string {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon', '--root_key_id=' + id, ...permissions]);
  if (result.error || result.status !== 0 || !/^(?:[0-9a-f]{2})+$/i.test(result.stdout.trim()))
    throw new FixtureInvalidError('Fixture bake unavailable');
  return register(Buffer.from(result.stdout.trim(), 'hex'));
}
export function probe(path: string): 'accepted' | 'rejected' {
  const remote = `/tmp/cp038-probe-${process.pid}.macaroon`;
  if (docker(['cp', path, 'lnd:' + remote]).status !== 0) throw new FixtureInvalidError('Fixture copy unavailable');
  try {
    const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', '--macaroonpath=' + remote, 'getinfo']);
    if (!result.error && result.status === 0) return 'accepted';
    if (result.status !== 0 && /root key with id [0-9]+ doesn't exist/.test(result.stderr)) return 'rejected';
    throw new FixtureInvalidError('Independent acceptance probe inconclusive');
  } finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
}
async function unlockedScenario(work: (f: Fixture) => Promise<void>): Promise<void> {
  if (process.env.MACWARDEN_CP038_FIXTURE_TURN !== 'exclusive')
    throw new FixtureInvalidError('CP-038 requires exclusive use of the regtest fixture');
  const copies = await fixtureCopies();
  const cert = join(copies, 'tls.cert');
  if (!existsSync(cert)) throw new FixtureInvalidError('Fixture certificate unavailable');
  const info = lncli(['getinfo']);
  const chains = info.chains as Array<{ network: string }> | undefined;
  if (chains?.[0]?.network !== 'regtest' || typeof info.version !== 'string' || !info.version.startsWith('0.21.4-beta'))
    throw new FixtureInvalidError('Fixture must be pinned LND on regtest');
  if (JSON.stringify(ids()) !== '["0"]') throw new FixtureInvalidError('Fixture has leftover root key IDs');
  const f = fixture();
  try {
    const own = liveBake('23038', vector('default-admin').permissions);
    f.flags[f.flags.indexOf('--macaroon') + 1] = own;
    f.flags[f.flags.indexOf('--tls-cert') + 1] = cert;
    f.flags[f.flags.indexOf('--lnd-rest') + 1] = `localhost:${fixtureTopology().restPort}`;
    for (const row of [f.old, f.next]) {
      row.outPath = liveBake(row.rootKeyId, row.permissions);
      row.fingerprint = 'fp:' + createHash('sha256').update(readFileSync(row.outPath)).digest('hex').slice(0, 16);
      row.nodePubkey = String(info.identity_pubkey);
    }
    f.save();
    await work(f);
  } finally { cleanupRootKeys(); }
}
function cleanupRootKeys(): void {
  docker(['unpause', 'lnd']);
  for (const id of ids().filter(id => id !== '0')) {
    if (lncli(['deletemacaroonid', id]).deleted !== true) throw new FixtureInvalidError('Fixture cleanup failed');
  }
  if (JSON.stringify(ids()) !== '["0"]') throw new FixtureInvalidError('Fixture cleanup left IDs');
}
// Vitest may schedule oracle files in different workers; the assigned fixture is
// shared, so each stateful scenario owns it from baseline validation through cleanup.
export async function scenario(work: (f: Fixture) => Promise<void>): Promise<void> {
  if (process.env.MACWARDEN_CP038_FIXTURE_TURN !== 'exclusive')
    throw new FixtureInvalidError('CP-038 requires exclusive use of the regtest fixture');
  const lock = join(root('MACWARDEN_TEST_TMP'), 'cp038-fixture-turn.lock');
  const deadline = Date.now() + 30000;
  let handle: Awaited<ReturnType<typeof open>>;
  for (;;) {
    try { handle = await open(lock, 'wx', 0o600); break; }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST' || Date.now() >= deadline)
        throw new FixtureInvalidError('Exclusive fixture scenario ownership unavailable');
      await new Promise(done => setTimeout(done, 100));
    }
  }
  try { await unlockedScenario(work); }
  finally { await handle.close(); await unlink(lock); }
}
export function writeEntries(f: Fixture, entries: Entry[]): void {
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
}
