// Shared driver for the WATCH/alert-shutdown real-child lifecycle tests (audit MW102-05).
// The POSIX variant (test/watch-alert-process.posix.test.ts) and the Windows variant
// (test/watch-alert-tree.windows.test.ts) run the real watch command with a scripted
// middleware session and a real alert child process: one canary use starts an alert
// command that ignores SIGTERM and never exits; a second use is folded into the window, so
// the shutdown flush makes a summary that would wait behind the running command. Then watch
// is stopped.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { withCancellation } from '../../src/cancellation.js';
import { run, type Deps, type Register } from '../../src/commands/watch.js';
import type { MiddlewareCall, MiddlewareEnd } from '../../src/lnd/index.js';
import { Secret } from '../../src/secret.js';

const PUBKEY = `02${'ab'.repeat(32)}`;
const CAVEAT = 'region-a1a2f213';
const CONDITION = '3a1e61423be44eaf';

/** Writes the registry (one canary), its canary configuration, a TLS file and the own macaroon. */
export function prepare(dir: string): string[] {
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [{ nodePubkey: PUBKEY, label: 'decoy', rootKeyId: '4294967342',
    permissions: ['info:read'], caveats: [{ type: 'lnd-custom', value: `${CAVEAT} ${CONDITION}` }], grade: 'READ',
    fingerprint: 'fp:0123456789abcdef', outPath: null, createdAt: '2026-10-01T00:00:00Z', verified: true, status: 'active',
    revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null }] }));
  writeFileSync(`${registry}.canary.json`, JSON.stringify({ schema: 1, caveatName: CAVEAT }));
  writeFileSync(join(dir, 'tls.cert'), 'not used by the scripted middleware');
  writeFileSync(join(dir, 'own.macaroon'), readFileSync(resolve('test/vectors/default-admin.macaroon')));
  return ['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'), '--macaroon', join(dir, 'own.macaroon'),
    '--registry', registry];
}

/** Lines appended by the alert child: one per started alert command. */
export const startedPids = (file: string): number[] =>
  existsSync(file) ? readFileSync(file, 'utf8').split(/\s+/).filter(Boolean).map(Number) : [];

export async function stopDuringAlert(args: string[], startsFile: string, deps: Partial<Deps> = {}) {
  const decide: ((call: MiddlewareCall) => string)[] = [];
  let registered!: () => void;
  const ready = new Promise<void>(done => { registered = done; });
  const register = ((_target, _registration, decision, onRegistered) => {
    decide.push(decision);
    let settle!: (value: MiddlewareEnd) => void;
    const ended = new Promise<MiddlewareEnd>(done => { settle = done; });
    queueMicrotask(() => { onRegistered(); if (decide.length === 2) registered(); });
    return { ended, close: () => settle({ registered: true, code: 4, stage: 'middleware-stream', message: 'closed', disabled: false }) };
  }) as Register;
  const lines: string[] = [];
  const controller = new AbortController();
  const result = withCancellation(controller.signal, () => run(args, {
    lnd: { getInfo: async () => ({ pubkey: PUBKEY, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }) } as never,
    register, fs, env: {}, clock: () => new Date(), emit: line => { lines.push(line); }, hostname: () => hostname(), pid: process.pid,
    ...deps,
  }));
  await ready;
  const macaroon = readFileSync(resolve('test/vectors/preset-read-only.macaroon'));
  const use = (n: number) => decide[1]({ kind: 'request', requestId: BigInt(n), method: '/lnrpc.Lightning/GetInfo', isError: false,
    customCaveatCondition: CONDITION, macaroon: new Secret(macaroon) });
  use(1);
  // The first alert command is running once it has recorded itself.
  for (let i = 0; i < 200 && startedPids(startsFile).length === 0; i++) await new Promise(done => setTimeout(done, 25));
  use(2);
  await new Promise(done => setTimeout(done, 50));
  const stoppedAt = performance.now();
  controller.abort();
  const output = await result;
  return { result: output, lines, elapsed: Math.round(performance.now() - stoppedAt) };
}
