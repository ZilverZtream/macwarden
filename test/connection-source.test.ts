import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { connectionSettings } from '../src/online.js';
import { captureMain } from './support/capture.js';
import { declare, register, scratch, vector } from './support/cp039-audit.js';

// RO-4: node address, TLS certificate and credential come from one source. A credential
// exported for node A (MACWARDEN_MACAROON) must never be presented to a node named by flags.
const names = ['MACWARDEN_LND_REST', 'MACWARDEN_TLS_CERT', 'MACWARDEN_MACAROON', 'MACWARDEN_LND_GRPC'] as const;
const original = Object.fromEntries(names.map(name => [name, process.env[name]]));
afterEach(() => {
  for (const name of names) if (original[name] === undefined) delete process.env[name]; else process.env[name] = original[name];
});

it('RO-4/connection-source environment-only and flag-only settings are accepted; any mix is refused naming the variables', () => {
  const env = { MACWARDEN_LND_REST: 'a:1', MACWARDEN_TLS_CERT: 'a.cert', MACWARDEN_MACAROON: 'a.macaroon' };
  const none = (): string | undefined => undefined;
  expect(connectionSettings(none, env)).toEqual({ host: 'a:1', cert: 'a.cert', own: 'a.macaroon', problem: null });
  const all = (flag: string) => ({ '--lnd-rest': 'b:2', '--tls-cert': 'b.cert', '--macaroon': 'b.macaroon' } as Record<string, string>)[flag];
  expect(connectionSettings(all, env)).toEqual({ host: 'b:2', cert: 'b.cert', own: 'b.macaroon', problem: null });
  const restOnly = (flag: string) => flag === '--lnd-rest' ? 'b:2' : undefined;
  const mixed = connectionSettings(restOnly, env);
  expect(mixed.problem).toMatch(/^--lnd-rest given on the command line, so MACWARDEN_TLS_CERT, MACWARDEN_MACAROON from the environment is not used/);
  // The environment's values are never returned in a mixed invocation, and never named.
  expect(mixed.own).toBeUndefined();
  expect(mixed.problem).not.toMatch(/a\.macaroon|a\.cert|a:1/);
  // A flag with no environment counterpart set stays an ordinary missing-flag case.
  expect(connectionSettings(restOnly, {})).toMatchObject({ host: 'b:2', cert: undefined, own: undefined, problem: null });
  expect(connectionSettings(restOnly, { MACWARDEN_MACAROON: '' }).problem).toBeNull();
  const ownOnly = (flag: string) => flag === '--macaroon' ? 'b.macaroon' : undefined;
  expect(connectionSettings(ownOnly, env).problem).toMatch(/MACWARDEN_LND_REST, MACWARDEN_TLS_CERT/);
  // watch: the gRPC address joins the set.
  const grpcOnly = (flag: string) => flag === '--lnd-grpc' ? 'b:10009' : undefined;
  expect(connectionSettings(grpcOnly, env, true).problem).toMatch(/^--lnd-grpc given/);
  expect(connectionSettings(all, { ...env, MACWARDEN_LND_GRPC: 'a:10009' }, true).problem).toMatch(/MACWARDEN_LND_GRPC/);
  expect(connectionSettings(none, { ...env, MACWARDEN_LND_GRPC: 'a:10009' }, true)).toMatchObject({ grpc: 'a:10009', problem: null });
});

it('RO-4/connection-source no online command presents an environment credential to a node chosen by flags', async () => scratch(async dir => {
  const cert = join(dir, 'peer.crt'), key = join(dir, 'peer.key'), config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', config,
    '-keyout', key, '-out', cert, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { timeout: 20_000 });
  if (made.status !== 0) throw new Error('Disposable HTTPS peer generation failed');
  // "Node A"'s credential, exported in the shell. Only its fingerprint is ever compared.
  const nodeA = register(vector('default-admin').bytes);
  const fingerprint = (value: string) => createHash('sha256').update(value).digest('hex');
  const presented: string[] = [];
  let connections = 0;
  const server = createServer({ cert: readFileSync(cert), key: readFileSync(key) }, (request, response) => {
    const header = request.headers['grpc-metadata-macaroon'];
    if (typeof header === 'string') presented.push(fingerprint(header));
    response.writeHead(503, { 'content-type': 'application/json' }); response.end('{}');
  });
  server.on('connection', () => { connections++; });
  await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
  const nodeB = `127.0.0.1:${(server.address() as AddressInfo).port}`;
  const out = join(dir, 'issued.macaroon'); declare(out);
  const registry = join(dir, 'registry.json');
  const commands: string[][] = [
    ['inventory'], ['bake', '--label', 'Alice', '--preset', 'invoice-only', '--out', out], ['rotate', 'Alice', '--out', out],
    ['revoke', 'Alice'], ['verify', nodeA], ['recommend', 'Alice'], ['respond', '--dry-run'], ['watch', '--until', '1m'],
  ];
  try {
    for (const command of commands) {
      // Flags name node B; the credential would come from the environment.
      for (const name of names) delete process.env[name];
      process.env.MACWARDEN_MACAROON = nodeA;
      const flagged = await captureMain(main, [...command, '--registry', registry, '--json', '--lnd-rest', nodeB, '--tls-cert', cert]);
      expect(flagged.code, command[0]).toBe(2);
      // watch writes its envelope through its own bounded event writer, not process.stdout.
      if (command[0] !== 'watch') {
        const document = JSON.parse(flagged.stdout) as { error: { code: number; message: string } };
        expect(document.error.message, command[0]).toMatch(/MACWARDEN_MACAROON from the environment is not used/);
      }
      expect(flagged.stdout + flagged.stderr).not.toContain(nodeA.replaceAll('\\', '\\\\'));
      // The reverse: the environment names node B, the credential is a flag.
      for (const name of names) delete process.env[name];
      process.env.MACWARDEN_LND_REST = nodeB; process.env.MACWARDEN_TLS_CERT = cert;
      const reverse = await captureMain(main, [...command, '--registry', registry, '--json', '--macaroon', nodeA]);
      expect(reverse.code, command[0]).toBe(2);
      if (command[0] !== 'watch') expect((JSON.parse(reverse.stdout) as { error: { message: string } }).error.message, command[0])
        .toMatch(/MACWARDEN_LND_REST, MACWARDEN_TLS_CERT from the environment is not used/);
    }
    // watch: a gRPC address from the environment never joins a flag-named node.
    for (const name of names) delete process.env[name];
    process.env.MACWARDEN_LND_GRPC = '127.0.0.1:1';
    const grpc = await captureMain(main, ['watch', '--registry', registry, '--json', '--until', '1m',
      '--lnd-rest', nodeB, '--tls-cert', cert, '--macaroon', nodeA]);
    expect(grpc.code).toBe(2);
    expect(connections).toBe(0);
    expect(presented).toEqual([]);
    // Control: environment-only settings still reach the node they name.
    for (const name of names) delete process.env[name];
    process.env.MACWARDEN_LND_REST = nodeB; process.env.MACWARDEN_TLS_CERT = cert; process.env.MACWARDEN_MACAROON = nodeA;
    const fromEnv = await captureMain(main, ['inventory', '--registry', registry, '--json']);
    expect(fromEnv.code).not.toBe(2);
    expect(connections).toBeGreaterThan(0);
  } finally { await new Promise(done => server.close(done)); }
}), 30_000);
