import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { createLndAdapter } from '../src/lnd/index.js';
import { Secret } from '../src/secret.js';
import { run as revoke } from '../src/commands/revoke.js';
import { run as rotate } from '../src/commands/rotate.js';
import { fixture, oldId, nextId, pubkey } from './helpers/cp038-online.js';
import { childEnvironment } from './helpers/environment.js';

const cases = (['revoke', 'finish'] as const).flatMap(mode =>
  (['transport', 'authentication', 'protocol'] as const).map(fault => [mode, fault] as const));
const backendCases = [['revoke', 'backend'], ['finish', 'backend'], ['revoke', 'malformed-error'], ['revoke', 'malformed-boolean']] as const;
it.each([...cases, ...backendCases])('CP-042/B7-post-mutation-and-cleanup-failure %s old baseline HTTPS %s error stops before mutation', async (mode, fault) => {
  const f = fixture(); if (mode === 'finish') f.save([f.old, f.next]);
  const before = readFileSync(f.registry), oldBytes = readFileSync(f.old.outPath!), nextBytes = readFileSync(f.next.outPath!);
  const config = join(f.dir, 'openssl.cnf'), cert = join(f.dir, 'local.crt'), key = join(f.dir, 'local.key');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-config', config, '-keyout', key, '-out', cert, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
    { env: childEnvironment(), encoding: 'utf8', timeout: 20_000 });
  expect(made.status, 'disposable HTTPS certificate generation').toBe(0);
  const state = { ids: ['0', String(oldId), String(nextId)], mutations: 0, faultObserved: false, laterRequests: 0, checks: 0 };
  const server = createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (request, response) => {
    request.resume(); request.on('end', () => {
      const path = request.url ?? ''; if (state.faultObserved) state.laterRequests++;
      let body: unknown;
      if (path === '/v1/getinfo') body = { identity_pubkey: pubkey, alias: 'local-regtest-peer', version: '0.21.4-beta', chains: [{ chain: 'bitcoin', network: 'regtest' }] };
      else if (path === '/v1/macaroon/permissions') body = { method_permissions: {} };
      else if (path === '/v1/macaroon/ids') body = { root_key_ids: state.ids };
      else if (path === '/v1/macaroon/checkpermissions') {
        state.checks++;
        if (state.checks === (mode === 'finish' ? 2 : 1)) {
          state.faultObserved = true;
          if (fault === 'transport') { request.socket.destroy(); return; }
          if (fault === 'authentication') { response.writeHead(401, { 'content-type': 'application/json' }); response.end(JSON.stringify({ message: 'authentication unavailable' })); return; }
          if (fault === 'backend') { response.writeHead(500, { 'content-type': 'application/json' }); response.end(JSON.stringify({ code: 13, message: 'backend unavailable' })); return; }
          if (fault === 'malformed-error') { response.writeHead(400, { 'content-type': 'application/json' }); response.end('{'); return; }
          if (fault === 'malformed-boolean') { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ valid: 'true' })); return; }
          response.writeHead(200, { 'content-type': 'application/json' }); response.end('{'); return;
        }
        body = { valid: true };
      } else if (request.method === 'DELETE') {
        state.mutations++; state.ids = state.ids.filter(id => path !== '/v1/macaroon/' + id); body = { deleted: true };
      } else { response.writeHead(500); response.end('{}'); return; }
      response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(body));
    });
  });
  await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
  try {
    const lnd = createLndAdapter({ restUrl: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, tlsCert: readFileSync(cert), macaroon: new Secret(readFileSync(f.own)) });
    const result = mode === 'revoke' ? await revoke(['Alice', '--yes', ...f.flags], { ...f.deps, lnd })
      : await rotate(['Alice', '--finish', '--yes', ...f.flags], { ...f.deps, lnd });
    expect(state.faultObserved).toBe(true); expect(state.mutations).toBe(0); expect(state.laterRequests).toBe(0);
    expect(result.error).toMatchObject({ code: fault === 'transport' || fault === 'authentication' ? 4 : 5, step: mode === 'revoke' ? 'V8' : 'F7' });
    expect(state.ids).toEqual(['0', String(oldId), String(nextId)]); expect(readFileSync(f.registry).equals(before)).toBe(true);
    expect(readFileSync(f.old.outPath!).equals(oldBytes)).toBe(true); expect(readFileSync(f.next.outPath!).equals(nextBytes)).toBe(true);
    expect(existsSync(f.registry + '.lock')).toBe(false);
  } finally { server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); }
}, 25_000);
