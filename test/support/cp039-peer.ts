import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { createLndAdapter } from '../../src/lnd/index.js';
import { Secret } from '../../src/secret.js';
import { repo, sentinel } from './cp039-audit.js';
import { scratchDirectory } from './cp039-scratch.js';

export async function localPeer() {
  const { dir, cleanup } = scratchDirectory('cp039-peer-');
  const key = join(dir, 'disposable-peer.pem'), cert = join(dir, 'disposable-peer.crt');
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-days', '1', '-config', config, '-keyout', key, '-out', cert, '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1'], { cwd: repo, encoding: 'utf8', timeout: 20_000 });
  if (result.status !== 0) throw new Error('Disposable local peer certificate generation failed');
  const ca = readFileSync(cert);
  const state = { status: 200, body: '{}', seen: [] as string[] };
  const server = createServer({ key: readFileSync(key), cert: ca }, (request, response) => {
    // Never retain headers or request bodies: they can contain the registered credential.
    request.resume();
    request.on('end', () => {
      state.seen.push(request.url ?? '');
      response.writeHead(state.status, { 'content-type': 'application/json' }); response.end(state.body);
    });
  });
  await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
  const restUrl = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { state, restUrl, ca, cert, adapter: () => createLndAdapter({ restUrl, tlsCert: ca, macaroon: new Secret(sentinel()) }),
    async close() {
      server.closeAllConnections(); await new Promise<void>(done => server.close(() => done()));
      cleanup();
    } };
}
