import { spawn, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { childEnvironment } from '../helpers/environment.js';
import { repo, scratchDirectory } from './cp041-controls.js';
export const pubkey = '02' + 'ab'.repeat(32);
export async function peer() {
  const owned = scratchDirectory('cp041-peer-'), key = join(owned.dir, 'disposable.pem'), cert = join(owned.dir, 'disposable.crt');
  const config = join(owned.dir, 'openssl.cnf'); writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-config', config, '-keyout', key, '-out', cert, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
    { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 20_000 });
  if (made.status !== 0) throw new Error('Disposable local regtest peer certificate unavailable');
  const state = { echo: 'ordinary-node', failure: false, calls: [] as string[] };
  const server = createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (request, response) => {
    request.resume(); request.on('end', () => {
      const path = request.url ?? ''; state.calls.push(path);
      let body: unknown;
      if (path === '/v1/getinfo') body = state.failure ? { message: `safe-left ${state.echo} safe-right` } : {
        identity_pubkey: pubkey, alias: state.echo, version: '0.21.4-beta', chains: [{ chain: 'bitcoin', network: 'regtest' }] };
      else if (path === '/v1/macaroon/permissions') body = { method_permissions: {} };
      else if (path === '/v1/macaroon/ids') body = { root_key_ids: ['0'] };
      else body = { message: 'Unexpected read-only endpoint' };
      response.writeHead(path === '/v1/getinfo' && state.failure ? 500 : 200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    });
  });
  await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
  return { state, async inventory(mode: 'text' | 'json') {
    state.calls = [];
    const endpoint = `127.0.0.1:${(server.address() as AddressInfo).port}`;
    return new Promise<{ code: number | null; stdout: string; stderr: string }>((done, fail) => {
      const child = spawn(process.execPath, [join(repo, 'dist/bin.js'), 'inventory', '--lnd-rest', endpoint,
        '--tls-cert', cert, '--macaroon', join(repo, 'test/vectors/default-admin.macaroon'), '--registry', join(owned.dir, 'missing-registry.json'),
        ...(mode === 'json' ? ['--json'] : [])], { cwd: repo, env: childEnvironment(), windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '', stderr = ''; const timer = setTimeout(() => child.kill(), 10_000);
      child.stdout.on('data', b => { stdout += String(b); }); child.stderr.on('data', b => { stderr += String(b); });
      child.once('error', () => { clearTimeout(timer); fail(new Error('Built inventory child failed')); });
      child.once('exit', code => { clearTimeout(timer); done({ code, stdout, stderr }); });
    });
  }, async close() {
    server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); owned.cleanup();
  } };
}
