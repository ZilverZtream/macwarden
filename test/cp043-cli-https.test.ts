import { spawn, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from './helpers/environment.js';
import { scratch, pubkey, register, vector, wireMacaroon, declare } from './support/cp039-audit.js';

type Document = { ok: boolean; error: { code: number; step: string } | null; result: { rootKeys?: Array<{ rootKeyId: string }> } | null };
async function peer(work: (f: { run: (args: string[], changes?: { host?: string; cert?: string }) => Promise<{ code: number | null; doc: Document }>;
  ids: string[]; seen: string[]; connections: () => number; status: { verify: number; auth: number }; out: string; registry: string; bakeTypes: string[] }) => Promise<void>, certificateHost = '127.0.0.1') {
  await scratch(async dir => {
    const cert = join(dir, 'peer.crt'), key = join(dir, 'peer.key'), config = join(dir, 'openssl.cnf');
    writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
    const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-config', config, '-keyout', key, '-out', cert, '-subj', `/CN=${certificateHost}`, '-addext', `subjectAltName=${certificateHost === '127.0.0.1' ? 'IP' : 'DNS'}:${certificateHost}`], { timeout: 20_000 });
    if (made.status !== 0) throw new Error('Disposable HTTPS peer generation failed');
    const ids = ['0', '9007199254740992', '9007199254740993', '18446744073709551615'];
    const seen: string[] = [], bakeTypes: string[] = [], status = { verify: 200, auth: 0 };
    const registry = join(dir, 'registry.json'), out = join(dir, 'issued.macaroon'); declare(out);
    const own = register(vector('default-admin').bytes);
    const server = createServer({ cert: readFileSync(cert), key: readFileSync(key) }, (request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', chunk => chunks.push(Buffer.from(chunk)));
      request.on('end', () => {
        const path = request.url ?? ''; seen.push(`${request.method} ${path}`);
        let body: unknown; let code = status.auth || 200;
        if (status.auth) body = { message: 'permission denied' };
        else if (path === '/v1/getinfo') body = { identity_pubkey: pubkey, alias: 'controlled HTTPS peer', version: '0.21.4-beta', chains: [{ network: 'regtest' }] };
        else if (path === '/v1/macaroon/ids') body = { root_key_ids: [...ids] };
        else if (path === '/v1/macaroon/permissions') body = { method_permissions: { '/lnrpc.Lightning/AddInvoice': { permissions: [{ entity: 'invoices', action: 'write' }] }, '/lnrpc.Lightning/ListInvoices': { permissions: [{ entity: 'invoices', action: 'read' }] } } };
        else if (request.method === 'DELETE') {
          const id = path.slice('/v1/macaroon/'.length), index = ids.indexOf(id);
          if (index >= 0) ids.splice(index, 1); body = { deleted: index >= 0 };
        } else if (path === '/v1/macaroon/checkpermissions') {
          code = status.verify; body = code === 200 ? { valid: true } : { message: code === 400 ? 'signature mismatch' : 'unknown verification error' };
        } else if (path === '/v1/macaroon') {
          const input = JSON.parse(Buffer.concat(chunks).toString()) as { root_key_id: string; permissions: Array<{ entity: string; action: string }> };
          bakeTypes.push(typeof input.root_key_id); ids.push(String(input.root_key_id));
          const bytes = wireMacaroon(input.permissions.map(p => `${p.entity}:${p.action}`), BigInt(input.root_key_id)); register(bytes);
          body = { macaroon: bytes.toString('hex') };
        } else { code = 404; body = { message: 'unexpected endpoint' }; }
        response.writeHead(code, { 'content-type': 'application/json' }); response.end(JSON.stringify(body));
      });
    });
    let connections = 0; server.on('connection', () => { connections++; });
    // Bind the same loopback address used by the hostname mismatch control:
    // connection refusal must not substitute for a real TLS rejection.
    await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
    const port = (server.address() as AddressInfo).port;
    async function run(args: string[], changes: { host?: string; cert?: string } = {}) {
      const child = spawn(process.execPath, [resolve('dist/bin.js'), ...args, '--json', '--registry', registry,
        '--lnd-rest', `${changes.host ?? '127.0.0.1'}:${port}`, '--tls-cert', changes.cert ?? cert, '--macaroon', own], { env: childEnvironment() });
      let output = ''; child.stdout.on('data', chunk => { output += String(chunk); }); child.stderr.resume();
      const timer = setTimeout(() => child.kill(), 15_000);
      const code = await new Promise<number | null>((done, fail) => { child.once('error', fail); child.once('close', done); }); clearTimeout(timer);
      return { code, doc: JSON.parse(output) as Document };
    }
    try { await work({ run, ids, seen, connections: () => connections, status, out, registry, bakeTypes }); }
    finally { server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); }
  });
}
it('CP-043/B1-built-cli-real-adapter inventory preserves distinct uint64 IDs and DELETE changes independent HTTPS peer state', async () => peer(async f => {
  const inventory = await f.run(['inventory']); expect(inventory.code).toBe(0);
  expect(inventory.doc.result?.rootKeys?.map(row => row.rootKeyId)).toEqual(f.ids);
  const id = '18446744073709551615'; const result = await f.run(['revoke', id, '--yes', '--unregistered']);
  expect(result.code).toBe(0); expect(f.ids).not.toContain(id);
  expect(f.seen).toContain(`DELETE /v1/macaroon/${id}`);
}), 30_000);
it.each([200, 400, 502])('CP-043/B1-built-cli-real-adapter built bake verification HTTP %s controls final registry outcome and string root_key_id', async verify => peer(async f => {
  f.status.verify = verify;
  const result = await f.run(['bake', '--label', 'Alice', '--preset', 'invoice-only', '--out', f.out]);
  expect(result.code).toBe(verify === 200 ? 0 : 7);
  expect(f.bakeTypes).toEqual(['string']);
  const entries = (JSON.parse(readFileSync(f.registry, 'utf8')) as { entries: Array<{ verified: boolean }> }).entries;
  expect(entries.some(row => row.verified)).toBe(verify === 200);
}), 30_000);
it.each([401, 403, 500])('CP-043/B1-built-cli-real-adapter own credential HTTP %s exits four without deletion', async auth => peer(async f => {
  f.status.auth = auth; const before = [...f.ids];
  const result = await f.run(['revoke', '9007199254740993', '--yes']); expect(result.code).toBe(4);
  expect(f.ids).toEqual(before); expect(f.seen.some(path => path.startsWith('DELETE'))).toBe(false);
}), 30_000);
it.each(['wrong CA', 'wrong hostname'])('CP-043/B1-built-cli-real-adapter %s exits four before mutation through actual TLS', async kind => peer(async f => {
  const result = await f.run(['revoke', '9007199254740993', '--yes'], kind === 'wrong CA'
    ? { cert: resolve('test/fixture/wrong-tls.cert') } : { host: '127.0.0.1' });
  expect(result.code).toBe(4); expect(f.seen).toEqual([]); expect(f.ids).toContain('9007199254740993');
  expect(f.connections()).toBeGreaterThan(0);
}, kind === 'wrong hostname' ? 'localhost' : '127.0.0.1'), 30_000);

