import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { createLndAdapter } from '../src/lnd/index.js';
import { identityCheck } from '../src/lnd/tls-identity.js';
import { endpoint } from '../src/online.js';
import { Secret } from '../src/secret.js';

// MW102-08: a literal IPv6 REST endpoint (--lnd-rest '[::1]:<port>') reaches a real local
// HTTPS server whose certificate names IP:::1, with TLS verification enabled throughout.
// The URL keeps its brackets; the transport host and TLS identity check use the bare address.
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');

it('LND/ipv6 a bracketed IPv6 REST endpoint verifies an IP:::1 certificate and reaches the node', async () => {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'ipv6-rest-'));
  const cert = join(dir, 'peer.crt'), key = join(dir, 'peer.key'), config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-config', config, '-keyout', key, '-out', cert, '-subj', '/CN=ipv6-peer', '-addext', 'subjectAltName=IP:::1'], { timeout: 20_000 });
  expect(made.status, 'disposable certificate generation').toBe(0);
  const ca = readFileSync(cert);
  const seen: string[] = [];
  const server = createServer({ cert: ca, key: readFileSync(key) }, (incoming, response) => {
    seen.push(`${incoming.method} ${incoming.url}`);
    incoming.resume();
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ identity_pubkey: `02${'11'.repeat(32)}`, alias: 'ipv6 peer', version: '0.21.4-beta',
      chains: [{ network: 'regtest' }] }));
  });
  await new Promise<void>((done, fail) => server.listen(0, '::1', done).once('error', fail));
  try {
    const port = (server.address() as AddressInfo).port;
    // Control: OpenSSL itself confirms the certificate names ::1 (Node 22's own
    // tls.checkServerIdentity refuses every IPv6 literal, so it cannot be the control).
    expect(new X509Certificate(ca).checkIP('::1')).toBe('::1');
    const url = endpoint(`[::1]:${port}`);
    expect(url).toBe(`https://[::1]:${port}/`);
    const macaroon = new Secret(readFileSync(join(resolve(), 'test/vectors/default-admin.macaroon')));
    const adapter = createLndAdapter({ restUrl: url!, tlsCert: ca, macaroon });
    const info = await adapter.getInfo();
    expect(info).toMatchObject({ pubkey: `02${'11'.repeat(32)}`, network: 'regtest' });
    expect(seen).toEqual(['GET /v1/getinfo']);
    // Verification is still on: a certificate for another address is refused before any request.
    const otherCert = join(dir, 'other.crt'), otherKey = join(dir, 'other.key');
    const other = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
      '-config', config, '-keyout', otherKey, '-out', otherCert, '-subj', '/CN=ipv6-other', '-addext', 'subjectAltName=IP:::2'], { timeout: 20_000 });
    expect(other.status).toBe(0);
    server.setSecureContext({ cert: readFileSync(otherCert), key: readFileSync(otherKey) });
    const refused = createLndAdapter({ restUrl: url!, tlsCert: readFileSync(otherCert), macaroon });
    await expect(refused.getInfo()).rejects.toMatchObject({ code: 4 });
    expect(seen).toHaveLength(1);
  } finally {
    await new Promise(done => server.close(done));
    rmSync(dir, { recursive: true, force: true });
  }
});

it('LND/ipv6 the IPv6 identity check accepts only a matching IP address SAN', () => {
  expect(identityCheck('example.test')).toEqual({});
  expect(identityCheck('127.0.0.1')).toEqual({});
  const check = identityCheck('[::1]').checkServerIdentity!;
  expect(identityCheck('::1').checkServerIdentity).toBeTypeOf('function');
  expect(check('::1', { subjectaltname: 'IP Address:0:0:0:0:0:0:0:1' })).toBeUndefined();
  expect(check('::1', { subjectaltname: 'DNS:localhost, IP Address:::1' })).toBeUndefined();
  for (const subjectaltname of [undefined, '', 'IP Address:::2', 'DNS:::1', 'IP Address:127.0.0.1',
    'DNS:"x, IP Address:::1"', 'IP Address:::1:0'])
    expect(check('::1', { subjectaltname }), String(subjectaltname)).toMatchObject({ code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
});
