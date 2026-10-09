import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { LndError } from '../src/errors.js';
import { createLndAdapter } from '../src/lnd/index.js';
import { redactKnownSecrets } from '../src/scan/redact.js';
import { Secret } from '../src/secret.js';

// A known NWC secret whose bytes are not valid UTF-8 (0xff), so only the latin1 form
// can represent the raw bytes as text.
const secretHex = 'ff' + '41'.repeat(30) + '80';
const secret = Buffer.from(secretHex, 'hex');
const secrets = new Set([secretHex]);

it('KNOWN-SECRET/latin1 the raw bytes of a known secret rendered as latin1 text are redacted', () => {
  expect(Buffer.from(secret.toString('utf8'), 'utf8').equals(secret)).toBe(false);
  expect(redactKnownSecrets(`before ${secret.toString('latin1')} after`, secrets)).toBe('before [redacted] after');
});

it('KNOWN-SECRET/wrapped base64 of a known secret wrapped by LF or CRLF line breaks is redacted', () => {
  for (const form of [secret.toString('base64'), secret.toString('base64url')]) {
    for (const newline of ['\n', '\r\n']) {
      const wrapped = form.match(/.{1,20}/g)!.join(newline);
      expect(wrapped).toContain(newline);
      expect(redactKnownSecrets(`key: ${wrapped} end`, secrets)).toBe('key: [redacted] end');
    }
  }
  // Two line breaks are not line wrapping; the text is left as it is.
  const loose = secret.toString('base64').match(/.{1,20}/g)!.join('\n\n');
  expect(redactKnownSecrets(loose, secrets)).toBe(loose);
});

// A real local HTTPS peer answering ListMacaroonIDs with a valid but oversized body.
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');
function cert(dir: string) {
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const key = join(dir, 'local.key'), crt = join(dir, 'local.crt');
  const run = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-config', config, '-keyout', key, '-out', crt, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
  { encoding: 'utf8', timeout: 20_000 });
  if (run.status !== 0) throw new Error('Local HTTPS certificate generation failed');
  return { key: readFileSync(key), ca: readFileSync(crt) };
}

it('LND-ADAPTER/response-cap a response larger than 1 MiB is refused instead of parsed', async () => {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'response-cap-'));
  const { key, ca } = cert(dir);
  // About 1.3 MiB of well-formed JSON: without the cap this would parse into 100,000 IDs.
  const ids = Array.from({ length: 100_000 }, (_, index) => String(4_294_967_296 + index));
  const body = JSON.stringify({ root_key_ids: ids });
  expect(body.length).toBeGreaterThan(1_048_576);
  const server: Server = createServer({ key, cert: ca }, (request, response) => {
    request.resume();
    request.on('end', () => { response.writeHead(200, { 'content-type': 'application/json' }); response.end(body); });
  });
  try {
    await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
    const url = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const own = new Secret(readFileSync(join(resolve(), 'test/sentinels/sentinel.macaroon')));
    let error: unknown;
    try { await createLndAdapter({ restUrl: url, tlsCert: ca, macaroon: own }).listMacaroonIds(); }
    catch (caught) { error = caught; }
    expect(error).toBeInstanceOf(LndError);
    expect(error).toMatchObject({ code: 5, message: 'LND response too large' });
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    rmSync(dir, { recursive: true, force: true });
  }
}, 30_000);
