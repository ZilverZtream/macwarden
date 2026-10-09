import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { LndError, LndUncertainError } from '../src/errors.js';
import { createLndAdapter } from '../src/lnd/index.js';
import { Secret } from '../src/secret.js';

// A real local HTTPS peer. "reset" closes the connection after the full request
// arrived, "stall" never answers: in both the request reached the peer, so the
// adapter must report the outcome as unknown, unlike a refused connection, a TLS
// failure or a definite HTTP error response.
type Behaviour = 'reset' | 'stall' | { status: number; body: unknown };
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');

function cert(dir: string, name: string, hostname: string) {
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const key = join(dir, `${name}.key`), crt = join(dir, `${name}.crt`);
  const run = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-config', config, '-keyout', key, '-out', crt, '-subj', `/CN=${hostname}`,
    '-addext', `subjectAltName=${hostname === '127.0.0.1' ? 'IP' : 'DNS'}:${hostname}`], { encoding: 'utf8', timeout: 20_000 });
  if (run.status !== 0) throw new Error('Local HTTPS certificate generation failed');
  return { key: readFileSync(key), ca: readFileSync(crt) };
}

async function withPeer(behaviour: Behaviour, work: (url: string, ca: Buffer, wrongCa: Buffer, seen: string[]) => Promise<void>) {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'uncertain-https-'));
  const good = cert(dir, 'local', '127.0.0.1'), wrong = cert(dir, 'other', 'other.invalid');
  const seen: string[] = [];
  const server: Server = createServer({ key: good.key, cert: good.ca }, (request, response) => {
    request.resume();
    request.on('end', () => {
      seen.push(`${request.method} ${request.url}`);
      if (behaviour === 'reset') request.socket.destroy();
      else if (behaviour !== 'stall') {
        response.writeHead(behaviour.status, { 'content-type': 'application/json' });
        response.end(JSON.stringify(behaviour.body));
      }
    });
  });
  try {
    await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
    await work(`https://127.0.0.1:${(server.address() as AddressInfo).port}`, good.ca, wrong.ca, seen);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    rmSync(dir, { recursive: true, force: true });
  }
}

const own = () => new Secret(readFileSync(join(resolve(), 'test/sentinels/sentinel.macaroon')));
async function caught(call: () => Promise<unknown>): Promise<Error> {
  try { await call(); } catch (error) { return error as Error; }
  throw new Error('expected a failure');
}

it('UNCERTAIN/adapter a connection reset after DeleteMacaroonID reached LND is an unknown outcome', async () => {
  await withPeer('reset', async (url, ca, _wrong, seen) => {
    const error = await caught(() => createLndAdapter({ restUrl: url, tlsCert: ca, macaroon: own() }).deleteMacaroonId(4294967301n));
    expect(seen).toEqual(['DELETE /v1/macaroon/4294967301']);
    expect(error).toBeInstanceOf(LndUncertainError);
    expect((error as LndError).code).toBe(4);
  });
});

it('UNCERTAIN/adapter a BakeMacaroon request that times out after reaching LND is an unknown outcome', async () => {
  await withPeer('stall', async (url, ca, _wrong, seen) => {
    const started = performance.now();
    const error = await caught(() => createLndAdapter({ restUrl: url, tlsCert: ca, macaroon: own() })
      .bakeMacaroon(['info:read'], 4294967302n));
    expect(performance.now() - started).toBeGreaterThanOrEqual(9_000);
    expect(seen).toEqual(['POST /v1/macaroon']);
    expect(error).toBeInstanceOf(LndUncertainError);
  });
}, 30_000);

it('UNCERTAIN/adapter a refused connection or failed TLS verification is a definite failure, not unknown', async () => {
  await withPeer('stall', async (url, ca, wrongCa, seen) => {
    const refused = await caught(() => createLndAdapter({ restUrl: url.replace(/:\d+$/, ':1'), tlsCert: ca, macaroon: own() })
      .deleteMacaroonId(4294967303n));
    expect(refused).toBeInstanceOf(LndError);
    expect(refused).not.toBeInstanceOf(LndUncertainError);
    const untrusted = await caught(() => createLndAdapter({ restUrl: url, tlsCert: wrongCa, macaroon: own() })
      .deleteMacaroonId(4294967303n));
    expect(untrusted).toBeInstanceOf(LndError);
    expect(untrusted).not.toBeInstanceOf(LndUncertainError);
    expect(seen).toEqual([]);
  });
});

it('UNCERTAIN/adapter an HTTP error response from LND is definite, not unknown', async () => {
  await withPeer({ status: 500, body: { code: 2, message: 'request rejected' } }, async (url, ca) => {
    const error = await caught(() => createLndAdapter({ restUrl: url, tlsCert: ca, macaroon: own() }).deleteMacaroonId(4294967304n));
    expect(error).toBeInstanceOf(LndError);
    expect(error).not.toBeInstanceOf(LndUncertainError);
    expect((error as LndError).code).toBe(5);
  });
});
