import { fixtureTopology } from './topology.mjs';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request } from 'node:https';
import { spawnSync } from 'node:child_process';

export async function observeEmptyBake() {
  const infoCall = spawnSync('docker', [...fixtureTopology().composeArgs, 'exec', '-T', 'lnd', 'lncli', '--network=regtest', 'getinfo'], { encoding: 'utf8', timeout: 30_000 });
  if (infoCall.status !== 0) throw new Error('Fixture getinfo failed before empty bake probe');
  const info = JSON.parse(infoCall.stdout);
  if (info.chains?.[0]?.network !== 'regtest' || !info.version?.startsWith('0.21.4-beta')) throw new Error('FixtureInvalidError: expected LND 0.21.4-beta on regtest');
  const fixture = join(tmpdir(), 'macwarden-fixture');
  const cert = readFileSync(join(fixture, 'tls.cert'));
  const credential = readFileSync(join(fixture, 'admin.macaroon'));
  const body = Buffer.from(JSON.stringify({ permissions: [], root_key_id: '4294967297' }));
  return await new Promise((resolve, reject) => {
    const req = request({ hostname: 'localhost', port: fixtureTopology().restPort, path: '/v1/macaroon', method: 'POST', ca: cert,
      headers: { 'Grpc-Metadata-macaroon': credential.toString('hex'), 'Content-Type': 'application/json', 'Content-Length': body.length } }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolve({ status: response.statusCode, message: parsed.message || null, code: parsed.code || null });
        } catch { reject(new Error('Invalid empty bake REST response')); }
      });
    });
    req.on('error', reject); req.end(body);
  });
}

if (process.argv[1]?.endsWith('observe-empty.mjs')) {
  try { process.stdout.write(JSON.stringify(await observeEmptyBake()) + '\n'); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
