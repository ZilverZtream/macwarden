import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { request } from 'node:https';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { createLndAdapter } from '../../src/lnd/index.js';
import { Secret } from '../../src/secret.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { declare, register, repo, scratch } from '../support/cp039-audit.js';

const compose = fixtureTopology().composeArgs;
function docker(args: string[]) {
  if (process.env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE !== '1')
    throw new FixtureInvalidError('CP-039 requires exclusive use of the regtest fixture (set MACWARDEN_CP039_FIXTURE_EXCLUSIVE=1)');
  return spawnSync('docker', [...compose, ...args], { cwd: repo, encoding: 'utf8', timeout: 30_000, maxBuffer: 1_000_000 });
}
function lncliRaw(args: string[]): string {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.error || result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  return result.stdout;
}
function lncli(args: string[]): Record<string, unknown> {
  const stdout = lncliRaw(args);
  try { return JSON.parse(stdout); } catch { throw new FixtureInvalidError('Fixture JSON unavailable'); }
}
function copies() {
  const supplied = process.env.MACWARDEN_FIXTURE_DIR;
  if (!supplied || !isAbsolute(supplied)) throw new FixtureInvalidError('Fixture copy directory is required');
  const local = relative(join(repo, 'test'), resolve(supplied));
  if (!local || isAbsolute(local) || local.startsWith('..')) throw new FixtureInvalidError('Fixture copies must be isolated under test/');
  return { ca: readFileSync(join(supplied, 'tls.cert')), admin: readFileSync(join(supplied, 'admin.macaroon')) };
}
async function rest(ca: Buffer, own: Buffer, path: string, body?: object) {
  return await new Promise<{ status: number; value: Record<string, unknown> }>((done, fail) => {
    const call = request({ hostname: 'localhost', port: fixtureTopology().restPort, ca, rejectUnauthorized: true, path,
      method: body ? 'POST' : 'GET', headers: { 'Grpc-Metadata-macaroon': own.toString('hex'), 'content-type': 'application/json' } }, response => {
      const chunks: Buffer[] = []; let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 1_048_576) call.destroy(new FixtureInvalidError('Fixture response exceeded safe bound'));
        else chunks.push(Buffer.from(chunk));
      });
      response.on('end', () => {
        try { done({ status: response.statusCode ?? 0, value: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { fail(new FixtureInvalidError('Fixture REST JSON unavailable')); }
      });
    });
    call.on('error', () => fail(new FixtureInvalidError('Fixture REST unavailable')));
    call.setTimeout(10_000, () => call.destroy(new Error('Fixture timeout')));
    call.end(body ? JSON.stringify(body) : undefined);
  });
}
function cleanupFixture(created: string[], remotes: string[]) {
  const value = lncli(['listmacaroonids']).root_key_ids;
  if (!Array.isArray(value)) throw new FixtureInvalidError('Fixture ID state unavailable');
  const ids = value.map(String);
  for (const id of created.filter(id => ids.includes(id))) {
    if (id === '0' || lncli(['deletemacaroonid', id]).deleted !== true) throw new FixtureInvalidError('Fixture cleanup failed');
  }
  for (const remote of remotes)
    if (docker(['exec', '-T', 'lnd', 'rm', '-f', remote]).status !== 0) throw new FixtureInvalidError('Fixture remote cleanup failed');
  requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
}
async function scenario(work: (f: {
  ca: Buffer; admin: Buffer;
  bake: (name: string, id: string, permissions: string[], flags?: string[]) => { bytes: Buffer; remote: string };
  copy: (name: string, bytes: Buffer) => string;
  probe: (remote: string, method?: string) => ReturnType<typeof docker>;
}) => Promise<void>) {
  await scratch(async dir => {
    requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
    const { ca, admin } = copies(), created: string[] = [], remotes: string[] = [];
    const copy = (name: string, bytes: Buffer) => {
      const path = register(bytes), remote = `/tmp/macwarden-cp039-${process.pid}-${name}.macaroon`;
      if (docker(['cp', path, `lnd:${remote}`]).status !== 0) throw new FixtureInvalidError('Fixture credential copy failed');
      remotes.push(remote); return remote;
    };
    try {
      await work({ ca, admin, copy,
        bake: (name, id, permissions, flags = []) => {
          const remote = `/tmp/macwarden-cp039-${process.pid}-${name}.macaroon`, path = join(dir, `${name}.macaroon`);
          created.push(id); remotes.push(remote); declare(path);
          lncliRaw(['bakemacaroon', `--root_key_id=${id}`, `--save_to=${remote}`, ...flags, ...permissions]);
          if (docker(['cp', `lnd:${remote}`, path]).status !== 0) throw new FixtureInvalidError('Fixture credential copy failed');
          const bytes = readFileSync(path); register(bytes); return { bytes, remote };
        },
        probe: (remote, method = 'getinfo') => docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${remote}`, method]),
      });
    } finally {
      cleanupFixture(created, remotes);
    }
  });
}

it('CP-039/adapter-auth-oracle live lncli and REST pin HTTP500 own expired denied and missing failures', async () => {
  await scenario(async f => {
    const missing = f.bake('own-missing', '39001', ['info:read']);
    expect(f.probe(missing.remote).status).toBe(0);
    expect(lncli(['deletemacaroonid', '39001']).deleted).toBe(true);
    const denied = f.bake('own-denied', '39002', ['info:read']);
    expect(f.probe(denied.remote).status).toBe(0);
    const expired = f.bake('own-expired', '39003', ['info:read'], ['--timeout=1']);
    await new Promise(done => setTimeout(done, 1_200));
    for (const [name, credential, path, method, pattern] of [
      ['missing', missing, '/v1/getinfo', 'getinfo', /root key with id 39001 doesn't exist/],
      ['denied', denied, '/v1/macaroon/ids', 'listmacaroonids', /permission denied/],
      ['expired', expired, '/v1/getinfo', 'getinfo', /expired/],
    ] as const) {
      const probe = f.probe(credential.remote, method);
      if (probe.error || probe.status === null) throw new FixtureInvalidError('Independent lncli probe unavailable');
      expect(probe.status === 0, `${name} ordinary RPC rejected`).toBe(false);
      expect(pattern.test(probe.stderr), `${name} independent rejection meaning`).toBe(true);
      const response = await rest(f.ca, credential.bytes, path);
      expect(response.status, `${name} pinned own-auth HTTP status`).toBe(500);
      expect(pattern.test(String(response.value.message)), `${name} pinned REST meaning`).toBe(true);
      const lnd = createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: f.ca, macaroon: new Secret(credential.bytes) });
      let failure: unknown;
      try { await (method === 'getinfo' ? lnd.getInfo() : lnd.listMacaroonIds()); } catch (error) { failure = error; }
      expect((failure as { code?: number })?.code, `${name} product auth classification`).toBe(4);
    }
  });
}, 120_000);
it('CP-039/adapter-auth-oracle live lncli and REST pin only HTTP400 missing-root and signature target proofs', async () => {
  await scenario(async f => {
    const target = f.bake('target', '39004', ['info:read']);
    expect(f.probe(target.remote).status).toBe(0);
    const corrupted = Buffer.from(target.bytes); corrupted[corrupted.length - 1] ^= 1;
    const remote = f.copy('signature', corrupted);
    const signatureProbe = f.probe(remote);
    expect(signatureProbe.status === 0, 'corrupt signature independently rejected').toBe(false);
    const body = (bytes: Buffer) => ({ macaroon: bytes.toString('base64'), permissions: [{ entity: 'info', action: 'read' }] });
    const signature = await rest(f.ca, f.admin, '/v1/macaroon/checkpermissions', body(corrupted));
    expect(signature.status).toBe(400); expect(String(signature.value.message).includes('signature mismatch')).toBe(true);
    const lnd = createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: f.ca, macaroon: new Secret(f.admin) });
    expect(await lnd.checkMacaroon(new Secret(corrupted), ['info:read'])).toMatchObject({ valid: false, reason: 'signature-mismatch' });
    expect(lncli(['deletemacaroonid', '39004']).deleted).toBe(true);
    const missingProbe = f.probe(target.remote);
    expect(missingProbe.status === 0).toBe(false);
    expect(missingProbe.stderr.includes("root key with id 39004 doesn't exist")).toBe(true);
    const missing = await rest(f.ca, f.admin, '/v1/macaroon/checkpermissions', body(target.bytes));
    expect(missing.status).toBe(400); expect(String(missing.value.message).includes("root key with id 39004 doesn't exist")).toBe(true);
    expect(await lnd.checkMacaroon(new Secret(target.bytes), ['info:read'])).toMatchObject({ valid: false, reason: 'root-key-missing' });
  });
}, 120_000);
