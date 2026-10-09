import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { cp024Compose } from '../fixture/cp024-fixture.mjs';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { declare, register } from '../helpers/cp025-bake-support.mjs';
import { manifest, repo, suite, validateManifest } from '../helpers/cp034-btcpay.mjs';

const ownSuite = suite('live');
const registry = join(ownSuite.dir, 'registry.json');
const out = join(ownSuite.dir, 'btcpay.macaroon');
const own = join(ownSuite.sentinelDir, 'fixture-own.macaroon');
const cert = join(ownSuite.dir, 'fixture.cert');
const remote = `/tmp/macwarden-cp034-${process.pid}.macaroon`;
let baseline: string[] = [], candidateId: string | undefined, invoiceHash = '', nodePubkey = '';
function docker(args: string[]) {
  return spawnSync('docker', [...cp024Compose, ...args], { cwd: repo, encoding: 'utf8',
    timeout: 20_000, maxBuffer: 2_000_000 });
}
function call(args: string[], credential?: string) {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    ...(credential ? [`--macaroonpath=${credential}`] : []), ...args]);
  if (result.error) {
    // Report spawn metadata only: command output and authentication arguments stay private.
    const code = (result.error as NodeJS.ErrnoException).code;
    const safeCode = typeof code === 'string' && /^[A-Z0-9_]+$/.test(code) ? code : 'unknown';
    const command = /^[a-z]+$/.test(args[0] || '') ? args[0] : 'unknown';
    throw new FixtureInvalidError(`Pinned fixture lncli invocation unavailable: command=${command}; code=${safeCode}; signal=${result.signal || 'none'}; status=${result.status ?? 'none'}`);
  }
  ownSuite.outputs.push(result.stdout, result.stderr);
  return result;
}
function json(args: string[]): Record<string, unknown> {
  const result = call(args);
  if (result.status !== 0) throw new FixtureInvalidError(`Pinned fixture ${args[0]} failed`);
  try { return JSON.parse(result.stdout); }
  catch { throw new FixtureInvalidError(`Pinned fixture ${args[0]} returned invalid JSON`); }
}
function invoiceHashHex(value: unknown): string {
  const wire = String(value);
  const decoded = Buffer.from(wire, /^[0-9a-fA-F]{64}$/.test(wire) ? 'hex' : 'base64');
  if (decoded.length !== 32) throw new FixtureInvalidError('Control invoice hash unavailable');
  return decoded.toString('hex');
}
async function prepareInvoices() {
  if (json(['getinfo']).synced_to_chain === true) return;
  // Reuse CP-015's independent regtest preparation; AddInvoice awaits chain readiness.
  const config = readFileSync(join(repo, 'test/fixture/docker-compose.yml'), 'utf8');
  const user = /-rpcuser=([^\r\n]+)/.exec(config)?.[1];
  const password = /-rpcpassword=([^\r\n]+)/.exec(config)?.[1];
  if (!user || !password) throw new FixtureInvalidError('Fixture bitcoin RPC configuration unavailable');
  const bitcoin = (args: string[]) => spawnSync('docker', [...cp024Compose, 'exec', '-T', 'bitcoind',
    'bitcoin-cli', '-regtest', `-rpcuser=${user}`, '-stdinrpcpass', ...args],
  { cwd: repo, input: `${password}\n`, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
  let address = bitcoin(['getnewaddress']);
  if (address.status !== 0) {
    if (bitcoin(['createwallet', 'cp034']).status !== 0)
      throw new FixtureInvalidError('Fixture bitcoin wallet unavailable');
    address = bitcoin(['getnewaddress']);
  }
  if (address.status !== 0 || bitcoin(['generatetoaddress', '6', address.stdout.trim()]).status !== 0)
    throw new FixtureInvalidError('Fixture regtest blocks could not be generated');
  for (let attempt = 0; attempt < 15; attempt++) {
    if (json(['getinfo']).synced_to_chain === true) return;
    await new Promise(resolveWait => setTimeout(resolveWait, 1000));
  }
  throw new FixtureInvalidError('Fixture LND did not sync to regtest blocks');
}
function ids(): string[] {
  const observed = json(['listmacaroonids']).root_key_ids;
  if (!Array.isArray(observed)) throw new FixtureInvalidError('Pinned fixture IDs unavailable');
  return observed.map(String);
}
function cli(output: string, dry: boolean) {
  declare(output);
  const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
  const result = spawnSync(process.execPath, [resolve('dist/bin.js'), 'bake', '--label', dry ? 'btcpay-plan' : 'btcpay',
    '--preset', 'btcpay', '--out', output, '--registry', registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`,
    '--tls-cert', cert, '--macaroon', own, '--json', ...(dry ? ['--dry-run'] : [])],
  { cwd: repo, env, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
  if (existsSync(output)) register(readFileSync(output));
  ownSuite.outputs.push(result.stdout, result.stderr);
  expect(ownSuite.leak()).toBeNull();
  expect(result.error).toBeUndefined();
  return result;
}
beforeAll(async () => {
  validateManifest();
  const info = json(['getinfo']), before = json(['listmacaroonids']);
  requirePinnedFixture(info, before);
  baseline = (before.root_key_ids as string[]).map(String);
  nodePubkey = String(info.identity_pubkey);
  // Fixture-owned copies only; no real-node or home-directory credentials.
  const fixtureDirectory = process.env.MACWARDEN_FIXTURE_DIR;
  if (!fixtureDirectory) throw new FixtureInvalidError('Fresh fixture copies are required');
  for (const [name, target] of [['admin.macaroon', own], ['tls.cert', cert]]) {
    const source = join(fixtureDirectory, name);
    if (!existsSync(source)) throw new FixtureInvalidError('Programmatic fixture copy unavailable');
    copyFileSync(source, target);
  }
  declare(own);
  writeFileSync(registry, '{"schema":1,"entries":[]}', { mode: 0o600 });
  const baked = cli(out, false);
  // Independently list any new ID even if the response was lost; cleanup cannot depend on a successful bake.
  const newIds = ids().filter(id => !baseline.includes(id));
  if (newIds.length === 1) candidateId = newIds[0];
  expect(baked.status, 'btcpay bake must succeed before independent authorization probes').toBe(0);
  expect(newIds).toHaveLength(1);
  expect(candidateId).toMatch(/^[1-9][0-9]*$/);
  const registered = register(readFileSync(out));
  if (docker(['cp', registered, `lnd:${remote}`]).status !== 0)
    throw new FixtureInvalidError('Pinned fixture credential copy failed');
  const printed = json(['printmacaroon', `--macaroon_file=${remote}`]);
  expect((printed.permissions as string[]).slice().sort()).toEqual(manifest.permissions);
  expect(printed.root_key_id).toBe(candidateId);
  const entry = JSON.parse(readFileSync(registry, 'utf8')).entries[0];
  expect(entry).toMatchObject({ rootKeyId: candidateId, verified: true, status: 'active', grade: 'SPEND' });
  if (process.platform !== 'win32') expect(statSync(out).mode & 0o777).toBe(0o600);
  // Authorized control invoice supplies real domain state for lookup/cancellation.
  await prepareInvoices();
  const invoice = json(['addinvoice', '--amt=1']);
  invoiceHash = invoiceHashHex(invoice.r_hash);
}, 60_000);

afterAll(() => {
  try {
    if (baseline.length) {
      for (const id of ids().filter(id => !baseline.includes(id))) {
        if (id === '0') throw new FixtureInvalidError('Refusing fixture root-zero cleanup');
        if (json(['deletemacaroonid', id]).deleted !== true)
          throw new FixtureInvalidError('Owned fixture root key cleanup failed');
      }
      if (docker(['exec', '-T', 'lnd', 'rm', '-f', remote]).status !== 0)
        throw new FixtureInvalidError('Owned fixture credential cleanup failed');
      requirePinnedFixture(json(['getinfo']), json(['listmacaroonids']));
    }
  } finally {
    process.env.MACWARDEN_TEST_TMP = ownSuite.previous.tmp;
    if (ownSuite.previous.sentinels === undefined) delete process.env.MACWARDEN_SENTINEL_DIR;
    else process.env.MACWARDEN_SENTINEL_DIR = ownSuite.previous.sentinels;
    rmSync(ownSuite.dir, { recursive: true, force: true });
  }
});

const permissionDenied = (text: string) => /permission denied|permission\b.*(?:denied|not allowed)|not authorized/i.test(text);
// Exact pinned lightning.yaml routes; fixture CA verification stays enabled.
function restOpenChannel(credential: string) {
  const body = Buffer.from(JSON.stringify({
    node_pubkey: Buffer.from(nodePubkey, 'hex').toString('base64'), local_funding_amount: '20000',
  }));
  return new Promise<{ status: number; code: number; message: string }>((resolveResult, reject) => {
    const probe = request({ hostname: 'localhost', port: fixtureTopology().restPort, path: '/v1/channels', method: 'POST',
      ca: readFileSync(cert), signal: AbortSignal.timeout(10_000),
      headers: { 'Grpc-Metadata-macaroon': readFileSync(credential).toString('hex'),
        'Content-Type': 'application/json', 'Content-Length': body.length } }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        const wire = Buffer.concat(chunks).toString('utf8'); ownSuite.outputs.push(wire);
        try {
          const value = JSON.parse(wire);
          resolveResult({ status: response.statusCode || 0, code: Number(value.code), message: String(value.message || '') });
        } catch { reject(new Error('Fixture OpenChannelSync returned invalid JSON')); }
      });
      response.on('error', () => reject(new Error('Fixture OpenChannelSync response failed')));
    });
    probe.on('error', () => reject(new Error('Fixture OpenChannelSync transport failed')));
    probe.end(body);
  });
}
async function subscribedInvoice(credential: string) {
  let content = '', status = 0, failed = false;
  const stream = request({ hostname: 'localhost', port: fixtureTopology().restPort, path: '/v1/invoices/subscribe', method: 'GET',
    ca: readFileSync(cert), headers: { 'Grpc-Metadata-macaroon': readFileSync(credential).toString('hex') } }, response => {
    status = response.statusCode || 0;
    response.on('data', chunk => { content += Buffer.from(chunk).toString('utf8'); });
    response.on('error', () => { failed = true; });
  });
  stream.on('error', () => { failed = true; });
  stream.end();
  try {
    // A newly created control invoice must be delivered; an open socket is insufficient.
    const created: string[] = [];
    for (let attempt = 0; attempt < 20; attempt++) {
      await new Promise(resolveWait => setTimeout(resolveWait, 250));
      if (failed) throw new Error('Fixture SubscribeInvoices transport failed');
      if (status && status !== 200) throw new Error('Fixture SubscribeInvoices authorization failed');
      if (attempt % 4 === 1) created.push(invoiceHashHex(json(['addinvoice', '--amt=1']).r_hash));
      const observed = [...content.matchAll(/"r_hash"\s*:\s*"([^"]+)"/g)].map(match => invoiceHashHex(match[1]));
      if (created.some(hash => observed.includes(hash))) {
        expect(status).toBe(200);
        return;
      }
    }
    throw new Error('Fixture SubscribeInvoices did not deliver a newly created invoice event');
  } finally { stream.destroy(); ownSuite.outputs.push(content); }
}
it('CP-034/btcpay-required-calls every required method passes independent fixture authorization controls', async () => {
  for (const required of manifest.calls) {
    if (required.method === '/lnrpc.Lightning/OpenChannelSync') {
      expect(required.restMapping.text).toContain('post: "/v1/channels"');
      const control = await restOpenChannel(own), candidate = await restOpenChannel(out);
      // A valid compressed public key naming this node cannot open a channel to itself.
      // Only the same explicit domain result from both authorized requests qualifies.
      expect(control.code).not.toBe(7);
      expect(permissionDenied(control.message)).toBe(false);
      expect(control.message).toMatch(/(?:self|itself|yourself|own node)/i);
      expect(control.status).toBeGreaterThanOrEqual(400);
      expect(candidate).toEqual(control);
      continue;
    }
    if (required.method === '/lnrpc.Lightning/SubscribeInvoices') {
      expect(required.restMapping.text).toContain('get: "/v1/invoices/subscribe"');
      await subscribedInvoice(own);
      await subscribedInvoice(out);
      continue;
    }
    if (!required.lncli.args) throw new Error('Required method has no independent fixture probe');
    const args = (required.lncli.args as string[]).map(arg => arg.replace('{invoiceHash}', invoiceHash)
      .replace('{nodePubkey}', nodePubkey).replace('{unknownHash}', '00'.repeat(32)));
    const control = call(args);
    const candidate = call(args, remote);
    const controlError = control.stderr.trim(), candidateError = candidate.stderr.trim();
    expect(permissionDenied(controlError), `${required.method} control must pass authorization`).toBe(false);
    expect(permissionDenied(candidateError), `${required.method} candidate must pass authorization`).toBe(false);
    if (control.status === 0) expect(candidate.status, required.method).toBe(0);
    else {
      // Only actual RPC domain errors qualify; local CLI/parser/transport errors never prove authorization.
      expect(controlError, `${required.method} control must reach LND`).toMatch(/rpc error: code = /);
      const code = /rpc error: code = ([A-Za-z]+)/.exec(controlError)?.[1] || 'unknown';
      const category = /connection refused/i.test(controlError) ? 'connection-refused' :
        /cannot connect to (?:self|yourself)|connection to (?:self|yourself)/i.test(controlError) ? 'self-connection' :
        /Unavailable|DeadlineExceeded|connection|transport|context deadline|unknown command|flag provided/i.test(controlError) ? 'transport-or-parser' : 'domain';
      const selfConnection = required.method === '/lnrpc.Lightning/ConnectPeer' &&
        code === 'Unknown' && category === 'self-connection';
      // LND's observed refusal to connect to its own identity is an authorized domain result.
      expect(category === 'domain' || selfConnection,
        `${required.method} control code=${code}; category=${category}`).toBe(true);
      expect(candidate.status, required.method).toBe(control.status);
      expect(candidateError, `${required.method} same authorized domain result`).toBe(controlError);
    }
  }
}, 120_000);

it('CP-034/btcpay-forbidden-call unrelated ListMacaroonIDs is denied while the authorized control succeeds', () => {
  expect(manifest.calls.some((call: {method:string;allowed:boolean}) => call.method === manifest.forbidden.method)).toBe(false);
  const control = call(manifest.forbidden.args), candidate = call(manifest.forbidden.args, remote);
  expect(control.status).toBe(0);
  expect(candidate.status).not.toBe(0);
  expect(permissionDenied(candidate.stderr)).toBe(true);
});

it('CP-034/btcpay-dry-run-state live IDs and independent registry/out state remain unchanged', () => {
  const beforeIds = ids(), beforeRegistry = readFileSync(registry), beforeStat = statSync(registry);
  const dryOut = join(ownSuite.dir, 'dry-run.macaroon');
  const result = cli(dryOut, true);
  expect(result.status).toBe(0);
  expect(JSON.parse(result.stdout).result).toMatchObject({ dryRun: true, grade: 'SPEND' });
  expect(ids()).toEqual(beforeIds);
  expect(readFileSync(registry).equals(beforeRegistry)).toBe(true);
  expect(statSync(registry).mtimeMs).toBe(beforeStat.mtimeMs);
  expect(existsSync(dryOut)).toBe(false);
  expect(existsSync(`${registry}.lock`)).toBe(false);
});

it('CP-034/leak-check only this suite’s outputs, registry and declared products enter the standing leak checker', () => {
  expect(ownSuite.leak()).toBeNull();
});
