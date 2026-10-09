import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { join, resolve } from 'node:path';
import { beforeAll, expect, it } from 'vitest';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { checkLiveReference, classifyAcceptance, registerFixtureSentinel, requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { findLeaks } from "../helpers/leak-check.js";
import { auditVectors, permissionTextVector } from '../helpers/cp015-audit-vectors.mjs';

const repo = resolve();
const suppliedTmp = process.env.MACWARDEN_TEST_TMP;
const suppliedSentinels = process.env.MACWARDEN_SENTINEL_DIR;
if (!suppliedTmp || !suppliedSentinels) throw new FixtureInvalidError('Scoped test tmp and sentinel directories required');
const outerTmp = resolve(suppliedTmp), sentinels = resolve(suppliedSentinels);
const tmp = join(outerTmp, 'cp015-facts');
const declarations = join(outerTmp, 'declared-out.txt');
const factsPath = join(tmp, 'cp015-facts.json');
const compose = fixtureTopology().composeArgs;
const remotePrefix = `/tmp/macwarden-cp015-${process.pid}`;
const source = 'lightninglabs/lnd:v0.21.4-beta@sha256:04d06edcc0f6e99a5e797ea34959f330add222226f840cd86afbc31f8f29627d';
const ids = { delete: '15001', max: '18446744073709551615', external: '15002' };
const remote = (name: string) => `${remotePrefix}-${name}.macaroon`;
const decodedBytes = (value: unknown) => typeof value === 'string' ?
  Buffer.from(value, /^[0-9a-fA-F]{64}$/.test(value) ? 'hex' : 'base64') : null;

function docker(args: string[], binary = false) {
  return spawnSync('docker', [...compose, ...args], { cwd: repo, encoding: binary ? null : 'utf8',
    maxBuffer: 4_000_000, timeout: 30_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout as string); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} invalid JSON`); }
}
function bake(id: string, name: string, permissions: string[], flags: string[] = []) {
  const path = remote(name);
  const run = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    `--root_key_id=${id}`, `--save_to=${path}`, ...flags, ...permissions]);
  if (run.status !== 0) throw new Error(`Fixture bake ${name} failed`);
  mkdirSync(sentinels, { recursive: true });
  const local = join(tmp, `${name}.macaroon`);
  if (docker(['cp', `lnd:${path}`, local]).status !== 0) throw new Error(`Fixture copy ${name} failed`);
  const registered = registerFixtureSentinel(local, `cp015-${name}.macaroon`, sentinels);
  unlinkSync(local);
  appendFileSync(declarations, `${registered}\n`);
  return { path, local: registered };
}
function probe(path: string, rpc = 'getinfo') {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${path}`, rpc]);
  return classifyAcceptance(result);
}
function record(key: string, value: unknown) {
  mkdirSync(tmp, { recursive: true });
  const previous = (() => { try { return JSON.parse(readFileSync(factsPath, 'utf8')); } catch { return {}; } })();
  writeFileSync(factsPath, JSON.stringify({ ...previous, source, [key]: value }, null, 2) + '\n');
}
function fixtureCredential(name: string): Buffer {
  const path = name === 'tls.cert' ? '/root/.lnd/tls.cert' :
    '/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon';
  const result = docker(['exec', '-T', 'lnd', 'cat', path], true);
  if (result.status !== 0) throw new FixtureInvalidError('Fixture credential unavailable');
  return result.stdout as unknown as Buffer;
}
let mined = false;
async function mineForInvoices() {
  if (mined) return;
  const config = readFileSync(join(repo, 'test/fixture/docker-compose.yml'), 'utf8');
  const user = /-rpcuser=([^\r\n]+)/.exec(config)?.[1];
  const password = /-rpcpassword=([^\r\n]+)/.exec(config)?.[1];
  if (!user || !password) throw new FixtureInvalidError('Fixture bitcoin RPC configuration unavailable');
  // bitcoin-cli reads the disposable fixture password on stdin, never in a command or report.
  const call = (args: string[]) => spawnSync('docker', [...compose, 'exec', '-T', 'bitcoind', 'bitcoin-cli',
    '-regtest', `-rpcuser=${user}`, '-stdinrpcpass', ...args],
  { cwd: repo, input: `${password}\n`, encoding: 'utf8', maxBuffer: 4_000_000, timeout: 30_000 });
  let address = call(['getnewaddress']);
  if (address.status !== 0) {
    if (call(['createwallet', 'cp015']).status !== 0) throw new FixtureInvalidError('Fixture bitcoin wallet unavailable');
    address = call(['getnewaddress']);
  }
  if (address.status !== 0 || call(['generatetoaddress', '6', address.stdout.trim()]).status !== 0)
    throw new FixtureInvalidError('Fixture regtest blocks could not be generated');
  for (let attempt = 0; attempt < 15; attempt++) {
    if (lncli(['getinfo']).synced_to_chain === true) { mined = true; record('invoicePreparation', { regtestBlocksMined: 6 }); return; }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  throw new FixtureInvalidError('Fixture LND did not sync to regtest blocks');
}
async function rest(path: string, method = 'GET', body?: Record<string, unknown>, macaroon?: Buffer, timeoutMs?: number) {
  const cert = fixtureCredential('tls.cert');
  const auth = macaroon || fixtureCredential('admin.macaroon');
  const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return await new Promise<{ status: number; json: Record<string, unknown> }>((resolveResult, reject) => {
    const call = request({ hostname: 'localhost', port: fixtureTopology().restPort, path, method, ca: cert,
      signal: timeoutMs === undefined ? undefined : AbortSignal.timeout(timeoutMs),
      headers: { 'Grpc-Metadata-macaroon': auth.toString('hex'),
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}) } }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        try { resolveResult({ status: response.statusCode || 0,
          json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { reject(new Error('Fixture REST returned invalid JSON')); }
      });
    });
    call.on('error', reject);
    if (data) call.write(data);
    call.end();
  });
}

beforeAll(() => {
  const info = lncli(['getinfo']);
  const roots = lncli(['listmacaroonids']);
  requirePinnedFixture(info, roots);
  mkdirSync(tmp, { recursive: true });
  writeFileSync(factsPath, '{}\n');
  // The caller owns the shared manifest; retain every earlier file's declarations.
  appendFileSync(declarations, '');
  record('fixture', { network: (info.chains as { network: string }[])[0].network,
    version: info.version, baselineRootKeyIds: roots.root_key_ids });
});

it('CP-015/fixture-basics pinned defaults, permissions and baked location', async () => {
  const names = ['admin', 'readonly', 'invoice'];
  const defaults = names.map(name => {
    const path = `/root/.lnd/data/chain/bitcoin/regtest/${name}.macaroon`;
    const facts = lncli(['printmacaroon', `--macaroon_file=${path}`]);
    return { name, location: facts.location, rootKeyId: facts.root_key_id,
      permissionCount: (facts.permissions as string[]).length, caveatCount: (facts.caveats as string[] | null)?.length || 0 };
  });
  const baked = bake(ids.external, 'fixture-basics', ['info:read']);
  const bakedFacts = lncli(['printmacaroon', `--macaroon_file=${baked.path}`]);
  const live = lncli(['listpermissions']).method_permissions as Record<string, { permissions?: { entity: string; action: string }[] }>;
  const methods = Object.fromEntries(Object.entries(live).map(([name, entry]) =>
    [name, (entry.permissions || []).map(p => `${p.entity}:${p.action}`)]));
  const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as { methods: typeof methods };
  const fact = { defaults, bakedLocation: bakedFacts.location, bakedRootKeyId: bakedFacts.root_key_id,
    methodCount: Object.keys(methods).length, snapshotMatches: JSON.stringify(methods) === JSON.stringify(snapshot.methods),
    uriGetInfo: methods['/lnrpc.Lightning/GetInfo'] };
  record('fixtureBasics', fact);
  expect(defaults.map(x => x.location)).toEqual(['lnd', 'lnd', 'lnd']);
  expect(defaults.map(x => x.permissionCount)).toEqual([19, 9, 5]);
  expect(fact.bakedLocation).toBe('lnd');
  expect(fact.snapshotMatches).toBe(true);
});

it('CP-015/root-key-ids-type REST reports decimal JSON types after a new bake', async () => {
  bake(ids.external, 'root-key-ids-type', ['info:read']);
  const result = await rest('/v1/macaroon/ids');
  const values = result.json.root_key_ids;
  const facts = { status: result.status, values, types: Array.isArray(values) ? values.map(value => typeof value) : null };
  record('rootKeyIdsType', facts);
  expect(result.status).toBe(200);
  expect(values).toContain(ids.external);
});

it('CP-015/delete-next-request deleted key is rejected on the next lncli request', () => {
  const baked = bake(ids.delete, 'delete-next-request', ['info:read']);
  const before = probe(baked.path);
  const deletion = lncli(['deletemacaroonid', ids.delete]);
  const after = probe(baked.path);
  record('deleteNextRequest', { rootKeyId: ids.delete, before, deleted: deletion.deleted, after });
  expect(before).toBe('accepted');
  expect(deletion.deleted).toBe(true);
  expect(after).toBe('rejected');
});

it('CP-015/rest-delete-error REST check records the root-key-missing error shape', async () => {
  const baked = readFileSync(join(sentinels, 'cp015-delete-next-request.macaroon'));
  const result = await rest('/v1/macaroon/checkpermissions', 'POST',
    { macaroon: baked.toString('base64'), permissions: [{ entity: 'info', action: 'read' }] });
  const message = typeof result.json.message === 'string' &&
    /root key with id [0-9]+ doesn't exist/.test(result.json.message) ?
      `root key with id ${ids.delete} doesn't exist` : 'other';
  record('restDeleteError', { status: result.status, code: result.json.code ?? null, message });
  expect(result.status).toBeGreaterThanOrEqual(400);
  expect(message).toContain(`root key with id ${ids.delete}`);
});

it('CP-015/bake-edge-facts maximum ID and external permission rules are observed', () => {
  const max = bake(ids.max, 'max-root', ['info:read']);
  const printed = lncli(['printmacaroon', `--macaroon_file=${max.path}`]);
  const unknown = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    '--root_key_id=15003', `--save_to=${remote('external-rejected')}`, 'remotesigner:generate']);
  const external = bake('15004', 'external-allowed', ['remotesigner:generate'], ['--allow_external_permissions']);
  const externalPrinted = lncli(['printmacaroon', `--macaroon_file=${external.path}`]);
  const fact = { maxRootKeyId: printed.root_key_id, maxProbe: probe(max.path),
    externalWithoutFlagExit: unknown.status, externalWithFlag: externalPrinted.permissions };
  record('bakeEdgeFacts', fact);
  expect(fact.maxRootKeyId).toBe(ids.max);
  expect(fact.maxProbe).toBe('accepted');
  expect(unknown.status).not.toBe(0);
}, 30_000);

it('CP-015/bake-edge-facts REST code and external URI acceptance follow pinned LND', async () => {
  const bad = await rest('/v1/macaroon', 'POST',
    { permissions: [{ entity: 'example', action: 'delete' }], root_key_id: '15009' });
  const uri = 'uri:/example.Unknown/Method';
  const without = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon',
    '--root_key_id=15010', `--save_to=${remote('uri-rejected')}`, uri]);
  const allowed = bake('15011', 'uri-allowed', [uri], ['--allow_external_permissions']);
  const printed = lncli(['printmacaroon', `--macaroon_file=${allowed.path}`]);
  const fact = { invalidStatus: bad.status, invalidCode: bad.json.code ?? null,
    unknownUriWithoutFlagExit: without.status, unknownUriWithFlag: printed.permissions };
  record('bakeRestAndUri', fact);
  checkLiveReference('bake-rest-error', fact, comparison => record('bakeRestReference', comparison));
  expect(bad.status).toBeGreaterThanOrEqual(400);
  expect(without.status).not.toBe(0);
  expect(printed.permissions).toEqual([uri]);
});

it('CP-015/rest-caveat-address host and container REST observe an address-bound credential', async () => {
  const bound = bake('15012', 'address-bound', ['info:read'], ['--ip_address=127.0.0.1']);
  const credential = readFileSync(bound.local);
  const host = await rest('/v1/getinfo', 'GET', undefined, credential);
  const inside = docker(['exec', '-T', 'lnd', 'wget', '-q', '--no-check-certificate',
    '-O', '/dev/null', `--header=Grpc-Metadata-macaroon: ${credential.toString('hex')}`,
    'https://127.0.0.1:8080/v1/getinfo']);
  const fact = { caveat: 'ipaddr 127.0.0.1', hostRestStatus: host.status,
    containerRestExit: inside.status, annotation: 'REST proxy' };
  record('restCaveatAddress', fact);
  checkLiveReference('rest-caveat-address', fact, comparison => record('restCaveatAddressReference', comparison));
  expect(host.status).toBeGreaterThan(0);
  expect(inside.status).not.toBeNull();
});

it('CP-015/B10 pinned printmacaroon records distinguishable permission order', () => {
  const baked = bake('15005', 'permission-order', ['invoices:write', 'info:read', 'invoices:read']);
  const printed = lncli(['printmacaroon', `--macaroon_file=${baked.path}`]);
  const permissions = printed.permissions as string[];
  record('permissionOrder', { input: ['invoices:write', 'info:read', 'invoices:read'], printed: permissions,
    source: 'lncli printmacaroon in pinned fixture' });
  expect(permissions).toHaveLength(3);
  expect(new Set(permissions).size).toBe(3);
});

it('CP-015/empty-permission-check expired and corrupted macaroons have separate live outcomes', async () => {
  const expired = bake('15006', 'expired', ['info:read'], ['--timeout=1']);
  const original = readFileSync(expired.local);
  const corrupt = Buffer.from(original);
  corrupt[corrupt.length - 1] ^= 1;
  const corruptPath = join(tmp, 'corrupt.macaroon');
  writeFileSync(corruptPath, corrupt);
  const registeredCorrupt = registerFixtureSentinel(corruptPath, 'cp015-corrupt.macaroon', sentinels);
  unlinkSync(corruptPath);
  appendFileSync(declarations, `${registeredCorrupt}\n`);
  const printed = lncli(['printmacaroon', `--macaroon_file=${expired.path}`]);
  const condition = (printed.caveats as string[]).find(value => value.startsWith('time-before '));
  const expiry = condition ? Date.parse(condition.slice('time-before '.length)) : Number.NaN;
  await new Promise(resolve => setTimeout(resolve, 1200));
  const expiredAtProbe = Date.now() >= expiry;
  const corruptRemote = remote('corrupt-check');
  if (docker(['cp', registeredCorrupt, `lnd:${corruptRemote}`]).status !== 0)
    throw new FixtureInvalidError('Fixture corrupt macaroon could not be copied');
  const ordinary = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    `--macaroonpath=${corruptRemote}`, 'getinfo']);
  const corruptRejected = ordinary.status !== 0 && /signature mismatch/i.test(ordinary.stderr as string);
  const check = async (bytes: Buffer) => {
    const result = await rest('/v1/macaroon/checkpermissions', 'POST',
      { macaroon: bytes.toString('base64'), permissions: [] });
    return { status: result.status, valid: result.json.valid ?? null,
      code: result.json.code ?? null };
  };
  const facts = { expired: await check(original), corrupted: await check(corrupt),
    expiredAtProbe, corruptRejectedByOrdinaryRpc: corruptRejected };
  record('emptyPermissionCheck', facts);
  expect(expiredAtProbe).toBe(true);
  expect(corruptRejected).toBe(true);
  expect(facts.expired.status).toBeGreaterThan(0);
  expect(facts.corrupted.status).toBeGreaterThan(0);
}, 30_000);

it('CP-015/preimage-read known fixture invoice is checked with invoices:read', async () => {
  await mineForInvoices();
  const preimage = randomBytes(32);
  const reader = bake('15007', 'invoice-reader', ['invoices:read']);
  const created = lncli(['addinvoice', '--amt=1', `--preimage=${preimage.toString('hex')}`]);
  const listed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    `--macaroonpath=${reader.path}`, 'listinvoices']);
  if (listed.status !== 0) throw new Error('Fixture ListInvoices with invoices:read failed');
  const invoices = JSON.parse(listed.stdout as string).invoices as { r_hash?: string; r_preimage?: string }[];
  const invoice = invoices.find(item => item.r_hash === created.r_hash);
  const observedPreimage = decodedBytes(invoice?.r_preimage);
  const offchain = bake('15013', 'offchain-reader', ['offchain:read']);
  const paymentsCall = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    `--macaroonpath=${offchain.path}`, 'listpayments']);
  const payments = paymentsCall.status === 0 ?
    (JSON.parse(paymentsCall.stdout as string).payments as unknown[] | undefined) : null;
  const observed = { invoiceFound: Boolean(invoice),
    preimagePresent: Boolean(invoice?.r_preimage),
    preimageMatchesKnown: observedPreimage?.equals(preimage) ?? false,
    preimageAllZero: observedPreimage?.every(byte => byte === 0) ?? null,
    offchainListPaymentsAccepted: paymentsCall.status === 0,
    offchainPaymentCount: payments?.length ?? null,
    offchainReadConfirmed: false };
  record('preimageRead', observed);
  expect(observed.invoiceFound).toBe(true);
}, 30_000);

it('CP-015/stream-after-delete an established SubscribeInvoices stream outlives root deletion', async () => {
  await mineForInvoices();
  const reader = bake('15008', 'stream-reader', ['invoices:read']);
  const cert = fixtureCredential('tls.cert');
  const credential = readFileSync(reader.local);
  let content = '';
  let status = 0;
  let chunkCount = 0;
  const stream = request({ hostname: 'localhost', port: fixtureTopology().restPort, path: '/v1/invoices/subscribe',
    method: 'GET', ca: cert, headers: { 'Grpc-Metadata-macaroon': credential.toString('hex') } });
  stream.on('response', response => {
    status = response.statusCode || 0;
    response.on('data', chunk => { chunkCount++; content += Buffer.from(chunk).toString('utf8'); });
  });
  stream.end();
  for (let attempt = 0; attempt < 20 && status === 0; attempt++)
    await new Promise(resolve => setTimeout(resolve, 250));
  const invoice = () => lncli(['addinvoice', '--amt=1', `--preimage=${randomBytes(32).toString('hex')}`]);
  const first = invoice();
  const waitFor = async (hash: unknown) => {
    const expected = decodedBytes(hash);
    for (let attempt = 0; attempt < 20; attempt++) {
      const wire = [...content.matchAll(/"r_hash"\s*:\s*"([^"]+)"/g)].map(match => decodedBytes(match[1]));
      if (expected && wire.some(value => value?.equals(expected))) return true;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    return false;
  };
  try {
    const firstDelivered = await waitFor(first.r_hash);
    const deletion = lncli(['deletemacaroonid', '15008']);
    const second = invoice();
    const afterDeleteDelivered = await waitFor(second.r_hash);
    const nextRequest = probe(reader.path, 'listinvoices');
    record('streamAfterDelete', { status, firstDelivered, deleted: deletion.deleted,
      afterDeleteDelivered, nextRequest, chunkCount, responseLength: content.length,
      containsHashField: content.includes('r_hash'), createdHashType: typeof first.r_hash,
      createdKeys: Object.keys(first).sort() });
    expect(status).toBe(200);
    expect(firstDelivered).toBe(true);
    expect(afterDeleteDelivered).toBe(true);
    expect(nextRequest).toBe('rejected');
  } finally { stream.destroy(); }
}, 30_000);

it('CP-015/decode-edge-reference pinned lncli confirms duplicate ordering and source vectors', () => {
  const names = ['duplicate-ops', 'third-party', 'trailing-bytes'];
  const facts = names.map(name => {
    const local = join(repo, 'test/vectors', `${name}.macaroon`);
    const path = remote(name);
    if (docker(['cp', local, `lnd:${path}`]).status !== 0) throw new Error('Fixture vector copy failed');
    const printed = lncli(['printmacaroon', `--macaroon_file=${path}`]);
    const bytes = readFileSync(local);
    return { name, source: 'hand-made', fingerprint: `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`,
      permissions: printed.permissions, location: printed.location, caveatCount: (printed.caveats as string[] | null)?.length || 0,
      lndAcceptanceClaim: false };
  });
  record('decodeEdgeReference', facts);
  expect(facts.find(x => x.name === 'duplicate-ops')?.permissions).toEqual(
    JSON.parse(readFileSync(join(repo, 'test/vectors/duplicate-ops.printmacaroon.json'), 'utf8')).permissions);
});

it('CP-015/decode-edge-reference hand-made caveat and protobuf boundaries have pinned parse outcomes', () => {
  const results = auditVectors(repo).map(entry => {
    const local = join(tmp, `${entry.name}.macaroon`);
    writeFileSync(local, entry.bytes);
    const sentinel = registerFixtureSentinel(local, `cp015-${entry.name}.macaroon`, sentinels);
    unlinkSync(local);
    appendFileSync(declarations, `${sentinel}\n`);
    const path = remote(entry.name);
    if (docker(['cp', sentinel, `lnd:${path}`]).status !== 0) throw new Error('Fixture audit vector copy failed');
    const run = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
      'printmacaroon', `--macaroon_file=${path}`]);
    const printed = run.status === 0 ? JSON.parse(run.stdout as string) as Record<string, unknown> : null;
    return { name: entry.name, audit: entry.audit, source: 'hand-made',
      fingerprint: `fp:${createHash('sha256').update(entry.bytes).digest('hex').slice(0, 16)}`,
      printAccepted: run.status === 0, location: printed?.location ?? null,
      permissions: printed?.permissions ?? null, caveats: printed?.caveats ?? null,
      lndAcceptanceClaim: false };
  });
  record('handMadeAuditReferences', results);
  expect(results).toHaveLength(7);
}, 30_000);

it('CP-015/decode-edge-reference leading permission BOMs preserve exact pinned printmacaroon text', () => {
  const cases = [
    { field: 'entity', entity: '\uFEFFinfo', action: 'read' },
    { field: 'action', entity: 'info', action: '\uFEFFread' },
  ];
  const facts = cases.map(({ field, entity, action }) => {
    const name = `bom-${field}`;
    const local = join(tmp, `${name}.macaroon`);
    const bytes = permissionTextVector(repo, entity, action);
    writeFileSync(local, bytes);
    const sentinel = registerFixtureSentinel(local, `cp015-${name}.macaroon`, sentinels);
    unlinkSync(local);
    appendFileSync(declarations, `${sentinel}\n`);
    const path = remote(name);
    if (docker(['cp', sentinel, `lnd:${path}`]).status !== 0) throw new Error('Fixture BOM vector copy failed');
    const printed = lncli(['printmacaroon', `--macaroon_file=${path}`]);
    return { name, source: 'hand-made', lndAcceptanceClaim: false,
      fingerprint: `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`,
      permissions: printed.permissions };
  });
  record('permissionBomReferences', facts);
  expect(facts[0].permissions).toEqual(['\uFEFFinfo:read']);
  expect(facts[1].permissions).toEqual(['info:\uFEFFread']);
});

it('CP-015/regeneration-invalidates a disposable root-key regeneration rejects an old macaroon', async () => {
  const original = bake(ids.max, 'regeneration-original', ['info:read']);
  expect(probe(original.path)).toBe('accepted');
  const previous = original.local;
  const oldBytes = readFileSync(previous);
  const oldAdminFile = join(tmp, 'old-admin.macaroon');
  writeFileSync(oldAdminFile, fixtureCredential('admin.macaroon'));
  const oldAdminSentinel = registerFixtureSentinel(oldAdminFile, 'cp015-old-admin.macaroon', sentinels);
  unlinkSync(oldAdminFile);
  appendFileSync(declarations, `${oldAdminSentinel}\n`);
  const base = readFileSync(join(repo, 'test/fixture/docker-compose.yml'), 'utf8');
  const service = /\n {2}lnd:\r?\n([\s\S]*?)(?=\nvolumes:)/.exec(base)?.[1];
  const commands = / {4}command:\r?\n((?: {6}- [^\r\n]+\r?\n)+)/.exec(service || '')?.[1]
    .split(/\r?\n/).filter(Boolean).map(line => line.replace(/^ {6}- /, ''));
  if (!commands?.includes('--noseedbackup')) throw new FixtureInvalidError('Fixture --noseedbackup command missing');
  const override = join(tmp, 'cp015-unlocker-compose.yml');
  writeFileSync(override, `services:\n  lnd:\n    command:\n${commands.filter(arg => arg !== '--noseedbackup')
    .map(arg => `      - ${arg}`).join('\n')}\n`);
  const composeOverride = (args: string[]) => spawnSync('docker', [...fixtureTopology().composeArgs, '-f', override, ...args],
  { cwd: repo, encoding: 'utf8', maxBuffer: 4_000_000, timeout: 60_000 });
  try {
    if (docker(['stop', 'lnd']).status !== 0 ||
        composeOverride(['up', '-d', '--no-deps', '--force-recreate', 'lnd']).status !== 0)
      throw new FixtureInvalidError('Fixture unlocker restart failed');
    const nextPassword = randomBytes(24);
    const cli = spawnSync('docker', [...compose, 'exec', '-T', 'lnd', 'lncli', '--network=regtest',
      'changepassword', '--new_mac_root_key', `--save_to=${remote('regenerated-admin')}`],
    { cwd: repo, input: `\n${nextPassword.toString('base64url')}\n${nextPassword.toString('base64url')}\n`,
      encoding: 'utf8', maxBuffer: 4_000_000, timeout: 20_000 });
    if (cli.status !== 0 && !/tty|terminal|ioctl/i.test(cli.stderr || ''))
      throw new FixtureInvalidError('Fixture lncli password change failed outside the non-TTY limitation');
    let changed: { status: number; json: Record<string, unknown> } | null = null;
    if (cli.status !== 0) {
      // Wait on a read-only unlocker endpoint; the mutation is sent exactly once.
      const deadline = Date.now() + 10_000;
      let locked = false;
      for (let attempt = 0; attempt < 20 && Date.now() < deadline; attempt++) {
        try {
          const state = await rest('/v1/state', 'GET', undefined, undefined,
            Math.min(1000, deadline - Date.now()));
          if (state.status === 200 && state.json.state === 'LOCKED') { locked = true; break; }
        } catch { /* The read-only unlocker endpoint may still be starting. */ }
        await new Promise(resolve => setTimeout(resolve, Math.min(500, Math.max(0, deadline - Date.now()))));
      }
      if (!locked) throw new FixtureInvalidError('Fixture unlocker never became ready');
      changed = await rest('/v1/changepassword', 'POST', {
        current_password: '', new_password: nextPassword.toString('base64'), new_macaroon_root_key: true },
      undefined, 10_000);
    }
    if (cli.status === 0) changed = { status: 200, json: {} };
    if (!changed) throw new FixtureInvalidError('Fixture unlocker never became available');
    expect(changed.status).toBe(200);
    const changedAt = Date.now();
    const errorKind = (result: ReturnType<typeof docker>) => result.status === 0 ? 'accepted' :
      /signature mismatch/i.test(result.stderr as string) ? 'signature-mismatch' :
        /root key with id [0-9]+ doesn't exist/i.test(result.stderr as string) ? 'root-key-missing' :
          /server.*start|starting|not.*ready/i.test(result.stderr as string) ? 'server-starting' :
            /connection refused|connect:|connection error|unavailable/i.test(result.stderr as string) ? 'transport-unavailable' : 'other';
    const readiness = { ready: false, elapsedMs: 0,
      probes: [] as { exit: number | null; kind: string; elapsedMs: number }[] };
    const readinessDeadline = changedAt + 10_000;
    for (let attempt = 0; attempt < 20 && Date.now() < readinessDeadline; attempt++) {
      // This path is the newly issued fixture authority, never either saved old credential.
      const current = spawnSync('docker', [...compose, 'exec', '-T', 'lnd', 'lncli', '--network=regtest',
        '--macaroonpath=/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon', 'getinfo'],
      { cwd: repo, encoding: 'utf8', maxBuffer: 4_000_000, timeout: Math.min(1000, readinessDeadline - Date.now()) });
      readiness.probes.push({ exit: current.status, kind: errorKind(current), elapsedMs: Date.now() - changedAt });
      if (current.status === 0) {
        let info;
        try { info = JSON.parse(current.stdout); }
        catch { throw new FixtureInvalidError('Fixture readiness returned invalid JSON'); }
        if (info.chains?.[0]?.network !== 'regtest' || !info.version?.startsWith('0.21.4-beta'))
          throw new FixtureInvalidError('Fixture readiness must be LND 0.21.4-beta on regtest');
        readiness.ready = true;
        break;
      }
      await new Promise(resolve => setTimeout(resolve, Math.min(500, Math.max(0, readinessDeadline - Date.now()))));
    }
    readiness.elapsedMs = Date.now() - changedAt;
    record('regenerationReadiness', readiness);
    if (!readiness.ready) throw new FixtureInvalidError('Fixture current authority did not become ready');
    const remoteOld = remote('old-after-regeneration');
    if (docker(['cp', previous, `lnd:${remoteOld}`]).status !== 0)
      throw new FixtureInvalidError('Fixture old macaroon could not be copied');
    const check = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
      `--macaroonpath=${remoteOld}`, 'getinfo']);
    const checkedAt = Date.now();
    const rejected = check.status !== 0 && /signature mismatch|root key with id [0-9]+ doesn't exist/i
      .test(check.stderr as string);
    const remoteAdmin = remote('old-admin-after-regeneration');
    if (docker(['cp', oldAdminSentinel, `lnd:${remoteAdmin}`]).status !== 0)
      throw new FixtureInvalidError('Fixture old admin macaroon could not be copied');
    const adminCheck = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
      `--macaroonpath=${remoteAdmin}`, 'getinfo']);
    const rootZeroRejected = adminCheck.status !== 0 &&
      /signature mismatch|root key with id [0-9]+ doesn't exist/i.test(adminCheck.stderr as string);
    record('regenerationInvalidates', { cliExit: cli.status, cliTtyRequired: /tty|terminal|ioctl/i.test(cli.stderr || ''),
      changeStatus: changed.status,
      changeCode: changed.json.code ?? null, oldMacaroonRejected: rejected,
      rootZeroRejected,
      firstProbeExit: check.status, changeToFirstProbeMs: checkedAt - changedAt,
      firstProbeErrorKind: errorKind(check),
      rootZeroRejectionKind: errorKind(adminCheck),
      rejectionKind: /signature mismatch/i.test(check.stderr as string) ? 'signature-mismatch' :
        /root key with id [0-9]+ doesn't exist/i.test(check.stderr as string) ? 'root-key-missing' : 'other' });
    if (check.status === 0 || adminCheck.status === 0)
      throw new Error('REFERENCE_CONFLICT: docs/architecture.md root-key regeneration invalidates every credential; pinned LND accepted an old credential after current-authority readiness');
    expect(changed.status).toBe(200);
    expect(rejected).toBe(true);
    expect(rootZeroRejected).toBe(true);
    expect(oldBytes.length).toBeGreaterThan(0);
  } finally { unlinkSync(override); }
}, 120_000);

it('CP-015/leak-check registered fixture credentials remain absent from facts and test output', () => {
  const leak = findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: sentinels,
    paths: [tmp], testTmp: outerTmp, root: repo });
  record('leakCheck', { clear: leak === null });
  expect(leak).toBeNull();
});
