import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { observeEmptyBake } from '../test/fixture/observe-empty.mjs';

const root = process.cwd();
const fixtureFile = 'test/fixture/docker-compose.yml';
const defaultPrefix = ['docker', 'compose', '-f', fixtureFile, 'exec', '-T', 'lnd', 'lncli', '--network=regtest'];
function prefix() {
  if (!process.env.MACWARDEN_LNCLI) return defaultPrefix;
  return process.env.MACWARDEN_LNCLI.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map(x => x.replace(/^['"]|['"]$/g, '')) || [];
}
function call(command, args = [], binary = false) {
  const [exe, ...pre] = prefix();
  const result = spawnSync(exe, [...pre, command, ...args], { cwd: root, encoding: binary ? null : 'utf8', maxBuffer: 16_000_000, timeout: 30_000 });
  if (result.error) throw new Error(`${command} process failed`);
  return result;
}
function checked(command, args = []) {
  const p = call(command, args);
  if (p.status !== 0) throw new Error(`${command} failed`);
  try { return JSON.parse(p.stdout); } catch { throw new Error(`${command} returned invalid JSON`); }
}
function docker(args) {
  const p = spawnSync('docker', ['compose', '-f', fixtureFile, ...args], { cwd: root, encoding: 'utf8', maxBuffer: 1_000_000, timeout: 30_000 });
  if (p.status !== 0) throw new Error(`Fixture file transfer failed during ${args[0]} for ${args.at(-1)}`);
}
function varint(number) {
  const bytes = [];
  do { let b = number & 127; number = Math.floor(number / 128); if (number) b |= 128; bytes.push(b); } while (number);
  return Buffer.from(bytes);
}
function readVarint(data, start) {
  let value = 0, shift = 0, i = start;
  for (; i < data.length; i++) { const b = data[i]; value += (b & 127) * 2 ** shift; if (!(b & 128)) return [value, i + 1]; shift += 7; }
  throw new Error('Invalid base vector');
}
function packet(type, bytes) { return Buffer.concat([varint(type), varint(bytes.length), bytes]); }
function parts(data) {
  if (data[0] !== 2) throw new Error('Invalid base vector');
  const out = []; let pos = 1;
  while (pos < data.length) {
    const start = pos;
    const [type, afterType] = readVarint(data, pos);
    if (type === 0) { out.push({ type, bytes: data.subarray(start, start + 1) }); pos = start + 1; continue; }
    const [length, afterLength] = readVarint(data, afterType);
    pos = afterLength + length;
    out.push({ type, bytes: data.subarray(start, pos), data: data.subarray(afterLength, pos) });
    if (type === 6) break;
  }
  return out;
}
function withCaveat(base, condition, location, vid) {
  const all = parts(base).map(x => x.bytes);
  const final = all.length - 2;
  const added = [];
  if (location) added.push(packet(1, Buffer.from(location)));
  added.push(packet(2, Buffer.from(condition)));
  if (vid) added.push(packet(4, Buffer.from(vid)));
  added.push(Buffer.from([0]));
  all.splice(final, 0, ...added);
  return Buffer.concat([Buffer.from([2]), ...all]);
}
function withDuplicateOp(base) {
  const all = parts(base);
  const index = all.findIndex(x => x.type === 2);
  const id = all[index].data;
  let pos = 1, lastOp;
  while (pos < id.length) {
    const start = pos; const [field, a] = readVarint(id, pos); const [length, b] = readVarint(id, a);
    pos = b + length;
    if (field === 26) lastOp = id.subarray(start, pos);
  }
  if (!lastOp) throw new Error('Base vector has no operation');
  all[index].bytes = packet(2, Buffer.concat([id, lastOp]));
  return Buffer.concat([Buffer.from([2]), ...all.map(x => x.bytes)]);
}
function withoutLocation(base) {
  const all = parts(base); const index = all.findIndex(x => x.type === 1);
  if (index < 0) throw new Error('Base vector has no location');
  all.splice(index, 1);
  return Buffer.concat([Buffer.from([2]), ...all.map(x => x.bytes)]);
}
function fingerprint(data) {
  const p = spawnSync('openssl', ['dgst', '-sha256', '-binary'], { input: data, maxBuffer: 1000 });
  if (p.status !== 0 || p.stdout?.length !== 32) throw new Error('openssl SHA-256 failed');
  return `fp:${p.stdout.toString('hex').slice(0, 16)}`;
}

const gradeRows = [
  ['admin-set', ['info:read', 'macaroon:generate'], 'ADMIN'],
  ['spend-pair', ['offchain:read', 'offchain:write'], 'SPEND'],
  ['signer-read', ['signer:read'], 'READ'],
  ['info-write', ['info:write'], 'OPERATE'],
  ['onchain-generate', ['onchain:generate'], 'SPEND'],
  ['peers-pair', ['peers:read', 'peers:write'], 'OPERATE'],
  ['uri-disconnect', ['uri:/lnrpc.Lightning/DisconnectPeer'], 'OPERATE'],
  ['invoice-send', ['invoices:read', 'uri:/routerrpc.Router/SendPaymentV2'], 'SPEND'],
  ['uri-read-pair', ['uri:/lnrpc.Lightning/GetInfo', 'uri:/lnrpc.Lightning/ListInvoices'], 'READ'],
  ['uri-add-invoice', ['uri:/lnrpc.Lightning/AddInvoice'], 'RECEIVE'],
  ['unknown-uri', ['uri:/example.Unknown/Method'], 'UNASSESSED'],
  ['unknown-entity', ['info:read', 'loop:write'], 'UNASSESSED'],
  ['remote-signer', ['remotesigner:generate'], 'UNASSESSED'],
  ['admin-unknown', ['macaroon:generate', 'loop:write'], 'ADMIN'],
  ['unknown-action', ['info:delete'], 'UNASSESSED'],
  ['malformed-info', ['info'], 'UNASSESSED'],
  ['malformed-info-empty', ['info:'], 'UNASSESSED'],
  ['malformed-empty-read', [':read'], 'UNASSESSED'],
  ['malformed-case', ['INFO:READ'], 'UNASSESSED'],
  ['malformed-uri-empty', ['uri:'], 'UNASSESSED'],
  ['malformed-uri-read', ['uri:read'], 'UNASSESSED'],
  ['empty', [], 'UNASSESSED'],
  ['duplicate-info', ['info:read', 'info:read'], 'READ'],
];
const presets = [
  ['read-only', ['info:read', 'onchain:read', 'offchain:read', 'address:read', 'invoices:read', 'peers:read'], 'READ'],
  ['invoice-only', ['info:read', 'invoices:read', 'invoices:write'], 'RECEIVE'],
  ['pay-only', ['info:read', 'uri:/routerrpc.Router/SendPaymentV2', 'uri:/routerrpc.Router/TrackPaymentV2', 'uri:/lnrpc.Lightning/DecodePayReq'], 'SPEND'],
];

let stage, baseTmp;
try {
  const info = checked('getinfo');
  if (info.chains?.[0]?.network !== 'regtest' || !info.version?.startsWith('0.21.4-beta')) throw new Error('FixtureInvalidError: expected LND 0.21.4-beta on regtest');
  const rawPermissions = checked('listpermissions').method_permissions;
  if (!rawPermissions || typeof rawPermissions !== 'object') throw new Error('Invalid ListPermissions response');
  const methods = Object.fromEntries(Object.entries(rawPermissions).map(([method, value]) => [method, (value.permissions || []).map(p => `${p.entity}:${p.action}`)]));
  const emptyBake = await observeEmptyBake();
  if (emptyBake.status < 400 || !emptyBake.message) throw new Error('REFERENCE_CONFLICT: LND accepted an empty permission list');
  baseTmp = resolve(process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp'));
  mkdirSync(baseTmp, { recursive: true });
  stage = join(baseTmp, `cp004-vectors-${process.pid}`);
  mkdirSync(stage, { recursive: true });
  const vectors = []; const notBakeable = [];
  function add(name, data, purpose, source, expectedGrade, canonicalLength = data.length) {
    const file = `${name}.macaroon`;
    writeFileSync(join(stage, file), data);
    const remote = `/tmp/macwarden-cp004-${process.pid}-${file}`;
    docker(['cp', join(stage, file), `lnd:${remote}`]);
    let output;
    try { output = checked('printmacaroon', [`--macaroon_file=${remote}`]); }
    finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
    writeFileSync(join(stage, `${name}.printmacaroon.json`), JSON.stringify(output, null, 2) + '\n');
    const fp = fingerprint(data.subarray(0, canonicalLength));
    vectors.push({ name, file, purpose, source, expectedGrade, fingerprint: fp, canonicalLength, network: 'regtest', lndVersion: info.version });
    process.stdout.write(`${name} ${fp}\n`);
  }
  function bake(name, permissions, grade, purpose, external = false, rootId) {
    if (permissions.length === 0) {
      notBakeable.push({ row: name, reason: `LND REST BakeMacaroon: ${emptyBake.message}` });
      return;
    }
    const remote = `/tmp/macwarden-cp004-${process.pid}-${name}.macaroon`;
    const args = [`--save_to=${remote}`, ...(rootId ? [`--root_key_id=${rootId}`] : []), ...(external ? ['--allow_external_permissions'] : []), ...permissions];
    const result = call('bakemacaroon', args);
    if (result.status !== 0) {
      notBakeable.push({ row: name, reason: String(result.stderr || result.stdout).trim().slice(0, 1000) });
      return;
    }
    const local = join(stage, `${name}.macaroon`);
    docker(['cp', `lnd:${remote}`, local]);
    docker(['exec', '-T', 'lnd', 'rm', '-f', remote]);
    add(name, readFileSync(local), purpose, 'lncli', grade);
  }
  for (const [name, remote, grade] of [
    ['default-admin', '/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon', 'ADMIN'],
    ['default-readonly', '/root/.lnd/data/chain/bitcoin/regtest/readonly.macaroon', 'READ'],
    ['default-invoice', '/root/.lnd/data/chain/bitcoin/regtest/invoice.macaroon', 'RECEIVE'],
  ]) {
    const local = join(stage, `${name}.macaroon`);
    docker(['cp', `lnd:${remote}`, local]);
    add(name, readFileSync(local), `LND ${name} file`, 'lncli', grade);
  }
  for (const [name, permissions, grade] of presets) bake(`preset-${name}`, permissions, grade, `${name} preset`);
  for (const [name, permissions, grade] of gradeRows) bake(`grade-${name}`, permissions, grade, `SPEC grade row ${name}`, true);
  bake('root-max', ['info:read'], 'READ', 'Maximum uint64 root key ID', false, '18446744073709551615');
  const base = readFileSync(join(stage, 'grade-signer-read.macaroon'));
  for (const [name, args, purpose] of [
    ['time-before', ['--timeout=3600'], 'time-before caveat'],
    ['ipaddr', ['--ip_address=127.0.0.1'], 'ipaddr caveat'],
  ]) {
    const remoteIn = `/tmp/macwarden-cp004-${process.pid}-${name}-in.macaroon`;
    const remoteOut = `/tmp/macwarden-cp004-${process.pid}-${name}-out.macaroon`;
    docker(['cp', join(stage, 'grade-signer-read.macaroon'), `lnd:${remoteIn}`]);
    const p = call('constrainmacaroon', [...args, remoteIn, remoteOut]);
    if (p.status !== 0) throw new Error(`${name} constraint failed`);
    const local = join(stage, `${name}.macaroon`);
    docker(['cp', `lnd:${remoteOut}`, local]);
    docker(['exec', '-T', 'lnd', 'rm', '-f', remoteIn, remoteOut]);
    add(name, readFileSync(local), purpose, 'lncli', 'READ');
  }
  const structural = [
    ['third-party', withCaveat(base, 'fixture-third-party', 'fixture-location', Buffer.from([1, 2, 3])), 'third-party caveat at fixture-location'],
    ['unknown-condition', withCaveat(base, 'mystery value'), 'unknown condition'],
    ['iprange', withCaveat(base, 'iprange 127.0.0.0/8'), 'iprange condition'],
    ['lnd-custom', withCaveat(base, 'lnd-custom fixture yes'), 'lnd-custom condition'],
    ['time-nanosecond', withCaveat(base, 'time-before 2030-01-01T00:00:00.123456789Z'), 'nanosecond time-before'],
    ['time-unparseable', withCaveat(base, 'time-before nonsense'), 'unparseable time-before'],
    ['duplicate-ops', withDuplicateOp(base), 'duplicate operation'],
    ['no-location', withoutLocation(base), 'missing location'],
    ['trailing-bytes', Buffer.concat([base, Buffer.from([0xde, 0xad])]), 'trailing bytes'],
  ];
  for (const [name, data, purpose] of structural) add(name, data, purpose, 'hand-made', 'READ', name === 'trailing-bytes' ? base.length : data.length);
  writeFileSync(join(stage, 'manifest.json'), JSON.stringify({ vectors, notBakeable }, null, 2) + '\n');
  writeFileSync(join(stage, 'README.md'), '# Test vectors\n\nThese files are throwaway regtest credentials from a disposable node. They carry no production authority. Regenerate with `npm run fixture:up` then `node scripts/make-vectors.mjs`. Structural files are labeled `hand-made` in the manifest and make no LND acceptance claim.\n');
  const out = join(root, 'test', 'vectors');
  if (resolve(out) !== resolve(root, 'test', 'vectors') || !resolve(out).startsWith(resolve(root) + sep)) throw new Error('Unsafe vector output path');
  if (existsSync(out)) rmSync(out, { recursive: true, force: true });
  renameSync(stage, out); stage = null;
  const snapshotDir = join(root, 'src', 'grade'); mkdirSync(snapshotDir, { recursive: true });
  writeFileSync(join(snapshotDir, 'lnd-permissions.json'), JSON.stringify({ lndVersion: '0.21.4-beta', methods }, null, 2) + '\n');
  process.stdout.write(`Generated ${vectors.length} vectors and ${Object.keys(methods).length} method permissions; ${notBakeable.length} rows could not bake.\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
} finally {
  if (stage && existsSync(stage)) {
    if (!baseTmp || !resolve(stage).startsWith(baseTmp + sep)) {
      process.stderr.write('Unsafe vector staging path\n');
      process.exitCode = 1;
    } else rmSync(stage, { recursive: true, force: true });
  }
}
