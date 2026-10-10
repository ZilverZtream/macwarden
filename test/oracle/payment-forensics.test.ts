import { expectDocumentValid, expectWatchEventValid } from '../helpers/output-schema.js';
import { fixtureTopology } from '../fixture/topology.mjs';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';
import { findLeaks } from '../helpers/leak-check.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { registerFixtureSentinel, requirePinnedFixture } from '../helpers/lnd-facts.mjs';

// Owner request 2026-10-09 (1.2.0): payments made with credentials macwarden baked, observed by
// `watch --payment-journal` and reconciled against LND. The pinned regtest node pays a second
// pinned LND (test/fixture/payments-compose.yml, added to the fixture's Compose project) through
// a direct channel, so payments really settle, fail and stay in flight. Credentials are read by
// path and never leave the container or this process except as fingerprints and credential IDs.
const repo = resolve();
const suppliedTmp = process.env.MACWARDEN_TEST_TMP;
const suppliedSentinels = process.env.MACWARDEN_SENTINEL_DIR;
if (!suppliedTmp || !suppliedSentinels) throw new FixtureInvalidError('Scoped test tmp and sentinel directories required');
const outerTmp = resolve(suppliedTmp), sentinelDir = resolve(suppliedSentinels);
const tmp = join(outerTmp, 'payment-forensics');
const declarations = join(outerTmp, 'declared-out.txt');
const topology = fixtureTopology();
const compose = [...topology.composeArgs, '-f', 'test/fixture/payments-compose.yml'];
const registry = join(tmp, 'registry.json');
const journal = join(tmp, 'payments.journal');
const remote = (part: string) => `/tmp/macwarden-payments-${process.pid}-${part}.macaroon`;
const BITCOIN_CLI = ['bitcoin-cli', '-regtest', '-rpcuser=fixture', '-rpcpassword=fixture-only-disposable'];
// A valid public key no node in this regtest network has: a keysend to it finds no route.
const UNREACHABLE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
let flags: string[] = [];
const bakedIds: string[] = [];
const heldHashes: string[] = [];

function docker(args: string[], timeout = 60_000) {
  return spawnSync('docker', [...compose, ...args], { cwd: repo, encoding: 'utf8', maxBuffer: 8_000_000, timeout, env: childEnvironment() });
}
function json(service: string, args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', service, ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture ${service} ${args.slice(0, 3).join(' ')} unavailable`);
  try { return JSON.parse(result.stdout) as Record<string, unknown>; }
  catch { throw new FixtureInvalidError(`Fixture ${service} ${args.slice(0, 3).join(' ')} returned invalid JSON`); }
}
const lncli = (args: string[]) => json('lnd', ['lncli', '--network=regtest', ...args]);
const payee = (args: string[]) => json('lnd-payee', ['lncli', '--network=regtest', ...args]);
const mine = (blocks: number, address: string) => {
  const result = docker(['exec', '-T', 'bitcoind', ...BITCOIN_CLI, 'generatetoaddress', String(blocks), address]);
  if (result.status !== 0) throw new FixtureInvalidError('Fixture block generation unavailable');
};
function declare(path: string): string { appendFileSync(declarations, `${path}\n`); return path; }
function cli(command: string, args: string[], withFlags = true) {
  return spawnSync(process.execPath, [resolve('dist/bin.js'), command, ...args, ...(withFlags ? flags : []), '--json'],
    { env: childEnvironment(), encoding: 'utf8', timeout: 120_000, windowsHide: true });
}
/** Copies a credential macwarden wrote into the payer container, for lncli to use there. */
function place(local: string, name: string): string {
  const target = remote(name);
  if (docker(['cp', local, `lnd:${target}`]).status !== 0) throw new FixtureInvalidError('Fixture credential copy unavailable');
  return target;
}
const sleep = (ms: number) => new Promise(done => setTimeout(done, ms));
async function waitFor<T>(what: string, probe: () => T | null | undefined | false, timeoutMs = 90_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let value: T | null | undefined | false;
    try { value = probe(); } catch { value = null; }
    if (value) return value;
    if (Date.now() > deadline) throw new FixtureInvalidError(`Fixture did not reach: ${what}`);
    await sleep(1_000);
  }
}
function startWatch(seconds: number) {
  const child = spawn(process.execPath, [resolve('dist/bin.js'), 'watch', ...flags, '--lnd-grpc', `localhost:${topology.grpcPort}`,
    '--payment-journal', journal, '--until', `${seconds}s`, '--json'], { env: childEnvironment(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout!.on('data', chunk => { stdout += String(chunk); });
  child.stderr!.on('data', chunk => { stderr += String(chunk); });
  const registered = new Promise<void>((done, fail) => {
    const timer = setTimeout(() => fail(new Error(`watch did not register: ${stdout} ${stderr}`)), 30_000);
    child.on('close', () => { clearTimeout(timer); if (!stdout.includes('"status":"registered"')) fail(new Error(`watch exited: ${stdout} ${stderr}`)); });
    child.stdout!.on('data', () => { if (stdout.includes('"status":"registered"')) { clearTimeout(timer); done(); } });
  });
  const exited = new Promise<number | null>(done => child.on('close', code => done(code)));
  return { registered, exited, lines: () => stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line) as Record<string, unknown>) };
}

beforeAll(async () => {
  requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true }); mkdirSync(sentinelDir, { recursive: true });
  const cert = declare(join(tmp, 'tls.cert'));
  if (docker(['cp', 'lnd:/root/.lnd/tls.cert', cert]).status !== 0) throw new FixtureInvalidError('Fixture certificate unavailable');
  const adminCopy = join(tmp, 'admin-source.macaroon');
  if (docker(['cp', 'lnd:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon', adminCopy]).status !== 0)
    throw new FixtureInvalidError('Fixture admin macaroon unavailable');
  const own = declare(registerFixtureSentinel(adminCopy, 'payments-own-admin.macaroon', sentinelDir));
  rmSync(adminCopy, { force: true });
  flags = ['--lnd-rest', `localhost:${topology.restPort}`, '--tls-cert', cert, '--macaroon', own, '--registry', registry];

  // The payee node, funds for the payer and one direct channel (the payer's outbound liquidity).
  if (docker(['up', '-d', 'lnd-payee'], 120_000).status !== 0) throw new FixtureInvalidError('Fixture payee node unavailable');
  const payeeInfo = await waitFor('payee getinfo', () => {
    const info = payee(['getinfo']);
    return typeof info.identity_pubkey === 'string' && (info.chains as { network?: string }[] | undefined)?.[0]?.network === 'regtest'
      && String(info.version).startsWith('0.21.4-beta') ? info : null;
  });
  const address = String(lncli(['newaddress', 'p2wkh']).address);
  mine(101, address);
  await waitFor('payer funds confirmed', () => Number(lncli(['walletbalance']).confirmed_balance) > 2_000_000 && lncli(['getinfo']).synced_to_chain === true);
  // The payee starts after 101 blocks were mined and must catch up; under full validation the
  // LND shards and the Core Lightning fixture share Docker, so catching up can take minutes.
  // A block every 10 s gives it a fresh tip to sync to; 170 s was not enough once in three full runs,
  // so the wait and the hook have their own budgets, inside the oracle command limit.
  let lastBlock = Date.now();
  await waitFor('payee synced', () => {
    if (payee(['getinfo']).synced_to_chain === true) return true;
    if (Date.now() - lastBlock >= 10_000) { mine(1, address); lastBlock = Date.now(); }
    return null;
  }, 480_000);
  const payeeKey = String(payeeInfo.identity_pubkey);
  await waitFor('peer connection', () => {
    const peers = lncli(['listpeers']).peers as { pub_key: string }[];
    if (peers.some(peer => peer.pub_key === payeeKey)) return true;
    docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'connect', `${payeeKey}@lnd-payee:9735`]);
    return false;
  });
  const channels = (lncli(['listchannels']).channels as { remote_pubkey: string; active: boolean }[]) ?? [];
  if (!channels.some(channel => channel.remote_pubkey === payeeKey)) {
    lncli(['openchannel', '--node_key', payeeKey, '--local_amt', '1000000']);
    mine(6, address);
  }
  await waitFor('active channel', () => (lncli(['listchannels', '--active_only']).channels as { remote_pubkey: string }[])
    .some(channel => channel.remote_pubkey === payeeKey));
  await waitFor('payee sees the channel', () => (payee(['listchannels', '--active_only']).channels as unknown[]).length > 0);
}, 600_000);

afterAll(() => {
  // Release held payments and remove what this file added; the shared fixture keeps its own nodes.
  for (const hash of heldHashes) docker(['exec', '-T', 'lnd-payee', 'lncli', '--network=regtest', 'cancelinvoice', hash]);
  for (const id of bakedIds) docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', id]);
  for (const name of ['payer', 'keysender', 'holder']) docker(['exec', '-T', 'lnd', 'rm', '-f', remote(name)]);
  docker(['rm', '-f', '-s', '-v', 'lnd-payee'], 120_000);
}, 180_000);

it('PAYMENTS/live journaled payments by baked credentials reconcile to LND outcomes per credential, with gaps and unattributed payments', async () => {
  const payerFile = declare(join(sentinelDir, 'payments-payer.macaroon'));
  const keysendFile = declare(join(sentinelDir, 'payments-keysender.macaroon'));
  for (const [label, file] of [['payer', payerFile], ['keysender', keysendFile]]) {
    const baked = cli('bake', ['--label', label, '--preset', 'pay-only', '--out', file]);
    expect(baked.status, baked.stderr).toBe(0);
    bakedIds.push(JSON.parse(baked.stdout).result.rootKeyId as string);
  }
  const [payerRoot, keysendRoot] = bakedIds;
  const payer = place(payerFile, 'payer');
  const keysender = place(keysendFile, 'keysender');
  const pay = (macaroon: string, args: string[]) => docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${macaroon}`, ...args], 90_000);

  const settled = payee(['addinvoice', '--amt', '1000', '--memo', 'forensics-settled']);
  const settledHash = String(settled.r_hash);
  const settledRequest = String(settled.payment_request);
  const preimage = randomBytes(32);
  const heldHash = createHash('sha256').update(preimage).digest('hex');
  heldHashes.push(heldHash);
  const held = payee(['addholdinvoice', heldHash, '--amt', '500']);
  const heldRequest = String(held.payment_request);

  const watch = startWatch(90);
  await watch.registered;
  // 1. An invoice paid by the payer credential: settles.
  expect(pay(payer, ['payinvoice', '--force', settledRequest]).status).toBe(0);
  // 2. A keysend to a node no route reaches, by the second credential: LND records it as failed.
  pay(keysender, ['sendpayment', '--keysend', '--dest', UNREACHABLE, '--amt', '100', '--force']);
  // 3. A hold invoice paid by the payer credential and held by the payee: stays in flight.
  docker(['exec', '-d', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${payer}`, 'payinvoice', '--force', heldRequest]);
  await waitFor('held payment accepted by the payee', () => payee(['lookupinvoice', heldHash]).state === 'ACCEPTED');
  // Let watch reach its --until and stop; the journal then ends with run-end.
  expect(await watch.exited).toBe(0);
  const events = watch.lines();
  for (const event of events.slice(0, -1)) expectWatchEventValid(JSON.stringify(event));
  const summary = events.at(-1)!;
  expectDocumentValid(summary as { command: string });
  expect(summary).toMatchObject({ ok: true, result: { paymentJournal: { stopped: null, dropped: 0 } } });

  // 4. A payment made with admin.macaroon after watch stopped: LND has it, the journal cannot.
  const later = payee(['addinvoice', '--amt', '700', '--memo', 'forensics-unwatched']);
  expect(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'payinvoice', '--force', String(later.payment_request)], 90_000).status).toBe(0);

  // Every journal line matches the published record schema.
  const journalText = readFileSync(journal, 'utf8');
  const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false, allErrors: true });
  const validate = ajv.compile(JSON.parse(readFileSync(join(repo, 'schemas/output/payment-journal-record.schema.json'), 'utf8')));
  for (const line of journalText.split('\n').filter(Boolean)) expect(validate(JSON.parse(line)), line).toBe(true);

  const reconciled = cli('reconcile', ['--payment-journal', journal]);
  expect(reconciled.status, reconciled.stderr).toBe(1);
  const document = JSON.parse(reconciled.stdout);
  expectDocumentValid(document);
  const result = document.result;
  const byHash = new Map<string, Record<string, unknown>>(result.payments.map((item: { paymentHash: string }) => [item.paymentHash, item]));
  expect(byHash.get(settledHash)).toMatchObject({ attribution: 'single',
    observation: { requestedMsat: '1000000', observations: [expect.objectContaining({ rootKeyId: payerRoot, label: 'payer' })] },
    settlement: { status: 'succeeded', settledMsat: '1000000', feesMsat: '0', attempts: 1, predatesObservation: false } });
  expect(byHash.get(heldHash)).toMatchObject({ settlement: { status: 'in-flight', inFlightMsat: '500000' } });
  const keysends = result.payments.filter((item: { observation: { observations: { rootKeyId: string }[] } }) =>
    item.observation.observations.some(observation => observation.rootKeyId === keysendRoot));
  expect(keysends).toHaveLength(1);
  expect(keysends[0].settlement.status).toBe('failed');
  expect(keysends[0].settlement.failureReason).not.toBeNull();
  const rows = new Map<string, Record<string, unknown>>(result.credentials.map((row: { rootKeyIds: string[] }) => [row.rootKeyIds[0], row]));
  expect(rows.get(payerRoot)).toMatchObject({ label: 'payer', payments: 2, succeeded: 1, inFlight: 1, settledMsat: '1000000',
    inFlightMsat: '500000' });
  expect(rows.get(keysendRoot)).toMatchObject({ label: 'keysender', payments: 1, failed: 1, settledMsat: '0' });
  // The unwatched payment is listed by LND, attributed to nobody, and placed in a gap.
  expect(result.unattributed).toEqual([expect.objectContaining({ paymentHash: String(later.r_hash), status: 'succeeded', coverage: 'gap' })]);
  expect(result.coverage.complete).toBe(false);
  expect(result.coverage.gaps.at(-1)).toMatchObject({ reason: 'not-running' });
  const codes = document.warnings.map((item: string | { code: string }) => typeof item === 'string' ? item : item.code);
  expect(codes).toEqual(expect.arrayContaining(['journal-gaps', 'unattributed-payments', 'payments-uncertain']));

  // No credential, invoice text or preimage in the journal or any output.
  const everything = journalText + reconciled.stdout + JSON.stringify(events);
  for (const value of [settledRequest, heldRequest, String(later.payment_request), preimage.toString('hex'),
    readFileSync(payerFile).toString('hex'), readFileSync(keysendFile).toString('hex')]) expect(everything).not.toContain(value);
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir, paths: [tmp], testTmp: outerTmp, root: repo,
    commandOutput: everything })).toBeNull();
}, 300_000);
