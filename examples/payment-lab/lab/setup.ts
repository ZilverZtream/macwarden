import { mkdirSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { NODE_NAMES, RUNTIME_DIR, type CredentialEntry, type LabManifest, type NodeName } from '../src/config.ts';
import { bitcoinCli, compose, composeOrThrow, field, lncli, lncliMaybe, mine } from './compose.ts';
import { bake, bakeArgs, macwardenScript } from './macwarden.ts';
import { command, fact, say, step, title, waitUntil } from './narrate.ts';

/**
 * Builds the lab from nothing: three regtest LND nodes (customer, router,
 * merchant) and bitcoind, funded wallets, four channels with known balances,
 * a routing fee policy on the router, and one least-privilege credential per
 * role baked with macwarden. Every wait polls real node state.
 *
 *   customer ==A==> router ==C==> merchant      A, B: 500,000 sat, opened by the customer
 *   customer ==B==> router                       D: 1,000,000 sat, opened by the router
 *   customer <==D== router                       C: 2,000,000 sat, opened by the router
 *
 * The merchant opens no channel: all of its channel balance starts on the
 * router's side, so it can receive but not send (scenario 3 relies on this).
 */

const REST_PORTS: Record<NodeName, number> = { customer: 19501, router: 19502, merchant: 19503 };
const SESSION_ROOT_KEY_ID = '9001';
const CHANNEL_A_SAT = 500_000n;
const CHANNEL_D_SAT = 1_000_000n;
const CHANNEL_C_SAT = 2_000_000n;
const ROUTER_BASE_FEE_MSAT = '1000';
const ROUTER_FEE_RATE_PPM = '2000';
const UTXOS_PER_NODE = 4;
const BTC_PER_UTXO = '1.0';
const WAIT = { timeoutMs: 180_000, intervalMs: 1000 };

const CREDENTIALS: { name: string; node: NodeName; preset: CredentialEntry['preset']; purpose: string }[] = [
  { name: 'customer-payer', node: 'customer', preset: 'pay-only', purpose: 'the customer\'s payment worker' },
  { name: 'customer-invoices', node: 'customer', preset: 'invoice-only', purpose: 'refund invoices the customer receives' },
  { name: 'customer-analysis', node: 'customer', preset: 'read-only', purpose: 'payment evidence and diagnosis on the customer node' },
  { name: 'router-analysis', node: 'router', preset: 'read-only', purpose: 'forwarding evidence on the router' },
  { name: 'merchant-invoices', node: 'merchant', preset: 'invoice-only', purpose: 'the merchant\'s order invoices and settlement worker' },
  { name: 'merchant-refunds', node: 'merchant', preset: 'pay-only', purpose: 'the merchant\'s refund worker' },
  { name: 'merchant-analysis', node: 'merchant', preset: 'read-only', purpose: 'liquidity diagnosis on the merchant node' },
];

function writePrivate(path: string, data: string | Buffer): void {
  writeFileSync(path, data, { mode: 0o600, flag: 'wx' });
}

async function syncedHeight(node: NodeName, height: number): Promise<Record<string, unknown> | undefined> {
  const info = await lncliMaybe(node, ['getinfo']);
  return info !== undefined && info.synced_to_chain === true && Number(info.block_height) >= height ? info : undefined;
}

async function waitSynced(height: number): Promise<void> {
  for (const node of NODE_NAMES) await waitUntil(`${node} to sync to height ${height}`, () => syncedHeight(node, height), WAIT);
}

interface ChannelRow { chan_id: string; remote_pubkey: string; initiator: boolean; active: boolean; capacity: string }

async function channels(node: NodeName): Promise<ChannelRow[]> {
  const list = await lncli(node, ['listchannels']);
  return (Array.isArray(list.channels) ? list.channels : []) as ChannelRow[];
}

async function sessionMacaroon(node: NodeName, path: string): Promise<void> {
  // A short-lived credential for macwarden itself, on its own root key ID so it
  // can be deleted once the role credentials are baked. Baking is
  // admin-equivalent: the file is owner-only and the root key is deleted below.
  const result = await compose(['exec', '-T', node, 'lncli', '--network=regtest', 'bakemacaroon', '--root_key_id', SESSION_ROOT_KEY_ID,
    '--timeout', '3600', 'macaroon:generate', 'macaroon:read', 'macaroon:write', 'info:read']);
  if (result.code !== 0) throw new Error(`bakemacaroon on ${node} failed: ${result.stderr.trim()}`);
  const output = result.stdout.trim();
  let hex = output;
  if (output.startsWith('{')) hex = field(JSON.parse(output) as Record<string, unknown>, 'macaroon');
  if (!/^(?:[0-9a-f]{2})+$/.test(hex)) throw new Error(`bakemacaroon on ${node} returned an unexpected format`);
  writePrivate(path, Buffer.from(hex, 'hex'));
}

async function main(): Promise<void> {
  title('macwarden payment lab: setup');
  const macwarden = macwardenScript();

  step('Check that no lab is running');
  const existing = await compose(['ps', '-a', '-q']);
  if (existing.code !== 0) throw new Error(`docker compose is not available: ${existing.stderr.trim()}`);
  if (existing.stdout.trim() !== '') throw new Error('lab containers already exist: run teardown.sh or teardown.ps1 first');

  step('Start bitcoind and three LND v0.21.4-beta nodes (images pinned by digest)');
  command('docker compose up -d --wait');
  await composeOrThrow(['up', '-d', '--wait', '--wait-timeout', '180'], 300_000);

  step('Create the miner wallet and mine 101 blocks');
  await bitcoinCli(['createwallet', 'lab'], false);
  let height = await mine(101);
  fact('height', height);
  await waitSynced(height);
  const pubkeys = {} as Record<NodeName, string>;
  for (const node of NODE_NAMES) pubkeys[node] = field(await lncli(node, ['getinfo']), 'identity_pubkey');

  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  const dir = join(RUNTIME_DIR, `lab-${stamp}`);
  for (const sub of ['tls', 'sessions', 'credentials', 'data']) mkdirSync(join(dir, sub), { recursive: true, mode: 0o700 });
  fact('lab run directory', relative(process.cwd(), dir) || dir);

  step('Copy each node\'s TLS certificate (public) and bake a short-lived session credential for macwarden');
  for (const node of NODE_NAMES) {
    writeFileSync(join(dir, 'tls', `${node}.cert`), await composeOrThrow(['exec', '-T', node, 'cat', '/root/.lnd/tls.cert']), { flag: 'wx' });
    await sessionMacaroon(node, join(dir, 'sessions', `${node}.macaroon`));
    command(`lncli bakemacaroon --root_key_id ${SESSION_ROOT_KEY_ID} --timeout 3600 macaroon:generate macaroon:read macaroon:write info:read   # on ${node}`);
  }

  step('Bake one least-privilege credential per role with macwarden');
  const registry = join(dir, 'registry.json');
  const credentials: Record<string, CredentialEntry> = {};
  for (const item of CREDENTIALS) {
    const out = join(dir, 'credentials', `${item.name}.macaroon`);
    const request = { label: `lab-${item.name}`, preset: item.preset, expires: '7d', out, rest: `127.0.0.1:${REST_PORTS[item.node]}`,
      tlsCert: join(dir, 'tls', `${item.node}.cert`), sessionMacaroon: join(dir, 'sessions', `${item.node}.macaroon`), registry };
    command(`macwarden ${bakeArgs(request).map(arg => (arg.includes(' ') ? `"${arg}"` : arg)).join(' ')}`);
    const baked = await bake(request);
    say(`${item.name}: ${item.preset} (${baked.grade}) on ${item.node}, root key ID ${baked.rootKeyId}, fp:${baked.fingerprint.replace(/^fp:/, '')}; for ${item.purpose}`);
    credentials[item.name] = { node: item.node, preset: item.preset, label: request.label, path: relative(dir, out),
      rootKeyId: baked.rootKeyId, fingerprint: baked.fingerprint };
  }
  say(`macwarden ran as ${macwarden}`);

  step(`Delete the session root key ${SESSION_ROOT_KEY_ID} on each node: the session credentials stop working`);
  for (const node of NODE_NAMES) {
    command(`lncli deletemacaroonid ${SESSION_ROOT_KEY_ID}   # on ${node}`);
    await lncli(node, ['deletemacaroonid', SESSION_ROOT_KEY_ID]);
  }

  step(`Fund each LND wallet with ${UTXOS_PER_NODE} on-chain outputs of ${BTC_PER_UTXO} BTC`);
  for (const node of NODE_NAMES) {
    for (let index = 0; index < UTXOS_PER_NODE; index += 1) {
      const address = field(await lncli(node, ['newaddress', 'p2tr']), 'address');
      await bitcoinCli(['sendtoaddress', address, BTC_PER_UTXO]);
    }
  }
  height = await mine(6);
  await waitSynced(height);
  const expectedSat = BigInt(UTXOS_PER_NODE) * 100_000_000n;
  for (const node of NODE_NAMES) {
    await waitUntil(`${node} to see ${expectedSat} sat confirmed`, async () => {
      const balance = await lncli(node, ['walletbalance']);
      return BigInt(field(balance, 'confirmed_balance')) >= expectedSat ? true : undefined;
    }, WAIT);
  }

  step('Connect peers: customer -> router, router -> merchant');
  await lncli('customer', ['connect', `${pubkeys.router}@router:9735`]);
  await lncli('router', ['connect', `${pubkeys.merchant}@merchant:9735`]);
  for (const [node, peer] of [['customer', 'router'], ['router', 'merchant']] as const) {
    await waitUntil(`${node} to list ${peer} as a peer`, async () => {
      const peers = await lncli(node, ['listpeers']);
      return Array.isArray(peers.peers) && peers.peers.some(item => (item as { pub_key?: unknown }).pub_key === pubkeys[peer]) ? true : undefined;
    }, WAIT);
  }

  step('Open channels A, B (customer), D and C (router)');
  const opens: [NodeName, NodeName, bigint, string][] = [
    ['customer', 'router', CHANNEL_A_SAT, 'A'], ['customer', 'router', CHANNEL_A_SAT, 'B'],
    ['router', 'customer', CHANNEL_D_SAT, 'D'], ['router', 'merchant', CHANNEL_C_SAT, 'C'],
  ];
  for (const [from, to, amount, name] of opens) {
    command(`lncli openchannel --node_key <${to}> --local_amt ${amount} --sat_per_vbyte 2   # channel ${name}, on ${from}`);
    await lncli(from, ['openchannel', '--node_key', pubkeys[to], '--local_amt', amount.toString(), '--sat_per_vbyte', '2']);
  }
  await waitUntil('the four funding transactions in the mempool', async () => {
    const info = JSON.parse(await bitcoinCli(['getmempoolinfo'], false)) as { size?: number };
    return (info.size ?? 0) >= opens.length ? true : undefined;
  }, WAIT);
  height = await mine(6);
  await waitSynced(height);
  const expectedActive: Record<NodeName, number> = { customer: 3, router: 4, merchant: 1 };
  for (const node of NODE_NAMES) {
    await waitUntil(`${node} to have ${expectedActive[node]} active channels`, async () => {
      const list = await channels(node);
      return list.filter(item => item.active).length === expectedActive[node] ? true : undefined;
    }, WAIT);
  }
  const routerChannels = await channels('router');
  const customerOpened = routerChannels.filter(item => item.remote_pubkey === pubkeys.customer && !item.initiator)
    .map(item => item.chan_id).sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
  const routerToCustomer = routerChannels.find(item => item.remote_pubkey === pubkeys.customer && item.initiator);
  const routerToMerchant = routerChannels.find(item => item.remote_pubkey === pubkeys.merchant && item.initiator);
  if (customerOpened.length !== 2 || !routerToCustomer || !routerToMerchant) throw new Error('the router does not show the expected channels');
  const ids = { customerRouterA: customerOpened[0] ?? '', customerRouterB: customerOpened[1] ?? '',
    routerCustomer: routerToCustomer.chan_id, routerMerchant: routerToMerchant.chan_id };
  for (const [name, id] of Object.entries(ids)) fact(`channel ${name}`, id);

  step(`Set the router's fee policy: ${ROUTER_BASE_FEE_MSAT} msat base + ${ROUTER_FEE_RATE_PPM} ppm on every channel`);
  command(`lncli updatechanpolicy --base_fee_msat ${ROUTER_BASE_FEE_MSAT} --fee_rate_ppm ${ROUTER_FEE_RATE_PPM} --time_lock_delta 40   # on router`);
  await lncli('router', ['updatechanpolicy', '--base_fee_msat', ROUTER_BASE_FEE_MSAT, '--fee_rate_ppm', ROUTER_FEE_RATE_PPM, '--time_lock_delta', '40']);

  step('Wait until each sender\'s graph has the router\'s policy for the channels it routes over');
  const routerPolicyVisible = async (viewer: NodeName, chanId: string): Promise<true | undefined> => {
    const edge = await lncliMaybe(viewer, ['getchaninfo', '--chan_id', chanId]);
    if (edge === undefined) return undefined;
    const policy = (edge.node1_pub === pubkeys.router ? edge.node1_policy : edge.node2_policy) as Record<string, unknown> | null;
    const other = (edge.node1_pub === pubkeys.router ? edge.node2_policy : edge.node1_policy) as Record<string, unknown> | null;
    return policy && other && String(policy.fee_rate_milli_msat) === ROUTER_FEE_RATE_PPM
      && String(policy.fee_base_msat) === ROUTER_BASE_FEE_MSAT ? true : undefined;
  };
  for (const [viewer, chanId, name] of [['customer', ids.routerMerchant, 'C'], ['merchant', ids.customerRouterA, 'A'],
    ['merchant', ids.customerRouterB, 'B'], ['merchant', ids.routerCustomer, 'D']] as const) {
    await waitUntil(`${viewer} to know channel ${name} with the router's policy`, () => routerPolicyVisible(viewer, chanId), WAIT);
  }

  step('Write the lab manifest');
  const manifest: LabManifest = {
    schema: 1,
    createdAt: new Date().toISOString(),
    composeProject: 'macwarden-payment-lab',
    nodes: {
      customer: { rest: `127.0.0.1:${REST_PORTS.customer}`, tlsCert: 'tls/customer.cert', pubkey: pubkeys.customer },
      router: { rest: `127.0.0.1:${REST_PORTS.router}`, tlsCert: 'tls/router.cert', pubkey: pubkeys.router },
      merchant: { rest: `127.0.0.1:${REST_PORTS.merchant}`, tlsCert: 'tls/merchant.cert', pubkey: pubkeys.merchant },
    },
    channels: ids,
    routerPolicy: { baseFeeMsat: ROUTER_BASE_FEE_MSAT, feeRatePpm: ROUTER_FEE_RATE_PPM },
    credentials,
  };
  writeFileSync(join(dir, 'lab.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
  writeFileSync(join(RUNTIME_DIR, 'current.json'), `${JSON.stringify({ dir: `lab-${stamp}` })}\n`);
  for (const node of NODE_NAMES) fact(`${node} REST`, `${manifest.nodes[node].rest} (${pubkeys[node]})`);
  say('Setup complete. Run a scenario, for example: scenarios/1-dropped-connection.sh');
}

main().catch((error: unknown) => {
  process.stderr.write(`\nsetup failed: ${error instanceof Error ? error.message : String(error)}\n`
    + 'The containers are left as they are for inspection; teardown.sh or teardown.ps1 removes them.\n');
  process.exitCode = 1;
});
