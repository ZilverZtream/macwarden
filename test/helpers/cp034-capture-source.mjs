// Reproduce the independent, immutable primary-source inventory; no LND contact.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const base = resolve('test/oracle/btcpay');
const scratch = resolve('test/.tmp/cp034/source');
const clientRevision = '62164e9394295bb27ebd06b769c6038f9277fb37';
const serverRevision = '2d5a0d8077bb33af080e949031da33d84b80638d';
const lndRevision = '390b2d2b7bdcc335c183962e483f5daeceb8f0e7';
const hash = value => createHash('sha256').update(value).digest('hex');
const sources = {};
mkdirSync(base, { recursive: true });
async function source(id, repository, revision, path, local) {
  const response = await fetch(`https://raw.githubusercontent.com/${repository}/${revision}/${path}`);
  if (!response.ok) throw new Error(`Primary source unavailable: ${path}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (!bytes.length || bytes.toString().startsWith('404:')) throw new Error(`Primary source unavailable: ${path}`);
  const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
  sources[id] = { repository, revision, path, url: `https://github.com/${repository}/blob/${revision}/${path}`,
    sha256: hash(bytes), gitBlob: blob, ...(local ? { local } : {}) };
  if (local) writeFileSync(join(base, local), bytes);
  return bytes.toString('utf8');
}
const client = await source('client', 'btcpayserver/BTCPayServer.Lightning', clientRevision,
  'src/BTCPayServer.Lightning.LND/LndClient.cs', 'LndClient.cs');
if (sources.client.gitBlob !== 'd62fe09cc56744ab291b35a42e2ba75b16336e6a') throw new Error('Client Git blob mismatch');
const swagger = await source('swagger', 'btcpayserver/BTCPayServer.Lightning', clientRevision,
  'src/BTCPayServer.Lightning.LND/LndSwaggerClient.cs');
const cancel = await source('cancel', 'btcpayserver/BTCPayServer.Lightning', clientRevision,
  'src/BTCPayServer.Lightning.LND/LndSwaggerClient.partial2.cs', 'LndSwaggerClient.partial2.cs');
await source('server', 'btcpayserver/btcpayserver', serverRevision, 'BTCPayServer/BTCPayServer.csproj', 'BTCPayServer.csproj');
const rpc = await source('rpc', 'lightningnetwork/lnd', lndRevision, 'rpcserver.go');
const router = await source('router', 'lightningnetwork/lnd', lndRevision, 'lnrpc/routerrpc/router_server.go');
const invoices = await source('invoices', 'lightningnetwork/lnd', lndRevision, 'lnrpc/invoicesrpc/invoices_server.go');
const lightningYaml = await source('lightningYaml', 'lightningnetwork/lnd', lndRevision, 'lnrpc/lightning.yaml');
const routerYaml = await source('routerYaml', 'lightningnetwork/lnd', lndRevision, 'lnrpc/routerrpc/router.yaml');
const invoicesYaml = await source('invoicesYaml', 'lightningnetwork/lnd', lndRevision, 'lnrpc/invoicesrpc/invoices.yaml');
const excerpt = (id, text, start, end) => ({ source: id, line: text.slice(0, start).split('\n').length,
  text: text.slice(start, end) });
const swMethod = name => {
  const pattern = new RegExp(`public async [^\\n]+\\b${name}\\(`);
  const match = pattern.exec(swagger);
  if (!match) throw new Error(`Unattributed helper: ${name}`);
  const end = swagger.indexOf('\n        ///', match.index);
  return excerpt('swagger', swagger, match.index, end < 0 ? swagger.length : end);
};
const entries = [
  ['AddInvoiceAsync', 'lnrpc.Lightning/AddInvoice', 'CreateInvoice', ['addinvoice', '--amt=1']],
  ['CancelInvoiceAsync', 'invoicesrpc.Invoices/CancelInvoice', 'CancelInvoice', ['cancelinvoice', '--paymenthash={invoiceHash}']],
  ['ListChannelsAsync', 'lnrpc.Lightning/ListChannels', 'ListChannels', ['listchannels']],
  ['GetInfoAsync', 'lnrpc.Lightning/GetInfo', 'GetInfo', ['getinfo']],
  ['WalletBalanceAsync', 'lnrpc.Lightning/WalletBalance', 'GetBalance', ['walletbalance']],
  ['ChannelBalanceAsync', 'lnrpc.Lightning/ChannelBalance', 'GetBalance', ['channelbalance']],
  ['PendingChannelsAsync', 'lnrpc.Lightning/PendingChannels', 'GetBalance; OpenChannel error-177 fallback', ['pendingchannels']],
  ['LookupInvoiceAsync', 'lnrpc.Lightning/LookupInvoice', 'GetInvoice overloads -> GetInvoice(byte[])', ['lookupinvoice', '{invoiceHash}']],
  ['ListInvoicesAsync', 'lnrpc.Lightning/ListInvoices', 'ListInvoices overloads', ['listinvoices']],
  ['ListPaymentsAsync', 'lnrpc.Lightning/ListPayments', 'ListPayments overloads', ['listpayments']],
  ['OpenChannelSyncAsync', 'lnrpc.Lightning/OpenChannelSync', 'OpenChannel', null],
  ['NewWitnessAddressAsync', 'lnrpc.Lightning/NewAddress', 'GetDepositAddress -> NewWitnessAddressAsync', ['newaddress', 'p2wkh']],
  ['ConnectPeer', 'lnrpc.Lightning/ConnectPeer', 'ConnectTo -> ConnectPeer -> ConnectPeerAsync', ['connect', '{nodePubkey}@127.0.0.1:1', '--timeout=1s']],
  [null, 'lnrpc.Lightning/SubscribeInvoices', 'Listen -> LndInvoiceClientSession.StartListening', null, 'v1/invoices/subscribe'],
  [null, 'routerrpc.Router/TrackPaymentV2', 'GetPayment -> LndPaymentClientSession(paymentHash)', ['trackpayment', '--json', '{unknownHash}'], 'v2/router/track/{hash}'],
  [null, 'routerrpc.Router/SendPaymentV2', 'Pay overloads -> PayAsync -> LndPaymentClientSession(sendRequest)',
    ['sendpayment', '--dest={nodePubkey}', '--amt=1', '--payment_hash={unknownHash}', '--final_cltv_delta=40', '--timeout=1s', '--json', '--force'], 'v2/router/send'],
];
const calls = entries.map(([helper, name, entry, args, direct]) => {
  const method = `/${name}`;
  let endpoints;
  if (helper === 'CancelInvoiceAsync') endpoints = [{ source: 'cancel', line: 1, text: cancel }];
  else if (helper) endpoints = [swMethod(helper), ...(helper === 'ConnectPeer' ? [swMethod('ConnectPeerAsync')] : [])];
  else endpoints = [];
  const needle = helper ? `SwaggerClient.${helper}(` : direct;
  const lines = client.split('\n').flatMap((text, index) => text.includes(needle) ? [{ source: 'client', line: index + 1, text }] : []);
  if (!lines.length) throw new Error(`Required call missing from client: ${method}`);
  const mapText = name.startsWith('routerrpc.') ? router : name.startsWith('invoicesrpc.') ? invoices : rpc;
  const mapId = name.startsWith('routerrpc.') ? 'router' : name.startsWith('invoicesrpc.') ? 'invoices' : 'rpc';
  const start = mapText.indexOf(`"${method}":`), end = mapText.indexOf('\n\t\t}},', start) + '\n\t\t}},'.length;
  if (start < 0 || end < start) throw new Error(`Missing LND permission attribution: ${method}`);
  const permissionsSource = excerpt(mapId, mapText, start, end);
  const permissions = [...permissionsSource.text.matchAll(/Entity: "([^"]+)",\s+Action: "([^"]+)"/g)]
    .map(match => `${match[1]}:${match[2]}`);
  const yaml = name.startsWith('routerrpc.') ? routerYaml : name.startsWith('invoicesrpc.') ? invoicesYaml : lightningYaml;
  const yamlId = name.startsWith('routerrpc.') ? 'routerYaml' : name.startsWith('invoicesrpc.') ? 'invoicesYaml' : 'lightningYaml';
  const selector = name.replace('/', '.');
  const ys = yaml.indexOf(`    - selector: ${selector}\n`), ye = yaml.indexOf('    - selector:', ys + 1);
  if (ys < 0) throw new Error(`Missing REST mapping: ${method}`);
  return { method, entry, helper, direct: direct || null, clientLocations: lines, endpointSources: endpoints,
    restMapping: excerpt(yamlId, yaml, ys, ye < 0 ? yaml.length : ye), permissions, permissionsSource,
    lncli: args ? { args } : { args: null, blocker: method.endsWith('/OpenChannelSync') ?
      'Pinned lncli openchannel invokes OpenChannel, not OpenChannelSync.' : 'Pinned lncli has no SubscribeInvoices invocation.' } };
}).sort((a, b) => a.method.localeCompare(b.method, 'en'));
const tree = JSON.parse(readFileSync(join(scratch, 'lnd-tree.json'), 'utf8'));
const commandPaths = tree.tree.filter(item => /^cmd\/commands\/.*\.go$/.test(item.path) && !item.path.endsWith('_test.go')).map(item => item.path);
const commandInventory = await Promise.all(commandPaths.map(async path => {
  const id = `lncli-${path.split('/').pop()}`;
  const text = await source(id, 'lightningnetwork/lnd', lndRevision, path);
  return { source: id, rpcCalls: [...text.matchAll(/\b(?:client|routerClient|lnClient|NewRouterClient\(payConn\))\.([A-Z]\w+)\(/g)]
    .map(match => ({ method: match[1], line: text.slice(0, match.index).split('\n').length })),
    unavailableMethodCalls: [...text.matchAll(/\.(SubscribeInvoices|OpenChannelSync)\(/g)].map(match => match[1]) };
}));
for (const record of commandInventory) if (record.unavailableMethodCalls.length) throw new Error('Re-evaluate lncli method coverage');
const packages = ['all', 'lnd'].map(name => {
  const bytes = readFileSync(join(scratch, `${name}.nupkg`));
  const expected = name === 'all' ? 'c8c08b1d74c6c5ec64a48e778796e31297b9033140447f04f3fb8c107504bdde' :
    '6f8e82b36135b0562c0545bead7bf23554dd6a7089e0afb989f432684fe40849';
  if (hash(bytes) !== expected) throw new Error('Official NuGet package hash mismatch');
  return { name: name === 'all' ? 'BTCPayServer.Lightning.All' : 'BTCPayServer.Lightning.LND',
    version: name === 'all' ? '1.7.8' : '1.7.2', sha256: expected,
    url: `https://api.nuget.org/v3-flatcontainer/btcpayserver.lightning.${name}/${name === 'all' ? '1.7.8' : '1.7.2'}/btcpayserver.lightning.${name}.${name === 'all' ? '1.7.8' : '1.7.2'}.nupkg` };
});
writeFileSync(join(base, 'manifest.json'), JSON.stringify({ schema: 1, supportedVersion: 'BTCPay Server v2.4.4',
  serverRevision, clientRevision, lndRevision, lndVersion: '0.21.4-beta', packages,
  supportedScope: 'All LndClient ILightningClient operations at the pinned dependency, including payment, cancellation, channels, balances, deposit address and peer helpers. No client operation is omitted. Uncalled generated Swagger endpoints, other backends and other versions are not claimed.',
  sources, calls, permissions: calls.map(call => `uri:${call.method}`).sort(), expectedGrade: 'SPEND',
  snapshotSha256: hash(readFileSync(resolve('src/grade/lnd-permissions.json'))), commandInventory,
  forbidden: { method: '/lnrpc.Lightning/ListMacaroonIDs', args: ['listmacaroonids'], permissions: ['macaroon:read'] },
}, null, 2) + '\n');
process.stdout.write(`Captured ${calls.length} required methods; two native lncli coverage blockers.\n`);
