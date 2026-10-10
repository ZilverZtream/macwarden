// Safe agent payments with macwarden: a regtest walk-through.
//
//   node demo.mjs              start the stack from scratch and run the story; the stack stays up
//   node demo.mjs --teardown   the same, then remove containers, volumes and runtime/
//   node demo.mjs down         remove containers, volumes and runtime/
//
// Every run starts from an empty stack, so it can be repeated. Every credential is a
// throwaway regtest credential created by this script; credential files live in runtime/
// (git-ignored) and nothing here prints their bytes.
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const runtime = join(here, 'runtime');
const composeFile = join(here, 'docker-compose.yml');
const macwardenBin = resolve(process.env.MACWARDEN_BIN ?? join(here, '..', '..', 'dist', 'bin.js'));
const isWindows = process.platform === 'win32';

// Host ports (see docker-compose.yml).
const PORTS = { rest: 19380, grpc: 19309, aperture: 19381 };
const LND_REST = `127.0.0.1:${PORTS.rest}`;
const LND_GRPC = `127.0.0.1:${PORTS.grpc}`;
const SERVICE_URL = `http://127.0.0.1:${PORTS.aperture}/api/forecast`;

// Paths as the operator types them (relative to this directory).
const paths = {
  operatorDir: 'runtime/operator',
  operatorCert: 'runtime/operator/tls.cert',
  session: 'runtime/operator/macwarden-session.macaroon',
  registry: 'runtime/operator/registry.json',
  alerts: 'runtime/alerts.jsonl',
  agentDir: 'runtime/agent',
  agentCert: 'runtime/agent/tls.cert',
  agentMacaroon: 'runtime/agent/agent.macaroon',
  decoyDir: 'runtime/agent/backup',
  decoy: 'runtime/agent/backup/readonly.macaroon',
};
// The alert command watch runs for each canary alert (POSIX; see README for Windows).
const alertCommand = join(here, 'alert.sh');
const SESSION_ROOT_KEY_ID = '7001';
const CHANNEL_SAT = '1000000';
const STEPS = 7;

const out = text => process.stdout.write(text);
const indent = (text, prefix = '  ') => text.replace(/\r/g, '').split('\n').filter((line, index, all) => line || index < all.length - 1)
  .map(line => `${prefix}${line}\n`).join('');
const step = (n, title) => out(`\n== Step ${n}/${STEPS}: ${title}\n`);
const note = text => out(`   # ${text}\n`);
const sleep = ms => new Promise(done => setTimeout(done, ms));

const checks = [];
function check(name, ok, detail = '') {
  checks.push({ name, ok: Boolean(ok) });
  out(`   [${ok ? 'ok' : 'FAILED'}] ${name}${detail ? ` (${detail})` : ''}\n`);
}

/** Runs a command and resolves {code, stdout, stderr}. echo=true streams its output, indented. */
function run(command, args, { env = process.env, echo = false, timeoutMs = 120_000 } = {}) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, { cwd: here, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`${command === process.execPath ? 'node' : command} ${args.slice(0, 3).join(' ')} did not finish within ${timeoutMs / 1000} s`));
    }, timeoutMs);
    child.stdout.on('data', chunk => { stdout += chunk; if (echo) out(indent(chunk.toString())); });
    child.stderr.on('data', chunk => { stderr += chunk; if (echo) out(indent(chunk.toString())); });
    child.on('error', error => { clearTimeout(timer); reject(new Error(`cannot run ${command}: ${error.message}`)); });
    child.on('close', code => { clearTimeout(timer); resolveRun({ code, stdout, stderr }); });
  });
}

const lastLines = text => text.trim().split('\n').slice(-3).join(' | ');
const docker = (args, options) => run('docker', ['compose', '-f', composeFile, '--project-directory', here, ...args], options);
async function dockerOk(args, what, options) {
  const result = await docker(args, options);
  if (result.code !== 0) throw new Error(`${what} failed (exit ${result.code}): ${lastLines(result.stderr || result.stdout)}`);
  return result.stdout;
}
async function lncli(node, ...args) {
  const text = await dockerOk(['exec', '-T', node, 'lncli', '--network=regtest', ...args], `lncli ${args[0]} on ${node}`);
  try { return JSON.parse(text); } catch { throw new Error(`lncli ${args[0]} on ${node} returned no JSON`); }
}
const bitcoinCli = (...args) => dockerOk(['exec', '-T', 'bitcoind', 'bitcoin-cli', '-regtest', '-rpcuser=demo', '-rpcpassword=regtest-demo-only', ...args],
  `bitcoin-cli ${args[0]}`);

/** Polls a readiness condition once a second until it holds or the deadline passes. */
async function waitFor(what, condition, timeoutMs = 120_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    try { const value = await condition(); if (value) return value; } catch (error) { last = error; }
    await sleep(1000);
  }
  throw new Error(`timed out after ${timeoutMs / 1000} s waiting for ${what}${last ? ` (last error: ${last.message})` : ''}`);
}

// macwarden refuses to run with NODE_OPTIONS or a network NODE_DEBUG (they could log credentials).
const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_OPTIONS' && key !== 'NODE_DEBUG'
  && key !== 'NODE_TLS_REJECT_UNAUTHORIZED'));
const operatorEnv = { ...baseEnv, MACWARDEN_LND_REST: LND_REST, MACWARDEN_LND_GRPC: LND_GRPC,
  MACWARDEN_TLS_CERT: paths.operatorCert, MACWARDEN_MACAROON: paths.session };
const agentEnv = { ...baseEnv, AGENT_LND_REST: LND_REST, AGENT_TLS_CERT: paths.agentCert, AGENT_MACAROON: paths.agentMacaroon,
  AGENT_SERVICE_URL: SERVICE_URL, AGENT_WORKDIR: paths.agentDir, AGENT_MAX_PRICE_SAT: '500', AGENT_MAX_FEE_SAT: '10' };

/** Prints and runs one macwarden command as the operator would type it. */
async function macwarden(...args) {
  out(`\n $ macwarden ${args.join(' ')}\n`);
  const result = await run(process.execPath, [macwardenBin, ...args], { env: operatorEnv, echo: true });
  out(`   (exit ${result.code})\n`);
  return result;
}

async function agent(...args) {
  out(`\n $ node agent.mjs ${args.join(' ')}\n`);
  return run(process.execPath, ['agent.mjs', ...args], { env: agentEnv, echo: true, timeoutMs: 180_000 });
}

function paidApiStatus() {
  return new Promise(resolveStatus => {
    const req = httpRequest(SERVICE_URL, res => { res.resume(); resolveStatus(res.statusCode); });
    req.setTimeout(10_000, () => req.destroy());
    req.on('error', () => resolveStatus(0));
    req.end();
  });
}

function portFree(port) {
  return new Promise(resolvePort => {
    const server = createServer();
    server.once('error', () => resolvePort(false));
    server.listen(port, '127.0.0.1', () => server.close(() => resolvePort(true)));
  });
}

function makePrivateDir(path) {
  mkdirSync(join(here, path), { recursive: true, mode: 0o700 });
  if (!isWindows) chmodSync(join(here, path), 0o700);
}

/** macwarden's engines range: ^22.23.2 || ^24.18.1 || >=26.5.1. */
function nodeVersionSupported() {
  const [major, minor, patch] = process.versions.node.split('.').map(Number);
  const atLeast = (wantMinor, wantPatch) => minor > wantMinor || (minor === wantMinor && patch >= wantPatch);
  if (major === 22) return atLeast(23, 2);
  if (major === 24) return atLeast(18, 1);
  if (major === 26) return atLeast(5, 1);
  return major > 26;
}

/** Removes containers, volumes and runtime/. Resolves true only when docker compose down succeeded; never rejects. */
async function teardown() {
  out('\n $ docker compose down -v --remove-orphans\n');
  // run() rejects when docker cannot be started or does not finish in time: that is a failed teardown too.
  const result = await docker(['down', '-v', '--remove-orphans'], { timeoutMs: 180_000 })
    .catch(error => ({ code: null, stdout: '', stderr: error.message }));
  if (result.code !== 0) out(indent(result.stderr || result.stdout));
  rmSync(runtime, { recursive: true, force: true });
  out(`   ${result.code === 0 ? 'removed containers, volumes and runtime/' : 'docker compose down failed; runtime/ removed'}\n`);
  return result.code === 0;
}

// --- watch -----------------------------------------------------------------

let watch = null;
const watchLines = [];
const sawWatchLine = pattern => watchLines.some(line => pattern.test(line));

function startWatch(args) {
  out(`\n $ macwarden ${args.join(' ')} &\n`);
  const child = spawn(process.execPath, [macwardenBin, ...args], { cwd: here, env: operatorEnv, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let pending = '';
  const onData = chunk => {
    pending += chunk.toString().replace(/\r/g, '');
    const lines = pending.split('\n');
    pending = lines.pop();
    for (const line of lines) { watchLines.push(line); out(`   watch | ${line}\n`); }
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  const exited = new Promise(done => {
    child.on('error', error => { onData(`cannot start watch: ${error.message}\n`); done(null); });
    child.on('close', code => { if (pending) onData('\n'); done(code); });
  });
  return { child, exited };
}

/** Stops watch: Ctrl+C (SIGINT) on POSIX. Resolves its exit code, or null when it had to be killed. */
async function stopWatch() {
  if (!watch) return null;
  const current = watch;
  watch = null;
  // Node cannot send a console Ctrl+C to a child on Windows: kill() terminates it at once,
  // so watch prints no summary there. It saves its usage file periodically while it runs.
  current.child.kill(isWindows ? undefined : 'SIGINT');
  // The deadline timer is cleared once the race settles: a pending 30 s timer would keep the process alive.
  let timer;
  const deadline = new Promise(done => { timer = setTimeout(() => done('timeout'), 30_000); });
  let code;
  try {
    code = await Promise.race([current.exited, deadline]);
  } finally {
    clearTimeout(timer);
  }
  if (code !== 'timeout') return code;
  current.child.kill('SIGKILL');
  return null;
}

// --- the story ---------------------------------------------------------------

async function preflight() {
  if (!nodeVersionSupported())
    throw new Error(`Node.js ${process.versions.node} is outside macwarden's supported range (22.23.2+ on 22, 24.18.1+ on 24, 26.5.1+)`);
  if (!existsSync(macwardenBin))
    throw new Error(`macwarden not found at ${macwardenBin}: run "npm ci && npm run build" in the repository root, or set MACWARDEN_BIN`);
  const compose = await run('docker', ['compose', 'version'], { timeoutMs: 30_000 }).catch(error => ({ code: -1, stderr: error.message }));
  if (compose.code !== 0) throw new Error(`Docker Compose v2 is not available: ${lastLines(compose.stderr || compose.stdout || '')}`);
  const daemon = await run('docker', ['info', '--format', '{{.ServerVersion}}'], { timeoutMs: 30_000 });
  if (daemon.code !== 0) throw new Error(`the Docker daemon is not reachable: ${lastLines(daemon.stderr)}`);
}

async function setUp() {
  step(1, 'Start bitcoind (regtest), alice (operator), bob (merchant), the paid API and Aperture');
  await preflight();
  // Idempotent start: remove whatever an earlier run left, including its credentials.
  out(' $ docker compose down -v --remove-orphans\n');
  await dockerOk(['down', '-v', '--remove-orphans'], 'docker compose down', { timeoutMs: 180_000 });
  rmSync(runtime, { recursive: true, force: true });
  for (const [name, port] of Object.entries(PORTS))
    if (!(await portFree(port))) throw new Error(`127.0.0.1:${port} (${name}) is in use by another program; free it and run again`);

  out(' $ docker compose up -d --wait bitcoind alice bob api\n');
  await dockerOk(['up', '-d', '--wait', '--wait-timeout', '180', 'bitcoind', 'alice', 'bob', 'api'], 'docker compose up', { timeoutMs: 600_000 });

  const { address } = await lncli('alice', 'newaddress', 'p2wkh');
  await bitcoinCli('generatetoaddress', '101', address);
  await waitFor('alice and bob to sync to the chain', async () =>
    (await lncli('alice', 'getinfo')).synced_to_chain && (await lncli('bob', 'getinfo')).synced_to_chain
    && Number((await lncli('alice', 'walletbalance')).confirmed_balance) > 0);
  out('   mined 101 blocks to alice; both nodes synced\n');

  const bob = (await lncli('bob', 'getinfo')).identity_pubkey;
  await lncli('alice', 'connect', `${bob}@bob:9735`);
  await waitFor('alice to see bob as a peer', async () => (await lncli('alice', 'listpeers')).peers?.some(peer => peer.pub_key === bob), 60_000);
  await lncli('alice', 'openchannel', '--node_key', bob, '--local_amt', CHANNEL_SAT);
  await waitFor('the funding transaction in the mempool', async () => JSON.parse(await bitcoinCli('getrawmempool')).length > 0, 60_000);
  await bitcoinCli('generatetoaddress', '6', address);
  await waitFor('the alice-bob channel to become active', async () =>
    (await lncli('alice', 'listchannels')).channels?.some(channel => channel.active && channel.remote_pubkey === bob)
    && (await lncli('bob', 'listchannels')).channels?.some(channel => channel.active));
  out(`   channel alice -> bob active: ${Number(CHANNEL_SAT).toLocaleString('en-US')} sat\n`);

  out(' $ docker compose up -d --wait aperture\n');
  await dockerOk(['up', '-d', '--wait', '--wait-timeout', '120', 'aperture'], 'docker compose up aperture', { timeoutMs: 300_000 });
  await waitFor('Aperture to answer with an L402 challenge', async () => (await paidApiStatus()) === 402, 60_000);
  out(`   Aperture (L402 proxy, invoices from bob) answers ${SERVICE_URL} with 402 Payment Required\n`);
  check('regtest stack is up', true);

  // The operator's own macwarden credential: dedicated, short-lived, on its own root key ID.
  makePrivateDir(paths.operatorDir);
  makePrivateDir(paths.agentDir);
  out(`\n $ lncli bakemacaroon --root_key_id ${SESSION_ROOT_KEY_ID} --timeout 7200 macaroon:generate macaroon:read macaroon:write info:read   (inside alice)\n`);
  const inContainer = '/tmp/macwarden-session.macaroon';
  await dockerOk(['exec', '-T', 'alice', 'lncli', '--network=regtest', 'bakemacaroon', '--root_key_id', SESSION_ROOT_KEY_ID,
    '--timeout', '7200', '--save_to', inContainer, 'macaroon:generate', 'macaroon:read', 'macaroon:write', 'info:read'], 'bakemacaroon');
  try {
    await dockerOk(['cp', `alice:${inContainer}`, paths.session], 'copy session macaroon');
  } finally {
    await docker(['exec', '-T', 'alice', 'rm', '-f', inContainer]);
  }
  if (!isWindows) chmodSync(join(here, paths.session), 0o600);
  await dockerOk(['cp', 'alice:/root/.lnd/tls.cert', paths.operatorCert], 'copy TLS certificate');
  await dockerOk(['cp', 'alice:/root/.lnd/tls.cert', paths.agentCert], 'copy TLS certificate');
  out(`   saved as ${paths.session}; the admin macaroon never leaves the container\n`);
}

async function story() {
  step(2, 'The operator issues the agent a scoped, expiring credential, and a decoy');
  out(`   export MACWARDEN_LND_REST=${LND_REST} MACWARDEN_LND_GRPC=${LND_GRPC}\n`);
  out(`   export MACWARDEN_TLS_CERT=${paths.operatorCert} MACWARDEN_MACAROON=${paths.session}\n`);
  const bake = await macwarden('bake', '--label', 'agent', '--preset', 'pay-only', '--expires', '1h',
    '--out', paths.agentMacaroon, '--registry', paths.registry);
  check('bake pay-only credential for the agent', bake.code === 0 && /\bSPEND\b/.test(bake.stdout));
  const agentRootKeyId = /root key ID (\d+)/.exec(bake.stdout)?.[1];
  if (!agentRootKeyId) throw new Error('bake did not report the agent credential; see its output above');
  const inspect = await macwarden('inspect', paths.agentMacaroon);
  check('agent credential holds only payment methods and info:read',
    inspect.code === 0 && /permissions\s+info:read uri:\/lnrpc\.Lightning\/DecodePayReq uri:\/routerrpc\.Router\/SendPaymentV2 uri:\/routerrpc\.Router\/TrackPaymentV2\s*$/m.test(inspect.stdout));
  makePrivateDir(paths.decoyDir);
  note('A canary: a decoy read-only macaroon placed where an intruder would look. LND refuses it unless watch runs;');
  note('while watch runs, every use is denied and alerted.');
  const canary = await macwarden('bake', '--label', 'decoy', '--canary', '--out', paths.decoy, '--registry', paths.registry);
  check('bake canary decoy', canary.code === 0);
  const inventory = await macwarden('inventory', '--registry', paths.registry);
  check('inventory lists agent and decoy', inventory.code === 0 && inventory.stdout.includes(agentRootKeyId) && /\bdecoy\b/.test(inventory.stdout));

  step(3, 'The operator watches the agent\'s calls live');
  note('alice runs with --rpcmiddleware.enable (never addmandatory); watch registers a read-only middleware over gRPC.');
  const watchArgs = ['watch', '--registry', paths.registry];
  if (isWindows) {
    note('--alert-command is not used on Windows here: it must be an .exe or .com file (see README).');
  } else {
    chmodSync(alertCommand, 0o755);
    watchArgs.push('--alert-command', alertCommand);
    note(`each canary alert also runs ${alertCommand}, which appends the event to ${paths.alerts}`);
  }
  watch = startWatch(watchArgs);
  // watch prints "watching (…)" once registered, or "error: <step>: …" and exits.
  await waitFor('watch to register its middleware', async () => sawWatchLine(/watching \(|^error:/), 60_000);
  if (!sawWatchLine(/watching \(/)) throw new Error('watch did not register; see its output above');
  check('watch registered, guarding the canary', sawWatchLine(/watching \(.*guarding 1 canary/));

  step(4, 'The agent buys data from the paid API with its pay-only credential');
  const buy = await agent('buy');
  check('agent paid the L402 invoice and got the data', buy.code === 0 && /SendPaymentV2: SUCCEEDED/.test(buy.stdout) && /→ 200/.test(buy.stdout));
  await waitFor('watch to report the payment', async () => sawWatchLine(/SendPaymentV2\s.*\bagent\b/), 15_000).catch(() => false);
  check('watch attributed the payment to the agent', sawWatchLine(/SendPaymentV2\s.*\bagent\b/));
  note('The same credential is refused for everything that is not a payment:');
  const probe = await agent('probe');
  check('non-payment calls are refused', probe.code === 0);
  note('LND checks permissions before RPC middleware runs, so watch lists only the calls LND accepted.');

  step(5, 'Leak drill: a careless debug log writes the agent\'s secrets to disk');
  const leak = await agent('buy', '--simulate-leak');
  check('leak drill wrote agent.log and .env', leak.code === 0
    && existsSync(join(here, paths.agentDir, 'agent.log')) && existsSync(join(here, paths.agentDir, '.env')));
  const scan = await macwarden('scan', paths.agentDir, '--fail-on', 'READ');
  check('scan finds the leaked agent macaroon in agent.log (exit 1)', scan.code === 1 && /agent\.log:\d+:\d+\s+macaroon-hex\s.*SPEND/.test(scan.stdout));
  note('The decoy is a macaroon file too, so scan lists it; it grants only reads and every use is denied and alerted.');
  const l402Findings = scan.stdout.split('\n').filter(line => /l402/i.test(line));
  if (l402Findings.length > 0) check('scan also reports the leaked L402 token', true, `${l402Findings.length} finding(s)`);
  else note('This macwarden build reports no L402 token findings: the token in agent.log and .env is not detected.');

  step(6, 'Incident response: revoke the agent, prove it is cut off');
  const revoke = await macwarden('revoke', 'agent', '--yes', '--registry', paths.registry);
  check('revoke agent', revoke.code === 0 && /macaroon rejected/.test(revoke.stdout));
  note(`watch also lists macwarden's own calls: its session credential (root key ${SESSION_ROOT_KEY_ID}) is not in the registry, so it shows as unregistered.`);
  const verify = await macwarden('verify', paths.agentMacaroon, '--registry', paths.registry);
  check('verify: conclusively rejected (exit 0)', verify.code === 0 && /root-key-missing/.test(verify.stdout));
  const after = await agent('buy');
  check('the agent can no longer pay', after.code === 1 && /root key with id \d+ doesn't exist/.test(after.stdout) && !/SUCCEEDED/.test(after.stdout));
  note('Limit: the L402 token the agent already paid for is a separate bearer credential. Aperture honours it');
  note('until it expires (timeout: 3600 in aperture.yaml); revoking the macaroon does not end it.');
  const reuse = await agent('reuse');
  check('the already-paid L402 token still works until it expires', reuse.code === 0);
  note('An intruder who found the leaked files tries the decoy next to them:');
  await agent('intruder', paths.decoy);
  await waitFor('the canary alert', async () => sawWatchLine(/ALERT canary decoy used/), 15_000).catch(() => false);
  check('watch raised a canary alert, LND denied the call', sawWatchLine(/ALERT canary decoy used: .*request denied/));
  if (!isWindows) {
    const alerts = await waitFor('the alert command to record the alert', async () => {
      const lines = readFileSync(join(here, paths.alerts), 'utf8').split('\n').filter(Boolean);
      return lines.length > 0 ? lines : null;
    }, 20_000).catch(() => []);
    out(`\n $ cat ${paths.alerts}\n`);
    for (const line of alerts) out(indent(line));
    check('the alert command received the canary event', alerts.some(line => /"event":"canary"/.test(line)));
  }
  // inventory reads canary hits from <registry>.usage.json, which watch saves periodically.
  await waitFor('watch to save the canary hit', async () => {
    const usage = JSON.parse(readFileSync(join(here, `${paths.registry}.usage.json`), 'utf8'));
    return Array.isArray(usage.canaryUses) && usage.canaryUses.length > 0;
  }, 30_000).catch(() => false);
  const inventoryAfter = await macwarden('inventory', '--registry', paths.registry);
  check('inventory: agent root key gone, canary triggered', inventoryAfter.code === 0
    && !inventoryAfter.stdout.includes(agentRootKeyId) && /CANARY TRIGGERED/.test(inventoryAfter.stdout));
  out(`\n $ (stop watch: ${isWindows ? 'terminated; on Windows it prints no summary' : 'Ctrl+C'})\n`);
  const watchCode = await stopWatch();
  if (!isWindows) check('watch stopped cleanly', watchCode === 0, `exit ${watchCode}`);
}

async function main() {
  const args = process.argv.slice(2);
  const known = new Set(['down', '--teardown']);
  if (args.some(arg => !known.has(arg)) || (args.includes('down') && args.length > 1)) {
    out('usage: node demo.mjs [--teardown] | node demo.mjs down\n');
    process.exitCode = 2;
    return;
  }
  if (args[0] === 'down') {
    step(STEPS, 'Teardown');
    process.exitCode = (await teardown()) ? 0 : 1;
    return;
  }
  const teardownAfter = args.includes('--teardown');
  const onSignal = () => { void stopWatch().finally(() => process.exit(130)); };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  let failure = null;
  try {
    await setUp();
    await story();
  } catch (error) {
    failure = error;
    out(`\nerror: ${error.message}\n`);
  } finally {
    await stopWatch();
  }
  step(STEPS, 'Teardown');
  // With --teardown, a failed docker compose down fails the run whatever the story's outcome: containers or
  // volumes the caller asked to remove may be left behind.
  const tornDown = teardownAfter ? await teardown() : true;
  if (!teardownAfter) out(`   The stack is still running${failure ? ' for inspection (docker compose logs)' : ''}. Remove containers, volumes and runtime/ with ./teardown.sh (or .\\teardown.ps1).\n`);
  const failed = checks.filter(item => !item.ok);
  out(`\n${checks.length - failed.length}/${checks.length} checks passed${failure ? '; the run stopped early' : ''}\n`);
  for (const item of failed) out(`  FAILED: ${item.name}\n`);
  if (!tornDown) out('  FAILED: teardown (docker compose down); containers or volumes may be left: run ./teardown.sh (or .\\teardown.ps1)\n');
  process.exitCode = failure || failed.length || !tornDown ? 1 : 0;
}

await main();
