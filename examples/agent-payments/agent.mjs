// A paying agent: a small L402 client that pays with one scoped LND macaroon.
//
// It talks to LND only over REST, with its own macaroon, and never sees the operator's
// admin or session credentials. Node.js built-ins only.
//
//   node agent.mjs buy                    request the paid API, pay the L402 invoice, retry with the token
//   node agent.mjs buy --simulate-leak    the same, then write the leak drill's files (see below)
//   node agent.mjs probe                  try calls outside the agent's permissions
//   node agent.mjs reuse                  call the API with the L402 token the leak drill saved
//   node agent.mjs intruder <file>        use another macaroon file the way a thief would
//
// Configuration (environment):
//   AGENT_LND_REST        host:port of LND's REST listener
//   AGENT_TLS_CERT        LND's TLS certificate (connections are verified against it)
//   AGENT_MACAROON        the agent's macaroon file
//   AGENT_SERVICE_URL     the paid API (http or https)
//   AGENT_WORKDIR         where the leak drill writes its files
//   AGENT_MAX_PRICE_SAT   highest invoice amount the agent pays (default 500)
//   AGENT_MAX_FEE_SAT     highest routing fee per payment (default 10)
//
// Logging rule: output names credentials and tokens by what they are, never by their bytes.
// Invoices are shown shortened; the payment preimage is never printed. Only the leak drill,
// on request, writes secrets to disk, to give `macwarden scan` something real to find.
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const LND_TIMEOUT_MS = 15_000;
const API_TIMEOUT_MS = 15_000;
const PAYMENT_TIMEOUT_S = 30;
const RETRY_ATTEMPTS = 3;
const RETRY_BASE_MS = 500;

class UsageError extends Error {}

/** An HTTP exchange that completed with a status code. Transport failures are plain Errors. */
class HttpStatusError extends Error {
  constructor(what, status, message) {
    super(`${what} failed with HTTP ${status}: ${message}`);
    this.status = status;
  }
}

const say = line => process.stdout.write(`  agent> ${line}\n`);
const short = text => (text.length > 24 ? `${text.slice(0, 12)}…${text.slice(-6)}` : text);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
/** Millisatoshi (BigInt) as satoshis, keeping any fraction: 500999n → "500.999". */
const formatMsat = msat => `${msat / 1000n}${msat % 1000n ? `.${String(msat % 1000n).padStart(3, '0').replace(/0+$/, '')}` : ''}`;
/** A non-negative integer field from LND's JSON (int64 arrives as a string), as BigInt; null when absent or malformed. */
const msatField = value => (typeof value === 'string' && /^\d{1,20}$/.test(value)) || (Number.isSafeInteger(value) && value >= 0) ? BigInt(value) : null;

function setting(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (value === undefined || value === '') throw new UsageError(`${name} is not set`);
  return value;
}

function satSetting(name, fallback) {
  const value = Number(setting(name, fallback));
  if (!Number.isSafeInteger(value) || value < 0) throw new UsageError(`${name} must be a whole number of satoshis`);
  return value;
}

function loadConfig() {
  const rest = setting('AGENT_LND_REST');
  const match = /^([^:]+|\[[^\]]+\]):(\d{1,5})$/.exec(rest);
  if (!match) throw new UsageError('AGENT_LND_REST must be host:port');
  const serviceUrl = new URL(setting('AGENT_SERVICE_URL'));
  if (serviceUrl.protocol !== 'http:' && serviceUrl.protocol !== 'https:') throw new UsageError('AGENT_SERVICE_URL must be http or https');
  return {
    lndHost: match[1].replace(/^\[|\]$/g, ''),
    lndPort: Number(match[2]),
    ca: readFileSync(setting('AGENT_TLS_CERT')),
    macaroonPath: setting('AGENT_MACAROON'),
    serviceUrl,
    workdir: setting('AGENT_WORKDIR', '.'),
    maxPriceSat: satSetting('AGENT_MAX_PRICE_SAT', '500'),
    maxFeeSat: satSetting('AGENT_MAX_FEE_SAT', '10'),
  };
}

const TRANSIENT_STATUSES = [502, 503, 504];

/** True for failures worth another attempt: transport errors and gateway/unavailable responses. */
const transient = error => !(error instanceof HttpStatusError) || TRANSIENT_STATUSES.includes(error.status);

/** Runs an idempotent operation up to RETRY_ATTEMPTS times with exponential backoff. */
async function withRetries(what, operation) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      if (attempt >= RETRY_ATTEMPTS || !transient(error)) throw error;
      const delay = RETRY_BASE_MS * 2 ** (attempt - 1);
      say(`${what}: ${error.message}; retrying in ${delay} ms (attempt ${attempt + 1} of ${RETRY_ATTEMPTS})`);
      await sleep(delay);
    }
  }
}

/** Reads a whole response, bounded in size, with one deadline for the exchange. */
function exchange(requestFn, options, body, timeoutMs, what) {
  return new Promise((resolve, reject) => {
    const req = requestFn(options, res => {
      const chunks = [];
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 4 * 1024 * 1024) req.destroy(new Error(`${what}: response larger than 4 MiB`));
        else chunks.push(chunk);
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headersDistinct, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`${what}: no response within ${timeoutMs / 1000} s`)));
    req.on('error', reject);
    req.end(body);
  });
}

function parseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

/** LND REST errors are {code, message} (or {error: {message}} on streams). Never echoes request data. */
function lndMessage(text) {
  const lines = text.split('\n').map(parseJson).filter(Boolean);
  const messages = lines.map(line => line.message ?? line.error?.message).filter(Boolean);
  return messages.join('; ') || 'no error message';
}

function createLnd(config, macaroonHex, onRequest) {
  /** One REST call. stream=true returns the newline-delimited JSON messages of a server stream. */
  return async function lnd(method, path, { body, stream = false, timeoutMs = LND_TIMEOUT_MS } = {}) {
    const headers = { 'Grpc-Metadata-macaroon': macaroonHex };
    const payload = body === undefined ? undefined : JSON.stringify(body);
    if (payload !== undefined) headers['content-type'] = 'application/json';
    onRequest?.(method, path, headers);
    const what = `${method} ${path.split('?')[0].replace(/\/lnbc\w+$/, '/<invoice>')}`;
    // rejectUnauthorized is explicit: an inherited NODE_TLS_REJECT_UNAUTHORIZED=0 would otherwise turn the pinned certificate off.
    const response = await exchange(httpsRequest, { host: config.lndHost, port: config.lndPort, method, path, headers, ca: config.ca, rejectUnauthorized: true },
      payload, timeoutMs, what);
    if (response.status !== 200) throw new HttpStatusError(what, response.status, lndMessage(response.text));
    if (!stream) return parseJson(response.text) ?? {};
    return response.text.split('\n').map(parseJson).filter(Boolean);
  };
}

/** One request to the paid API, optionally with an Authorization header. */
function callApi(config, authorization) {
  const headers = authorization ? { authorization } : {};
  const https = config.serviceUrl.protocol === 'https:';
  // The L402 token is a bearer credential: rejectUnauthorized is explicit, as for LND, so an inherited
  // NODE_TLS_REJECT_UNAUTHORIZED=0 cannot send it to a certificate nobody trusts.
  return exchange(https ? httpsRequest : httpRequest, { host: config.serviceUrl.hostname, port: config.serviceUrl.port || undefined,
    path: `${config.serviceUrl.pathname}${config.serviceUrl.search}`, headers, ...(https ? { rejectUnauthorized: true } : {}) },
  undefined, API_TIMEOUT_MS, `GET ${config.serviceUrl.pathname}`);
}

/**
 * callApi with retries. A 502, 503 or 504 is thrown inside the retried operation, so it is retried like a
 * transport error; every other status (402 with its challenge, 200, other 4xx and 5xx) is returned at once for
 * the caller to judge. The response body of a transient failure is not echoed.
 */
function callApiWithRetries(config, authorization) {
  return withRetries('paid API', async () => {
    const response = await callApi(config, authorization);
    if (TRANSIENT_STATUSES.includes(response.status))
      throw new HttpStatusError(`GET ${config.serviceUrl.pathname}`, response.status, 'service temporarily unavailable');
    return response;
  });
}

/** Parses `WWW-Authenticate: L402 macaroon="…", invoice="…"`. Aperture also sends the legacy LSAT form first. */
function l402Challenge(headers) {
  // headersDistinct: Node keeps only the first of repeated WWW-Authenticate headers in res.headers.
  const value = (headers['www-authenticate'] ?? []).join(', ');
  const match = /\bL402\s+macaroon="([A-Za-z0-9+/=_-]+)",\s*invoice="([a-z0-9]+)"/i.exec(value);
  return match ? { macaroon: match[1], invoice: match[2] } : null;
}

/** The final state of a payment from TrackPaymentV2, used when SendPaymentV2's stream did not end cleanly. */
async function trackPayment(lnd, paymentHashHex) {
  // grpc-gateway takes bytes in the path as padded URL-safe base64.
  const hash = Buffer.from(paymentHashHex, 'hex').toString('base64url');
  const path = `/v2/router/track/${hash}${'='.repeat((4 - (hash.length % 4)) % 4)}?no_inflight_updates=true`;
  const messages = await withRetries('TrackPaymentV2', () => lnd('GET', path, { stream: true, timeoutMs: (PAYMENT_TIMEOUT_S + 15) * 1000 }));
  return messages.map(message => message.result).filter(Boolean).at(-1) ?? null;
}

/** Pays one invoice after checking it. Returns the final payment (status SUCCEEDED) or throws. */
async function pay(config, lnd, invoice) {
  const decoded = await withRetries('DecodePayReq', () => lnd('GET', `/v1/payreq/${invoice}`));
  // num_msat, not num_satoshis: num_satoshis drops the millisatoshi part, so 500999 msat would read as 500 sat
  // and 999 msat as no amount. All amount checks are in millisatoshi, as BigInt.
  const amountMsat = msatField(decoded.num_msat ?? '0');
  const expiresAt = (Number(decoded.timestamp) + Number(decoded.expiry)) * 1000;
  if (amountMsat === null) throw new Error('DecodePayReq returned no readable amount; not paying');
  say(`DecodePayReq: ${formatMsat(amountMsat)} sat to ${short(decoded.destination)}, "${decoded.description || 'no description'}", hash ${short(decoded.payment_hash)}`);
  // The agent's own spending rules. They are advisory: the macaroon itself limits no amount.
  const maxPriceMsat = BigInt(config.maxPriceSat) * 1000n;
  if (amountMsat <= 0n) throw new Error('invoice without an amount; not paying');
  if (amountMsat > maxPriceMsat) throw new Error(`price ${formatMsat(amountMsat)} sat is above the agent's limit of ${config.maxPriceSat} sat; not paying`);
  if (!(expiresAt > Date.now() + 5_000)) throw new Error('invoice expired or about to expire; not paying');

  // SendPaymentV2 is sent once. LND refuses a second payment of the same payment hash, and an
  // unclear outcome (timeout, reset) is settled with TrackPaymentV2 instead of paying again.
  let final = null;
  try {
    const messages = await lnd('POST', '/v2/router/send', {
      body: { payment_request: invoice, timeout_seconds: PAYMENT_TIMEOUT_S, fee_limit_msat: String(BigInt(config.maxFeeSat) * 1000n), no_inflight_updates: true },
      stream: true, timeoutMs: (PAYMENT_TIMEOUT_S + 15) * 1000 });
    const streamError = messages.map(message => message.error?.message).find(Boolean);
    if (streamError) throw new HttpStatusError('POST /v2/router/send', 200, streamError);
    final = messages.map(message => message.result).filter(Boolean).at(-1) ?? null;
  } catch (error) {
    if (error instanceof HttpStatusError) throw error; // LND answered: the payment was refused or failed.
    say(`SendPaymentV2: ${error.message}; checking the payment's state with TrackPaymentV2`);
  }
  if (!final || final.status === 'IN_FLIGHT' || final.status === 'INITIATED') final = await trackPayment(lnd, decoded.payment_hash);
  if (final?.status !== 'SUCCEEDED') throw new Error(`payment ${final?.status ?? 'state unknown'}${final?.failure_reason ? ` (${final.failure_reason})` : ''}`);
  if (!/^[0-9a-f]{64}$/.test(final.payment_preimage ?? '')) throw new Error('payment succeeded without a usable preimage');
  const paidMsat = msatField(final.value_msat);
  const feeMsat = msatField(final.fee_msat);
  say(`SendPaymentV2: SUCCEEDED, ${paidMsat === null ? '?' : formatMsat(paidMsat)} sat + ${feeMsat === null ? '?' : formatMsat(feeMsat)} sat fee`);
  return final;
}

async function buy(config, { simulateLeak }) {
  const macaroonHex = readFileSync(config.macaroonPath).toString('hex');
  const leakedRequests = [];
  const lnd = createLnd(config, macaroonHex, simulateLeak ? (method, path, headers) => {
    // The mistake under drill: a debug log of request headers, credential included.
    leakedRequests.push(`${new Date().toISOString()} DEBUG lnd request ${method} ${path} headers=${JSON.stringify(headers)}`);
  } : undefined);

  say(`GET ${config.serviceUrl.href}`);
  const first = await callApiWithRetries(config);
  if (first.status !== 402) throw new Error(`expected 402 Payment Required, got HTTP ${first.status}`);
  const challenge = l402Challenge(first.headers);
  if (!challenge) throw new Error('402 response without an L402 challenge');
  say(`402 Payment Required: L402 challenge, invoice ${short(challenge.invoice)}`);

  const payment = await pay(config, lnd, challenge.invoice);
  const token = `${challenge.macaroon}:${payment.payment_preimage}`;
  const second = await callApiWithRetries(config, `L402 ${token}`);
  say(`GET with Authorization: L402 <token> → ${second.status}`);
  if (second.status !== 200) throw new Error(`paid request failed with HTTP ${second.status}`);
  say(`data: ${second.text}`);

  if (simulateLeak) {
    const log = join(config.workdir, 'agent.log');
    const env = join(config.workdir, '.env');
    writeFileSync(log, `${[...leakedRequests, `${new Date().toISOString()} DEBUG paid request Authorization: L402 ${token}`].join('\n')}\n`, { mode: 0o600 });
    writeFileSync(env, `LND_REST=${process.env.AGENT_LND_REST}\nLND_MACAROON_PATH=${config.macaroonPath}\nL402_TOKEN=${token}\n`, { mode: 0o600 });
    say(`leak drill: wrote ${log} (request headers with the macaroon, the L402 Authorization header)`);
    say(`leak drill: wrote ${env} (LND_REST, LND_MACAROON_PATH, L402_TOKEN)`);
  }
}

async function probe(config) {
  const lnd = createLnd(config, readFileSync(config.macaroonPath).toString('hex'));
  const attempts = [
    { what: 'GetInfo (info:read, granted)', method: 'GET', path: '/v1/getinfo', allowed: true },
    { what: 'WalletBalance (needs onchain:read)', method: 'GET', path: '/v1/balance/blockchain', allowed: false },
    { what: 'ListChannels (needs offchain:read)', method: 'GET', path: '/v1/channels', allowed: false },
    { what: 'NewAddress (needs address:write)', method: 'GET', path: '/v1/newaddress?type=WITNESS_PUBKEY_HASH', allowed: false },
    // A syntactically valid request; LND checks permissions before it looks at the peer.
    { what: 'OpenChannelSync (needs onchain:write, offchain:write)', method: 'POST', path: '/v1/channels',
      body: { node_pubkey_string: `02${'11'.repeat(32)}`, local_funding_amount: '20000' }, allowed: false },
    { what: 'BakeMacaroon (needs macaroon:generate)', method: 'POST', path: '/v1/macaroon',
      body: { permissions: [{ entity: 'onchain', action: 'write' }] }, allowed: false },
  ];
  let unexpected = 0;
  for (const attempt of attempts) {
    let verdict;
    let allowed;
    try {
      await lnd(attempt.method, attempt.path, { body: attempt.body });
      allowed = true;
      verdict = 'allowed';
    } catch (error) {
      if (!(error instanceof HttpStatusError)) throw error;
      allowed = false;
      verdict = `refused (${error.message.replace(/^.*failed with /, '')})`;
    }
    if (allowed !== attempt.allowed) unexpected += 1;
    say(`${attempt.what.padEnd(56)} ${verdict}`);
  }
  if (unexpected) throw new Error(`${unexpected} call(s) did not behave as the agent's permissions say`);
}

async function reuse(config) {
  const env = readFileSync(join(config.workdir, '.env'), 'utf8');
  const line = env.split('\n').find(entry => entry.startsWith('L402_TOKEN='));
  if (!line) throw new Error('no L402_TOKEN in .env');
  const response = await callApiWithRetries(config, `L402 ${line.slice('L402_TOKEN='.length).trim()}`);
  say(`GET with the L402 token from .env, no payment → ${response.status}`);
  if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
  say(`data: ${response.text}`);
}

async function intruder(config, file) {
  const lnd = createLnd(config, readFileSync(file).toString('hex'));
  for (const [what, path] of [['GetInfo', '/v1/getinfo'], ['WalletBalance', '/v1/balance/blockchain']]) {
    try {
      await lnd('GET', path);
      say(`intruder ${what.padEnd(14)} → allowed`);
    } catch (error) {
      if (!(error instanceof HttpStatusError)) throw error;
      say(`intruder ${what.padEnd(14)} → refused (${error.message.replace(/^.*failed with /, '')})`);
    }
  }
}

const [command, ...args] = process.argv.slice(2);
try {
  const config = loadConfig();
  if (command === 'buy' && args.every(arg => arg === '--simulate-leak')) await buy(config, { simulateLeak: args.length > 0 });
  else if (command === 'probe' && args.length === 0) await probe(config);
  else if (command === 'reuse' && args.length === 0) await reuse(config);
  else if (command === 'intruder' && args.length === 1) await intruder(config, args[0]);
  else throw new UsageError('usage: agent.mjs buy [--simulate-leak] | probe | reuse | intruder <macaroon file>');
} catch (error) {
  say(`error: ${error.message}`);
  process.exitCode = error instanceof UsageError ? 2 : 1;
}
