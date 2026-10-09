import { cancellationSignal } from '../cancellation.js';
import { revealSecret } from '../secret-capability.js';
import { request } from 'node:https';
import { LndError, LndUncertainError, UsageError } from '../errors.js';
import { Secret } from '../secret.js';
import { openGrpcStream } from './grpc.js';
import { identityCheck } from './tls-identity.js';
import { decodeMiddlewareRequest, encodeFeedback, encodeRegistration, type InterceptKind } from './middleware-proto.js';

export interface LndAdapter {
  getInfo(): Promise<{ pubkey: string; alias: string; network: string; version: string }>;
  listMacaroonIds(): Promise<bigint[]>;
  listPermissions(): Promise<Record<string, string[]>>;
  bakeMacaroon(perms: string[], rootKeyId: bigint): Promise<Secret>;
  deleteMacaroonId(rootKeyId: bigint): Promise<{ deleted: boolean }>;
  checkMacaroon(mac: Secret, perms: string[]): Promise<
    { valid: true }
    | { valid: false; reason: 'root-key-missing' | 'signature-mismatch' | 'other'; message: string }
    | { valid: false; reason: 'expired'; caveat: string; message: string }>;
}

type Config = { restUrl: string; tlsCert: Buffer; macaroon: Secret };
type Response = { status: number; body: string };
const MAX_RESPONSE = 1_048_576;
const TIMEOUT_MS = 10_000;
const ROOT_MISSING = /root key with id [0-9]+ doesn't exist/i;
const SIGNATURE_MISMATCH = /signature mismatch/i;
// LND v0.21.4 CheckMacaroonPermissions (rpcserver.go) returns gRPC InvalidArgument with err.Error() of
// macaroons/service.go CheckMacAuth. Its bakery (macaroon-bakery v2.0.1) checks every first-party caveat
// in order and reports the first that fails as `caveat %q not satisfied: <reason>` (checkers.go), and
// for an expired time-before the reason is `macaroon has expired` (checkers/time.go), judged by the
// node's clock. Only that exact whole message is expiry evidence; the caveat value is returned so the
// caller can match it against the credential's own decoded caveats.
const NODE_EXPIRED = /^caveat "time-before ([^"\\]*)" not satisfied: macaroon has expired$/;
const MAX_ROOT_KEY_ID = (1n << 64n) - 1n;

function ownAuthenticationFailure(response: Response): boolean {
  if (response.status === 401 || response.status === 403) return true;
  if (response.status !== 500) return false;
  try {
    const value: unknown = JSON.parse(response.body);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const message = (value as Record<string, unknown>).message;
    return typeof message === 'string' && (ROOT_MISSING.test(message)
      || /permission denied|macaroon.*expired|expired.*macaroon|caveat.*(expired|not satisfied)|verification failed|signature mismatch/i.test(message));
  } catch { return false; }
}

class BakeLndError extends LndError {
  readonly kind: 'root-key-missing' | 'other';

  constructor(kind: 'root-key-missing' | 'other') {
    super(5, 'bake-macaroon', 'LND rejected bake request');
    this.kind = kind;
  }
}

function endpoint(config: Config): URL {
  let url: URL;
  try { url = new URL(config.restUrl); }
  catch { throw new UsageError('invalid LND REST endpoint'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash) {
    throw new UsageError('invalid LND REST endpoint');
  }
  return url;
}

function permission(value: string): { entity: string; action: string } {
  const separator = value.indexOf(':');
  if (separator < 1 || separator === value.length - 1) throw new UsageError('invalid permission');
  return { entity: value.slice(0, separator), action: value.slice(separator + 1) };
}

function json(body: string, stage: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(body);
    if (value && typeof value === 'object' && !Array.isArray(value))
      return value as Record<string, unknown>;
  } catch { /* Invalid response is an LND protocol error. */ }
  throw new LndError(5, stage, 'invalid LND response');
}

function string(value: unknown, stage: string): string {
  if (typeof value !== 'string') throw new LndError(5, stage, 'invalid LND response');
  return value;
}

function ids(body: string): bigint[] {
  const stage = 'list-macaroon-ids';
  // The one accepted field is parsed as JSON strings to preserve uint64 tokens.
  const match = /^\s*\{\s*"root_key_ids"\s*:\s*\[([\s\S]*?)\]\s*\}\s*$/.exec(body);
  if (!match) throw new LndError(5, stage, 'invalid LND response');
  const entries = match[1].trim();
  if (!entries) return [];
  return entries.split(',').map(entry => {
    const token = entry.trim();
    const digits = /^"(0|[1-9][0-9]*)"$/.exec(token)?.[1]
      ?? /^(0|[1-9][0-9]*)$/.exec(token)?.[1];
    if (digits === undefined || digits.length > 20) throw new LndError(5, stage, 'invalid LND response');
    const id = BigInt(digits);
    if (id > MAX_ROOT_KEY_ID) throw new LndError(5, stage, 'invalid LND response');
    return id;
  });
}

type CallOptions = {
  /** Largest response body accepted (default MAX_RESPONSE); a larger one fails the call. */
  maxResponse?: number;
  /**
   * A streaming (server-streaming REST) call: the body is complete at its first newline, which
   * grpc-gateway writes after each message; the rest of the stream is not read.
   */
  firstLine?: boolean;
};

/** One HTTPS request at a time to LND's REST proxy, with the pinned certificate and own macaroon. */
function transport(config: Config) {
  const peer = endpoint(config);
  // WHATWG URL keeps an IPv6 literal in brackets ("[::1]"); the transport and its TLS
  // identity check need the bare address, or Node treats it as a DNS name and the
  // certificate's IP SAN never matches. Printed URLs and commands keep the brackets.
  const transportHost = peer.hostname.replace(/^\[(.*)\]$/, '$1');
  const ca = Buffer.from(config.tlsCert);
  const own = config.macaroon;

  function call(stage: string, method: 'GET' | 'POST' | 'DELETE', path: string, payload?: object,
    options: CallOptions = {}): Promise<Response> {
    const limit = options.maxResponse ?? MAX_RESPONSE;
    const body = payload === undefined ? undefined : JSON.stringify(payload);
    return new Promise((resolve, reject) => {
      let settled = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let req: ReturnType<typeof request> | undefined;
      const signal = cancellationSignal();
      let abort: (() => void) | undefined;
      // Set once TLS is established: from then on LND may have received the request,
      // so a missing response leaves the outcome unknown rather than "not sent".
      let reached = false;
      const cleanup = () => {
        clearTimeout(timer);
        if (abort) signal?.removeEventListener('abort', abort);
      };
      const fail = (code: 4 | 5, message: string) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(reached ? new LndUncertainError(code, stage, message) : new LndError(code, stage, message));
      };
      if (signal?.aborted) { fail(4, 'LND request cancelled'); return; }
      try {
      req = request({ protocol: 'https:', hostname: transportHost, port: peer.port || 443,
        method, path, ca, rejectUnauthorized: true, ...identityCheck(transportHost), agent: false,
        headers: { 'Grpc-Metadata-macaroon': revealSecret(own).toString('hex'),
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) } }, response => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', chunk => {
          if (settled) return;
          const part = Buffer.from(chunk);
          size += part.length;
          if (size > limit) {
            response.destroy();
            fail(5, 'LND response too large');
            req?.destroy();
            return;
          }
          chunks.push(part);
          if (options.firstLine && part.includes(0x0a)) {
            // The first message of a stream is complete; the call ends here (a read-only lookup).
            const whole = Buffer.concat(chunks);
            settled = true;
            cleanup();
            response.destroy();
            req?.destroy();
            resolve({ status: response.statusCode ?? 0, body: whole.subarray(0, whole.indexOf(0x0a)).toString('utf8') });
          }
        });
        response.on('end', () => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') });
        });
        response.on('error', () => fail(4, 'LND transport failure'));
      });
      req.on('socket', socket => { socket.once('secureConnect', () => { reached = true; }); });
      req.on('error', () => fail(4, 'LND transport failure'));
      abort = () => {
        fail(4, 'LND request cancelled');
        req?.destroy();
      };
      if (!settled) signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) { abort(); return; }
      if (!settled) timer = setTimeout(() => {
        fail(4, 'LND transport timeout');
        req?.destroy();
      }, TIMEOUT_MS);
      if (body !== undefined) req.write(body);
      req.end();
      } catch { fail(4, 'LND transport failure'); req?.destroy(); }
    });
  }

  async function read(stage: string, method: 'GET' | 'POST' | 'DELETE', path: string, payload?: object,
    options: CallOptions = {}): Promise<string> {
    const response = await call(stage, method, path, payload, options);
    if (ownAuthenticationFailure(response))
      throw new LndError(4, stage, 'LND authentication failure');
    if (response.status < 200 || response.status >= 300)
      throw new LndError(5, stage, 'LND request rejected');
    return response.body;
  }

  return { call, read };
}

export function createLndAdapter(config: Config): LndAdapter & PaymentLookup {
  const { call, read } = transport(config);
  return {
    async getInfo() {
      const stage = 'get-info';
      const value = json(await read(stage, 'GET', '/v1/getinfo'), stage);
      const chains = value.chains;
      if (!Array.isArray(chains) || !chains[0] || typeof chains[0] !== 'object')
        throw new LndError(5, stage, 'invalid LND response');
      const pubkey = string(value.identity_pubkey, stage);
      if (!/^(02|03)[0-9a-f]{64}$/i.test(pubkey)) throw new LndError(5, stage, 'invalid LND response');
      const network = string((chains[0] as Record<string, unknown>).network, stage);
      // Network metadata is a short identifier, never an arbitrary peer string.
      if (!/^[a-z][a-z0-9-]{0,31}$/.test(network)) throw new LndError(5, stage, 'invalid LND response');
      const printable = (input: unknown): string => {
        const text = string(input, stage);
        // eslint-disable-next-line no-control-regex
        if (text.length > 256 || /[\x00-\x1f\x7f-\x9f]/.test(text))
          throw new LndError(5, stage, 'invalid LND response');
        return text;
      };
      return { pubkey: pubkey.toLowerCase(), alias: printable(value.alias),
        network,
        version: printable(value.version) };
    },
    async listMacaroonIds() {
      return ids(await read('list-macaroon-ids', 'GET', '/v1/macaroon/ids'));
    },
    async listPermissions() {
      const stage = 'list-permissions';
      const value = json(await read(stage, 'GET', '/v1/macaroon/permissions'), stage);
      const methods = value.method_permissions;
      if (!methods || typeof methods !== 'object' || Array.isArray(methods))
        throw new LndError(5, stage, 'invalid LND response');
      const result: Record<string, string[]> = Object.create(null);
      for (const [name, entry] of Object.entries(methods)) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry))
          throw new LndError(5, stage, 'invalid LND response');
        const permissions = (entry as Record<string, unknown>).permissions;
        if (!Array.isArray(permissions)) throw new LndError(5, stage, 'invalid LND response');
        result[name] = permissions.map(item => {
          if (!item || typeof item !== 'object') throw new LndError(5, stage, 'invalid LND response');
          const pair = item as Record<string, unknown>;
          return `${string(pair.entity, stage)}:${string(pair.action, stage)}`;
        });
      }
      return result;
    },
    async bakeMacaroon(perms, rootKeyId) {
      const stage = 'bake-macaroon';
      if (rootKeyId < 1n || rootKeyId > MAX_ROOT_KEY_ID)
        throw new UsageError('invalid root key ID');
      const response = await call(stage, 'POST', '/v1/macaroon',
        { permissions: perms.map(permission), root_key_id: rootKeyId.toString() });
      if (ownAuthenticationFailure(response))
        throw new LndError(4, stage, 'LND authentication failure');
      if (response.status < 200 || response.status >= 300)
        throw new BakeLndError(ROOT_MISSING.test(response.body) ? 'root-key-missing' : 'other');
      const value = json(response.body, stage);
      const macaroon = string(value.macaroon, stage);
      if (!macaroon || macaroon.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(macaroon))
        throw new LndError(5, stage, 'invalid LND response');
      return new Secret(Buffer.from(macaroon, 'hex'));
    },
    async deleteMacaroonId(rootKeyId) {
      const stage = 'delete-macaroon-id';
      if (rootKeyId < 1n || rootKeyId > MAX_ROOT_KEY_ID)
        throw new UsageError('invalid root key ID');
      const value = json(await read(stage, 'DELETE', `/v1/macaroon/${rootKeyId.toString()}`), stage);
      if (typeof value.deleted !== 'boolean') throw new LndError(5, stage, 'invalid LND response');
      return { deleted: value.deleted };
    },
    async checkMacaroon(mac, perms) {
      const stage = 'check-macaroon';
      if (!perms.length) throw new UsageError('verification requires permissions');
      const response = await call(stage, 'POST', '/v1/macaroon/checkpermissions',
        { macaroon: revealSecret(mac).toString('base64'), permissions: perms.map(permission) });
      if (ownAuthenticationFailure(response))
        throw new LndError(4, stage, 'LND authentication failure');
      if (response.status < 200 || response.status >= 300) {
        if (response.status !== 400)
          throw new LndError(5, stage, 'LND request rejected');
        // Classify only the observed target failures; never emit LND's response text.
        const value = json(response.body, stage);
        const message = string(value.message, stage).trim();
        if (!message) throw new LndError(5, stage, 'invalid LND response');
        const missing = response.status === 400 && ROOT_MISSING.test(message);
        const mismatch = response.status === 400 && SIGNATURE_MISMATCH.test(message);
        const expired = NODE_EXPIRED.exec(message);
        if (expired && !missing && !mismatch)
          return { valid: false, reason: 'expired', caveat: expired[1], message: 'LND rejected macaroon' };
        const reason = missing && !mismatch ? 'root-key-missing'
          : mismatch && !missing
            ? 'signature-mismatch' : 'other';
        return { valid: false, reason,
          message: 'LND rejected macaroon' };
      }
      const value = json(response.body, stage);
      if (Object.hasOwn(value, 'valid') && typeof value.valid !== 'boolean')
        throw new LndError(5, stage, 'invalid LND response');
      if (value.valid === true) return { valid: true };
      return { valid: false, reason: 'other', message: 'LND rejected macaroon' };
    },
    ...paymentLookup(call, read),
  };
}

/** A payment as LND reports it (lnrpc.Payment), reduced to the settlement evidence reconcile uses. */
export type LndPayment = {
  /** Lower-case hex payment hash. */
  paymentHash: string;
  status: 'succeeded' | 'failed' | 'in-flight' | 'unknown';
  /** Creation time, nanoseconds since the Unix epoch. */
  createdAtNs: bigint;
  /** LND's summary: amount sent to the destination and fees paid, in millisatoshi. */
  valueMsat: bigint;
  feeMsat: bigint;
  /** One per HTLC attempt: its status, the amount it delivers and its route's fees. */
  htlcs: { status: 'succeeded' | 'failed' | 'in-flight' | 'unknown'; amountMsat: bigint; feesMsat: bigint }[];
  /** LND's failure reason without the FAILURE_REASON_ prefix, lower case with dashes; null for none. */
  failureReason: string | null;
  /** LND's payment index (for paging ListPayments). */
  index: bigint;
};

/** Read-only payment lookups for reconcile: ListPayments and TrackPaymentV2 (offchain:read). */
export interface PaymentLookup {
  /**
   * One page of ListPayments, incomplete payments included, created in [startSeconds, endSeconds]
   * (Unix seconds), after index `indexOffset`, at most `max` payments.
   */
  listPayments(query: { startSeconds: number; endSeconds: number; indexOffset: bigint; max: number }):
    Promise<{ payments: LndPayment[]; lastIndexOffset: bigint }>;
  /** The current state of one payment (the first TrackPaymentV2 update), or null when LND has no payment with this hash. */
  trackPayment(paymentHash: string): Promise<LndPayment | null>;
}

/** Largest ListPayments page or TrackPaymentV2 update read: payments with many HTLC attempts carry a route each. */
const PAYMENT_RESPONSE_LIMIT = 8 * 1024 * 1024;
const MAX_PAGE = 1_000;
const MAX_UINT64 = (1n << 64n) - 1n;
// LND (paymentsdb) refuses to track a hash it holds no payment for with this error text.
const NOT_INITIATED = /payment isn'?t initiated|payment not initiated/i;
const HTLC_STATUS: Record<string, LndPayment['htlcs'][number]['status']> = { IN_FLIGHT: 'in-flight', SUCCEEDED: 'succeeded', FAILED: 'failed' };
const PAYMENT_STATUS: Record<string, LndPayment['status']> = { SUCCEEDED: 'succeeded', FAILED: 'failed', IN_FLIGHT: 'in-flight',
  INITIATED: 'in-flight', UNKNOWN: 'unknown' };

function paymentLookup(call: ReturnType<typeof transport>['call'], read: ReturnType<typeof transport>['read']): PaymentLookup {
  // grpc-gateway writes int64 and uint64 as JSON strings; a safe JSON integer is accepted too.
  const integer = (value: unknown, stage: string, signed = false): bigint => {
    if (typeof value === 'string' && (signed ? /^-?(0|[1-9][0-9]{0,19})$/ : /^(0|[1-9][0-9]{0,19})$/).test(value)) return BigInt(value);
    if (typeof value === 'number' && Number.isSafeInteger(value) && (signed || value >= 0)) return BigInt(value);
    throw new LndError(5, stage, 'invalid LND response');
  };
  const record = (value: unknown, stage: string): Record<string, unknown> => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new LndError(5, stage, 'invalid LND response');
    return value as Record<string, unknown>;
  };
  const payment = (value: unknown, stage: string): LndPayment => {
    const item = record(value, stage);
    const hash = string(item.payment_hash, stage).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new LndError(5, stage, 'invalid LND response');
    const htlcs = item.htlcs === undefined || item.htlcs === null ? [] : item.htlcs;
    if (!Array.isArray(htlcs)) throw new LndError(5, stage, 'invalid LND response');
    const reason = item.failure_reason === undefined ? 'FAILURE_REASON_NONE' : string(item.failure_reason, stage);
    if (!/^FAILURE_REASON_[A-Z_]{1,64}$/.test(reason)) throw new LndError(5, stage, 'invalid LND response');
    // Only these fields are read; the preimage and the payment request LND also returns are never kept.
    return {
      paymentHash: hash,
      status: PAYMENT_STATUS[string(item.status, stage)] ?? 'unknown',
      createdAtNs: integer(item.creation_time_ns, stage, true),
      valueMsat: integer(item.value_msat, stage, true),
      feeMsat: integer(item.fee_msat, stage, true),
      htlcs: htlcs.map(entry => {
        const htlc = record(entry, stage);
        const route = record(htlc.route, stage);
        const total = integer(route.total_amt_msat, stage, true);
        const fees = integer(route.total_fees_msat, stage, true);
        if (fees < 0n || total < fees) throw new LndError(5, stage, 'invalid LND response');
        return { status: HTLC_STATUS[string(htlc.status, stage)] ?? 'unknown', amountMsat: total - fees, feesMsat: fees };
      }),
      failureReason: reason === 'FAILURE_REASON_NONE' ? null : reason.slice('FAILURE_REASON_'.length).toLowerCase().replaceAll('_', '-'),
      index: integer(item.payment_index, stage),
    };
  };
  return {
    async listPayments({ startSeconds, endSeconds, indexOffset, max }) {
      const stage = 'list-payments';
      if (!Number.isSafeInteger(startSeconds) || !Number.isSafeInteger(endSeconds) || startSeconds < 0 || endSeconds < startSeconds
        || !Number.isSafeInteger(max) || max < 1 || max > MAX_PAGE || indexOffset < 0n || indexOffset > MAX_UINT64)
        throw new UsageError('invalid payment query');
      const query = new URLSearchParams({ include_incomplete: 'true', index_offset: indexOffset.toString(), max_payments: String(max),
        reversed: 'false', count_total_payments: 'false', creation_date_start: String(startSeconds), creation_date_end: String(endSeconds) });
      const value = json(await read(stage, 'GET', `/v1/payments?${query.toString()}`, undefined, { maxResponse: PAYMENT_RESPONSE_LIMIT }), stage);
      const payments = value.payments === undefined || value.payments === null ? [] : value.payments;
      if (!Array.isArray(payments) || payments.length > max) throw new LndError(5, stage, 'invalid LND response');
      return { payments: payments.map(item => payment(item, stage)), lastIndexOffset: integer(value.last_index_offset, stage) };
    },
    async trackPayment(paymentHash) {
      const stage = 'track-payment';
      if (!/^[0-9a-f]{64}$/.test(paymentHash)) throw new UsageError('invalid payment hash');
      // A bytes path parameter is base64; grpc-gateway also accepts the URL-safe alphabet.
      const path = `/v2/router/track/${encodeURIComponent(Buffer.from(paymentHash, 'hex').toString('base64url'))}`;
      const response = await call(stage, 'GET', path, undefined, { maxResponse: PAYMENT_RESPONSE_LIMIT, firstLine: true });
      if (ownAuthenticationFailure(response)) throw new LndError(4, stage, 'LND authentication failure');
      let value: Record<string, unknown>;
      try { value = json(response.body, stage); }
      catch (error) {
        if (NOT_INITIATED.test(response.body.slice(0, 4096))) return null;
        throw error;
      }
      // A stream that fails before its first message carries {"error": {...}} (grpc-gateway);
      // a unary-style error body carries the message at the top level.
      const failure = value.error;
      const message = failure && typeof failure === 'object' && !Array.isArray(failure)
        && typeof (failure as Record<string, unknown>).message === 'string' ? (failure as Record<string, unknown>).message as string
        : typeof failure === 'string' ? failure : typeof value.message === 'string' ? value.message : null;
      if (failure !== undefined && failure !== null || response.status < 200 || response.status >= 300) {
        if (message !== null && NOT_INITIATED.test(message)) return null;
        throw new LndError(5, stage, 'LND request rejected');
      }
      const result = payment(value.result, stage);
      if (result.paymentHash !== paymentHash) throw new LndError(5, stage, 'invalid LND response');
      return result;
    },
  };
}

export type MiddlewareCall = {
  kind: Exclude<InterceptKind, 'reg_complete' | 'none'>;
  requestId: bigint;
  method: string;
  isError: boolean;
  customCaveatCondition: string;
  /**
   * The intercepted caller's macaroon; null when the call carried none. Read it while the
   * handler runs: it is copied on first read, and afterwards it is null.
   */
  readonly macaroon: Secret | null;
  /** A macaroon above MAX_MACAROON_BYTES was presented; it was not copied. */
  oversizedMacaroon?: boolean;
  /** Size of the macaroon bytes held by this call (0 without one), for memory accounting. */
  macaroonBytes?: number;
  /**
   * The serialized request of a method selected with `payloadMethods` (at most
   * MAX_PAYLOAD_BYTES), copied on first read while the handler runs; null otherwise and afterwards.
   */
  readonly payload?: Buffer | null;
  /** Size of that request payload (0 without one), for memory accounting. */
  payloadBytes?: number;
  /** A selected method's request payload was above MAX_PAYLOAD_BYTES; it was not copied. */
  oversizedPayload?: boolean;
};

export type MiddlewareEnd = { registered: boolean; code: 3 | 4 | 5; stage: string; message: string; disabled: boolean };

export type MiddlewareSession = { ended: Promise<MiddlewareEnd>; close(): void };

const MIDDLEWARE_PATH = '/lnrpc.Lightning/RegisterRPCMiddleware';

/**
 * Registers an RPC middleware over gRPC (RegisterRPCMiddleware). `decide` runs
 * synchronously for every intercepted message and returns '' to accept or an error
 * text to deny; its answer is sent before any other work so LND is never kept waiting.
 */
/** Time LND gets to confirm a middleware registration (reg_complete). */
const REGISTRATION_TIMEOUT_MS = 30_000;

export function registerMiddleware(config: { host: string; port: number; tlsCert: Buffer; macaroon: Secret;
  pingIntervalMs?: number; pingTimeoutMs?: number; registrationTimeoutMs?: number; stallTimeoutMs?: number },
  registration: { name: string; readOnly: boolean; caveatName?: string },
  decide: (call: MiddlewareCall) => string, onRegistered: () => void,
  options: { payloadMethods?: ReadonlySet<string> } = {}): MiddlewareSession {
  if (!/^[A-Za-z0-9._-]{5,64}$/.test(registration.name)
    || (registration.readOnly === (registration.caveatName !== undefined))
    || (registration.caveatName !== undefined && !/^[A-Za-z0-9_-]{5,64}$/.test(registration.caveatName)))
    throw new UsageError('invalid middleware registration');
  let registered = false;
  let refused = '';
  let registrationTimedOut = false;
  const stream = openGrpcStream({ host: config.host, port: config.port, ca: Buffer.from(config.tlsCert),
    path: MIDDLEWARE_PATH, metadata: { macaroon: revealSecret(config.macaroon).toString('hex') },
    pingIntervalMs: config.pingIntervalMs, pingTimeoutMs: config.pingTimeoutMs, stallTimeoutMs: config.stallTimeoutMs }, message => {
    const request = decodeMiddlewareRequest(message, options.payloadMethods);
    // A read-only observer always accepts; a read/write registration (the canary guard) fails closed.
    const fallback = registration.readOnly ? '' : 'permission denied';
    if (request.kind === 'none') {
      // An intercept type this version does not know still gets feedback, so LND never waits for it.
      if (registered && request.msgId !== 0n) stream.send(encodeFeedback(request.msgId, fallback));
      return;
    }
    if (request.kind === 'reg_complete') {
      registered = true;
      clearTimeout(registrationDeadline);
      onRegistered();
      return;
    }
    if (!registered) { refused = 'intercept before registration'; throw new LndError(5, 'middleware-stream', 'invalid LND middleware message'); }
    // The macaroon is copied into a Secret only if `decide` reads it, and only while it runs:
    // the copy and its fingerprint are most of the per-call cost, and an observer that is
    // shedding load never needs them. The frame (and so rawMacaroon) is wiped afterwards.
    let raw: Buffer | null = request.rawMacaroon.length ? request.rawMacaroon : null;
    let macaroon: Secret | null = null;
    // The same for a selected request payload (watch --payment-journal): copied only if read.
    let rawPayload: Buffer | null = request.payload.length ? request.payload : null;
    let payload: Buffer | null = null;
    const call: MiddlewareCall = { kind: request.kind, requestId: request.requestId, method: request.method,
      isError: request.isError, customCaveatCondition: request.customCaveatCondition,
      get macaroon() { if (raw) { macaroon = new Secret(raw); raw = null; } return macaroon; },
      get payload() { if (rawPayload) { payload = Buffer.from(rawPayload); rawPayload = null; } return payload; },
      macaroonBytes: request.rawMacaroon.length, payloadBytes: request.payload.length,
      ...(request.oversizedMacaroon ? { oversizedMacaroon: true } : {}),
      ...(request.oversizedPayload ? { oversizedPayload: true } : {}) };
    let verdict: string;
    try { verdict = decide(call); } catch { verdict = fallback; }
    raw = null;
    macaroon = null;
    rawPayload = null;
    payload = null;
    // Feedback is required for every intercepted message, including responses.
    stream.send(encodeFeedback(request.msgId, verdict));
  });
  stream.send(encodeRegistration(registration));
  // A peer that never confirms the registration would leave watch silently idle: give up
  // after REGISTRATION_TIMEOUT_MS so the caller reconnects.
  const registrationDeadline = setTimeout(() => {
    if (registered) return;
    registrationTimedOut = true;
    stream.close();
  }, config.registrationTimeoutMs ?? REGISTRATION_TIMEOUT_MS);
  const ended = stream.ended.then(end => {
    clearTimeout(registrationDeadline);
    if (registrationTimedOut)
      return { registered: false, code: 4 as const, stage: 'middleware-register', message: 'LND did not complete the middleware registration', disabled: false };
    const message = end.message;
    const disabled = /RPC middleware not enabled/i.test(message);
    const auth = end.status === 16 || end.status === 7 || /permission denied|verification failed|signature mismatch|cannot get macaroon|expired/i.test(message);
    if (disabled) return { registered, code: 4 as const, stage: 'middleware-register', message: 'LND RPC middleware is disabled', disabled };
    if (!registered && auth) return { registered, code: 4 as const, stage: 'middleware-register', message: 'LND authentication failure', disabled };
    if (!registered && /already registered/i.test(message))
      return { registered, code: 3 as const, stage: 'middleware-register', message: 'a middleware with this name or caveat is already registered', disabled };
    if (refused || (!end.transport && end.status === null && message !== 'closed'))
      return { registered, code: 5 as const, stage: 'middleware-stream', message: 'invalid LND middleware stream', disabled };
    if (message === 'closed') return { registered, code: 4 as const, stage: 'middleware-stream', message: 'closed', disabled };
    return { registered, code: 4 as const, stage: registered ? 'middleware-stream' : 'middleware-register',
      message: end.transport ? 'LND transport failure' : 'LND ended the middleware stream', disabled };
  });
  return { ended, close: () => stream.close() };
}
