import { readFileSync, statSync } from 'node:fs';
import { request, type RequestOptions } from 'node:https';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { TLSSocket } from 'node:tls';
import { LndError, ProtocolError, TransportError } from './errors.ts';
import { asObject, type JsonObject } from './json.ts';

/**
 * A minimal client for LND's REST interface: one credential, one node, TLS
 * verified against the node's own certificate. Every response is size-bounded
 * before it is parsed, because a node or a path in between controls its length.
 */

const MAX_UNARY_BYTES = 16 * 1024 * 1024;
const MAX_STREAM_LINE_BYTES = 16 * 1024 * 1024;
const MAX_MACAROON_BYTES = 64 * 1024;
const MAX_CERT_BYTES = 64 * 1024;
const DEFAULT_UNARY_TIMEOUT_MS = 30_000;
const CONNECT_TIMEOUT_MS = 10_000;
const KEEPALIVE_MS = 15_000;

export interface LndConnection {
  /** Name used in messages, for example `customer (pay-only)`. */
  label: string;
  host: string;
  port: number;
  tlsCert: Buffer;
  macaroonHex: string;
}

function readBounded(path: string, limit: number, what: string): Buffer {
  const size = statSync(path).size;
  if (size === 0 || size > limit) throw new Error(`${what} at ${path} has an unexpected size`);
  return readFileSync(path);
}

/** Reads the certificate and credential by path; the credential is kept only as the header value. */
export function loadConnection(label: string, rest: string, tlsCertPath: string, macaroonPath: string): LndConnection {
  const match = /^([0-9.]+|localhost):([0-9]{1,5})$/.exec(rest);
  if (!match) throw new Error(`REST address ${rest} must be host:port`);
  const port = Number(match[2]);
  if (port < 1 || port > 65535) throw new Error(`REST port ${port} is out of range`);
  return { label, host: match[1] ?? '', port, tlsCert: readBounded(tlsCertPath, MAX_CERT_BYTES, 'TLS certificate'),
    macaroonHex: readBounded(macaroonPath, MAX_MACAROON_BYTES, 'macaroon').toString('hex') };
}

/** What a stream handler wants after one message. `drop` cuts the connection abruptly, as a network failure would. */
export type StreamDecision = 'continue' | 'stop' | 'drop';

export interface CallOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface StreamOptions {
  signal?: AbortSignal;
}

function lndErrorFrom(body: unknown, httpStatus: number | undefined): LndError {
  if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
    const o = body as JsonObject;
    const message = typeof o.message === 'string' ? o.message : `HTTP ${httpStatus ?? 'error'}`;
    const code = typeof o.code === 'number' ? o.code : typeof o.grpc_code === 'number' ? o.grpc_code : undefined;
    const status = typeof o.http_code === 'number' ? o.http_code : httpStatus;
    return new LndError(message, code, status);
  }
  return new LndError(`HTTP ${httpStatus ?? 'error'}`, undefined, httpStatus);
}

export class LndRestClient {
  readonly #connection: LndConnection;

  constructor(connection: LndConnection) {
    this.#connection = connection;
  }

  get label(): string {
    return this.#connection.label;
  }

  #open(method: string, path: string, body: unknown): { req: ClientRequest; payload: Buffer | undefined; connected: () => boolean } {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8');
    const options: RequestOptions = {
      host: this.#connection.host,
      port: this.#connection.port,
      method,
      path,
      ca: this.#connection.tlsCert,
      // Explicit: an inherited NODE_TLS_REJECT_UNAUTHORIZED=0 would otherwise turn the pinned certificate off.
      rejectUnauthorized: true,
      agent: false,
      headers: {
        'Grpc-Metadata-macaroon': this.#connection.macaroonHex,
        Accept: 'application/json',
        ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': String(payload.length) }),
      },
    };
    let secure = false;
    const req = request(options);
    req.on('socket', socket => {
      socket.setKeepAlive(true, KEEPALIVE_MS);
      (socket as TLSSocket).once('secureConnect', () => { secure = true; });
    });
    return { req, payload, connected: () => secure };
  }

  /** A unary call. Resolves with the response object or rejects with LndError, TransportError or ProtocolError. */
  call(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown, options: CallOptions = {}): Promise<JsonObject> {
    const { req, payload, connected } = this.#open(method, path, body);
    return new Promise<JsonObject>((resolve, reject) => {
      let settled = false;
      const finish = (error: Error | undefined, value?: JsonObject): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        options.signal?.removeEventListener('abort', onAbort);
        if (error) { req.destroy(); reject(error); } else resolve(value as JsonObject);
      };
      const phase = (): 'connect' | 'response' => (connected() ? 'response' : 'connect');
      const timer = setTimeout(() => finish(new TransportError(`${this.label}: no complete response within ${options.timeoutMs ?? DEFAULT_UNARY_TIMEOUT_MS} ms`, phase())),
        options.timeoutMs ?? DEFAULT_UNARY_TIMEOUT_MS);
      const onAbort = (): void => finish(new TransportError(`${this.label}: call aborted`, phase()));
      // The error listener comes first: finish() destroys the request, which emits ECONNRESET.
      req.on('error', error => finish(new TransportError(`${this.label}: ${error.message}`, phase(), { cause: error })));
      if (options.signal?.aborted) { onAbort(); return; }
      options.signal?.addEventListener('abort', onAbort, { once: true });
      req.on('response', (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_UNARY_BYTES) { finish(new ProtocolError(`${this.label}: response larger than ${MAX_UNARY_BYTES} bytes`)); return; }
          chunks.push(chunk);
        });
        res.on('error', error => finish(new TransportError(`${this.label}: ${error.message}`, 'response', { cause: error })));
        res.on('close', () => { if (!res.complete) finish(new TransportError(`${this.label}: response ended early`, 'response')); });
        res.on('end', () => {
          let parsed: unknown;
          try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {
            if (res.statusCode !== 200) { finish(lndErrorFrom(undefined, res.statusCode)); return; }
            finish(new ProtocolError(`${this.label}: response is not JSON`));
            return;
          }
          if (res.statusCode !== 200) { finish(lndErrorFrom(parsed, res.statusCode)); return; }
          try { finish(undefined, asObject(parsed, 'response')); } catch (error) { finish(error as Error); }
        });
      });
      req.end(payload);
    });
  }

  /**
   * A server-streaming call. LND's gateway writes one JSON object per line,
   * `{"result": …}` or `{"error": …}`. Resolves when the server ends the stream
   * or the handler returns `stop`. Rejects with LndError for an in-stream error
   * and with TransportError when the connection ends any other way, including
   * `drop`. A stream has no idle timeout: a held payment can be silent for
   * hours. TCP keepalive detects a vanished peer; `signal` bounds the wait.
   */
  stream(method: 'GET' | 'POST', path: string, body: unknown, onMessage: (message: JsonObject) => StreamDecision,
    options: StreamOptions = {}): Promise<void> {
    const { req, payload, connected } = this.#open(method, path, body);
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      let responded = false;
      const finish = (error: Error | undefined): void => {
        if (settled) return;
        settled = true;
        clearTimeout(connectTimer);
        options.signal?.removeEventListener('abort', onAbort);
        req.destroy();
        if (error) reject(error); else resolve();
      };
      const phase = (): 'connect' | 'response' => (connected() ? 'response' : 'connect');
      const connectTimer = setTimeout(() => { if (!connected()) finish(new TransportError(`${this.label}: no connection within ${CONNECT_TIMEOUT_MS} ms`, 'connect')); },
        CONNECT_TIMEOUT_MS);
      const onAbort = (): void => finish(new TransportError(`${this.label}: stream aborted by the caller`, phase()));
      // The error listener comes first: finish() destroys the request, which emits ECONNRESET.
      req.on('error', error => finish(new TransportError(`${this.label}: ${error.message}`, phase(), { cause: error })));
      if (options.signal?.aborted) { onAbort(); return; }
      options.signal?.addEventListener('abort', onAbort, { once: true });
      req.on('response', (res: IncomingMessage) => {
        responded = true;
        if (res.statusCode !== 200) {
          // A non-200 status carries one error object, not a stream.
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => { size += chunk.length; if (size <= MAX_UNARY_BYTES) chunks.push(chunk); });
          res.on('end', () => {
            let parsed: unknown;
            try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { parsed = undefined; }
            const inner = parsed !== null && typeof parsed === 'object' && 'error' in parsed ? (parsed as JsonObject).error : parsed;
            finish(lndErrorFrom(inner, res.statusCode));
          });
          return;
        }
        let pending: Buffer[] = [];
        let halted = false;
        let pendingSize = 0;
        const handleLine = (line: Buffer): void => {
          const text = line.toString('utf8').trim();
          if (text === '') return;
          let parsed: JsonObject;
          try { parsed = asObject(JSON.parse(text), 'stream message'); } catch {
            finish(new ProtocolError(`${this.label}: stream message is not a JSON object`));
            return;
          }
          if (parsed.error !== undefined && parsed.error !== null) { finish(lndErrorFrom(parsed.error, undefined)); return; }
          let decision: StreamDecision;
          try { decision = onMessage(asObject(parsed.result ?? {}, 'stream result')); } catch (error) {
            finish(error instanceof Error ? error : new Error(String(error)));
            return;
          }
          if (decision === 'stop') finish(undefined);
          if (decision === 'drop') {
            // Destroy the socket without a clean close, as a lost network path does;
            // the close handler below then reports it as a transport error.
            halted = true;
            res.socket.destroy();
          }
        };
        res.on('data', (chunk: Buffer) => {
          if (halted) return;
          let start = 0;
          for (let index = chunk.indexOf(0x0a); index !== -1 && !settled && !halted; index = chunk.indexOf(0x0a, start)) {
            pending.push(chunk.subarray(start, index));
            const line = Buffer.concat(pending);
            pending = [];
            pendingSize = 0;
            start = index + 1;
            handleLine(line);
          }
          if (settled || halted || start >= chunk.length) return;
          pendingSize += chunk.length - start;
          if (pendingSize > MAX_STREAM_LINE_BYTES) { finish(new ProtocolError(`${this.label}: stream message larger than ${MAX_STREAM_LINE_BYTES} bytes`)); return; }
          pending.push(Buffer.from(chunk.subarray(start)));
        });
        res.on('error', error => finish(new TransportError(`${this.label}: ${error.message}`, 'response', { cause: error })));
        res.on('close', () => {
          if (settled) return;
          if (!res.complete) { finish(new TransportError(`${this.label}: stream connection closed before the server ended it`, 'response')); return; }
          if (pendingSize > 0 && !halted) handleLine(Buffer.concat(pending));
          finish(undefined);
        });
      });
      req.on('close', () => {
        if (!responded) finish(new TransportError(`${this.label}: connection closed before a response`, phase()));
      });
      req.end(payload);
    });
  }
}
