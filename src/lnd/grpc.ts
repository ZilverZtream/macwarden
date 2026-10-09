// A single bidirectional gRPC stream over node:http2 (no runtime dependencies).
// TLS trusts only the configured LND certificate, exactly like the REST adapter.
// LND's gRPC server accepts messages up to 200 MiB (lnrpc.MaxGrpcMsgSize); the
// middleware stream must receive every intercepted response, so the same limit
// applies here. Framing: 1-byte compression flag (must be 0), 4-byte length, payload.
import { connect, constants, type ClientHttp2Session, type ClientHttp2Stream } from 'node:http2';
import { LndError } from '../errors.js';
import { identityCheck } from './tls-identity.js';

export const MAX_GRPC_MESSAGE = 200 * 1024 * 1024;

export type GrpcEnd = { status: number | null; message: string; transport: boolean };

export type GrpcStream = {
  /** Sends one protobuf message; returns false when the stream is no longer writable. */
  send(message: Buffer): boolean;
  /** Ends the call (client half-close plus cancel) and the HTTP/2 session. */
  close(): void;
  /** Settles once when the call ends, with the gRPC status when one was received. */
  ended: Promise<GrpcEnd>;
};

export type GrpcTarget = { host: string; port: number; ca: Buffer; path: string;
  metadata: Record<string, string>; connectTimeoutMs?: number;
  /** HTTP/2 PING liveness: interval and the time allowed for its acknowledgement. */
  pingIntervalMs?: number; pingTimeoutMs?: number;
  /** An incomplete message that receives no data for this long ends the call. */
  stallTimeoutMs?: number };

/** A message that stops arriving midway (a stuck or hostile peer) ends the call after this. */
export const STALL_TIMEOUT_MS = 60_000;
/**
 * Feedback the peer has not read, counted as memory: above this the call ends instead of
 * buffering more. Each outstanding write costs about 200 to 400 bytes besides its data
 * (measured with Node 22 and 24 against a peer that stopped reading), and an accept is only
 * about 16 bytes, so writes are charged WRITE_OVERHEAD_BYTES each as well: counting data
 * alone let a million unread accepts hold over 600 MiB.
 */
export const MAX_PENDING_WRITE_BYTES = 16 * 1024 * 1024;
export const WRITE_OVERHEAD_BYTES = 1024;
/** A split message is collected in blocks of this size, so a trickle of tiny frames cannot multiply its memory. */
const BODY_BLOCK_BYTES = 64 * 1024;

/** A dead peer (crashed host, dropped NAT entry) sends nothing; PINGs detect it. */
export const PING_INTERVAL_MS = 30_000;
export const PING_TIMEOUT_MS = 20_000;

function frame(message: Buffer): Buffer {
  const framed = Buffer.allocUnsafe(5 + message.length);
  framed[0] = 0;
  framed.writeUInt32BE(message.length, 1);
  message.copy(framed, 5);
  return framed;
}

function decodeGrpcMessage(value: string | string[] | undefined): string {
  const text = Array.isArray(value) ? value[0] : value;
  if (!text) return '';
  try { return decodeURIComponent(text); } catch { return text; }
}

/**
 * Opens a bidirectional call. `onMessage` runs synchronously for each complete message;
 * it must respond quickly because LND waits for the middleware's feedback.
 */
export function openGrpcStream(target: GrpcTarget, onMessage: (message: Buffer) => void): GrpcStream {
  let session: ClientHttp2Session | undefined;
  const call: { stream?: ClientHttp2Stream } = {};
  let settle!: (end: GrpcEnd) => void;
  let settled = false;
  const ended = new Promise<GrpcEnd>(resolve => { settle = resolve; });
  const finish = (end: GrpcEnd) => {
    if (settled) return;
    settled = true;
    clearTimeout(connectTimer);
    clearInterval(pinger);
    clearTimeout(pingDeadline);
    clearTimeout(stallTimer);
    wipeParts();
    try { call.stream?.close(constants.NGHTTP2_CANCEL); } catch { /* already closed */ }
    try { session?.close(); } catch { /* already closed */ }
    session?.destroy();
    settle(end);
  };
  const connectTimer = setTimeout(() => finish({ status: null, message: 'connect timeout', transport: true }),
    target.connectTimeoutMs ?? 10_000);
  let pinger: ReturnType<typeof setInterval> | undefined;
  let pingDeadline: ReturnType<typeof setTimeout> | undefined;
  let stallTimer: ReturnType<typeof setTimeout> | undefined;
  // Message assembly: the 5-byte header, then the body. A body that is wholly inside the
  // received chunk is handed over as a view (no copy). One split across chunks is copied
  // into blocks of BODY_BLOCK_BYTES as it arrives and joined only once complete, so an
  // announced but unsent 190 MiB message costs what arrived (rounded up to one block),
  // never the announced length.
  const header = Buffer.alloc(5);
  let headerFill = 0;
  let inBody = false;
  let parts: Buffer[] = [];
  let bodyLength = 0;
  let bodyFill = 0;
  const wipeParts = (): void => {
    for (const part of parts) part.fill(0);
    parts = [];
  };
  let status: number | null = null;
  let statusMessage = '';
  const servername = /^[0-9.]+$|:/.test(target.host) ? undefined : target.host;
  try {
    session = connect(`https://${target.host.includes(':') ? `[${target.host}]` : target.host}:${target.port}`, {
      ca: target.ca, rejectUnauthorized: true, servername, ...identityCheck(target.host),
    });
  } catch {
    finish({ status: null, message: 'transport failure', transport: true });
    return { send: () => false, close: () => finish({ status: null, message: 'closed', transport: false }), ended };
  }
  session.on('error', () => finish({ status: null, message: 'transport failure', transport: true }));
  session.on('goaway', () => finish({ status: status, message: statusMessage || 'connection closed by LND', transport: status === null }));
  session.once('connect', () => {
    clearTimeout(connectTimer);
    // TCP keepalive as well, so the operating system also notices a vanished peer.
    try { (session!.socket as unknown as { setKeepAlive(enable: boolean, delay: number): void }).setKeepAlive(true, 30_000); }
    catch { /* PING liveness below still applies */ }
    const every = target.pingIntervalMs ?? PING_INTERVAL_MS;
    pinger = setInterval(() => {
      if (settled || pingDeadline) return;
      pingDeadline = setTimeout(() => finish({ status: null, message: 'liveness timeout', transport: true }),
        target.pingTimeoutMs ?? PING_TIMEOUT_MS);
      try {
        session!.ping(error => {
          clearTimeout(pingDeadline);
          pingDeadline = undefined;
          if (error) finish({ status: null, message: 'liveness failure', transport: true });
        });
      } catch { finish({ status: null, message: 'liveness failure', transport: true }); }
    }, every);
  });
  const stream = session.request({
    ':method': 'POST', ':path': target.path, 'content-type': 'application/grpc', te: 'trailers',
    ...target.metadata,
  }, { endStream: false });
  call.stream = stream;

  const readStatus = (headers: Record<string, string | string[] | undefined>) => {
    const value = headers['grpc-status'];
    if (value !== undefined) {
      const parsed = Number(Array.isArray(value) ? value[0] : value);
      status = Number.isInteger(parsed) ? parsed : 2;
      statusMessage = decodeGrpcMessage(headers['grpc-message']);
    }
  };
  stream.on('response', headers => {
    const code = Number(headers[':status']);
    if (code !== 200) { finish({ status: null, message: `HTTP ${code}`, transport: false }); return; }
    // Trailers-only responses carry the status in the initial headers.
    readStatus(headers as Record<string, string | string[] | undefined>);
  });
  stream.on('trailers', headers => readStatus(headers as Record<string, string | string[] | undefined>));

  const stallMs = target.stallTimeoutMs ?? STALL_TIMEOUT_MS;
  const deliver = (message: Buffer): boolean => {
    try { onMessage(message); }
    catch (error) {
      message.fill(0);
      finish({ status: null, message: error instanceof LndError ? error.message : 'middleware handler failure', transport: false });
      return false;
    }
    // The handler copies what it needs; intercepted macaroons must not linger in receive buffers.
    message.fill(0);
    // The handler's feedback can end the session (unsent-feedback limit): stop there.
    return !settled;
  };
  stream.on('data', (chunk: Buffer) => {
    if (settled) return;
    // Feedback for the messages of every chunk read in this turn goes out together (see send).
    batching = true;
    try { receive(chunk); } finally {
      // Raw receive buffers may hold intercepted macaroons too.
      chunk.fill(0);
      batching = false;
    }
  });
  const receive = (chunk: Buffer): void => {
    let offset = 0;
    while (offset < chunk.length) {
      // A session that ended mid-chunk delivers nothing more and keeps no pieces.
      if (settled) return;
      if (!inBody) {
        const take = Math.min(5 - headerFill, chunk.length - offset);
        chunk.copy(header, headerFill, offset, offset + take);
        headerFill += take;
        offset += take;
        if (headerFill < 5) break;
        headerFill = 0;
        if (header[0] !== 0) { finish({ status: null, message: 'compressed gRPC message refused', transport: false }); return; }
        const length = header.readUInt32BE(1);
        if (length > MAX_GRPC_MESSAGE) { finish({ status: null, message: 'gRPC message too large', transport: false }); return; }
        if (chunk.length - offset >= length) {
          const message = chunk.subarray(offset, offset + length);
          offset += length;
          if (!deliver(message)) return;
          continue;
        }
        inBody = true;
        bodyLength = length;
        bodyFill = 0;
      }
      // Copied: the chunk is wiped when this handler returns.
      // A new block only once the previous one is full (a chunk can end right after a header).
      if (bodyFill === parts.length * BODY_BLOCK_BYTES) parts.push(Buffer.allocUnsafe(Math.min(BODY_BLOCK_BYTES, bodyLength - bodyFill)));
      const blockFill = bodyFill - (parts.length - 1) * BODY_BLOCK_BYTES;
      const block = parts[parts.length - 1];
      const take = Math.min(block.length - blockFill, chunk.length - offset);
      chunk.copy(block, blockFill, offset, offset + take);
      bodyFill += take;
      offset += take;
      if (bodyFill < bodyLength) continue;
      const message = parts.length === 1 ? parts[0] : Buffer.concat(parts, bodyLength);
      if (parts.length > 1) wipeParts(); else parts = [];
      inBody = false;
      if (!deliver(message)) return;
    }
    if (settled) return;
    // A message that stops arriving midway must not hold its pieces forever.
    clearTimeout(stallTimer);
    stallTimer = inBody || headerFill
      ? setTimeout(() => finish({ status: null, message: 'stalled gRPC message', transport: true }), stallMs) : undefined;
  };
  stream.on('error', () => finish({ status, message: statusMessage || 'transport failure', transport: status === null }));
  // LND ends the call (with its status in the trailers) while our half is still open.
  stream.on('end', () => finish({ status, message: statusMessage || (status === null ? 'stream closed' : ''), transport: status === null }));
  stream.on('close', () => finish({ status, message: statusMessage || (status === null ? 'stream closed' : ''), transport: status === null }));

  // Memory held by feedback handed to HTTP/2 but not yet sent (see MAX_PENDING_WRITE_BYTES),
  // counted from write() until its callback, which runs once the data has gone out.
  let pending = 0;
  // Feedback for received messages is collected and written once per event-loop turn (after
  // every chunk read in it): one HTTP/2 write per turn instead of one per intercepted call,
  // which was the largest per-call cost under load. Nothing waits longer than that turn.
  let batching = false;
  let batch: Buffer[] = [];
  let batchBytes = 0;
  const write = (data: Buffer): void => {
    const cost = data.length + WRITE_OVERHEAD_BYTES;
    pending += cost;
    stream.write(data, () => { pending -= cost; });
  };
  let flushScheduled = false;
  const flushBatch = (): void => {
    flushScheduled = false;
    if (!batch.length) return;
    const data = batch.length === 1 ? batch[0] : Buffer.concat(batch, batchBytes);
    batch = [];
    batchBytes = 0;
    if (settled || stream.destroyed || !stream.writable) return;
    write(data);
  };
  return {
    send(message) {
      if (settled || stream.destroyed || !stream.writable) return false;
      const data = frame(message);
      if (batching) {
        batch.push(data);
        batchBytes += data.length;
        if (!flushScheduled) { flushScheduled = true; setImmediate(flushBatch); }
      } else write(data);
      // A peer that stops reading feedback must not grow our buffers without bound.
      if (pending + batchBytes + WRITE_OVERHEAD_BYTES > MAX_PENDING_WRITE_BYTES || stream.writableLength > MAX_PENDING_WRITE_BYTES) {
        finish({ status: null, message: 'LND is not reading middleware feedback', transport: true });
        return false;
      }
      return true;
    },
    close() { finish({ status: null, message: 'closed', transport: false }); },
    ended,
  };
}
