// Minimal protobuf codec for LND's RegisterRPCMiddleware stream (lnrpc/lightning.proto,
// v0.21.4-beta): RPCMiddlewareRequest is decoded, RPCMiddlewareResponse is encoded.
// Only the fields macwarden needs are read; every other field is skipped by wire type and
// never copied. Serialized RPC payloads are skipped too, except the request payload of a
// method the caller names in `payloadMethods` (watch --payment-journal: the payment and
// payment-deletion requests), which is passed on as a view, never copied here.
import { LndError } from '../errors.js';

export type InterceptKind = 'stream_auth' | 'request' | 'response' | 'reg_complete' | 'none';

export type MiddlewareRequest = {
  requestId: bigint;
  msgId: bigint;
  /** Raw macaroon bytes of the intercepted call; empty when the call carried none. */
  rawMacaroon: Buffer;
  customCaveatCondition: string;
  kind: InterceptKind;
  method: string;
  isError: boolean;
  /** The call carried a macaroon larger than MAX_MACAROON_BYTES; it was not copied. */
  oversizedMacaroon: boolean;
  /**
   * A view of the serialized request message (RPCMessage.serialized) of a `request` intercept
   * whose method is in `payloadMethods`, at most MAX_PAYLOAD_BYTES; empty otherwise.
   */
  payload: Buffer;
  /** The request payload of a selected method was larger than MAX_PAYLOAD_BYTES; it is not passed on. */
  oversizedPayload: boolean;
};

const MAX_UINT64 = (1n << 64n) - 1n;
// Caller- or LND-controlled fields are bounded before anything is copied or decoded:
// a real macaroon is a few KiB and a gRPC method name well under 100 bytes. Larger values
// are never copied, so a hostile peer cannot make watch amplify a huge field.
export const MAX_MACAROON_BYTES = 64 * 1024;
export const MAX_METHOD_BYTES = 256;
export const MAX_CONDITION_BYTES = 256;
export const UNKNOWN_METHOD = '/unknown/Unknown';
/** Largest request payload passed on for a selected method (see payload). */
export const MAX_PAYLOAD_BYTES = 64 * 1024;

function protocolError(): never {
  throw new LndError(5, 'middleware-stream', 'invalid LND middleware message');
}

const EMPTY = Buffer.alloc(0);

// Every intercepted call is decoded here before its feedback is sent, so this path avoids
// BigInt arithmetic, generators and copies; it accepts and rejects exactly what the exact
// (BigInt) reader below does.
function exactVarint(data: Buffer, start: number): [bigint, number] {
  let value = 0n;
  let shift = 0n;
  let position = start;
  for (;;) {
    if (position >= data.length || shift > 63n) protocolError();
    const byte = data[position++];
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  if (value > MAX_UINT64) protocolError();
  return [value, position];
}

/** A varint of at most 7 bytes (49 bits) is read as a number; longer ones exactly. */
function varint(data: Buffer, start: number): [number | bigint, number] {
  let value = 0;
  let scale = 1;
  const last = Math.min(data.length, start + 7);
  for (let position = start; position < last; position++) {
    const byte = data[position];
    value += (byte & 0x7f) * scale;
    if ((byte & 0x80) === 0) return [value, position + 1];
    scale *= 128;
  }
  return exactVarint(data, start);
}

type Visit = (number: number, wire: number, value: number | bigint, bytes: Buffer | null) => void;

/** Visits top-level fields; length-delimited values are passed as views, not copies. */
function eachField(data: Buffer, visit: Visit): void {
  let position = 0;
  while (position < data.length) {
    const [tag, afterTag] = varint(data, position);
    position = afterTag;
    const number = typeof tag === 'number' ? Math.floor(tag / 8) : Number(tag >> 3n);
    const wire = typeof tag === 'number' ? tag % 8 : Number(tag & 7n);
    if (number < 1) protocolError();
    if (wire === 0) {
      const [value, next] = varint(data, position);
      position = next;
      visit(number, wire, value, null);
    } else if (wire === 2) {
      const [length, next] = varint(data, position);
      if (typeof length !== 'number' || length > data.length - next) protocolError();
      const end = next + length;
      visit(number, wire, length, data.subarray(next, end));
      position = end;
    } else if (wire === 1) {
      if (position + 8 > data.length) protocolError();
      position += 8;
    } else if (wire === 5) {
      if (position + 4 > data.length) protocolError();
      position += 4;
    } else protocolError();
  }
}

// Strict UTF-8 (invalid sequences throw) that keeps a leading byte order mark as text.
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function text(bytes: Buffer | null): string {
  if (!bytes) protocolError();
  try { return utf8.decode(bytes); } catch { return protocolError(); }
}

const exact = (value: number | bigint): bigint => (typeof value === 'bigint' ? value : BigInt(value));

/**
 * RPCMessage (fields 5 and 6) and StreamAuth (field 4): method URI and error flag, and the
 * serialized payload (field 4 of RPCMessage) as a view, returned only to the caller that
 * asked for it (a request of a selected method).
 */
function rpcMessage(bytes: Buffer, result: MiddlewareRequest): Buffer | null {
  result.method = '';
  result.isError = false;
  let serialized: Buffer | null = null;
  eachField(bytes, (number, wire, value, field) => {
    if (number === 1 && wire === 2)
      result.method = field!.length > MAX_METHOD_BYTES ? UNKNOWN_METHOD : text(field);
    else if (number === 5 && wire === 0) result.isError = value !== 0 && value !== 0n;
    else if (number === 4 && wire === 2) serialized = field;
  });
  return serialized;
}

/**
 * Decodes one RPCMiddlewareRequest. `payloadMethods` names the methods whose request payload
 * is passed on (as a view into `data`, at most MAX_PAYLOAD_BYTES); for every other method,
 * and for responses and stream authentication, no payload is passed on.
 */
export function decodeMiddlewareRequest(data: Buffer, payloadMethods?: ReadonlySet<string>): MiddlewareRequest {
  const result: MiddlewareRequest = { requestId: 0n, msgId: 0n, rawMacaroon: EMPTY,
    customCaveatCondition: '', kind: 'none', method: '', isError: false, oversizedMacaroon: false,
    payload: EMPTY, oversizedPayload: false };
  eachField(data, (number, wire, value, bytes) => {
    switch (number) {
      case 1: if (wire === 0) result.requestId = exact(value); break;
      case 7: if (wire === 0) result.msgId = exact(value); break;
      // A view into `data`, not a copy: the caller copies it into a Secret only if it needs
      // it, before the frame is wiped.
      case 2:
        if (wire !== 2) break;
        if (bytes!.length > MAX_MACAROON_BYTES) { result.oversizedMacaroon = true; result.rawMacaroon = EMPTY; }
        else result.rawMacaroon = bytes!;
        break;
      // A longer condition cannot belong to a canary (16 hex characters): it is ignored.
      case 3: if (wire === 2 && bytes!.length <= MAX_CONDITION_BYTES) result.customCaveatCondition = text(bytes); break;
      case 4: if (wire === 2) { result.kind = 'stream_auth'; const isError = result.isError; rpcMessage(bytes!, result); result.isError = isError; result.payload = EMPTY; result.oversizedPayload = false; } break;
      case 5:
        if (wire !== 2) break;
        result.kind = 'request';
        {
          const serialized = rpcMessage(bytes!, result);
          result.payload = EMPTY;
          result.oversizedPayload = false;
          if (serialized && payloadMethods?.has(result.method)) {
            if (serialized.length > MAX_PAYLOAD_BYTES) result.oversizedPayload = true;
            else result.payload = serialized;
          }
        }
        break;
      case 6: if (wire === 2) { result.kind = 'response'; rpcMessage(bytes!, result); result.payload = EMPTY; result.oversizedPayload = false; } break;
      case 8: if (wire === 0 && value !== 0 && value !== 0n) result.kind = 'reg_complete'; break;
      default: break;
    }
  });
  return result;
}

function encodeVarint(value: bigint): Buffer {
  if (value < 0n || value > MAX_UINT64) throw new RangeError('varint out of range');
  const bytes: number[] = [];
  let rest = value;
  do {
    let byte = Number(rest & 0x7fn);
    rest >>= 7n;
    if (rest) byte |= 0x80;
    bytes.push(byte);
  } while (rest);
  return Buffer.from(bytes);
}

function tag(number: number, wire: number): Buffer { return encodeVarint(BigInt((number << 3) | wire)); }

function lengthDelimited(number: number, bytes: Buffer): Buffer {
  return Buffer.concat([tag(number, 2), encodeVarint(BigInt(bytes.length)), bytes]);
}

/** RPCMiddlewareResponse{ register: MiddlewareRegistration } */
export function encodeRegistration(registration: { name: string; readOnly: boolean; caveatName?: string }): Buffer {
  const parts = [lengthDelimited(1, Buffer.from(registration.name, 'utf8'))];
  if (registration.caveatName) parts.push(lengthDelimited(2, Buffer.from(registration.caveatName, 'utf8')));
  if (registration.readOnly) parts.push(tag(3, 0), encodeVarint(1n));
  return lengthDelimited(2, Buffer.concat(parts));
}

/** RPCMiddlewareResponse{ ref_msg_id, feedback: InterceptFeedback{ error } }; an empty error accepts. */
export function encodeFeedback(refMsgId: bigint, error = ''): Buffer {
  if (error) {
    const feedback = lengthDelimited(1, Buffer.from(error, 'utf8'));
    return Buffer.concat([tag(1, 0), encodeVarint(refMsgId), lengthDelimited(3, feedback)]);
  }
  // Accepting is the per-call answer: tag 1, the id, then an empty field 3, in one buffer.
  if (refMsgId < 0n || refMsgId > MAX_UINT64) throw new RangeError('varint out of range');
  const out = Buffer.allocUnsafe(13);
  out[0] = 0x08;
  let position = 1;
  let rest = refMsgId;
  do {
    let byte = Number(rest & 0x7fn);
    rest >>= 7n;
    if (rest) byte |= 0x80;
    out[position++] = byte;
  } while (rest);
  out[position++] = 0x1a;
  out[position++] = 0x00;
  return out.subarray(0, position);
}
