import { EventEmitter } from 'node:events';
import { afterEach, expect, it, vi } from 'vitest';

// A scripted HTTP/2 peer: openGrpcStream's real receive and send code runs against it.
// The peer never confirms writes, so the client's unsent-feedback limit ends the session
// partway through a chunk; nothing may be delivered or armed after that.
type Peer = { stream: EventEmitter };
const peers: Peer[] = [];
vi.mock('node:http2', () => ({
  constants: { NGHTTP2_CANCEL: 8 },
  connect: () => {
    const session = Object.assign(new EventEmitter(), {
      socket: { setKeepAlive() {} }, closed: false, destroyed: false,
      close() { session.closed = true; }, destroy() { session.destroyed = true; },
      ping(cb: (error: Error | null) => void) { setImmediate(() => cb(null)); return true; },
      request() {
        const stream = Object.assign(new EventEmitter(), {
          destroyed: false, writable: true, writableLength: 0,
          // Never confirmed: the peer has stopped reading.
          write(data: Buffer) { stream.writableLength += data.length; return true; },
          close() { stream.destroyed = true; stream.writable = false; },
        });
        peers.push({ stream });
        return stream;
      },
    });
    setImmediate(() => session.emit('connect'));
    return session;
  },
}));

const { openGrpcStream } = await import('../src/lnd/grpc.js');
const { encodeFeedback } = await import('../src/lnd/middleware-proto.js');

const varint = (value: number) => { const out: number[] = []; let x = value; do { let y = x & 0x7f; x = Math.floor(x / 128); if (x) y |= 0x80; out.push(y); } while (x); return Buffer.from(out); };
const field = (number: number, body: Buffer) => Buffer.concat([varint((number << 3) | 2), varint(body.length), body]);
const intField = (number: number, value: number) => Buffer.concat([varint(number << 3), varint(value)]);
const frame = (message: Buffer) => { const header = Buffer.alloc(5); header.writeUInt32BE(message.length, 1); return Buffer.concat([header, message]); };

afterEach(() => { vi.restoreAllMocks(); peers.length = 0; });

it('WATCH/session-end a session ended by the unsent-feedback limit mid-chunk delivers nothing more and arms no stall timer', async () => {
  const armed: number[] = [];
  let ended = false;
  const realSetTimeout = globalThis.setTimeout;
  vi.spyOn(globalThis, 'setTimeout').mockImplementation(((callback: () => void, ms?: number) => {
    if (ended && ms === 60_000) armed.push(ms);
    return realSetTimeout(callback, ms);
  }) as typeof setTimeout);
  let delivered = 0, deliveredAfterEnd = 0;
  const stream = openGrpcStream({ host: 'h', port: 1, ca: Buffer.from('x'), path: '/p', metadata: {} }, () => {
    delivered += 1;
    if (ended) deliveredAfterEnd += 1;
    if (!stream.send(encodeFeedback(2n))) ended = true;
  });
  void stream.ended.then(() => { ended = true; });
  await new Promise(resolve => setImmediate(resolve));
  const rpc = Buffer.concat([field(1, Buffer.from('/a/B')), field(4, Buffer.from('payload'))]);
  const one = frame(Buffer.concat([intField(1, 1), field(2, Buffer.concat([Buffer.from('0201', 'hex'), Buffer.alloc(3000, 0x41)])),
    field(5, rpc), intField(7, 2)]));
  // Two whole messages plus the start of a third per chunk, so the limit is crossed with a
  // partial message still in the chunk.
  for (let turn = 0; turn < 50_000 && !ended; turn++) {
    peers[0].stream.emit('data', Buffer.concat([one, one, one.subarray(0, 2000)]));
    if (!ended) peers[0].stream.emit('data', Buffer.from(one.subarray(2000)));
    await new Promise(resolve => setImmediate(resolve));
  }
  await new Promise(resolve => realSetTimeout(resolve, 10));
  expect(ended).toBe(true);
  expect(delivered).toBeGreaterThan(0);
  expect(deliveredAfterEnd).toBe(0);
  expect(armed).toEqual([]);
});
