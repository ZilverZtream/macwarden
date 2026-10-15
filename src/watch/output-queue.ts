// Event output for `macwarden watch` that can never stall the event loop answering LND.
// process.stdout writes are synchronous for files and pipes (and for terminals on
// POSIX), so a reader that stops (a paused pager, a backed-up log shipper) would block
// every intercept feedback and make LND fail node RPCs at its middleware timeout.
// Lines are queued in memory up to a byte limit and written by one asynchronous
// fs.write at a time: a blocked write waits in the libuv thread pool, never on the event
// loop. Lines beyond the limit are dropped and counted; priority lines (canary alerts and
// drop notices) are queued up to a hard ceiling. Only a closed reader (EPIPE, EBADF) stops
// output; a full non-blocking pipe (EAGAIN) is backpressure and the write is retried.
//
// Node switches stdout to non-blocking mode once process.stdout is touched (the CLI does
// that at load), so on Linux a full pipe or socket answers EAGAIN instead of blocking a
// thread-pool write. Treating that as a closed reader would silence every later line,
// canary alerts included, while the reader is alive.
import { write as fsWrite } from 'node:fs';

const PRIORITY_FACTOR = 4;

export const OUTPUT_LIMIT_BYTES = 1 << 20;
const BATCH_BYTES = 1 << 16;

/**
 * Writes a chunk and resolves with the number of bytes written: at least one for a non-empty
 * chunk, or it rejects. A writer that waits for a full reader retries itself (fdWriter).
 */
export type ChunkWriter = (chunk: Buffer) => Promise<number>;

export type OutputQueue = {
  push(line: string, priority?: boolean): void;
  /** Lines dropped because the reader fell behind or output was closed. */
  dropped(): number;
  /** Resolves true once everything queued is written, or false after timeoutMs. */
  drain(timeoutMs: number): Promise<boolean>;
  /** After close: resolves true once the write already in flight has completed, or false after timeoutMs. */
  settle(timeoutMs: number): Promise<boolean>;
  /**
   * Stops output for good: queued lines are dropped and counted, later lines are dropped,
   * and a writer built with the same stop predicate stops retrying. Used when a final
   * drain times out, so a reader that never reads cannot keep the process alive.
   */
  close(): void;
};

type RawWrite = (fd: number, chunk: Buffer, callback: (error: NodeJS.ErrnoException | null, written: number) => void) => void;
const rawWrite: RawWrite = (fd, chunk, callback) => fsWrite(fd, chunk, 0, chunk.length, null, callback);
const RETRY_MIN_MS = 5;
const RETRY_MAX_MS = 200;

/** True for a write error that only means "not now": the reader is alive but full. */
export function retryable(error: NodeJS.ErrnoException): boolean {
  return error.code === 'EAGAIN' || error.code === 'EWOULDBLOCK' || error.code === 'EINTR';
}

/**
 * Writes to a file descriptor. EAGAIN, EWOULDBLOCK and EINTR are retried with a capped
 * backoff (timers, never a busy loop); any other error rejects, which closes the queue.
 * A write that moved no byte of a non-empty chunk is retried the same way (audit 1.3.2): it
 * was retried at once and forever. It is backed off rather than rejected because a
 * rejection closes output for good, canary alerts included, and nothing shows the reader
 * gone; close() still ends the retries through `stopped`.
 */
export function fdWriter(fd: number, write: RawWrite = rawWrite,
  // Retry timers are unref'd: on their own they never keep the process alive.
  wait: (ms: number) => Promise<void> = ms => new Promise(resolve => { setTimeout(resolve, ms).unref(); }),
  stopped: () => boolean = () => false): ChunkWriter {
  return chunk => new Promise((resolve, reject) => {
    let delay = RETRY_MIN_MS;
    const attempt = (): void => write(fd, chunk, (error, written) => {
      if (!error && (written > 0 || !chunk.length)) { resolve(written); return; }
      if ((error && !retryable(error)) || stopped()) { reject(error ?? new Error('write made no progress')); return; }
      const ms = delay;
      delay = Math.min(delay * 2, RETRY_MAX_MS);
      void wait(ms).then(attempt);
    });
    attempt();
  });
}

export function createOutputQueue(writeChunk: ChunkWriter, limitBytes = OUTPUT_LIMIT_BYTES): OutputQueue {
  const queue: Buffer[] = [];
  let queued = 0;
  let dropped = 0;
  let busy = false;
  let closed = false;
  const waiters = new Set<() => void>();
  const idle = () => { if (!busy && !queue.length) for (const waiter of [...waiters]) waiter(); };
  const pump = (): void => {
    if (busy || closed || !queue.length) { idle(); return; }
    busy = true;
    const parts: Buffer[] = [];
    let size = 0;
    while (queue.length && (size === 0 || size + queue[0].length <= BATCH_BYTES)) {
      const part = queue.shift()!;
      parts.push(part);
      size += part.length;
    }
    const chunk = parts.length === 1 ? parts[0] : Buffer.concat(parts, size);
    // A writer that made no progress broke its contract: requeued at once, the batch would be
    // retried on microtasks forever, starving the event loop. It fails like a write error (audit 1.3.2).
    writeChunk(chunk).then(written => {
      if (!(written > 0) && chunk.length) throw new Error('write made no progress');
      return written;
    }).then(written => {
      busy = false;
      const count = Math.max(0, Math.min(written, chunk.length));
      if (count < chunk.length) {
        // A partial write returns the rest as the lines it came from (only the first one
        // sliced), so a later loss counts every line that was not completely written.
        let skip = count;
        let first = 0;
        while (skip >= parts[first].length) { skip -= parts[first].length; first++; }
        const rest = [parts[first].subarray(skip), ...parts.slice(first + 1)];
        // After close nothing more is written: the rest is dropped and counted (1.2.1).
        if (closed) dropped += rest.length;
        else queue.unshift(...rest);
      }
      // close() already emptied the queue and its byte count.
      if (!closed) queued -= count;
      pump();
    }, () => {
      busy = false;
      closed = true;
      // The batch being written is lost with everything still queued (1.2.1).
      dropped += parts.length + queue.length;
      queue.length = 0;
      queued = 0;
      idle();
    });
  };
  return {
    push(line, priority = false) {
      if (closed) { dropped += 1; return; }
      const bytes = Buffer.from(line, 'utf8');
      // Priority lines (canary alerts, status) may exceed the normal limit, but only up to a
      // hard ceiling: they are already rate-limited, and nothing may grow without bound.
      if (queued + bytes.length > (priority ? limitBytes * PRIORITY_FACTOR : limitBytes)) { dropped += 1; return; }
      queue.push(bytes);
      queued += bytes.length;
      pump();
    },
    dropped: () => dropped,
    close() {
      if (closed) return;
      closed = true;
      dropped += queue.length;
      queue.length = 0;
      queued = 0;
      idle();
    },
    /** Resolves once no write is in flight (after close, the queue is empty): true when settled within the deadline. */
    settle(timeoutMs) {
      if (!busy) return Promise.resolve(true);
      return new Promise(resolve => {
        const timer = setTimeout(() => { waiters.delete(done); resolve(false); }, timeoutMs);
        const done = () => { clearTimeout(timer); waiters.delete(done); resolve(true); };
        waiters.add(done);
      });
    },
    drain(timeoutMs) {
      if (!busy && !queue.length) return Promise.resolve(true);
      return new Promise(resolve => {
        const timer = setTimeout(() => { waiters.delete(done); resolve(false); }, timeoutMs);
        function done() { clearTimeout(timer); waiters.delete(done); resolve(true); }
        waiters.add(done);
      });
    },
  };
}
