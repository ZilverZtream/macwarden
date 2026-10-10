import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { getEventListeners } from 'node:events';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, expect, it, vi } from 'vitest';
import { Cancelled, withCancellation } from '../src/cancellation.js';
import { readCredential, InputError } from '../src/input/index.js';
import { main } from '../src/cli.js';
import { handlers } from '../src/commands/handlers.js';
import { run as inspectRun } from '../src/commands/inspect.js';

afterEach(() => { vi.restoreAllMocks(); });

const vector = readFileSync(join(resolve(), 'test/vectors', 'default-readonly.macaroon'));
const LIMIT = 1_048_576;

function openStdin(): PassThrough & { isTTY: boolean } {
  const stream = new PassThrough() as PassThrough & { isTTY: boolean };
  stream.isTTY = false;
  return stream;
}

function waitListeners(stream: PassThrough): number {
  return stream.listenerCount('readable') + stream.listenerCount('end') + stream.listenerCount('error');
}

it('F14/stdin an abort wakes a stdin wait whose producer never ends: Cancelled, listeners released', async () => {
  const stdin = openStdin();
  const baseline = waitListeners(stdin);
  const controller = new AbortController();
  // Half a credential arrives, then the producer stays open without ending.
  stdin.write(vector.subarray(0, 10));
  const pending = withCancellation(controller.signal, () => readCredential('-', { stdin, fs }, { unsafeArg: false }));
  let settled = false;
  pending.then(() => { settled = true; }, () => { settled = true; });
  await new Promise(resolve => setImmediate(resolve));
  expect(settled).toBe(false);
  controller.abort();
  const error = await pending.catch((failure: unknown) => failure);
  expect(error).toBeInstanceOf(Cancelled);
  expect(error).not.toBeInstanceOf(InputError);
  expect(waitListeners(stdin)).toBeLessThanOrEqual(baseline);
  expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
});

it('F14/stdin an already-aborted signal rejects with Cancelled before waiting', async () => {
  const stdin = openStdin();
  const controller = new AbortController();
  controller.abort();
  const error = await withCancellation(controller.signal, () => readCredential('-', { stdin, fs }, { unsafeArg: false }))
    .catch((failure: unknown) => failure);
  expect(error).toBeInstanceOf(Cancelled);
});

it('F14/stdin a completed read releases the abort listener and is unaffected by the signal', async () => {
  const stdin = openStdin();
  const controller = new AbortController();
  const pending = withCancellation(controller.signal, () => readCredential('-', { stdin, fs }, { unsafeArg: false }));
  await new Promise(resolve => setImmediate(resolve));
  stdin.end(vector);
  const result = await pending;
  expect(result.literal).toBe(false);
  expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
});

it('F14/cli inspect - with an open producer exits 6 cancelled on SIGINT, not an input or internal failure', async () => {
  const stdin = openStdin();
  stdin.write(vector.subarray(0, 10));
  let out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => { out += String(chunk); return true; }) as typeof process.stdout.write);
  vi.spyOn(handlers, 'inspect').mockImplementation(async args => {
    const running = inspectRun(args, { stdin, fs, clock: () => new Date(0) });
    setImmediate(() => process.emit('SIGINT'));
    return running;
  });
  const code = await main(['inspect', '-', '--json']);
  expect(code).toBe(6);
  expect(JSON.parse(out)).toMatchObject({ command: 'inspect', ok: false, result: null,
    error: { code: 6, step: 'cancelled', message: 'interrupted' } });
});

function inTemp<T>(action: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'macwarden-input-'));
  return action(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

/** fs.open whose handles record every read buffer's length. */
function recordingFs(lengths: number[]): typeof fs {
  return { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    const read = handle.read.bind(handle) as (...a: unknown[]) => Promise<unknown>;
    (handle as unknown as { read: unknown }).read = (buffer: Buffer, ...rest: unknown[]) => { lengths.push(buffer.length); return read(buffer, ...rest); };
    return handle;
  }) as typeof fs.open };
}

it('O06/file a small credential file is read into a buffer sized to the file, not the 1 MiB limit', async () => {
  await inTemp(async dir => {
    const file = join(dir, 'small.macaroon');
    writeFileSync(file, vector);
    const lengths: number[] = [];
    const result = await readCredential(file, { stdin: openStdin(), fs: recordingFs(lengths) }, { unsafeArg: false });
    expect(result.literal).toBe(false);
    expect(lengths.length).toBeGreaterThan(0);
    expect(Math.max(...lengths)).toBeLessThanOrEqual(vector.length + 1);
  });
});

it('O06/file the 1 MiB limit still holds: exactly the limit decodes, one byte more is input-read', async () => {
  await inTemp(async dir => {
    const hex = vector.toString('hex');
    const atLimit = join(dir, 'at-limit.hex');
    writeFileSync(atLimit, hex + ' '.repeat(LIMIT - hex.length));
    const result = await readCredential(atLimit, { stdin: openStdin(), fs }, { unsafeArg: false });
    expect(result.literal).toBe(false);
    const over = join(dir, 'over-limit.hex');
    writeFileSync(over, hex + ' '.repeat(LIMIT + 1 - hex.length));
    const error = await readCredential(over, { stdin: openStdin(), fs }, { unsafeArg: false }).catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(InputError);
    expect((error as InputError).stage).toBe('input-read');
  });
});

it('O06/file a file that grows past its reported size is still cut at the limit and refused', async () => {
  await inTemp(async dir => {
    const file = join(dir, 'growing.macaroon');
    writeFileSync(file, vector);
    let served = 0;
    const growing = { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
      const handle = await fs.open(...args);
      // fstat reports the small file; reads keep yielding data, as a file appended to meanwhile.
      (handle as unknown as { read: unknown }).read = async (buffer: Buffer, offset: number, length: number) => {
        buffer.fill(0x20, offset, offset + length);
        served += length;
        return { bytesRead: length, buffer };
      };
      return handle;
    }) as typeof fs.open };
    const error = await readCredential(file, { stdin: openStdin(), fs: growing }, { unsafeArg: false }).catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(InputError);
    expect((error as InputError).stage).toBe('input-read');
    expect(served).toBeLessThanOrEqual(LIMIT + 1);
  });
});
