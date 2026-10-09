import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { acquireLock, type Deps as WatchDeps } from '../../src/commands/watch.js';
import type { MiddlewareCall } from '../../src/lnd/index.js';
import { Secret } from '../../src/secret.js';
import { PaymentJournal, type WriterDeps } from '../../src/watch/payment-journal.js';

export const NODE = `02${'ab'.repeat(32)}`;
export const OTHER_NODE = `03${'cd'.repeat(32)}`;
const repo = resolve();
export const vector = (name: string) => readFileSync(join(repo, 'test/vectors', `${name}.macaroon`));

/** Independent credential ID: SHA-256 of the identifier packet (packet type 2 of the header section). */
export function identityOf(bytes: Buffer): string {
  const varint = (at: number): [number, number] => {
    let value = 0, shift = 0;
    for (;;) { const b = bytes[at++]; value += (b & 0x7f) * 2 ** shift; if (!(b & 0x80)) return [value, at]; shift += 7; }
  };
  let at = 1;
  for (;;) {
    const [type, afterType] = varint(at);
    const [length, start] = varint(afterType);
    if (type === 2) return `id:${createHash('sha256').update(bytes.subarray(start, start + length)).digest('hex').slice(0, 16)}`;
    at = start + length;
  }
}

/** The lock watch uses (`<journal>.lock`), with this process as owner. */
export function lock(): WriterDeps['lock'] {
  const deps = { fs, env: {}, clock: () => new Date(), emit: () => undefined, hostname: () => hostname(), pid: process.pid,
    processDomain: async () => null } as unknown as WatchDeps;
  return path => acquireLock(path, deps);
}

export function writerDeps(overrides: Partial<WriterDeps> = {}): WriterDeps {
  let now = Date.parse('2026-10-09T10:00:00.000Z');
  return { fs, clock: () => new Date(now += 1_000), lock: lock(), ...overrides };
}

export async function openJournal(path: string, overrides: Partial<WriterDeps> = {}, node = NODE): Promise<PaymentJournal> {
  return PaymentJournal.open(path, node, '1.2.0-test', writerDeps(overrides));
}

/** A request intercept as registerMiddleware hands it to the observer. */
export function paymentCall(method: string, payload: Buffer | null, macaroon: Buffer | null, requestId = 1n,
  extra: Partial<MiddlewareCall> = {}): MiddlewareCall {
  return { kind: 'request', requestId, method, isError: false, customCaveatCondition: '',
    macaroon: macaroon ? new Secret(macaroon) : null, payload: payload ? Buffer.from(payload) : null,
    payloadBytes: payload?.length ?? 0, macaroonBytes: macaroon?.length ?? 0, ...extra };
}

const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false, allErrors: true });
const validate = ajv.compile(JSON.parse(readFileSync(join(repo, 'schemas/output/payment-journal-record.schema.json'), 'utf8')));
/** Every complete line of a journal file matches the published record schema. */
export function expectLinesValid(text: string, expectValid: (ok: boolean, detail: string) => void): void {
  for (const line of text.split('\n').filter(Boolean)) {
    const ok = validate(JSON.parse(line)) as boolean;
    expectValid(ok, `${line} ${JSON.stringify(validate.errors)}`);
  }
}

/** Waits until the journal has decoded and written what it was given (several event-loop turns). */
export async function settle(turns = 20): Promise<void> {
  for (let i = 0; i < turns; i++) await new Promise(done => setImmediate(done));
  await new Promise(done => setTimeout(done, 20));
}
