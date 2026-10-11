import { appendFileSync, existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import {
  labModuleUrl, loadLab, preimageFor, tempDirectory,
  type EffectTarget, type Invoice, type Lab, type PassResult, type RawDb, type ReceiverStore,
} from './helpers/payment-lab-modules.js';

/**
 * The payment lab's outbox (examples/payment-lab/src/outbox) against the pre-1.4 audits: on POSIX
 * a key file open to group or others is refused (anyone who reads it can sign a receipt the
 * worker accepts as already written); an effect is written as the bytes of its whole text, so a
 * character outside the BMP is never split, and what is on disk is checked before the ack; a
 * directory sync that fails for a reason other than the platform not supporting it is an error;
 * a worker started with an aborted signal performs nothing. The mode and sync rules are checked
 * for every platform's answer, whatever platform runs the test.
 */

type ReceiptFields = Record<string, string | number | null>;
let effects: {
  keyModeProblem(path: string, mode: number, platform?: NodeJS.Platform): string | undefined;
  directorySyncUnsupported(code: string | undefined, platform?: NodeJS.Platform): boolean;
  publish(target: EffectTarget, subject: string, fields: ReceiptFields, hooks?: { duringWrite?(tmpPath: string): void }): 'written' | 'already-present';
  readEffect(path: string, key: Buffer): { state: string; fields?: ReceiptFields; reason?: string };
  effectPath(target: EffectTarget, subject: string): string;
  sign(key: Buffer, fields: ReceiptFields): string;
};
let worker: {
  runOutbox(db: RawDb, target: EffectTarget, options: { emit: (event: Record<string, unknown>) => void; once: boolean; intervalMs: number;
    signal: AbortSignal }): Promise<PassResult>;
};
let lab: Lab;
const dir = tempDirectory();
const KEY = Buffer.from('5c'.repeat(32), 'hex');

beforeAll(async () => {
  lab = await loadLab();
  effects = await import(/* @vite-ignore */ labModuleUrl('outbox/effects.ts')) as typeof effects;
  worker = await import(/* @vite-ignore */ labModuleUrl('outbox/worker.ts')) as typeof worker;
});
afterAll(() => dir.remove());

const opened: { close(): void }[] = [];
afterEach(() => {
  for (const store of opened.splice(0)) {
    try { store.close(); } catch { /* already closed */ }
  }
});

describe('payment lab outbox audit: the key file must be owner-only on POSIX', () => {
  it('a key readable or writable by group or others is refused, naming the key and its mode', () => {
    for (const platform of ['linux', 'darwin'] as const) {
      expect(effects.keyModeProblem('/lab/outbox.key', 0o100644, platform)).toMatch(/^\/lab\/outbox\.key is open to group or others \(mode 0644\).*chmod 600/);
      expect(effects.keyModeProblem('/lab/outbox.key', 0o100620, platform)).toMatch(/mode 0620/);
      expect(effects.keyModeProblem('/lab/outbox.key', 0o100604, platform)).toMatch(/mode 0604/);
      expect(effects.keyModeProblem('/lab/outbox.key', 0o100600, platform)).toBeUndefined();
      expect(effects.keyModeProblem('/lab/outbox.key', 0o100400, platform)).toBeUndefined();
    }
  });

  it('on Windows the mode bits are not the DACL, and nothing is refused on them', () => {
    expect(effects.keyModeProblem('C:\\lab\\outbox.key', 0o100666, 'win32')).toBeUndefined();
  });
});

describe('payment lab outbox audit: a lost key is not recreated while profile directories hold signed files', () => {
  it('effects only under receipts/<profile>/ and no outbox.key: refused, naming the key and a file, and no key is written', () => {
    const labDir = dir.path('lost-key-profile-lab');
    const target = { dir: join(labDir, 'receipts', 'alice'), key: KEY };
    expect(effects.publish(target, 'ORD-K', { kind: 'fulfill-order', idempotencyKey: 'ORD-K:h', orderId: 'ORD-K' })).toBe('written');
    expect(() => lab.outbox.labKey(labDir)).toThrow(`${join(labDir, 'outbox.key')} is missing`);
    expect(() => lab.outbox.labKey(labDir)).toThrow(join(labDir, 'receipts', 'alice'));
    expect(existsSync(join(labDir, 'outbox.key'))).toBe(false);
    expect(readdirSync(labDir)).toEqual(['receipts']);
  });

  it('a profile directory holding only temporary files does not block a new key', () => {
    const labDir = dir.path('fresh-profile-lab');
    mkdirSync(join(labDir, 'confirmations', 'bob'), { recursive: true });
    writeFileSync(join(labDir, 'confirmations', 'bob', '.op.json.0000000000000000.1.tmp'), '{');
    expect(lab.outbox.labKey(labDir)).toHaveLength(32);
  });
});

describe('payment lab outbox audit: an effect file is the bytes of its whole text, checked before the ack', () => {
  /** Fields whose effect text has a surrogate pair straddling the middle of its UTF-16 length (where 1.3.0 split the write). */
  function straddling(): ReceiptFields {
    for (let pad = 0; pad < 64; pad += 1) {
      const fields: ReceiptFields = { kind: 'fulfill-order', idempotencyKey: 'ORD-E:h', orderId: 'ORD-E', note: `${'x'.repeat(pad)}${'\u{1F600}'.repeat(40)}` };
      const content = `${JSON.stringify({ ...fields, hmacSha256: effects.sign(KEY, fields) }, null, 2)}\n`;
      const code = content.charCodeAt(Math.floor(content.length / 2) - 1);
      if (code >= 0xd800 && code <= 0xdbff) return fields;
    }
    throw new Error('no padding puts a surrogate pair across the middle');
  }

  it('a character outside the BMP across the middle is written intact and verifies', () => {
    const target = { dir: dir.path('surrogate-receipts'), key: KEY };
    const fields = straddling();
    expect(effects.publish(target, 'ORD-E', fields)).toBe('written');
    expect(effects.readEffect(effects.effectPath(target, 'ORD-E'), KEY)).toEqual({ state: 'valid', fields });
  });

  it('a file that does not verify once written is reported damaged, not written', () => {
    const target = { dir: dir.path('damaged-receipts'), key: KEY };
    const fields: ReceiptFields = { kind: 'fulfill-order', idempotencyKey: 'ORD-D:h', orderId: 'ORD-D' };
    expect(() => effects.publish(target, 'ORD-D', fields, { duringWrite: tmp => { appendFileSync(tmp, 'x'.repeat(4096)); } }))
      .toThrow(/not a valid effect file/);
  });
});

describe('payment lab outbox audit: directory sync', () => {
  it('only the platform or file system not supporting it is skipped; an I/O error is not', () => {
    for (const code of ['EISDIR', 'EPERM', 'EACCES', 'EINVAL', 'ENOTSUP']) expect(effects.directorySyncUnsupported(code, 'win32'), code).toBe(true);
    for (const code of ['EINVAL', 'ENOTSUP']) expect(effects.directorySyncUnsupported(code, 'linux'), code).toBe(true);
    for (const code of ['EIO', 'ENOSPC', 'EPERM', 'EACCES', 'EISDIR', undefined]) expect(effects.directorySyncUnsupported(code, 'linux'), String(code)).toBe(false);
    expect(effects.directorySyncUnsupported('EIO', 'win32')).toBe(false);
  });
});

describe('payment lab outbox audit: a worker started with an aborted signal', () => {
  it('performs no pass: the row stays pending and nothing is written', async () => {
    const store: ReceiverStore = new lab.ReceiverStore(dir.path('aborted.db'));
    opened.push(store);
    const { preimage, paymentHash } = preimageFor('aborted-order');
    store.recordInvoiceIntent({ orderId: 'ORD-A', amountMsat: 1000n, kind: 'standard', preimage, paymentHash });
    store.markCreated(paymentHash, 'lnbcrt1a', 1n);
    const settled: Invoice = { paymentHash, state: 'SETTLED', memo: '', valueMsat: 1000n, amtPaidMsat: 1000n, addIndex: 1n, settleIndex: 1n,
      paymentRequest: '', htlcs: [] };
    expect(store.applyInvoice(settled, 'subscription')).toBe('fulfilled');
    const target = { dir: dir.path('aborted-receipts'), key: KEY };
    const events: Record<string, unknown>[] = [];
    const result = await worker.runOutbox(store.db, target, { emit: event => { events.push(event); }, once: false, intervalMs: 10,
      signal: AbortSignal.abort() });
    expect(result).toMatchObject({ performed: 0, remaining: 1 });
    expect(store.outbox('ORD-A').map(row => row.state)).toEqual(['pending']);
    expect(existsSync(target.dir) ? readdirSync(target.dir) : []).toEqual([]);
  });
});
