import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';

// 1.2.1: the writer checks every record with the reader's rules before writing it. A fact outside
// its documented form (here forced through the facts decoder) is written as 'malformed' with no
// facts, never as a line that would make the whole journal unreadable.
const TRIGGER = createHash('sha256').update('out-of-form').digest();
vi.mock('../src/watch/payment-request.js', async importOriginal => {
  const actual = await importOriginal<typeof import('../src/watch/payment-request.js')>();
  return { ...actual, paymentFacts: (...args: Parameters<typeof actual.paymentFacts>) => {
    const facts = actual.paymentFacts(...args);
    return facts.paymentHash === TRIGGER.toString('hex') ? { ...facts, amountMsat: '-1', amountSource: 'request' as const } : facts;
  } };
});

const { readJournal } = await import('../src/watch/payment-journal.js');
const { bytes } = await import('./helpers/payment-proto.js');
const { openJournal, paymentCall, vector } = await import('./helpers/payment-journal.js');

const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

it('PAYJ/invariant a record the reader would refuse is written as malformed with no facts, and the journal stays readable', async () => {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'payment-journal-invariant-'));
  dirs.push(dir);
  const path = join(dir, 'invariant.journal');
  const journal = await openJournal(path);
  journal.registered();
  journal.capture(paymentCall('/routerrpc.Router/SendPaymentV2', bytes(3, TRIGGER), vector('preset-pay-only')));
  journal.capture(paymentCall('/routerrpc.Router/SendPaymentV2', bytes(3, createHash('sha256').update('plain').digest()), vector('preset-pay-only'), 2n));
  const stats = await journal.close();
  expect(stats).toMatchObject({ payments: 2, dropped: 0, stopped: null });
  const read = await readJournal(path);
  const payments = read.records.filter(item => item.type === 'payment') as Array<Record<string, unknown>>;
  expect(payments[0]).toMatchObject({ paymentHash: null, amountMsat: null, amountSource: null, feeLimitMsat: null, amp: false, extraction: 'malformed',
    credential: expect.stringMatching(/^id:[0-9a-f]{16}$/), requestId: '1' });
  expect(payments[1]).toMatchObject({ paymentHash: createHash('sha256').update('plain').digest('hex'), extraction: 'complete' });
});
