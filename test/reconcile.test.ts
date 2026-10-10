import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { LIST_LIMIT, LIST_PAGE, MAX_MSAT, RECONCILE_BUDGET_MS, TRACK_LIMIT, run } from '../src/commands/reconcile.js';
import { LndError } from '../src/errors.js';
import snapshot from '../src/grade/lnd-permissions.json' with { type: 'json' };
import type { LndAdapter, LndPayment, PaymentLookup } from '../src/lnd/index.js';
import { render, type ReconcileResult } from '../src/output/index.js';
import { expectSchemaValid } from './helpers/output-schema.js';
import { NODE, OTHER_NODE, vector } from './helpers/payment-journal.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const BASE = Date.parse('2026-10-09T10:00:00.000Z');
const at = (seconds: number) => new Date(BASE + seconds * 1_000).toISOString();
const ns = (seconds: number) => BigInt(BASE + seconds * 1_000) * 1_000_000n;
const H = (name: string) => createHash('sha256').update(name).digest('hex');
const RUN = '11111111-2222-4333-8444-555555555555';
const RUN2 = '66666666-7777-4888-9999-aaaaaaaaaaaa';
const C1 = 'id:0123456789abcdef';
const C2 = 'id:fedcba9876543210';
const SEND = '/routerrpc.Router/SendPaymentV2';
const ROUTE = '/routerrpc.Router/SendToRouteV2';

const line = (type: string, seconds: number, extra: Record<string, unknown> = {}, run = RUN) =>
  JSON.stringify({ v: 1, type, time: at(seconds), run, ...extra });
const start = (seconds: number, run = RUN, node = NODE) => line('run-start', seconds, { node, version: '1.2.0', repairedTail: false }, run);
let requestId = 0;
const payment = (seconds: number, credential: string, rootKeyId: string, paymentHash: string | null, amountMsat: string | null,
  extra: Record<string, unknown> = {}, run = RUN) => line('payment', seconds, { requestId: String(++requestId), method: SEND, credential, rootKeyId,
  paymentHash, amountMsat, amountSource: amountMsat === null ? null : 'request', feeLimitMsat: '5000', amp: false,
  extraction: paymentHash ? 'complete' : 'amp', ...extra }, run);

type Htlc = { status: 'succeeded' | 'failed' | 'in-flight' | 'unknown'; amountMsat: bigint; feesMsat: bigint };
// An LND payment as the adapter reduces it: the attempts are summed by status, not kept.
function lnd(paymentHash: string, createdSeconds: number, status: LndPayment['status'], htlcs: Htlc[] = [],
  failureReason: string | null = null, index = 1n): LndPayment {
  const succeeded = htlcs.filter(item => item.status === 'succeeded');
  const inFlight = htlcs.filter(item => item.status === 'in-flight');
  return { paymentHash, status, createdAtNs: ns(createdSeconds), valueMsat: succeeded.reduce((total, item) => total + item.amountMsat, 0n),
    feeMsat: succeeded.reduce((total, item) => total + item.feesMsat, 0n), attempts: htlcs.length, succeededAttempts: succeeded.length,
    succeededMsat: succeeded.reduce((total, item) => total + item.amountMsat, 0n),
    succeededFeesMsat: succeeded.reduce((total, item) => total + item.feesMsat, 0n),
    inFlightMsat: inFlight.reduce((total, item) => total + item.amountMsat, 0n), failureReason, index };
}
const htlc = (status: Htlc['status'], amountMsat: bigint, feesMsat: bigint): Htlc => ({ status, amountMsat, feesMsat });

type Fake = Partial<LndAdapter & PaymentLookup> & { listed?: LndPayment[]; tracked?: Map<string, LndPayment | null | Error>; calls?: string[] };
function fakeLnd(fake: Fake): LndAdapter & PaymentLookup {
  const unexpected = (): never => { throw new Error('unexpected adapter call'); };
  const calls = fake.calls ?? [];
  return {
    getInfo: async () => { calls.push('getInfo'); return { pubkey: NODE, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }; },
    listPermissions: async () => { calls.push('listPermissions'); return snapshot.methods as Record<string, string[]>; },
    listMacaroonIds: unexpected, bakeMacaroon: unexpected, deleteMacaroonId: unexpected, checkMacaroon: unexpected,
    listPayments: async ({ startSeconds, endSeconds, indexOffset, max }) => {
      calls.push(`listPayments ${startSeconds} ${endSeconds} ${indexOffset}`);
      const inWindow = (fake.listed ?? []).filter(item => item.createdAtNs >= BigInt(startSeconds) * 1_000_000_000n
        && item.createdAtNs <= BigInt(endSeconds) * 1_000_000_000n && item.index > indexOffset).slice(0, max);
      return { payments: inWindow, lastIndexOffset: inWindow.at(-1)?.index ?? indexOffset };
    },
    trackPayment: async hash => {
      calls.push(`trackPayment ${hash}`);
      const found = fake.tracked?.get(hash);
      if (found instanceof Error) throw found;
      return found ?? null;
    },
    ...fake,
  } as LndAdapter & PaymentLookup;
}

function setup(journal: string[], registryEntries: object[] = []) {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'reconcile-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'tls.cert'), 'not used by the fake adapter');
  writeFileSync(join(dir, 'own.macaroon'), vector('default-readonly'));
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: registryEntries }));
  const path = join(dir, 'payments.journal');
  writeFileSync(path, journal.length ? `${journal.join('\n')}\n` : '');
  return { dir, path, args: ['--payment-journal', path, '--lnd-rest', 'localhost:8080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', registry] };
}

const entry = (label: string, rootKeyId: string) => ({ nodePubkey: NODE, label, rootKeyId, permissions: ['offchain:write'], caveats: [],
  grade: 'SPEND', fingerprint: 'fp:0123456789abcdef', outPath: null, createdAt: '2026-10-01T00:00:00Z', verified: true, status: 'active',
  revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null });

const reconcile = (args: string[], lnd: LndAdapter & PaymentLookup, clock = '2026-10-09T12:00:00.000Z') =>
  run(args, { lnd, fs, env: {}, clock: () => new Date(clock) });

it('RECONCILE/classification settlement, attribution, gaps and unattributed payments, each kept as separate evidence', async () => {
  const journal = [
    start(0), line('registered', 10, { session: 1 }),
    payment(100, C1, '4294967341', H('h1'), '100000'),
    payment(200, C1, '4294967341', H('h2'), '200000'),
    payment(300, C2, '0', H('h3'), '50000'),
    payment(400, C2, '0', H('h4'), '10000'),
    payment(500, C1, '4294967341', H('h5'), '7000'),
    payment(600, C1, '4294967341', H('h6'), '1000'),
    payment(610, C2, '0', H('h6'), '1000'),
    payment(700, C2, '0', null, '3000', { amp: true, extraction: 'amp' }),
    line('deletion', 800, { requestId: '900', method: '/lnrpc.Lightning/DeletePayment', credential: C2, rootKeyId: '0', paymentHash: H('h4'),
      scope: 'payment', extraction: 'complete' }),
    line('drop', 900, { count: 2, first: at(850), last: at(860), reason: 'overload' }),
    line('unregistered', 1000, { session: 1, reason: 'stream-lost' }),
    line('registered', 1100, { session: 2 }),
    payment(1200, C1, '4294967341', H('h7'), '4000'),
    line('unregistered', 1500, { session: 2, reason: 'stopping' }),
    line('run-end', 1501, { payments: 9, deletions: 1, dropped: 2 }),
    start(2000, RUN2), line('registered', 2010, { session: 1 }, RUN2), line('alive', 2400, {}, RUN2),
  ];
  const s = setup(journal, [entry('shop', '4294967341')]);
  const listed = [
    lnd(H('h1'), 101, 'succeeded', [htlc('failed', 100_000n, 1_000n), htlc('failed', 100_000n, 1_200n), htlc('succeeded', 100_000n, 2_500n)], null, 1n),
    lnd(H('h2'), 201, 'failed', [], 'no-route', 2n),
    lnd(H('h3'), 301, 'in-flight', [htlc('in-flight', 50_000n, 100n)], null, 3n),
    lnd(H('h6'), 601, 'succeeded', [htlc('succeeded', 1_000n, 0n)], null, 4n),
    lnd(H('u1'), 1050, 'succeeded', [htlc('succeeded', 9_000n, 10n)], null, 5n),
    lnd(H('u3'), 1120, 'failed', [], 'timeout', 6n),
    lnd(H('u2'), 1300, 'succeeded', [htlc('succeeded', 8_000n, 0n)], null, 7n),
  ];
  const tracked = new Map<string, LndPayment | null | Error>([
    [H('h4'), null],
    [H('h5'), new LndError(5, 'track-payment', 'LND request rejected')],
    // Created a day before the journaled request: an earlier attempt's outcome.
    [H('h7'), lnd(H('h7'), -86_400, 'succeeded', [htlc('succeeded', 4_000n, 1n)], null, 99n)],
  ]);
  const calls: string[] = [];
  const output = await reconcile([...s.args, '--since', at(0), '--until', at(3_600)], fakeLnd({ listed, tracked, calls }));
  expectSchemaValid(output);
  expect(output).toMatchObject({ ok: true, command: 'reconcile', error: null, exitCode: 1 });
  const result = output.result as ReconcileResult;
  // Q5 to Q7: GetInfo, ListPermissions, one listing of the widened window, then one lookup per hash the listing lacks.
  expect(calls.slice(0, 3)).toEqual(['getInfo', 'listPermissions', `listPayments ${BASE / 1_000 - 60} ${BASE / 1_000 + 3_660} 0`]);
  expect(calls.filter(call => call.startsWith('trackPayment')).sort()).toEqual([H('h4'), H('h5'), H('h7')].map(hash => `trackPayment ${hash}`).sort());

  const byHash = new Map(result.payments.map(item => [item.paymentHash, item]));
  expect(result.payments.map(item => item.paymentHash)).toEqual(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7'].map(H));
  expect(byHash.get(H('h1'))).toMatchObject({ attribution: 'single', credentials: [C1],
    observation: { calls: 1, requestedMsat: '100000', feeLimitMsat: '5000', routeAttemptsMsat: null },
    settlement: { status: 'succeeded', source: 'list-payments', settledMsat: '100000', feesMsat: '2500', inFlightMsat: '0', attempts: 3,
      failureReason: null, predatesObservation: false } });
  expect(byHash.get(H('h1'))!.observation.observations[0]).toMatchObject({ credential: C1, rootKeyId: '4294967341', label: 'shop', method: SEND });
  expect(byHash.get(H('h2'))!.settlement).toMatchObject({ status: 'failed', settledMsat: '0', feesMsat: '0', attempts: 0, failureReason: 'no-route' });
  expect(byHash.get(H('h3'))!.settlement).toMatchObject({ status: 'in-flight', settledMsat: '0', inFlightMsat: '50000', attempts: 1 });
  // Not found is LND's evidence (no record), never proof that nothing was paid; here a deletion was journaled for it.
  expect(byHash.get(H('h4'))).toMatchObject({ settlement: { status: 'not-found', source: null, settledMsat: null, attempts: null }, deletedBy: [C2] });
  expect(byHash.get(H('h5'))!.settlement).toMatchObject({ status: 'unknown', source: null });
  expect(byHash.get(H('h6'))).toMatchObject({ attribution: 'ambiguous', credentials: [C2, C1].sort(), observation: { calls: 2 } });
  expect(byHash.get(H('h7'))!.settlement).toMatchObject({ status: 'succeeded', source: 'track-payment', predatesObservation: true });

  const rows = new Map(result.credentials.map(row => [row.credential, row]));
  // h7's LND record predates its journaled request (1.2.1): historical, counted for no credential.
  expect(byHash.get(H('h7'))).toMatchObject({ attribution: 'historical', credentials: [C1] });
  expect(rows.get(C1)).toEqual({ credential: C1, rootKeyIds: ['4294967341'], label: 'shop', payments: 3, succeeded: 1, failed: 1, inFlight: 0,
    notFound: 0, unknown: 1, ambiguous: 1, historical: 1, unmatched: 0, deletions: 0, requestedMsat: String(100_000 + 200_000 + 7_000),
    settledMsat: String(100_000), feesMsat: String(2_500), inFlightMsat: '0' });
  expect(rows.get(C2)).toEqual({ credential: C2, rootKeyIds: ['0'], label: null, payments: 2, succeeded: 0, failed: 0, inFlight: 1,
    notFound: 1, unknown: 0, ambiguous: 1, historical: 0, unmatched: 1, deletions: 1, requestedMsat: '60000', settledMsat: '0', feesMsat: '0',
    inFlightMsat: '50000' });
  expect(result.unmatched).toEqual([expect.objectContaining({ credential: C2, extraction: 'amp', time: at(700) })]);
  expect(result.unattributed.map(item => [item.paymentHash, item.coverage, item.status, item.settledMsat])).toEqual([
    [H('u1'), 'gap', 'succeeded', '9000'], [H('u3'), 'boundary', 'failed', '0'], [H('u2'), 'covered', 'succeeded', '8000']]);
  expect(result.deletions).toEqual([expect.objectContaining({ credential: C2, scope: 'payment', paymentHash: H('h4') })]);
  expect(result.coverage.gaps.map(gap => [gap.from, gap.to, gap.reason, gap.dropped])).toEqual([
    [at(0), at(10), 'not-registered', 0], [at(850), at(860), 'dropped', 2], [at(1000), at(1100), 'not-registered', 0],
    [at(1500), at(2010), 'not-running', 0], [at(2400), at(3600), 'unconfirmed', 0]]);
  expect(result.coverage).toMatchObject({ windowSeconds: 3_600, complete: false, gapCount: 5, gapSeconds: 10 + 10 + 100 + 510 + 1_200,
    coveredSeconds: 3_600 - (10 + 10 + 100 + 510 + 1_200) });
  expect(result.journal).toMatchObject({ runs: 2, records: journal.length, otherNodeRecords: 0, tornTail: false });
  expect(result.lookups).toEqual({ listed: 7, listTruncated: false, tracked: 2, trackFailed: 1, trackLimited: 0, attributedOutsideWindow: 0 });
  const codes = output.warnings.map(item => typeof item === 'string' ? item : item.code);
  expect(codes).toEqual(expect.arrayContaining(['journal-gaps', 'unattributed-payments', 'payments-uncertain', 'journal-unmatched',
    'attribution-ambiguous', 'payment-deletions']));
  expect(codes).not.toContain('snapshot-drift');

  // The text says which evidence is which, and never merges them.
  const text = render(output, 'text');
  expect(text).toContain(`payment      ${H('h1')}  observed: ${C1}, 1 request, requested 100000 msat, fee limit 5000 msat  |  LND: succeeded, `
    + 'settled 100000 msat, fees 2500 msat, 3 attempts');
  expect(text).toContain(`unattributed ${H('u1')}  created ${at(1050)}  succeeded, settled 9000 msat, fees 10 msat  (in a journal gap)`);
  expect(text).toContain('LND record predates the observed request');
  expect(text).toMatch(/^evidence {5}observed requests \(journal\) and settlement \(LND\) are separate/m);
  // No credential bytes in any output.
  const own = vector('default-readonly');
  for (const rendered of [text, render(output, 'json')])
    for (const form of [own.toString('hex'), own.toString('base64')]) expect(rendered).not.toContain(form);
});

it('RECONCILE/complete a fully covered window where every payment settled exits 0', async () => {
  const s = setup([start(0), line('registered', 1, { session: 1 }), payment(10, C1, '4294967341', H('ok'), '1000'),
    payment(20, C1, '4294967341', H('ok'), '1000', { method: ROUTE, amountSource: 'route' }),
    line('unregistered', 100, { session: 1, reason: 'stopping' }), line('run-end', 100, { payments: 2, deletions: 0, dropped: 0 })]);
  const listed = [lnd(H('ok'), 10, 'succeeded', [htlc('failed', 1_000n, 5n), htlc('succeeded', 1_000n, 3n)])];
  const output = await reconcile([...s.args, '--since', at(1), '--until', at(100)], fakeLnd({ listed }));
  expectSchemaValid(output);
  expect(output).toMatchObject({ ok: true, error: null });
  expect(output.exitCode).toBeUndefined();
  const result = output.result as ReconcileResult;
  expect(result.coverage).toMatchObject({ complete: true, gapCount: 0, coveredSeconds: 99 });
  expect(result.payments[0]).toMatchObject({ observation: { calls: 2, requestedMsat: '1000', routeAttemptsMsat: '1000' },
    settlement: { status: 'succeeded', settledMsat: '1000', feesMsat: '3', attempts: 2 } });
  // The session credential here is LND's default readonly macaroon (root key 0), which every
  // online command reports (SAFE-09); reconcile itself adds no warning for a complete window.
  expect(output.warnings).toEqual(['own-root-key-0']);
});

it('RECONCILE/window defaults run from the first record to now; records of another node are ignored and counted', async () => {
  const s = setup([start(0, RUN, OTHER_NODE), payment(5, C1, '1', H('other'), '1', {}, RUN), line('run-end', 6, { payments: 1, deletions: 0, dropped: 0 }),
    start(10, RUN2), line('registered', 11, { session: 1 }, RUN2), payment(20, C2, '0', H('mine'), '2', {}, RUN2)]);
  const output = await reconcile(s.args, fakeLnd({ listed: [lnd(H('mine'), 20, 'succeeded', [htlc('succeeded', 2n, 0n)])] }), at(30));
  expectSchemaValid(output);
  const result = output.result as ReconcileResult;
  expect(result.window).toEqual({ since: at(10), until: at(30) });
  expect(result.journal).toMatchObject({ records: 3, otherNodeRecords: 3, runs: 1 });
  expect(result.payments.map(item => item.paymentHash)).toEqual([H('mine')]);
  expect(output.warnings.map(item => typeof item === 'string' ? item : item.code)).toContain('journal-other-node');
});

it('RECONCILE/relative windows and a payment journaled before the window is attributed, not unattributed', async () => {
  const s = setup([start(0), line('registered', 1, { session: 1 }), payment(10, C1, '4294967341', H('early'), '1'), line('alive', 3_590)]);
  const listed = [lnd(H('early'), 1_900, 'succeeded', [htlc('succeeded', 1n, 0n)])];
  const output = await reconcile([...s.args, '--since', '1h'], fakeLnd({ listed }), at(3_600));
  const result = output.result as ReconcileResult;
  expect(result.window).toEqual({ since: at(0), until: at(3_600) });
  expect(result.unattributed).toEqual([]);
  expect(result.payments.map(item => item.paymentHash)).toEqual([H('early')]);
  const later = await reconcile([...s.args, '--since', at(1_800), '--until', at(2_000)], fakeLnd({ listed }), at(3_600));
  expect((later.result as ReconcileResult).unattributed).toEqual([]);
  expect((later.result as ReconcileResult).lookups.attributedOutsideWindow).toBe(1);
});

it('RECONCILE/steps arguments, permissions, the journal and LND failures stop at their step with nothing changed', async () => {
  const s = setup([start(0)]);
  const lndOk = fakeLnd({});
  const cases: [string[], number, string][] = [
    [s.args.filter((_, index) => index > 1), 2, 'Q1'],
    [[...s.args, '--since', 'yesterday'], 2, 'Q1'],
    [[...s.args, '--until', '2026-02-30T00:00:00Z'], 2, 'Q1'],
    [[...s.args, '--since', at(100), '--until', at(50)], 2, 'Q1'],
    [[...s.args, '--frobnicate'], 2, 'Q1'],
    [[...s.args, 'operand'], 2, 'Q1'],
    [[...s.args, '--since', at(1), '--since', at(2)], 2, 'Q1'],
  ];
  for (const [args, code, step] of cases) {
    const output = await reconcile(args, lndOk);
    expect(output.error, args.join(' ')).toMatchObject({ code, step });
    expectSchemaValid(output);
  }
  expect((await run(s.args, { lnd: lndOk, fs, env: { NODE_OPTIONS: '--inspect' }, clock: () => new Date() })).error)
    .toMatchObject({ code: 2, step: 'Q2' });
  // Least privilege: info:read and offchain:read (default-readonly has both); pay-only lacks offchain:read, invoice lacks info:read.
  for (const [name, message] of [['preset-pay-only', 'offchain:read'], ['default-invoice', 'info:read']]) {
    writeFileSync(join(s.dir, 'own.macaroon'), vector(name));
    const calls: string[] = [];
    const output = await reconcile(s.args, fakeLnd({ calls }));
    expect(output.error, name).toMatchObject({ code: 4, step: 'Q3' });
    expect(output.error!.message).toContain(message);
    expect(calls).toEqual([]);
  }
  writeFileSync(join(s.dir, 'own.macaroon'), vector('default-readonly'));
  const broken = setup([start(0), 'not json', line('alive', 5)]);
  expect((await reconcile(broken.args, lndOk)).error).toMatchObject({ code: 3, step: 'Q4' });
  const missing = await reconcile([...s.args.slice(2), '--payment-journal', join(s.dir, 'absent.journal')], lndOk);
  expect(missing.error).toMatchObject({ code: 3, step: 'Q4', message: 'payment journal not found' });
  const protectedJournal = await reconcile([...s.args.slice(2), '--payment-journal', join(s.dir, 'wallet.db')], lndOk);
  expect(protectedJournal.error).toMatchObject({ code: 3, step: 'Q4' });
  const unreachable = await reconcile(s.args, fakeLnd({ getInfo: async () => { throw new LndError(4, 'get-info', 'LND transport failure'); } }));
  expect(unreachable.error).toMatchObject({ code: 4, step: 'Q5' });
  const refused = await reconcile(s.args, fakeLnd({ listPayments: async () => { throw new LndError(5, 'list-payments', 'LND request rejected'); } }));
  expect(refused.error).toMatchObject({ code: 5, step: 'Q6' });
  const journaled = setup([start(0), line('registered', 1, { session: 1 }), payment(2, C1, '1', H('t'), '1')]);
  const authFailure = await reconcile(journaled.args, fakeLnd({ tracked: new Map([[H('t'), new LndError(4, 'track-payment', 'LND authentication failure')]]) }));
  expect(authFailure.error).toMatchObject({ code: 4, step: 'Q7' });
});

it('RECONCILE/bounds the listing is paged and capped, and per-hash lookups are limited, both reported', async () => {
  // LND keeps returning full pages: the listing stops at LIST_LIMIT and says so.
  let pages = 0;
  const endless = fakeLnd({ listPayments: async ({ indexOffset, max }) => {
    pages += 1;
    const payments = Array.from({ length: max }, (_, index) => lnd(H(`bulk-${indexOffset + BigInt(index)}`), 10, 'succeeded', [], null,
      indexOffset + BigInt(index) + 1n));
    return { payments, lastIndexOffset: indexOffset + BigInt(max) };
  } });
  const s = setup([start(0), line('registered', 1, { session: 1 })]);
  const output = await reconcile([...s.args, '--since', at(0), '--until', at(100)], endless);
  expectSchemaValid(output);
  const result = output.result as ReconcileResult;
  expect(pages).toBe(LIST_LIMIT / LIST_PAGE);
  expect(result.lookups).toMatchObject({ listed: LIST_LIMIT, listTruncated: true });
  expect(output.exitCode).toBe(1);
  expect(output.warnings).toContainEqual({ code: 'lookups-limited',
    message: `LND's payment listing stopped at ${LIST_LIMIT} payments; narrow the window with --since and --until` });

  const many = [start(0), line('registered', 1, { session: 1 }),
    ...Array.from({ length: TRACK_LIMIT + 3 }, (_, index) => payment(2 + index / 1_000, C1, '1', H(`t-${index}`), '1'))];
  const limited = setup(many);
  const trackCalls: string[] = [];
  const looked = await reconcile([...limited.args, '--since', at(0), '--until', at(100)], fakeLnd({ calls: trackCalls }));
  expectSchemaValid(looked);
  const lookups = (looked.result as ReconcileResult).lookups;
  expect(lookups).toMatchObject({ tracked: TRACK_LIMIT, trackLimited: 3 });
  expect(trackCalls.filter(call => call.startsWith('trackPayment')).length).toBe(TRACK_LIMIT);
  expect((looked.result as ReconcileResult).payments.filter(item => item.settlement.status === 'unknown').length).toBe(3);
});

it('RECONCILE/budget a listing the 10 minute budget ends is reported as the budget, not the count limit (audit 1.2.1 N2)', async () => {
  // The budget runs out while the third page is read: the listing stops there, far below LIST_LIMIT.
  let clock = Date.now();
  vi.spyOn(Date, 'now').mockImplementation(() => clock);
  let pages = 0;
  const slow = fakeLnd({ listPayments: async ({ indexOffset, max }) => {
    pages += 1;
    if (pages === 3) clock += RECONCILE_BUDGET_MS + 1;
    const payments = Array.from({ length: max }, (_, index) => lnd(H(`slow-${indexOffset + BigInt(index)}`), 10, 'succeeded', [], null,
      indexOffset + BigInt(index) + 1n));
    return { payments, lastIndexOffset: indexOffset + BigInt(max) };
  } });
  const s = setup([start(0), line('registered', 1, { session: 1 })]);
  const output = await reconcile([...s.args, '--since', at(0), '--until', at(100)], slow);
  expectSchemaValid(output);
  expect(pages).toBe(3);
  expect((output.result as ReconcileResult).lookups).toMatchObject({ listed: 3 * LIST_PAGE, listTruncated: true });
  expect(output.exitCode).toBe(1);
  const limited = output.warnings.find(item => typeof item !== 'string' && item.code === 'lookups-limited');
  expect(limited).toEqual({ code: 'lookups-limited', message: `LND's payment listing stopped after ${3 * LIST_PAGE} payments when the `
    + `${RECONCILE_BUDGET_MS / 60_000} minute budget ran out; narrow the window with --since and --until` });
  expect(JSON.stringify(limited)).not.toContain(String(LIST_LIMIT));
});

it('RECONCILE/sums LND amounts that sum past an int64 for one credential are not LND records: exit 5 at Q6 (audit 1.2.1 N1)', async () => {
  // Each payment is within LND's int64 type (the adapter refuses a larger one); their sum for one credential is not.
  const journal = [start(0), line('registered', 1, { session: 1 }), payment(10, C1, '1', H('big-1'), '1000'), payment(20, C1, '1', H('big-2'), '1000')];
  const listed = [lnd(H('big-1'), 10, 'succeeded', [htlc('succeeded', MAX_MSAT, 0n)], null, 1n),
    lnd(H('big-2'), 20, 'succeeded', [htlc('succeeded', 1n, 0n)], null, 2n)];
  const s = setup(journal);
  const output = await reconcile([...s.args, '--since', at(0), '--until', at(100)], fakeLnd({ listed }));
  expectSchemaValid(output);
  expect(output).toMatchObject({ ok: false, result: null, error: { code: 5, step: 'Q6', message: 'invalid LND response' } });
  for (const [fees, inFlight] of [[MAX_MSAT, 0n], [0n, MAX_MSAT]]) {
    const other = [lnd(H('big-1'), 10, inFlight ? 'in-flight' : 'succeeded', [htlc(inFlight ? 'in-flight' : 'succeeded', inFlight || 1n, fees)], null, 1n),
      lnd(H('big-2'), 20, inFlight ? 'in-flight' : 'succeeded', [htlc(inFlight ? 'in-flight' : 'succeeded', 1n, inFlight ? 0n : 1n)], null, 2n)];
    const failed = await reconcile([...s.args, '--since', at(0), '--until', at(100)], fakeLnd({ listed: other }));
    expectSchemaValid(failed);
    expect(failed.error).toEqual({ code: 5, step: 'Q6', message: 'invalid LND response' });
  }
  // At the bound exactly, the sum is reported and the output stays within its schema.
  const atBound = [lnd(H('big-1'), 10, 'succeeded', [htlc('succeeded', MAX_MSAT - 1n, 0n)], null, 1n),
    lnd(H('big-2'), 20, 'succeeded', [htlc('succeeded', 1n, 0n)], null, 2n)];
  const fine = await reconcile([...s.args, '--since', at(0), '--until', at(100)], fakeLnd({ listed: atBound }));
  expectSchemaValid(fine);
  expect((fine.result as ReconcileResult).credentials[0]).toMatchObject({ credential: C1, settledMsat: MAX_MSAT.toString() });
});

it('RECONCILE/sums journaled requests that sum past an int64 are capped and said so; the output stays within its schema (audit 1.2.1 N1)', async () => {
  // A credential can ask for any amount (LND refuses it); the requests are journaled and summed.
  const MAX = MAX_MSAT.toString();
  const journal = [start(0), line('registered', 1, { session: 1 }),
    ...Array.from({ length: 11 }, (_, index) => payment(10 + index, C1, '1', H(`ask-${index}`), MAX)),
    ...Array.from({ length: 11 }, (_, index) => payment(30 + index, C2, '2', H('route'), MAX, { method: ROUTE, amountSource: 'route' }))];
  const s = setup(journal);
  const output = await reconcile([...s.args, '--since', at(0), '--until', at(100)], fakeLnd({}));
  expectSchemaValid(output);
  expect(output).toMatchObject({ ok: true, error: null, exitCode: 1 });
  const result = output.result as ReconcileResult;
  expect(result.credentials.map(row => [row.credential, row.requestedMsat])).toEqual([[C1, MAX], [C2, MAX]]);
  expect(result.payments.find(item => item.paymentHash === H('route'))!.observation.routeAttemptsMsat).toBe(MAX);
  expect(output.warnings.map(item => typeof item === 'string' ? item : item.code)).toContain('requested-amounts-capped');
});

it('RECONCILE/read-only reconcile never writes: the journal and registry are unchanged', async () => {
  const s = setup([start(0), line('registered', 1, { session: 1 }), payment(2, C1, '1', H('ro'), '1')], [entry('shop', '1')]);
  const before = [readFileSync(s.path), readFileSync(join(s.dir, 'registry.json'))];
  const output = await reconcile(s.args, fakeLnd({ listed: [lnd(H('ro'), 2, 'succeeded', [htlc('succeeded', 1n, 0n)])] }), at(10));
  expect(output.ok).toBe(true);
  expect(readFileSync(s.path).equals(before[0])).toBe(true);
  expect(readFileSync(join(s.dir, 'registry.json')).equals(before[1])).toBe(true);
  expect((await fs.readdir(s.dir)).sort()).toEqual(['own.macaroon', 'payments.journal', 'registry.json', 'tls.cert']);
});

// 1.2.1: a payment hash's attribution uses every journaled request for it, in the window or before
// it, and LND's one record is not credited to a credential whose request came after it.
it('RECONCILE/attribution an earlier request by another credential shares the hash; a record older than every request is historical', async () => {
  const journal = [
    start(0), line('registered', 1, { session: 1 }),
    payment(100, C1, '4294967341', H('reuse'), '100000'),
    payment(2000, C2, '0', H('reuse'), '100000'),
    payment(2100, C2, '0', H('old'), '5000'),
    line('alive', 3_590),
  ];
  const s = setup(journal, [entry('shop', '4294967341')]);
  // Both LND records were created outside the window, so the listing lacks them; each is looked up by hash.
  const tracked = new Map<string, LndPayment | null | Error>([
    [H('reuse'), lnd(H('reuse'), 101, 'succeeded', [htlc('succeeded', 100_000n, 10n)], null, 1n)],
    [H('old'), lnd(H('old'), -86_400, 'succeeded', [htlc('succeeded', 5_000n, 1n)], null, 9n)]]);
  const output = await reconcile([...s.args, '--since', at(1_800), '--until', at(3_600)], fakeLnd({ tracked }), at(3_600));
  expectSchemaValid(output);
  expect(output).toMatchObject({ ok: true, exitCode: 1 });
  const result = output.result as ReconcileResult;
  const reuse = result.payments.find(item => item.paymentHash === H('reuse'))!;
  // C1's request lies before the window; it still shares the attribution, and the settlement is not C2's.
  expect(reuse).toMatchObject({ attribution: 'ambiguous', credentials: [C1, C2].sort(), observation: { first: at(100), last: at(2000), calls: 2 },
    settlement: { status: 'succeeded', source: 'track-payment', settledMsat: '100000', predatesObservation: false } });
  const old = result.payments.find(item => item.paymentHash === H('old'))!;
  expect(old).toMatchObject({ attribution: 'historical', credentials: [C2], settlement: { status: 'succeeded', predatesObservation: true } });
  const c2 = result.credentials.find(row => row.credential === C2)!;
  expect(c2).toMatchObject({ payments: 0, succeeded: 0, ambiguous: 1, historical: 1, settledMsat: '0', feesMsat: '0', requestedMsat: '0' });
  const c1 = result.credentials.find(row => row.credential === C1)!;
  expect(c1).toMatchObject({ payments: 0, ambiguous: 1, historical: 0, settledMsat: '0' });
  expect(output.warnings).toContainEqual(expect.objectContaining({ code: 'attribution-historical' }));
  expect(output.warnings).toContainEqual(expect.objectContaining({ code: 'attribution-ambiguous' }));
  const text = render(output, 'text');
  expect(text).toContain(`observed: ambiguous (${[C1, C2].sort().join(', ')})`);
  expect(text).toContain('(historical: LND\'s record is older than every journaled request)');
  expect(text).toContain('1 with an LND record older than any journaled request');
});

// 1.2.1 (owner finding): the window is ordered after --until defaults to now.
it('RECONCILE/window a --since after now is refused, never a negative window reported as complete', async () => {
  const s = setup([start(0), line('registered', 1, { session: 1 }), line('alive', 100)]);
  const output = await reconcile([...s.args, '--since', at(7_200)], fakeLnd({}), at(3_600));
  expect(output).toMatchObject({ ok: false, error: { code: 2, step: 'Q1', message: expect.stringContaining('--since must not be after') } });
});
