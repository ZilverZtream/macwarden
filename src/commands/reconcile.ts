// `macwarden reconcile --payment-journal <path>`: joins what watch observed (the payment
// journal: which credential asked LND to pay which payment hash, and when watch was or was
// not watching) with what LND reports about each payment (ListPayments, TrackPaymentV2).
// Read-only: nothing is changed in LND, the registry or the journal. Observation and
// settlement stay separate evidence: a journaled request never counts as a payment LND made,
// and the absence of a journal record or an LND record never counts as proof that no payment
// was made.
import * as nodeFs from 'node:fs/promises';
import { Cancelled } from '../cancellation.js';
import { decodeMacaroon } from '../decode/index.js';
import { unsafeNodeDiagnostics } from '../environment.js';
import { LndError } from '../errors.js';
import { isInstant } from '../instant.js';
import { createLndAdapter, type LndAdapter, type LndPayment, type PaymentLookup } from '../lnd/index.js';
import { cancellable } from '../cancellation.js';
import { credentialText, endpoint, failureDetails, nodeInfo, onlineAdapter, readBoundedFile, readOnlineCredential,
  connectionSettings, drift } from '../online.js';
import type { OutputResult, ReconcileCredential, ReconcileObservation, ReconcilePayment, ReconcileResult,
  ReconcileSettlement, ReconcileUnattributed } from '../output/index.js';
import { isProtectedPath } from '../protected-path.js';
import { openRegistry } from '../registry/index.js';
import type { Secret } from '../secret.js';
import { JournalError, journalCoverage, readJournal, type DeletionRecord, type PaymentRecord } from '../watch/payment-journal.js';

export type Deps = {
  lnd?: LndAdapter & PaymentLookup;
  createAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => LndAdapter & PaymentLookup;
  fs: typeof nodeFs;
  env: Record<string, string | undefined>;
  clock: () => Date;
  /** A monotonic clock in milliseconds for the command budget (default performance.now): a system clock step never ends or extends it. */
  monotonic?: () => number;
};

type ReconcileOutput = OutputResult & { schema: 1; exitCode?: number };

function fail(code: number, step: string, message: string, warnings: ReconcileOutput['warnings'] = []): ReconcileOutput {
  return { schema: 1, command: 'reconcile', ok: false, warnings, result: null, error: { code, step, message } };
}

const valueFlags = new Set(['--lnd-rest', '--tls-cert', '--macaroon', '--registry', '--payment-journal', '--since', '--until']);
/**
 * Clocks of the watch host and the LND host may differ: a payment LND created within this
 * many milliseconds of a coverage boundary is reported as `boundary`, never as `covered`.
 */
export const CLOCK_TOLERANCE_MS = 60_000;
/** ListPayments page size and the most payments listed for one window. */
export const LIST_PAGE = 100;
export const LIST_LIMIT = 100_000;
/** Most journaled payment hashes looked up one by one (TrackPaymentV2) when the window's listing does not hold them. */
export const TRACK_LIMIT = 1_000;
/** Most gaps and observations per payment listed in full; counts are always exact. */
export const GAP_LIST_LIMIT = 1_000;
export const OBSERVATION_LIST_LIMIT = 100;
/**
 * Journal credentials that name no credential: a call without a macaroon watch could decode. Any
 * number of different credentials share them (audit 1.4.0: a pay credential re-encoded or padded so
 * watch could not read it was reported as one `single` credential and the run could exit 0).
 */
const UNIDENTIFIED = new Set(['id:none', 'id:undecodable']);

/** `<instant>` (UTC, as macwarden writes them) or `<n>(m|h|d)` before now; null when neither. */
function timeArgument(value: string, now: number): number | null {
  if (isInstant(value)) return Date.parse(value);
  const match = /^([1-9][0-9]{0,5})(m|h|d)$/.exec(value);
  if (!match) return null;
  return now - Number(match[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[match[2] as 'm' | 'h' | 'd'];
}

const iso = (ms: number) => new Date(ms).toISOString();

/** Whether one covered span (sorted, disjoint) holds [from, to]: a binary search (audit 1.2.1: a scan per payment was quadratic). */
function coveredSpan(covered: [number, number][], from: number, to: number): boolean {
  let low = 0, high = covered.length - 1, found = -1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (covered[middle][0] <= from) { found = middle; low = middle + 1; } else high = middle - 1;
  }
  return found >= 0 && to <= covered[found][1];
}

/** Whether any span (sorted, disjoint, ends included) meets [from, to]: a binary search. */
function touchesSpan(spans: [number, number][], from: number, to: number): boolean {
  let low = 0, high = spans.length - 1, found = -1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (spans[middle][0] <= to) { found = middle; low = middle + 1; } else high = middle - 1;
  }
  return found >= 0 && spans[found][1] >= from;
}

// Every LND request has its own timeout; the command as a whole has this budget too (audit 1.2.1),
// after which the remaining pages and lookups are counted as not done and reported.
export const RECONCILE_BUDGET_MS = 10 * 60_000;
const nsToMs = (ns: bigint) => Number(ns / 1_000_000n);
const sum = (values: bigint[]) => values.reduce((total, value) => total + value, 0n);
/**
 * No real amount reaches an int64 of millisatoshi (21 million bitcoin is 2.1e18 msat): a sum of
 * LND's amounts above it means the records are not LND's (exit 5), and a sum of journaled
 * requests above it (a credential can ask for any amount; LND refuses) is reported as this
 * ceiling with the warning `requested-amounts-capped`, so the output stays within its schema.
 */
export const MAX_MSAT = (1n << 63n) - 1n;

/** Settlement evidence from one LND payment record; amounts from its HTLC attempts. */
function settlement(payment: LndPayment, source: 'list-payments' | 'track-payment', firstObserved: number | null): ReconcileSettlement {
  // A succeeded payment whose attempts LND no longer lists keeps LND's own summary amounts.
  const fromSummary = payment.status === 'succeeded' && payment.succeededAttempts === 0;
  const createdAt = nsToMs(payment.createdAtNs);
  return {
    status: payment.status, source, createdAt: iso(createdAt),
    settledMsat: (fromSummary ? payment.valueMsat : payment.succeededMsat).toString(),
    feesMsat: (fromSummary ? payment.feeMsat : payment.succeededFeesMsat).toString(),
    inFlightMsat: payment.inFlightMsat.toString(),
    attempts: payment.attempts,
    failureReason: payment.status === 'failed' ? payment.failureReason ?? 'unknown' : null,
    // LND's record is older than the earliest request watch saw for this hash (beyond clock skew):
    // its outcome may belong to an earlier attempt, made by any credential.
    predatesObservation: firstObserved !== null && createdAt < firstObserved - CLOCK_TOLERANCE_MS,
  };
}

const unknownSettlement = (status: 'not-found' | 'unknown'): ReconcileSettlement => ({ status, source: null, createdAt: null,
  settledMsat: null, feesMsat: null, inFlightMsat: null, attempts: null, failureReason: null, predatesObservation: false });

async function runSteps(args: string[], deps: Deps): Promise<ReconcileOutput> {
  // Q1: flags.
  const flags = new Map<string, string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--json') continue;
    if (!valueFlags.has(arg)) return fail(2, 'Q1', arg.startsWith('--') ? 'unknown flag' : 'reconcile takes no operands');
    const value = args[++i];
    if (flags.has(arg)) return fail(2, 'Q1', `repeated flag ${arg}`);
    if (value === undefined || value.startsWith('--')) return fail(2, 'Q1', `missing value for ${arg}`);
    flags.set(arg, value);
  }
  const journalPath = flags.get('--payment-journal');
  if (!journalPath) return fail(2, 'Q1', 'missing --payment-journal <path>');
  const now = deps.clock().getTime();
  const sinceArg = flags.get('--since'), untilArg = flags.get('--until');
  const sinceFlag = sinceArg === undefined ? null : timeArgument(sinceArg, now);
  const untilFlag = untilArg === undefined ? null : timeArgument(untilArg, now);
  if (sinceArg !== undefined && sinceFlag === null) return fail(2, 'Q1', '--since must be a UTC time (YYYY-MM-DDThh:mm:ssZ) or <n>(m|h|d) before now');
  if (untilArg !== undefined && untilFlag === null) return fail(2, 'Q1', '--until must be a UTC time (YYYY-MM-DDThh:mm:ssZ) or <n>(m|h|d) before now');
  // The journal holds no time before the Unix epoch, and a window reaching before the year 0
  // cannot be written as an instant the output schema accepts (PF-2).
  if (sinceFlag !== null && sinceFlag < 0) return fail(2, 'Q1', '--since must not be before 1970-01-01T00:00:00Z');
  if (untilFlag !== null && untilFlag < 0) return fail(2, 'Q1', '--until must not be before 1970-01-01T00:00:00Z');
  if (sinceFlag !== null && untilFlag !== null && sinceFlag > untilFlag) return fail(2, 'Q1', '--since must not be after --until');
  if (sinceFlag !== null && sinceFlag === untilFlag) return fail(2, 'Q1', 'empty window: --since must be before --until');
  const { host, cert: certPath, own: ownPath, problem: mixedSource } = connectionSettings(flag => flags.get(flag), deps.env);
  if (mixedSource) return fail(2, 'Q1', mixedSource);
  if (!host) return fail(2, 'Q1', 'missing --lnd-rest (or MACWARDEN_LND_REST)');
  if (!certPath) return fail(2, 'Q1', 'missing --tls-cert (or MACWARDEN_TLS_CERT)');
  if (!ownPath) return fail(2, 'Q1', 'missing --macaroon (or MACWARDEN_MACAROON)');
  if (ownPath === '-' || credentialText(ownPath)) return fail(2, 'Q1', 'own macaroon must be a file path');
  const rest = endpoint(host);
  if (!rest) return fail(2, 'Q1', 'invalid LND REST endpoint');
  // Q2: ENV.
  if (unsafeNodeDiagnostics(deps.env)) return fail(2, 'Q2', 'unsafe Node diagnostic settings');

  // Q3: OWN. Least privilege: info:read and offchain:read, or exactly these four methods.
  let cert: Buffer;
  let own: Secret;
  try {
    if (isProtectedPath(certPath)) return fail(4, 'Q3', 'unreadable TLS certificate');
    const resolved = await deps.fs.realpath(certPath);
    if (isProtectedPath(resolved)) return fail(4, 'Q3', 'unreadable TLS certificate');
    cert = await readBoundedFile(resolved, deps.fs);
  } catch { return fail(4, 'Q3', 'unreadable TLS certificate'); }
  try { own = (await readOnlineCredential(ownPath, { stdin: process.stdin, fs: deps.fs })).secret; }
  catch { return fail(4, 'Q3', 'unreadable own macaroon'); }
  let facts;
  try { facts = decodeMacaroon(own); } catch { return fail(4, 'Q3', 'undecodable own macaroon'); }
  const held = new Set(facts.permissions);
  const holds = (permission: string, methods: string[]) => held.has(permission) || methods.every(method => held.has(`uri:${method}`));
  if (!holds('info:read', ['/lnrpc.Lightning/GetInfo', '/lnrpc.Lightning/ListPermissions']))
    return fail(4, 'Q3', 'own macaroon missing permission: info:read (GetInfo, ListPermissions)');
  if (!holds('offchain:read', ['/lnrpc.Lightning/ListPayments', '/routerrpc.Router/TrackPaymentV2']))
    return fail(4, 'Q3', 'own macaroon missing permission: offchain:read (ListPayments, TrackPaymentV2)');
  const warnings: ReconcileOutput['warnings'] = facts.rootKeyId === 0n ? ['own-root-key-0'] : [];

  // Q4: the journal and the registry (labels only), read-only.
  let contents;
  try { contents = await readJournal(journalPath, deps.fs); }
  catch (error) {
    if (error instanceof JournalError) return fail(3, 'Q4', error.message, warnings);
    return fail(3, 'Q4', 'cannot read payment journal', warnings);
  }
  const registryPath = flags.get('--registry');
  if (registryPath && isProtectedPath(registryPath)) return fail(3, 'Q4', 'protected registry path', warnings);
  let registry;
  try { registry = await openRegistry(registryPath, { fs: deps.fs, env: deps.env }); }
  catch { return fail(3, 'Q4', 'unreadable or invalid registry', warnings); }

  // Q5: GetInfo and ListPermissions.
  const adapter = deps.lnd ?? deps.createAdapter?.({ restUrl: rest, tlsCert: cert, macaroon: own });
  if (!adapter) return fail(8, 'internal', 'unexpected failure', warnings);
  const lnd = onlineAdapter(adapter);
  let node: { pubkey: string; alias: string; network: string };
  try {
    const info = nodeInfo(await lnd.getInfo());
    node = { pubkey: info.pubkey, alias: info.alias, network: info.network };
    if (drift(await lnd.listPermissions())) warnings.push('snapshot-drift');
  } catch (error) {
    if (error instanceof Cancelled) return fail(6, 'cancelled', 'operation interrupted; nothing was changed', warnings);
    const failure = failureDetails(error); return fail(failure.code, 'Q5', failure.message, warnings);
  }

  const labels = new Map<string, string>();
  for (const entry of registry.entries)
    if (entry.nodePubkey.toLowerCase() === node.pubkey && entry.status === 'active' && entry.rootKeyId !== '0' && entry.label)
      labels.set(entry.rootKeyId, entry.label);
  const labelFor = (rootKeyId: string) => labels.get(rootKeyId) ?? null;

  // The journal's records for this node: a run belongs to the node its run-start names.
  const runNodes = new Map<string, string>();
  for (const record of contents.records) if (record.type === 'run-start') runNodes.set(record.run, record.node);
  const mine = contents.records.filter(record => runNodes.get(record.run) === node.pubkey);
  const otherNodeRecords = contents.records.length - mine.length;
  // The default window starts at the earliest record time for this node, not the first appended
  // record: times never go back within a run, but a clock set back between runs makes a later run
  // start earlier, and its payments would fall before the first record's time.
  // The journal's time span (journal.firstRecord, lastRecord) is the earliest and latest record time
  // for the same reason, not the first and last line (audit 1.4.0).
  let earliestMine: number | null = null;
  let latestMine: number | null = null;
  for (const record of mine) {
    const ms = Date.parse(record.time);
    if (earliestMine === null || ms < earliestMine) earliestMine = ms;
    if (latestMine === null || ms > latestMine) latestMine = ms;
  }
  const until = untilFlag ?? now;
  // A default window with no width would report nothing as if nothing happened: refuse it instead.
  if (sinceFlag === null && earliestMine === null) return fail(2, 'Q1',
    'no default window: the journal holds no record for this node; give --since to reconcile LND\'s payments against it', warnings);
  if (sinceFlag === null && earliestMine !== null && earliestMine > until) return fail(2, 'Q1',
    `no default window: the journal's earliest record for this node (${new Date(earliestMine).toISOString()}) is after ` +
    `${untilFlag === null ? 'now (the clock may be behind the journal)' : '--until'}; give --since and --until explicitly`, warnings);
  const since = sinceFlag ?? earliestMine!;
  if (since > until) return fail(2, 'Q1', '--since must not be after --until (now when --until is not given)');
  // A window of no width proves nothing either way (audit 1.4.0: one at an uncovered instant was reported complete).
  if (since === until) return fail(2, 'Q1', 'empty window: --since must be before --until (now when --until is not given)', warnings);
  const inWindow = (ms: number) => ms >= since && ms <= until;
  // Requests journaled after the window never establish who initiated a payment in it, nor change
  // its observations (1.2.1): a retry of an already paid invoice after --until would otherwise
  // hide an unattributed payment in the window, or add its credential and amount to one.
  const payments = mine.filter((record): record is PaymentRecord => record.type === 'payment' && Date.parse(record.time) <= until);
  const deletionRecords = mine.filter((record): record is DeletionRecord => record.type === 'deletion' && inWindow(Date.parse(record.time)));
  const observation = (record: PaymentRecord): ReconcileObservation => ({ time: record.time, run: record.run, requestId: record.requestId,
    method: record.method, credential: record.credential, rootKeyId: record.rootKeyId, label: labelFor(record.rootKeyId),
    amountMsat: record.amountMsat, amountSource: record.amountSource, feeLimitMsat: record.feeLimitMsat, extraction: record.extraction });
  const byHash = new Map<string, PaymentRecord[]>();
  const unmatched: ReconcileObservation[] = [];
  // Every hash the journal attributes for this node up to the window's end: a listed payment with
  // one of them is attributed even when the request was journaled before the window.
  const journaledHashes = new Set(payments.flatMap(record => record.paymentHash ? [record.paymentHash] : []));
  // A hash journaled in the window is attributed from every request for it the journal holds, in
  // the window or before it, never after it (1.2.1): a credential that requested the same hash earlier shares the
  // attribution, and LND's one record for the hash cannot be its alone.
  const windowHashes = new Set(payments.flatMap(record => record.paymentHash && inWindow(Date.parse(record.time)) ? [record.paymentHash] : []));
  for (const record of payments) {
    if (!record.paymentHash) { if (inWindow(Date.parse(record.time))) unmatched.push(observation(record)); continue; }
    if (!windowHashes.has(record.paymentHash)) continue;
    const list = byHash.get(record.paymentHash);
    if (list) list.push(record); else byHash.set(record.paymentHash, [record]);
  }

  // Q6: LND's payments created in the window (with clock tolerance), paged.
  const listed = new Map<string, LndPayment>();
  // The listing stops at the count limit or at the budget; each is reported as itself (audit 1.2.1).
  let listLimited = false, budgetReached = false;
  const monotonic = deps.monotonic ?? (() => performance.now());
  const deadline = monotonic() + RECONCILE_BUDGET_MS;
  try {
    let offset = 0n;
    const startSeconds = Math.max(0, Math.floor((since - CLOCK_TOLERANCE_MS) / 1_000));
    const endSeconds = Math.max(startSeconds, Math.ceil((until + CLOCK_TOLERANCE_MS) / 1_000));
    for (;;) {
      const page = await cancellable(() => adapter.listPayments({ startSeconds, endSeconds, indexOffset: offset, max: LIST_PAGE }));
      for (const payment of page.payments) listed.set(payment.paymentHash, payment);
      if (page.payments.length < LIST_PAGE || page.lastIndexOffset <= offset) break;
      listLimited = listed.size >= LIST_LIMIT;
      budgetReached = monotonic() > deadline;
      if (listLimited || budgetReached) break;
      offset = page.lastIndexOffset;
    }
  } catch (error) {
    if (error instanceof Cancelled) return fail(6, 'cancelled', 'operation interrupted; nothing was changed', warnings);
    const failure = failureDetails(error); return fail(failure.code, 'Q6', failure.message, warnings);
  }

  // Q7: each journaled hash the listing does not hold, one lookup each (bounded).
  const results: ReconcilePayment[] = [];
  let tracked = 0, trackFailed = 0, trackLimited = 0;
  // Deletions that may have removed this payment's record or some of its attempts: one naming
  // the hash, or any DeleteAllPayments LND accepts (its scope covers payments, or their failed
  // attempts with failed_htlcs_only, by status, not by hash).
  // Indexed once (audit 1.2.1): a filter over every deletion per journaled hash was quadratic.
  const deletionsByHash = new Map<string, Set<string>>();
  const deletedAllBy = new Set<string>();
  for (const record of deletionRecords) {
    // A deletion whose request was not read in full (oversized or malformed) may have deleted anything:
    // LND skips fields it does not know, so a padded DeleteAllPayments still deletes (audit 1.4.0).
    if ((record.method === '/lnrpc.Lightning/DeleteAllPayments' && record.scope !== 'none') || record.extraction !== 'complete')
      deletedAllBy.add(record.credential);
    if (record.paymentHash) {
      const set = deletionsByHash.get(record.paymentHash) ?? new Set<string>();
      set.add(record.credential);
      deletionsByHash.set(record.paymentHash, set);
    }
  }
  const listTruncated = listLimited || budgetReached;
  let requestsCapped = false;
  const capped = (value: bigint) => { if (value > MAX_MSAT) { requestsCapped = true; return MAX_MSAT; } return value; };
  const deletedBy = (hash: string) => [...new Set([...(deletionsByHash.get(hash) ?? []), ...deletedAllBy])].sort();
  // The earliest and latest request time per hash (audit 1.4.0): records keep file order, which is
  // capture order (the latest SendPaymentV2 is the last one), but a clock set back between runs makes
  // a later run's times earlier, so the first record in the file is not always the earliest request.
  // LND's record must predate every journaled request to be historical, and the observation spans
  // the earliest to the latest time.
  const span = new Map<string, { first: number; last: number }>();
  for (const [hash, records] of byHash) {
    let first = Infinity, last = -Infinity;
    for (const record of records) { const ms = Date.parse(record.time); first = Math.min(first, ms); last = Math.max(last, ms); }
    span.set(hash, { first, last });
  }
  for (const [hash, records] of [...byHash].sort((a, b) => span.get(a[0])!.first - span.get(b[0])!.first || (a[0] < b[0] ? -1 : 1))) {
    const { first: firstObserved, last: lastObserved } = span.get(hash)!;
    let found: ReconcileSettlement;
    const fromList = listed.get(hash);
    if (fromList) found = settlement(fromList, 'list-payments', firstObserved);
    else if (tracked + trackFailed >= TRACK_LIMIT || monotonic() > deadline) { trackLimited += 1; found = unknownSettlement('unknown'); }
    else {
      try {
        const payment = await cancellable(() => adapter.trackPayment(hash));
        tracked += 1;
        found = payment ? settlement(payment, 'track-payment', firstObserved) : unknownSettlement('not-found');
      } catch (error) {
        if (error instanceof Cancelled) return fail(6, 'cancelled', 'operation interrupted; nothing was changed', warnings);
        // Transport, TLS or authentication failures stop the command: later lookups would fail the same way.
        if (error instanceof LndError && error.code === 4) { const failure = failureDetails(error); return fail(failure.code, 'Q7', failure.message, warnings); }
        if (!(error instanceof LndError)) throw error;
        trackFailed += 1;
        found = unknownSettlement('unknown');
      }
    }
    const credentials = [...new Set(records.map(record => record.credential))].sort();
    // Requested amount: the latest SendPaymentV2 request; route attempts (SendToRouteV2) are summed
    // separately, since a retried shard is requested again.
    const sendRequests = records.filter(record => record.method === '/routerrpc.Router/SendPaymentV2');
    const latest = sendRequests.at(-1);
    const routes = records.filter(record => record.method === '/routerrpc.Router/SendToRouteV2' && record.amountMsat !== null);
    // LND's record older than every journaled request for the hash: its outcome may belong to an
    // attempt no credential here is known to have made (1.2.1), so no credential gets it.
    // A requester the journal could not identify may be any credential: the payment is attributed to none.
    const attribution: ReconcilePayment['attribution'] = credentials.some(credential => UNIDENTIFIED.has(credential)) ? 'unidentified'
      : credentials.length > 1 ? 'ambiguous' : found.predatesObservation ? 'historical' : 'single';
    results.push({ paymentHash: hash, attribution, credentials,
      observation: { first: iso(firstObserved), last: iso(lastObserved), calls: records.length,
        requestedMsat: latest?.amountMsat ?? null,
        routeAttemptsMsat: routes.length ? capped(sum(routes.map(record => BigInt(record.amountMsat!)))).toString() : null,
        feeLimitMsat: latest?.feeLimitMsat ?? null,
        observations: records.slice(-OBSERVATION_LIST_LIMIT).map(observation) },
      settlement: found, deletedBy: deletedBy(hash) });
  }

  // Coverage of the window, and LND payments in it that the journal does not attribute.
  const coverage = journalCoverage(mine, node.pubkey, since, until);
  // Each unattributed payment is classified against coverage beyond the window's edges by the clock
  // tolerance it is checked with (audit 1.4.0: coverage clipped at --since and --until made a payment
  // near either edge `boundary` inside covered time).
  const around = journalCoverage(mine, node.pubkey, since - CLOCK_TOLERANCE_MS, until + CLOCK_TOLERANCE_MS);
  const unattributed: ReconcileUnattributed[] = [];
  let attributedOutsideWindow = 0;
  // Recorded drops, kept as excluded spans for the per-payment classification (1.2.1): a drop
  // that lasted no measurable time leaves the covered time whole, yet a payment created at that
  // instant may be the call it lost. Sorted and merged, so one binary search answers each payment.
  const dropSpans: [number, number][] = [];
  for (const gap of around.gaps.filter(gap => gap.reason === 'dropped').sort((a, b) => a.from - b.from)) {
    const previous = dropSpans.at(-1);
    if (previous && gap.from <= previous[1]) previous[1] = Math.max(previous[1], gap.to);
    else dropSpans.push([gap.from, gap.to]);
  }
  for (const payment of [...listed.values()].sort((a, b) => (a.createdAtNs < b.createdAtNs ? -1 : a.createdAtNs > b.createdAtNs ? 1 : 0))) {
    const created = nsToMs(payment.createdAtNs);
    if (!inWindow(created)) continue;
    if (byHash.has(payment.paymentHash)) continue;
    if (journaledHashes.has(payment.paymentHash)) { attributedOutsideWindow += 1; continue; }
    const inside = coveredSpan(around.covered, created, created) && !touchesSpan(dropSpans, created, created);
    const clear = coveredSpan(around.covered, created - CLOCK_TOLERANCE_MS, created + CLOCK_TOLERANCE_MS)
      && !touchesSpan(dropSpans, created - CLOCK_TOLERANCE_MS, created + CLOCK_TOLERANCE_MS);
    const facts = settlement(payment, 'list-payments', null);
    unattributed.push({ paymentHash: payment.paymentHash, createdAt: facts.createdAt!, status: payment.status, settledMsat: facts.settledMsat!,
      feesMsat: facts.feesMsat!, inFlightMsat: facts.inFlightMsat!, attempts: facts.attempts!, failureReason: facts.failureReason,
      coverage: clear ? 'covered' : inside ? 'boundary' : 'gap' });
  }

  // Per credential: totals over the payments it alone requested; shared hashes are counted as ambiguous.
  const perCredential = new Map<string, ReconcileCredential>();
  const credentialRow = (credential: string): ReconcileCredential => {
    let row = perCredential.get(credential);
    if (!row) {
      row = { credential, rootKeyIds: [], label: null, payments: 0, succeeded: 0, failed: 0, inFlight: 0, notFound: 0, unknown: 0,
        ambiguous: 0, historical: 0, unmatched: 0, deletions: 0, requestedMsat: '0', settledMsat: '0', feesMsat: '0', inFlightMsat: '0' };
      perCredential.set(credential, row);
    }
    return row;
  };
  const noteRoot = (row: ReconcileCredential, rootKeyId: string) => {
    if (!row.rootKeyIds.includes(rootKeyId)) row.rootKeyIds.push(rootKeyId);
    row.label = row.rootKeyIds.length === 1 ? labelFor(row.rootKeyIds[0]) : null;
  };
  const add = (value: string, extra: string | null) => (BigInt(value) + BigInt(extra ?? '0')).toString();
  // LND's amounts summed past an int64 for one credential cannot be real (audit 1.2.1): not LND's records.
  let impossible = false;
  const addLnd = (value: string, extra: string | null) => {
    const total = BigInt(value) + BigInt(extra ?? '0');
    if (total > MAX_MSAT) impossible = true;
    return total.toString();
  };
  for (const item of results) {
    const records = byHash.get(item.paymentHash)!;
    if (item.attribution === 'unidentified') {
      // Counted in no credential's totals; an identified credential that also requested the hash shares it with an unknown one.
      for (const record of records) if (!UNIDENTIFIED.has(record.credential)) noteRoot(credentialRow(record.credential), record.rootKeyId);
      for (const credential of item.credentials) if (!UNIDENTIFIED.has(credential)) credentialRow(credential).ambiguous += 1;
      continue;
    }
    for (const record of records) noteRoot(credentialRow(record.credential), record.rootKeyId);
    if (item.attribution === 'ambiguous') { for (const credential of item.credentials) credentialRow(credential).ambiguous += 1; continue; }
    if (item.attribution === 'historical') { credentialRow(item.credentials[0]).historical += 1; continue; }
    const row = credentialRow(item.credentials[0]);
    row.payments += 1;
    const status = item.settlement.status;
    if (status === 'succeeded') row.succeeded += 1; else if (status === 'failed') row.failed += 1;
    else if (status === 'in-flight') row.inFlight += 1; else if (status === 'not-found') row.notFound += 1; else row.unknown += 1;
    row.requestedMsat = capped(BigInt(add(row.requestedMsat, item.observation.requestedMsat ?? item.observation.routeAttemptsMsat))).toString();
    row.settledMsat = addLnd(row.settledMsat, item.settlement.settledMsat);
    row.feesMsat = addLnd(row.feesMsat, item.settlement.feesMsat);
    row.inFlightMsat = addLnd(row.inFlightMsat, item.settlement.inFlightMsat);
  }
  if (impossible) return fail(5, 'Q6', 'invalid LND response', warnings);
  for (const record of unmatched) { const row = credentialRow(record.credential); row.unmatched += 1; noteRoot(row, record.rootKeyId); }
  for (const record of deletionRecords) { const row = credentialRow(record.credential); row.deletions += 1; noteRoot(row, record.rootKeyId); }
  for (const row of perCredential.values()) row.rootKeyIds.sort((a, b) => a === 'none' ? 1 : b === 'none' ? -1 : (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0));

  const runs = new Set(mine.map(record => record.run)).size;
  const uncertain = results.filter(item => item.settlement.status !== 'succeeded' && item.settlement.status !== 'failed').length;
  const ambiguous = results.filter(item => item.attribution === 'ambiguous').length;
  const historical = results.filter(item => item.attribution === 'historical').length;
  const unidentified = results.filter(item => item.attribution === 'unidentified').length;
  // The window less the covered time (1.2.1): listed gaps can overlap (a drop inside time that is
  // uncovered for another reason is listed beside it), so their sum counted such time twice.
  const gapMs = Math.max(0, until - since - coverage.coveredMs);
  const result: ReconcileResult = {
    node,
    journal: { path: journalPath, size: contents.size, runs, records: mine.length, firstRecord: earliestMine === null ? null : iso(earliestMine),
      lastRecord: latestMine === null ? null : iso(latestMine), otherNodeRecords, tornTail: contents.tornTail, repairedLines: contents.repairedLines },
    window: { since: iso(since), until: iso(until) },
    coverage: { windowSeconds: Math.floor((until - since) / 1_000), coveredSeconds: Math.floor(coverage.coveredMs / 1_000),
      complete: coverage.gaps.length === 0, gapCount: coverage.gaps.length, gapSeconds: Math.ceil(gapMs / 1_000),
      gaps: coverage.gaps.slice(0, GAP_LIST_LIMIT).map(gap => ({ from: iso(gap.from), to: iso(gap.to), reason: gap.reason, dropped: gap.dropped })) },
    credentials: [...perCredential.values()].sort((a, b) => (a.credential < b.credential ? -1 : a.credential > b.credential ? 1 : 0)),
    payments: results,
    unmatched,
    unattributed,
    deletions: deletionRecords.map(record => ({ time: record.time, run: record.run, requestId: record.requestId, method: record.method,
      credential: record.credential, rootKeyId: record.rootKeyId, label: labelFor(record.rootKeyId), scope: record.scope,
      paymentHash: record.paymentHash, extraction: record.extraction })),
    lookups: { listed: listed.size, listTruncated, tracked, trackFailed, trackLimited, attributedOutsideWindow },
  };

  if (!result.coverage.complete) warnings.push({ code: 'journal-gaps', message: `the journal does not cover ${result.coverage.gapCount} `
    + `period${result.coverage.gapCount === 1 ? '' : 's'} of the window (${result.coverage.gapSeconds} s): payments made then are not attributed, `
    + 'and their absence from the journal is no evidence that none were made' });
  if (historical) warnings.push({ code: 'attribution-historical', message: `${historical} payment hash${historical === 1 ? ' has' : 'es have'} `
    + 'an LND record older than every journaled request for it: the outcome may belong to an attempt made before the journal observed '
    + 'the hash, by any credential, so it is not counted for the credential that requested it later' });
  if (unidentified) warnings.push({ code: 'attribution-unidentified', message: `${unidentified} payment hash${unidentified === 1 ? ' was' : 'es were'} `
    + 'requested by a caller whose macaroon watch could not decode (id:none or id:undecodable): any credential may have made the request, '
    + 'so their outcomes are not counted for any credential' });
  if (unattributed.length) warnings.push({ code: 'unattributed-payments', message: `LND lists ${unattributed.length} payment`
    + `${unattributed.length === 1 ? '' : 's'} in the window that the journal does not attribute to any credential (made during a gap, `
    + 'by a path the middleware does not see, or recorded in another journal)' });
  if (uncertain) warnings.push({ code: 'payments-uncertain', message: `${uncertain} journaled payment${uncertain === 1 ? ' has' : 's have'} `
    + 'no final outcome from LND (in flight, not found or not looked up); run reconcile again later' });
  if (unmatched.length) warnings.push({ code: 'journal-unmatched', message: `${unmatched.length} journaled payment request`
    + `${unmatched.length === 1 ? '' : 's'} carried no readable payment hash (AMP, malformed or oversized) and cannot be matched to LND's records` });
  if (ambiguous) warnings.push({ code: 'attribution-ambiguous', message: `${ambiguous} payment hash${ambiguous === 1 ? ' was' : 'es were'} `
    + 'requested by more than one credential; their outcomes are not counted for any single credential' });
  if (deletionRecords.length) warnings.push({ code: 'payment-deletions', message: `${deletionRecords.length} call${deletionRecords.length === 1 ? '' : 's'} `
    + 'to delete LND payment records were journaled in the window; LND may no longer list the payments they removed' });
  const budget = `the ${RECONCILE_BUDGET_MS / 60_000} minute budget`;
  const listing = listLimited && budgetReached ? `LND's payment listing stopped at ${LIST_LIMIT} payments as ${budget} ran out; `
    : listLimited ? `LND's payment listing stopped at ${LIST_LIMIT} payments; `
      : budgetReached ? `LND's payment listing stopped after ${listed.size} payments when ${budget} ran out; ` : '';
  if (listTruncated || trackLimited) warnings.push({ code: 'lookups-limited', message: listing
    + `${trackLimited ? `${trackLimited} payment hashes were not looked up (limit ${TRACK_LIMIT}, or the ${RECONCILE_BUDGET_MS / 60_000} minute budget ran out); ` : ''}narrow the window with --since and --until` });
  if (requestsCapped) warnings.push({ code: 'requested-amounts-capped', message: 'journaled requests sum to more than '
    + `${MAX_MSAT} msat (more than all bitcoin): such sums are reported as ${MAX_MSAT}; the requests were for amounts no payment can reach` });
  if (contents.tornTail) warnings.push({ code: 'journal-torn-tail', message: 'the journal ends with an incomplete line (watch is writing it, '
    + 'or stopped while writing it); it was ignored' });
  if (otherNodeRecords) warnings.push({ code: 'journal-other-node', message: `${otherNodeRecords} journal records belong to another node and were ignored` });

  // Exit 1 (a finding, ok: true) unless every journaled payment has a final LND outcome and one
  // identified credential, the window is fully covered and LND lists no payment the journal does not attribute.
  const complete = result.coverage.complete && !unattributed.length && !uncertain && !unmatched.length && !ambiguous && !historical
    && !unidentified && !deletionRecords.length && !listTruncated && !trackLimited;
  return { schema: 1, command: 'reconcile', ok: true, warnings, result, error: null, ...(complete ? {} : { exitCode: 1 }) };
}

export async function run(args: string[], deps: Deps): Promise<ReconcileOutput> { return runSteps(args, deps); }

export async function reconcile(args: string[]): Promise<OutputResult & { exitCode?: number }> {
  return run(args, { createAdapter: createLndAdapter, fs: nodeFs, env: { ...process.env }, clock: () => new Date() });
}
