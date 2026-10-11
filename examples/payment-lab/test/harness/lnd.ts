import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { HtlcAttempt, Invoice, InvoiceApi, Lab, Payment, PayerApi, StreamDecision } from './lab.ts';

/**
 * A scripted LND for the harness: one payment node (SendPaymentV2, TrackPaymentV2) and one invoice
 * node (AddInvoice, AddHoldInvoice, LookupInvoice, SettleInvoice, CancelInvoice, SubscribeInvoices).
 *
 * Every RPC a workflow makes becomes a pending Call. Nothing is answered on its own: the event
 * sequence decides when a request reaches LND, when a stream delivers its next message and how a
 * call ends (an answer, a transport error, an LND error, a lost answer), so any interleaving of two
 * processes' calls can be produced and replayed. LND itself is truthful: a payment it reports
 * SUCCEEDED was initiated by a request that reached it, a NotFound means it holds no such payment or
 * invoice at that moment, and a definite refusal means the request was handled and nothing created.
 *
 * Faults are injected on purpose, each one a case a README rule is for: a lookup reporting an invoice
 * canceled that is not (misreport), a payment or an invoice paid for another amount than the invoice's
 * (over or under), a settled invoice reported again for another amount (resettle: a hostile or buggy
 * node), and an invoice on the node that the receiver never created (foreign).
 */

export type Proc = 'p0' | 'p1';
export type CallKind = 'send' | 'track' | 'sub' | 'create' | 'lookup' | 'settle' | 'cancel';
type Item = { payment: Payment } | { invoice: Invoice } | { error: Error };

export interface Workflow {
  id: number;
  proc: Proc;
  incarnation: number;
  kind: string;
  label: string;
  controller: AbortController | undefined;
  done: boolean;
  result?: unknown;
  error?: unknown;
  /** submit: the submission its claim counted. */
  submission?: number;
  /** The last RPC the workflow made (its outcome is what the workflow's next store call is about). */
  lastCall?: Call;
}

export interface Call {
  id: number;
  kind: CallKind;
  proc: Proc;
  label: string;
  hash: string;
  workflow: Workflow | undefined;
  /** For payment streams: the submission the stream speaks for (see Run.callCreated in harness.ts). */
  submission: number | undefined;
  /** The client still waits on it. */
  open: boolean;
  /** Stream messages produced by LND and not yet delivered to the client. */
  queue: Item[];
  /** A stream LND will push nothing more to (it sent a terminal state or an error). */
  serverDone: boolean;
  /** The request reached LND and LND handled it. */
  arrived: boolean;
  /** The client stopped waiting, and the request may still reach LND (it is in transit). */
  inTransit: boolean;
  /** A lookup's answer as the client received it: the invoice state, or not-found (undefined: no answer, or an error). */
  answered?: string;
  /** How the client's side of the call ended: resolved ('ok') or rejected ('error'); undefined while it waits. */
  outcome?: 'ok' | 'error';
  onUpdate: ((value: never) => StreamDecision) | undefined;
  resolve: (value?: unknown) => void;
  reject: (error: unknown) => void;
  request: { preimage?: string; paymentHash?: string; valueMsat?: bigint; hold?: boolean; from?: { addIndex: bigint; settleIndex: bigint };
    /** A lookup: the invoice as LND held it when the request arrived (for an answer that is delivered late). */
    seen?: Invoice | null };
}

export interface LndPayment {
  hash: string;
  label: string;
  status: 'IN_FLIGHT' | 'SUCCEEDED' | 'FAILED';
  valueMsat: bigint;
  feeMsat: bigint;
  preimage: string;
  failureReason: string;
  htlcs: HtlcAttempt[];
  index: number;
  /**
   * When LND (re)initialised the payment, in the payer's clock (wallClockNs in src/payer/store.ts): a SendPaymentV2
   * for a hash LND holds as FAILED initialises it again, deleting the old HTLC attempts and setting a new creation time.
   */
  creationTimeNs: bigint;
}

/** Wall-clock nanoseconds, computed as src/payer/store.ts's wallClockNs is (the harness also runs older sources without it). */
const wallClockNs = (): bigint => BigInt(Math.round(performance.timeOrigin * 1e6)) + BigInt(Math.round(performance.now() * 1e6));

export interface LndInvoice {
  hash: string;
  label: string;
  hold: boolean;
  state: 'OPEN' | 'ACCEPTED' | 'SETTLED' | 'CANCELED';
  valueMsat: bigint;
  amtPaidMsat: bigint;
  addIndex: bigint;
  settleIndex: bigint;
  /**
   * A fault, not LND's normal behaviour: lookups report this invoice CANCELED although it is not (the "stale or wrong
   * cancel" the README's settled-outranks-canceled rule is for). Its later states are reported truthfully.
   */
  misreported: boolean;
  /**
   * A resettle fault reported it again for another amount: LND is not one source of truth for it any more, so the oracle
   * runs the receiver's ledger verify without LND for the rest of the case (its settlement rules judge what the store did).
   */
  resettled?: boolean;
}

/** ListPayments and ListInvoices as `ledger verify` reads them (src/ledger/verify.ts, LndLedgerSource). */
export interface LedgerSource {
  listPaymentsPage(indexOffset: bigint, maxPayments: number): Promise<{ payments: Payment[]; lastIndexOffset: bigint }>;
  listInvoicesPage(indexOffset: bigint, maxInvoices: number): Promise<{ invoices: Invoice[]; lastIndexOffset: bigint }>;
}

/** Payment and invoice facts a predicate needs at the moment of a call (see Oracle.onSettleCall). */
export interface LndHooks {
  /** SettleInvoice was called for this invoice (before LND handles it). */
  settleCalled(proc: Proc, hash: string): void;
  /** Bumped on every call and every answer, so the runner knows when the workflows are idle. */
  progress(): void;
  /** The workflow making the call now (AsyncLocalStorage in the runner). */
  currentWorkflow(): Workflow | undefined;
  /** A call was made (the runner tags payment streams with their submission, and answers calls itself in quiescence). */
  callCreated(call: Call): void;
  /** Whether the process (the workflow's incarnation of it) still runs. */
  alive(proc: Proc, workflow: Workflow | undefined): boolean;
}

export const sha256Hex = (hex: string): string => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const DESTINATION = `02${'11'.repeat(32)}`;
const FEE_PER_SHARD_MSAT = 10n;
/** How far a payment or an invoice paid for another amount is off: over or under by this much. */
const PAYMENT_SKEW_MSAT = 100n;
const INVOICE_SKEW_MSAT = 500n;
export type AmountVariant = 'exact' | 'over' | 'under';
const skewed = (amount: bigint, variant: AmountVariant | undefined, skew: bigint): bigint =>
  variant === 'over' ? amount + skew : variant === 'under' ? amount - skew : amount;

export class FakeLnd {
  readonly lab: Lab;
  readonly hooks: LndHooks;
  readonly calls: Call[] = [];
  readonly payments = new Map<string, LndPayment>();
  readonly invoices = new Map<string, LndInvoice>();
  /** Payer side: label (op0/i1) of each payment hash, and the preimage and amount the payee would reveal. */
  readonly paymentLabels = new Map<string, { label: string; preimage: string; amountMsat: bigint }>();
  /** Receiver side: label (o1#2) of each invoice hash the workflows created. */
  readonly invoiceLabels = new Map<string, string>();
  #callSeq = 0;
  #attemptSeq = 0;
  #paymentIndex = 0;
  #addIndex = 0n;
  #settleIndex = 0n;
  #creates = new Map<string, number>();
  #foreign = 0;
  /** Per payment hash and submission: when that submission's first SendPaymentV2 call was made (wall-clock ns). */
  #sendMade = new Map<string, bigint>();
  /**
   * Per payment hash: the highest submission a SendPaymentV2 call was made for, the submission LND holds the payment for
   * from then on (the harness claims and sends in one step, so it is the payer's current submission). What a stream shows
   * the payer is recorded under it, not under the submission the stream was opened for: a stream opened for an earlier
   * submission can observe the current one's payment (a tracking request that reaches LND after the retry's send did).
   */
  #latestSend = new Map<string, number>();
  /** Per HTLC attempt: the submission LND held the payment for (#latestSend) when a payment stream first delivered it to the payer. */
  #attemptFirstSeen = new Map<string, number | undefined>();
  /** Per payment hash and submission (#latestSend when delivered): the highest creation time a payment stream showed the payer. */
  #creationSeen = new Map<string, { submission: number; creationTimeNs: bigint }>();
  #lastNs = 0n;

  constructor(lab: Lab, hooks: LndHooks) {
    this.lab = lab;
    this.hooks = hooks;
  }

  labelOf(hash: string): string {
    return this.paymentLabels.get(hash)?.label ?? this.invoiceLabels.get(hash) ?? hash.slice(0, 12);
  }

  addIndexes(): bigint[] {
    return [...this.invoices.values()].map(item => item.addIndex).sort((a, b) => (a < b ? -1 : 1));
  }

  settleIndexes(): bigint[] {
    return [...this.invoices.values()].filter(item => item.settleIndex > 0n).map(item => item.settleIndex).sort((a, b) => (a < b ? -1 : 1));
  }

  // ------------------------------------------------------------------------------------------
  // Calls.

  #call(proc: Proc, kind: CallKind, hash: string, label: string, signal: AbortSignal | undefined, request: Call['request'],
    onUpdate?: Call['onUpdate']): { call: Call; promise: Promise<unknown> } {
    if (!this.hooks.alive(proc, this.hooks.currentWorkflow())) {
      // A killed process sends nothing: the call fails at once and LND never sees it.
      const dead = Promise.reject(new this.lab.TransportError('process killed', 'connect'));
      return { call: undefined as unknown as Call, promise: dead };
    }
    let settle!: (value?: unknown) => void;
    let fail!: (error: unknown) => void;
    const promise = new Promise((done, failed) => { settle = done; fail = failed; });
    // The first way the call ends is its outcome (a promise settles once).
    const resolve = (value?: unknown): void => { call.outcome ??= 'ok'; settle(value); };
    const reject = (error: unknown): void => { call.outcome ??= 'error'; fail(error); };
    const workflow = this.hooks.currentWorkflow();
    const call: Call = { id: ++this.#callSeq, kind, proc, label, hash, workflow, submission: undefined, open: true, queue: [], serverDone: false,
      arrived: false, inTransit: false, onUpdate, resolve, reject, request };
    if (workflow !== undefined) workflow.lastCall = call;
    this.calls.push(call);
    this.hooks.callCreated(call);
    const made = `${hash}#${String(call.submission)}`;
    if (kind === 'send' && !this.#sendMade.has(made)) this.#sendMade.set(made, this.#now());
    if (kind === 'send' && call.submission !== undefined && (this.#latestSend.get(hash) ?? 0) < call.submission) this.#latestSend.set(hash, call.submission);
    this.hooks.progress();
    if (signal !== undefined) {
      const abort = (): void => this.cut(call, new this.lab.TransportError('aborted by the caller', 'response'));
      if (signal.aborted) queueMicrotask(abort);
      else signal.addEventListener('abort', abort, { once: true });
    }
    return { call, promise };
  }

  #close(call: Call): void {
    call.open = false;
    this.hooks.progress();
  }

  /** The client's side of the call ends with `error` (abort, killed process); a request not yet handled stays in transit. */
  cut(call: Call, error: Error): void {
    if (!call.open) return;
    this.#close(call);
    if (!call.arrived && (call.kind === 'send' || call.kind === 'create')) call.inTransit = true;
    call.reject(error);
  }

  /** Every open call of a process, for a kill. */
  openCalls(proc: Proc): Call[] {
    return this.calls.filter(call => call.open && call.proc === proc);
  }

  payerApi(proc: Proc): PayerApi {
    return {
      decodePayReq: () => Promise.reject(new Error('the harness records intents with a decoded invoice')),
      sendPaymentV2: (request, onUpdate, signal) => {
        const paymentRequest = (request as { paymentRequest: string }).paymentRequest;
        const hash = [...this.paymentLabels.entries()].find(([, item]) => `lnbcrt-${item.label}` === paymentRequest)?.[0];
        if (hash === undefined) return Promise.reject(new Error(`unknown payment request ${paymentRequest}`));
        return this.#call(proc, 'send', hash, this.labelOf(hash), signal, {}, onUpdate as Call['onUpdate']).promise as Promise<void>;
      },
      trackPaymentV2: (hash, onUpdate, signal) => {
        const { call, promise } = this.#call(proc, 'track', hash, this.labelOf(hash), signal, {}, onUpdate as Call['onUpdate']);
        if (call === undefined) return promise as Promise<void>;
        const payment = this.payments.get(hash);
        if (payment === undefined) this.#queue(call, { error: this.notFound('payment isn\'t initiated') });
        else this.#queue(call, { payment: this.#snapshot(payment) });
        return promise as Promise<void>;
      },
    };
  }

  invoiceApi(proc: Proc): InvoiceApi {
    const created = (hash: string, memo: string): string => {
      let label = this.invoiceLabels.get(hash);
      if (label === undefined) {
        const n = (this.#creates.get(memo) ?? 0) + 1;
        this.#creates.set(memo, n);
        label = `${memo}#${n}`;
        this.invoiceLabels.set(hash, label);
      }
      return label;
    };
    return {
      addInvoice: request => {
        const hash = sha256Hex(request.preimage);
        return this.#call(proc, 'create', hash, created(hash, request.memo), undefined,
          { preimage: request.preimage, valueMsat: request.valueMsat, hold: false }).promise as Promise<{ paymentHash: string; paymentRequest: string; addIndex: bigint }>;
      },
      addHoldInvoice: request => this.#call(proc, 'create', request.paymentHash, created(request.paymentHash, request.memo), undefined,
        { paymentHash: request.paymentHash, valueMsat: request.valueMsat, hold: true }).promise as Promise<{ paymentRequest: string; addIndex: bigint }>,
      lookupInvoice: (hash, signal) => {
        const item = this.invoices.get(hash);
        return this.#call(proc, 'lookup', hash, this.labelOf(hash), signal, { seen: item === undefined ? null : this.#invoice(item) }).promise as Promise<Invoice>;
      },
      settleInvoice: preimage => {
        const hash = sha256Hex(preimage);
        this.hooks.settleCalled(proc, hash);
        return this.#call(proc, 'settle', hash, this.labelOf(hash), undefined, { preimage }).promise as Promise<void>;
      },
      cancelInvoice: hash => this.#call(proc, 'cancel', hash, this.labelOf(hash), undefined, {}).promise as Promise<void>,
      subscribeInvoices: (from, onInvoice, signal) => {
        const { call, promise } = this.#call(proc, 'sub', '', 'invoices', signal, { from }, onInvoice as Call['onUpdate']);
        if (call === undefined) return promise as Promise<void>;
        const all = [...this.invoices.values()];
        if (from.addIndex > 0n) {
          for (const item of all.filter(entry => entry.addIndex > from.addIndex).sort((a, b) => (a.addIndex < b.addIndex ? -1 : 1))) {
            this.#queue(call, { invoice: this.#invoice(item) });
          }
        }
        if (from.settleIndex > 0n) {
          for (const item of all.filter(entry => entry.settleIndex > from.settleIndex).sort((a, b) => (a.settleIndex < b.settleIndex ? -1 : 1))) {
            this.#queue(call, { invoice: this.#invoice(item) });
          }
        }
        return promise as Promise<void>;
      },
    };
  }

  // ------------------------------------------------------------------------------------------
  // Streams.

  #queue(call: Call, item: Item): void {
    if (!call.open || call.serverDone) return;
    call.queue.push(item);
    if ('error' in item || ('payment' in item && (item.payment.status === 'SUCCEEDED' || item.payment.status === 'FAILED'))) call.serverDone = true;
  }

  /** Delivers the stream's next message to the client. */
  deliver(call: Call): void {
    if (!call.open) return;
    const item = call.queue.shift();
    if (item === undefined) return;
    this.hooks.progress();
    if ('error' in item) {
      this.#close(call);
      call.reject(item.error);
      return;
    }
    let decision: StreamDecision;
    try {
      decision = (call.onUpdate as (value: unknown) => StreamDecision)('payment' in item ? item.payment : item.invoice);
    } catch (error) {
      // What the REST client does when the handler throws: the stream is torn down and the error propagates.
      this.#close(call);
      call.reject(error);
      return;
    }
    // The payer recorded these attempts (a handler that returns has applied the update): note under which submission each was
    // first shown, the one LND holds the payment for now (#latestSend), whichever submission this stream was opened for.
    if ('payment' in item) {
      const current = this.#latestSend.get(item.payment.paymentHash) ?? call.submission;
      for (const attempt of item.payment.htlcs) if (!this.#attemptFirstSeen.has(attempt.attemptId)) this.#attemptFirstSeen.set(attempt.attemptId, current);
      if (current !== undefined) {
        const key = `${item.payment.paymentHash}#${current}`;
        const seen = this.#creationSeen.get(key);
        if (seen === undefined || item.payment.creationTimeNs > seen.creationTimeNs) {
          this.#creationSeen.set(key, { submission: current, creationTimeNs: item.payment.creationTimeNs });
        }
      }
    }
    if (decision === 'stop' || (call.serverDone && call.queue.length === 0)) {
      this.#close(call);
      call.resolve();
    }
  }

  /** Ends a SendPaymentV2 stream without its remaining messages. Returns false when the mode does not apply now. */
  endSend(call: Call, mode: string): boolean {
    if (!call.open || call.kind !== 'send') return false;
    switch (mode) {
      case 'connect':
        if (call.arrived || call.inTransit) return false;
        this.#close(call);
        call.reject(new this.lab.TransportError('connect ECONNREFUSED', 'connect'));
        return true;
      case 'definite':
        if (call.arrived) return false;
        this.#close(call);
        call.reject(new this.lab.LndError('rate limit exceeded', 8, 429));
        return true;
      case 'eof':
        if (!call.arrived) return false;
        this.#close(call);
        call.resolve();
        return true;
      case 'ambiguous-504':
      case 'ambiguous-502':
      case 'transport': {
        const error = mode === 'transport' ? new this.lab.TransportError('socket hang up', 'response')
          : mode === 'ambiguous-504' ? new this.lab.LndError('upstream request timeout', 4, 504) : new this.lab.LndError('Bad Gateway', undefined, 502);
        this.cut(call, error);
        return true;
      }
      default:
        return false;
    }
  }

  /** Ends a TrackPaymentV2 stream early: a dropped connection, or the server closing it without a terminal state. */
  endTrack(call: Call, mode: string): boolean {
    if (!call.open || call.kind !== 'track') return false;
    this.#close(call);
    if (mode === 'eof') call.resolve();
    else call.reject(new this.lab.TransportError('socket hang up', 'response'));
    return true;
  }

  /** Ends a SubscribeInvoices stream while its process lives: the server closing it (eof) or the connection dropping (transport). */
  endSub(call: Call, mode: string): boolean {
    if (!call.open || call.kind !== 'sub') return false;
    this.#close(call);
    if (mode === 'eof') call.resolve();
    else call.reject(new this.lab.TransportError('socket hang up', 'response'));
    return true;
  }

  /** ListPayments and ListInvoices over what LND holds, oldest first, paged by payment index and add index. */
  ledgerSource(): LedgerSource {
    const page = <T>(items: { index: bigint; item: T }[], offset: bigint, max: number): { items: T[]; last: bigint } => {
      const chosen = items.filter(entry => entry.index > offset).sort((a, b) => (a.index < b.index ? -1 : a.index > b.index ? 1 : 0)).slice(0, max);
      return { items: chosen.map(entry => entry.item), last: chosen.at(-1)?.index ?? offset };
    };
    return {
      listPaymentsPage: (offset, max) => {
        const { items, last } = page([...this.payments.values()].filter(item => item.index > 0)
          .map(item => ({ index: BigInt(item.index), item: this.#snapshot(item) })), offset, max);
        return Promise.resolve({ payments: items, lastIndexOffset: last });
      },
      listInvoicesPage: (offset, max) => {
        const { items, last } = page([...this.invoices.values()]
          .map(item => ({ index: item.addIndex, item: this.#invoice(item) })), offset, max);
        return Promise.resolve({ invoices: items, lastIndexOffset: last });
      },
    };
  }

  // ------------------------------------------------------------------------------------------
  // Payments.

  notFound(message: string): Error {
    return new this.lab.LndError(message, 5, 404);
  }

  /** Wall-clock nanoseconds, strictly increasing across this LND's payments and calls. */
  #now(): bigint {
    const now = wallClockNs();
    this.#lastNs = now > this.#lastNs ? now : this.#lastNs + 1n;
    return this.#lastNs;
  }

  /**
   * Whether a payment snapshot shows the payment as LND held it before `submission`'s first SendPaymentV2 call
   * was made, as far as the payer can know: every HTLC attempt in it was first shown to the payer while LND held the
   * payment for an earlier submission (#latestSend when delivered, not the submission the delivering stream was opened
   * for), or it has no attempts and LND created it no later than a payment shown for an earlier submission (else, when
   * none was, before that call). Such a snapshot is an earlier submission's answer (oracle predicate
   * notfound-revert-keeps-live-updates).
   */
  predatesSubmission(snapshot: Payment, submission: number): boolean {
    if (submission <= 1) return false;
    if (snapshot.htlcs.length > 0) {
      return snapshot.htlcs.every(attempt => {
        const seen = this.#attemptFirstSeen.get(attempt.attemptId);
        return seen !== undefined && seen < submission;
      });
    }
    // Without attempts: created no later than a creation time an earlier submission's stream showed the payer (both LND's
    // clock), or, when none did, created before the submission's SendPaymentV2 call was made.
    let earlier: bigint | undefined;
    for (const [key, seen] of this.#creationSeen) {
      if (key.startsWith(`${snapshot.paymentHash}#`) && seen.submission < submission && (earlier === undefined || seen.creationTimeNs > earlier)) {
        earlier = seen.creationTimeNs;
      }
    }
    if (earlier !== undefined) return snapshot.creationTimeNs <= earlier;
    const made = this.#sendMade.get(`${snapshot.paymentHash}#${submission}`);
    return made !== undefined && snapshot.creationTimeNs < made;
  }

  #snapshot(payment: LndPayment): Payment {
    return { paymentHash: payment.hash, status: payment.status, valueMsat: payment.valueMsat, feeMsat: payment.status === 'SUCCEEDED' ? payment.feeMsat : 0n,
      preimage: payment.status === 'SUCCEEDED' ? payment.preimage : undefined, paymentRequest: `lnbcrt-${payment.label}`,
      failureReason: payment.status === 'FAILED' ? payment.failureReason : 'FAILURE_REASON_NONE', creationTimeNs: payment.creationTimeNs,
      paymentIndex: String(payment.index), htlcs: payment.htlcs.map(item => ({ ...item, route: { ...item.route, hops: [...item.route.hops] } })) };
  }

  /** Pushes the payment's current state to every stream that follows it. */
  #push(payment: LndPayment): void {
    const snapshot = this.#snapshot(payment);
    for (const call of this.calls) {
      if (call.hash !== payment.hash || !call.open || call.serverDone) continue;
      if (call.kind === 'track' || (call.kind === 'send' && call.arrived)) this.#queue(call, { payment: snapshot });
    }
  }

  /** A SendPaymentV2 request reaches LND (on time, or late from transit). */
  arrive(call: Call): boolean {
    if (call.kind !== 'send' || call.arrived || (!call.open && !call.inTransit)) return false;
    call.arrived = true;
    call.inTransit = false;
    this.hooks.progress();
    const existing = this.payments.get(call.hash);
    if (existing !== undefined && existing.status !== 'FAILED') {
      // LND refuses a second payment for a hash it holds in flight or has settled.
      this.#queue(call, { error: new this.lab.LndError(existing.status === 'SUCCEEDED' ? 'invoice is already paid' : 'payment is in transition', 2, 500) });
      return true;
    }
    const info = this.paymentLabels.get(call.hash);
    if (info === undefined) throw new Error(`no payment known for ${call.hash}`);
    const payment: LndPayment = existing ?? { hash: call.hash, label: info.label, status: 'IN_FLIGHT', valueMsat: info.amountMsat, feeMsat: 0n,
      preimage: info.preimage, failureReason: 'FAILURE_REASON_NONE', htlcs: [], index: 0, creationTimeNs: 0n };
    // A new payment, or a FAILED one LND initialises again (channeldb InitPayment): the old HTLC attempts are deleted and the
    // creation time is new. Until this request arrived, TrackPaymentV2 showed the earlier FAILED, attempts and all.
    payment.status = 'IN_FLIGHT';
    payment.failureReason = 'FAILURE_REASON_NONE';
    payment.valueMsat = info.amountMsat;
    payment.feeMsat = 0n;
    payment.htlcs = [];
    payment.creationTimeNs = this.#now();
    payment.index = ++this.#paymentIndex;
    this.payments.set(call.hash, payment);
    this.#push(payment);
    return true;
  }

  #attempt(payment: LndPayment, status: HtlcAttempt['status']): HtlcAttempt {
    const id = ++this.#attemptSeq;
    return { attemptId: String(id), status, route: { totalAmtMsat: payment.valueMsat + FEE_PER_SHARD_MSAT, totalFeesMsat: FEE_PER_SHARD_MSAT,
      hops: [{ chanId: '1', pubKey: DESTINATION, amtToForwardMsat: payment.valueMsat, feeMsat: FEE_PER_SHARD_MSAT }] },
    principalMsat: payment.valueMsat, attemptTimeNs: BigInt(id), resolveTimeNs: status === 'IN_FLIGHT' ? 0n : BigInt(id) + 1n,
    failureCode: status === 'FAILED' ? 'TEMPORARY_CHANNEL_FAILURE' : undefined, failureSourceIndex: status === 'FAILED' ? 1 : undefined };
  }

  /** LND's own progress on an in-flight payment: a new HTLC attempt, a failed attempt, the payment failing or succeeding. */
  paymentEvent(hash: string, what: 'attempt' | 'attempt-fail' | 'fail' | 'succeed', amount?: AmountVariant): boolean {
    const payment = this.payments.get(hash);
    if (payment === undefined || payment.status !== 'IN_FLIGHT') return false;
    const inFlight = payment.htlcs.filter(item => item.status === 'IN_FLIGHT');
    switch (what) {
      case 'attempt':
        // The harness pays with max_parts 1: each attempt carries the whole amount, so LND has at most one in flight at a
        // time (a new one after the last failed), never two whose principals would add up to more than the payment.
        if (inFlight.length > 0) return false;
        payment.htlcs.push(this.#attempt(payment, 'IN_FLIGHT'));
        break;
      case 'attempt-fail': {
        const target = inFlight[0];
        if (target === undefined) return false;
        Object.assign(target, { status: 'FAILED', resolveTimeNs: target.attemptTimeNs + 1n, failureCode: 'TEMPORARY_CHANNEL_FAILURE', failureSourceIndex: 1 });
        break;
      }
      case 'fail':
        for (const item of inFlight) Object.assign(item, { status: 'FAILED', resolveTimeNs: item.attemptTimeNs + 1n, failureCode: 'TEMPORARY_CHANNEL_FAILURE', failureSourceIndex: 1 });
        payment.status = 'FAILED';
        payment.failureReason = 'FAILURE_REASON_NO_ROUTE';
        break;
      case 'succeed': {
        // LND reports the value it paid; a fault reports another than the invoice's amount (the record's amount-mismatch event).
        payment.valueMsat = skewed(payment.valueMsat, amount, PAYMENT_SKEW_MSAT);
        // One shard (max_parts 1) succeeds, carrying the value LND paid: the successful principals sum to the payment's value.
        const shard = inFlight[0] ?? this.#attempt(payment, 'IN_FLIGHT');
        if (inFlight.length === 0) payment.htlcs.push(shard);
        Object.assign(shard, { status: 'SUCCEEDED', resolveTimeNs: shard.attemptTimeNs + 1n, principalMsat: payment.valueMsat,
          route: { ...shard.route, totalAmtMsat: payment.valueMsat + FEE_PER_SHARD_MSAT,
            hops: shard.route.hops.map(hop => ({ ...hop, amtToForwardMsat: payment.valueMsat })) } });
        payment.status = 'SUCCEEDED';
        payment.feeMsat = FEE_PER_SHARD_MSAT;
        break;
      }
    }
    this.hooks.progress();
    this.#push(payment);
    return true;
  }

  // ------------------------------------------------------------------------------------------
  // Invoices.

  #invoice(item: LndInvoice): Invoice {
    return { paymentHash: item.hash, state: item.state, memo: item.label, valueMsat: item.valueMsat, amtPaidMsat: item.amtPaidMsat,
      addIndex: item.addIndex, settleIndex: item.settleIndex, paymentRequest: `lnbcrt-invoice-${item.label}`, htlcs: [] };
  }

  #notifySubscribers(item: LndInvoice): void {
    // SubscribeInvoices reports additions and settlements. LND's invoice registry does not dispatch accepted and canceled
    // updates to SubscribeInvoices clients ("for backwards compatibility"; only SubscribeSingleInvoice gets them), so
    // neither does the fake.
    if (item.state !== 'OPEN' && item.state !== 'SETTLED') return;
    const snapshot = this.#invoice(item);
    for (const call of this.calls) if (call.kind === 'sub' && call.open) this.#queue(call, { invoice: snapshot });
  }

  /** LND handles a unary request: creates, settles or cancels. Returns the answer it gives. */
  #handle(call: Call): { value?: unknown; error?: Error } {
    call.arrived = true;
    call.inTransit = false;
    this.hooks.progress();
    const item = this.invoices.get(call.hash);
    switch (call.kind) {
      case 'create': {
        if (item !== undefined) return { error: new this.lab.LndError('invoice with payment hash already exists', 2, 500) };
        const created: LndInvoice = { hash: call.hash, label: call.label, hold: call.request.hold === true, state: 'OPEN',
          valueMsat: call.request.valueMsat ?? 0n, amtPaidMsat: 0n, addIndex: ++this.#addIndex, settleIndex: 0n, misreported: false };
        this.invoices.set(call.hash, created);
        this.#notifySubscribers(created);
        const paymentRequest = `lnbcrt-invoice-${call.label}`;
        return { value: created.hold ? { paymentRequest, addIndex: created.addIndex } : { paymentHash: call.hash, paymentRequest, addIndex: created.addIndex } };
      }
      case 'settle':
        // LND's own errors (invoices.ErrInvoiceNotFound, ErrInvoiceAlreadySettled, ErrInvoiceAlreadyCanceled, ErrInvoiceStillOpen),
        // all gRPC Unknown (2), HTTP 500 through the REST proxy: a settled invoice is not settled "again" without an error.
        if (item === undefined) return { error: new this.lab.LndError('unable to locate invoice', 2, 500) };
        if (item.state === 'SETTLED') return { error: new this.lab.LndError('invoice already settled', 2, 500) };
        if (item.state === 'CANCELED') return { error: new this.lab.LndError('invoice already canceled', 2, 500) };
        if (item.state !== 'ACCEPTED') return { error: new this.lab.LndError('invoice still open', 2, 500) };
        item.state = 'SETTLED';
        item.settleIndex = ++this.#settleIndex;
        this.#notifySubscribers(item);
        return { value: undefined };
      case 'cancel':
        // CancelInvoice of a hash LND does not hold: invoices.ErrInvoiceNotFound, gRPC Unknown (2), HTTP 500 (not NotFound, 5/404).
        if (item === undefined) return { error: new this.lab.LndError('unable to locate invoice', 2, 500) };
        if (item.state === 'SETTLED') return { error: new this.lab.LndError('invoice already settled', 2, 500) };
        item.state = 'CANCELED';
        item.amtPaidMsat = 0n;
        return { value: undefined };
      case 'lookup':
        if (item === undefined) return { error: this.notFound('unable to locate invoice') };
        if (item.misreported && (item.state === 'OPEN' || item.state === 'ACCEPTED')) return { value: { ...this.#invoice(item), state: 'CANCELED', amtPaidMsat: 0n } };
        return { value: this.#invoice(item) };
      default:
        throw new Error(`not a unary call: ${call.kind}`);
    }
  }

  /**
   * Answers a unary call. `ok`: handled and answered. `lost-answer`: handled, then the connection broke.
   * `in-transit`: the connection broke first; a create can still reach LND later. `ambiguous-done` and
   * `ambiguous-pending`: a gateway's DeadlineExceeded (504) after or before LND handled it. `definite`: LND refused it.
   * `connect`: no connection, never sent.
   */
  answer(call: Call, mode: string): boolean {
    if (!call.open || call.kind === 'send' || call.kind === 'track' || call.kind === 'sub') return false;
    const transport = (): Error => new this.lab.TransportError('socket hang up', 'response');
    const gateway = (): Error => new this.lab.LndError('upstream request timeout', 4, 504);
    switch (mode) {
      case 'ok': {
        const answer = this.#handle(call);
        this.#close(call);
        if (call.kind === 'lookup') call.answered = answer.error === undefined ? (answer.value as Invoice).state : 'not-found';
        if (answer.error !== undefined) call.reject(answer.error);
        else call.resolve(answer.value);
        return true;
      }
      case 'lost-answer':
      case 'ambiguous-done':
        this.#handle(call);
        this.#close(call);
        call.reject(mode === 'lost-answer' ? transport() : gateway());
        return true;
      case 'in-transit':
      case 'ambiguous-pending':
        this.cut(call, mode === 'in-transit' ? transport() : gateway());
        return true;
      case 'stale': {
        // The lookup reached LND when it was made; its answer arrives only now, describing the invoice as it was then.
        if (call.kind !== 'lookup') return false;
        this.#close(call);
        const seen = call.request.seen;
        call.answered = seen === undefined || seen === null ? 'not-found' : seen.state;
        if (seen === undefined || seen === null) call.reject(this.notFound('unable to locate invoice'));
        else call.resolve(seen);
        return true;
      }
      case 'definite':
        if (call.kind === 'lookup') return false;
        this.#close(call);
        call.reject(new this.lab.LndError(call.kind === 'create' ? 'invoice expiry exceeds the maximum' : 'invoice operation refused', 3, 400));
        return true;
      case 'connect':
        this.#close(call);
        call.reject(new this.lab.TransportError('connect ECONNREFUSED', 'connect'));
        return true;
      default:
        return false;
    }
  }

  /** An invoice someone else created on the node (the receiver has no record of it), announced to the subscribers. */
  foreignInvoice(): string {
    const n = ++this.#foreign;
    const hash = sha256Hex(createHash('sha256').update(`payment-lab-harness:foreign:${n}`).digest('hex'));
    const label = `foreign#${n}`;
    this.invoiceLabels.set(hash, label);
    const item: LndInvoice = { hash, label, hold: false, state: 'OPEN', valueMsat: 4000n, amtPaidMsat: 0n, addIndex: ++this.#addIndex, settleIndex: 0n,
      misreported: false };
    this.invoices.set(hash, item);
    this.#notifySubscribers(item);
    this.hooks.progress();
    return hash;
  }

  /** A create request in transit reaches LND late: the invoice exists although its creator stopped waiting. */
  arriveLate(call: Call): boolean {
    if (call.kind !== 'create' || !call.inTransit || call.arrived) return false;
    this.#handle(call);
    return true;
  }

  /** What happens to an invoice outside the receiver: a payer pays it, a held HTLC times out, it expires. */
  invoiceEvent(hash: string, what: 'pay' | 'htlc-timeout' | 'expire' | 'misreport' | 'resettle' | 'delete', amount?: AmountVariant): boolean {
    const item = this.invoices.get(hash);
    if (item === undefined) return false;
    if (what === 'misreport' && (item.state === 'OPEN' || item.state === 'ACCEPTED') && !item.misreported) {
      item.misreported = true;
    } else if (what === 'resettle' && item.state === 'SETTLED') {
      item.resettled = true;
      // A hostile or buggy node reports the settled invoice again, for another amount: under the invoice's amount
      // when it was paid in full, the full amount when it was underpaid.
      item.amtPaidMsat = item.amtPaidMsat >= item.valueMsat ? item.valueMsat - INVOICE_SKEW_MSAT : item.valueMsat;
      this.#notifySubscribers(item);
    } else if (what === 'pay' && item.state === 'OPEN') {
      item.amtPaidMsat = skewed(item.valueMsat, amount, INVOICE_SKEW_MSAT);
      if (item.hold) item.state = 'ACCEPTED';
      else {
        item.state = 'SETTLED';
        item.settleIndex = ++this.#settleIndex;
        this.#notifySubscribers(item);
      }
    } else if (what === 'htlc-timeout' && item.state === 'ACCEPTED') {
      item.state = 'OPEN';
      item.amtPaidMsat = 0n;
    } else if (what === 'expire' && item.state === 'OPEN') {
      item.state = 'CANCELED';
    } else if (what === 'delete' && item.state === 'CANCELED') {
      // LND deletes canceled invoices (gc-canceled-invoices-on-startup / -on-the-fly, DeleteCanceledInvoice): lookups answer NotFound.
      this.invoices.delete(hash);
    } else return false;
    this.hooks.progress();
    return true;
  }
}
