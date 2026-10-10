import { createHash } from 'node:crypto';
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
}

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

  constructor(lab: Lab, hooks: LndHooks) {
    this.lab = lab;
    this.hooks = hooks;
  }

  labelOf(hash: string): string {
    return this.paymentLabels.get(hash)?.label ?? this.invoiceLabels.get(hash) ?? hash.slice(0, 12);
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
    let resolve!: (value?: unknown) => void;
    let reject!: (error: unknown) => void;
    const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
    const workflow = this.hooks.currentWorkflow();
    const call: Call = { id: ++this.#callSeq, kind, proc, label, hash, workflow, submission: undefined, open: true, queue: [], serverDone: false,
      arrived: false, inTransit: false, onUpdate, resolve, reject, request };
    if (workflow !== undefined) workflow.lastCall = call;
    this.calls.push(call);
    this.hooks.callCreated(call);
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

  // ------------------------------------------------------------------------------------------
  // Payments.

  notFound(message: string): Error {
    return new this.lab.LndError(message, 5, 404);
  }

  #snapshot(payment: LndPayment): Payment {
    return { paymentHash: payment.hash, status: payment.status, valueMsat: payment.valueMsat, feeMsat: payment.status === 'SUCCEEDED' ? payment.feeMsat : 0n,
      preimage: payment.status === 'SUCCEEDED' ? payment.preimage : undefined, paymentRequest: `lnbcrt-${payment.label}`,
      failureReason: payment.status === 'FAILED' ? payment.failureReason : 'FAILURE_REASON_NONE', creationTimeNs: 1n,
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
      preimage: info.preimage, failureReason: 'FAILURE_REASON_NONE', htlcs: [], index: 0 };
    payment.status = 'IN_FLIGHT';
    payment.failureReason = 'FAILURE_REASON_NONE';
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
  paymentEvent(hash: string, what: 'attempt' | 'attempt-fail' | 'fail' | 'succeed'): boolean {
    const payment = this.payments.get(hash);
    if (payment === undefined || payment.status !== 'IN_FLIGHT') return false;
    const inFlight = payment.htlcs.filter(item => item.status === 'IN_FLIGHT');
    switch (what) {
      case 'attempt':
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
        const shards = inFlight.length > 0 ? inFlight : [this.#attempt(payment, 'IN_FLIGHT')];
        if (inFlight.length === 0) payment.htlcs.push(shards[0] as HtlcAttempt);
        for (const item of shards) Object.assign(item, { status: 'SUCCEEDED', resolveTimeNs: item.attemptTimeNs + 1n });
        payment.status = 'SUCCEEDED';
        payment.feeMsat = FEE_PER_SHARD_MSAT * BigInt(shards.length);
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
    // SubscribeInvoices reports additions and settlements.
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
        if (item?.state === 'SETTLED') return { value: undefined };
        if (item?.state !== 'ACCEPTED') return { error: new this.lab.LndError('invoice still open', 2, 500) };
        item.state = 'SETTLED';
        item.settleIndex = ++this.#settleIndex;
        this.#notifySubscribers(item);
        return { value: undefined };
      case 'cancel':
        if (item === undefined) return { error: this.notFound('unable to locate invoice') };
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

  /** A create request in transit reaches LND late: the invoice exists although its creator stopped waiting. */
  arriveLate(call: Call): boolean {
    if (call.kind !== 'create' || !call.inTransit || call.arrived) return false;
    this.#handle(call);
    return true;
  }

  /** What happens to an invoice outside the receiver: a payer pays it, a held HTLC times out, it expires. */
  invoiceEvent(hash: string, what: 'pay' | 'htlc-timeout' | 'expire' | 'misreport'): boolean {
    const item = this.invoices.get(hash);
    if (item === undefined) return false;
    if (what === 'misreport' && (item.state === 'OPEN' || item.state === 'ACCEPTED') && !item.misreported) {
      item.misreported = true;
    } else if (what === 'pay' && item.state === 'OPEN') {
      item.amtPaidMsat = item.valueMsat;
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
    } else return false;
    this.hooks.progress();
    return true;
  }
}
