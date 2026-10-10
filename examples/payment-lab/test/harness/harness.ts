import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { DEFAULT_LAB_SRC, loadLab, type EffectTarget, type Lab, type OutboxRowView, type PayerDeps, type ReceiverDeps, type Store } from './lab.ts';
import { FakeLnd, sha256Hex, type AmountVariant, type Call, type Proc, type Workflow } from './lnd.ts';
import { MAX_INT64, Oracle, PREDICATES, type InvoiceRow, type PredicateName, type StoreCall, type Violation } from './oracle.ts';

/**
 * Model-based harness for the payment lab's state machines (design brief 1.3.0, item 1).
 *
 * A case is a sequence of events: workflow starts on two processes (p0, p1) sharing one payer and one
 * receiver database file, LND's answers and stream messages in any order, LND's own progress (HTLC
 * attempts, a payment failing or succeeding, an invoice paid, a held HTLC timing out), requests that
 * reach LND late, clock steps past the invoice creation window, graceful aborts and process kills
 * (the store is closed and reopened from its file; nothing the killed process still had in flight is
 * written), and outbox worker passes that may be killed at any point of a row (claimed, writing its
 * effect file, effect written, acknowledged). The real stores and workflows run against the scripted LND
 * in lnd.ts, and the oracle in oracle.ts checks every README rule after every store call and every step.
 *
 * Events are generated from a seed with the generator of scripts/payment-fuzz.mjs (xorshift128 seeded
 * through splitmix32, one seed per case derived from the campaign seed and the case index), so a case
 * is reproduced from (seed, case index). A failing case is shrunk by delta debugging over its event
 * list and written as a replay file holding everything needed to run it again: the configuration, the
 * reduced events, the violated predicate and the records before and after the violation. Events name
 * their targets (process, operation, invoice index, order) and pick pending calls by position, so any
 * subsequence of a case is itself a runnable case.
 */

// ---------------------------------------------------------------------------------------------
// Generator (the same as scripts/payment-fuzz.mjs).

export interface Rng { next(): number; int(low: number, high: number): number; pick<T>(items: readonly T[]): T; chance(p: number): boolean }

/** xorshift128 seeded through splitmix32, as in scripts/payment-fuzz.mjs. */
export function xorshift(seed: number): Rng {
  let s = seed >>> 0;
  const split = (): number => {
    s = (s + 0x9e3779b9) >>> 0;
    let z = s;
    z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
    z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
    return (z ^ (z >>> 16)) >>> 0;
  };
  let x = split() || 1, y = split(), z = split(), w = split();
  const u32 = (): number => {
    const t = (x ^ (x << 11)) >>> 0;
    x = y; y = z; z = w;
    w = (w ^ (w >>> 19) ^ (t ^ (t >>> 8))) >>> 0;
    return w;
  };
  const next = (): number => u32() / 4294967296;
  return { next, int: (low, high) => low + Math.floor(next() * (high - low + 1)), pick: items => items[Math.floor(next() * items.length)] as never,
    chance: p => next() < p };
}

/** The per-case seed: a case is reproduced from the campaign seed and its index (as caseSeed in scripts/payment-fuzz.mjs). */
export function caseSeed(seed: number, index: number): number {
  return createHash('sha256').update(`payment-lab-harness:${seed}:${index}`).digest().readUInt32LE(0);
}

// ---------------------------------------------------------------------------------------------
// Cases.

export type HarnessEvent = { t: string; [field: string]: string | number | boolean | null };

export interface CaseConfig {
  /** small: amounts of a few thousand msat; huge: amounts near 2^62, where sums pass 2^63 - 1. */
  scale: 'small' | 'huge';
  /** Whether the payer's operations reserve against budget B. */
  budget: boolean;
  /** Budget B's limit (decimal msat). */
  limit: string;
}

interface OperationConfig { amount: bigint; fee: bigint }
const ORDERS = ['o0', 'o1', 'o2'] as const;
const ORDER_AMOUNTS = [5000n, 6000n, 7000n];
const INVOICES_PER_OPERATION = 3;
const PROCS: readonly Proc[] = ['p0', 'p1'];
const DESTINATION = `02${'11'.repeat(32)}`;
const quiet = (): void => undefined;
/** How far the worker's clock moves per pass: past the 60 s lease, so a row a killed worker held is claimed again by the next pass. */
const WORKER_STEP_MS = 61_000;
export const OUTBOX_CRASH_POINTS = ['none', 'after-claim', 'during-write', 'after-effect', 'after-ack'] as const;

function operations(config: CaseConfig): OperationConfig[] {
  return config.scale === 'small'
    ? [{ amount: 1000n, fee: 100n }, { amount: 2000n, fee: 100n }]
    // op1 asks for principal + fee allowance above 2^63 - 1: always refused, and the refusal must not overflow.
    : [{ amount: 2n ** 62n, fee: 1000n }, { amount: 2n ** 62n + 1n, fee: 2n ** 62n }];
}

export function randomConfig(rng: Rng): CaseConfig {
  const scale = rng.chance(0.2) ? 'huge' : 'small';
  return { scale, budget: rng.chance(0.75), limit: scale === 'huge' ? MAX_INT64.toString() : rng.pick(['2200', '3200', '10000']) };
}

const MUTATING = {
  payer: new Set(['recordIntent', 'claimForSubmission', 'markUncertain', 'markNotInitiated', 'markRejected', 'applyUpdate', 'prepareRetry', 'setBudget', 'event']),
  receiver: new Set(['recordInvoiceIntent', 'markCreated', 'markNotCreated', 'applyInvoice', 'setCursor']),
};

interface ProcState {
  name: Proc;
  incarnation: number;
  payer: Store;
  receiver: Store;
  payerDeps: PayerDeps;
  receiverDeps: ReceiverDeps;
  workflows: Set<Workflow>;
}

const settleTurn = (): Promise<void> => new Promise(done => setImmediate(done));

/** One case: two processes over one payer file and one receiver file, the scripted LND and the oracle. */
export class Run {
  readonly lab: Lab;
  readonly config: CaseConfig;
  readonly ops: OperationConfig[];
  lnd!: FakeLnd;
  oracle!: Oracle;
  readonly dir: string;
  procs!: Record<Proc, ProcState>;
  readonly counts: Record<string, number> = {};
  readonly #als = new AsyncLocalStorage<Workflow>();
  readonly #storeErrors = new WeakSet<object>();
  #progress = 0;
  #workflowSeq = 0;
  #delivering: Call | undefined;
  #autoAnswer = false;
  #cliBusy = false;
  readonly #stdoutWrite = process.stdout.write;

  #clockMs = Date.now();
  #effectKey: Buffer | undefined;

  constructor(lab: Lab, config: CaseConfig, scratch: string) {
    this.lab = lab;
    this.config = config;
    this.ops = operations(config);
    this.dir = mkdtempSync(join(scratch, 'case-'));
    try {
      this.#init(lab, config);
    } catch (error) {
      // A case that cannot start leaves no open store and no directory behind, and its own error is the one reported.
      for (const state of Object.values((this as { procs?: Record<Proc, ProcState> }).procs ?? {})) closeQuietly(state);
      (this as { oracle?: Oracle }).oracle?.close();
      try { rmSync(this.dir, { recursive: true, force: true }); } catch { /* reported below: the error that stopped the case */ }
      throw error;
    }
  }

  #init(lab: Lab, config: CaseConfig): void {
    this.lnd = new FakeLnd(lab, {
      settleCalled: (proc, hash) => this.oracle.settleCalled(proc, hash),
      progress: () => { this.#progress += 1; },
      currentWorkflow: () => this.#delivering?.workflow ?? this.#als.getStore(),
      callCreated: call => this.#callCreated(call),
      alive: (proc, workflow) => workflow === undefined || this.procs[proc].incarnation === workflow.incarnation,
    });
    this.oracle = new Oracle(this.lnd, join(this.dir, 'payer.db'), join(this.dir, 'receiver.db'));
    for (let op = 0; op < this.ops.length; op += 1) {
      for (let inv = 0; inv < INVOICES_PER_OPERATION; inv += 1) {
        const label = `op${op}/i${inv}`;
        const preimage = createHash('sha256').update(`payment-lab-harness:${label}`).digest('hex');
        this.lnd.paymentLabels.set(sha256Hex(preimage), { label, preimage, amountMsat: (this.ops[op] as OperationConfig).amount });
      }
    }
    this.procs = { p0: this.#open('p0', 0), p1: this.#open('p1', 0) };
    if (config.budget) (this.procs.p0.payer.setBudget as (id: string, limit: bigint) => void)('B', BigInt(config.limit));
    this.oracle.budgetStatus = budget => (this.procs.p0.payer.budgetStatus as (id: string) => ReturnType<NonNullable<Oracle['budgetStatus']>>)(budget);
    this.oracle.verifyLedger = lab.verifyLedger;
    const outbox = lab.outbox;
    if (outbox !== undefined) {
      this.oracle.effects = {
        read: (side, subject) => outbox.readEffect(outbox.effectPath(this.#effectTarget(side), subject), this.#effectTarget(side).key),
        fields: row => outbox.effectFields({ kind: row.kind, idempotencyKey: row.key, payload: row.payload }),
        count: side => {
          const dir = this.#effectTarget(side).dir;
          return existsSync(dir) ? readdirSync(dir).filter(name => name.endsWith('.json') && !name.startsWith('.')).length : 0;
        },
      };
    }
  }

  /** The lab's effect directory for a side, in the case directory, with the lab's HMAC key (created on first use). */
  #effectTarget(side: 'payer' | 'receiver'): EffectTarget {
    const outbox = this.lab.outbox;
    if (outbox === undefined) throw new Error('this lab source has no outbox');
    this.#effectKey ??= outbox.labKey(this.dir);
    return { dir: join(this.dir, side === 'receiver' ? 'receipts' : 'confirmations'), key: this.#effectKey };
  }

  hashOf(op: number, inv: number): string {
    const label = `op${op}/i${inv}`;
    const entry = [...this.lnd.paymentLabels.entries()].find(([, item]) => item.label === label);
    if (entry === undefined) throw new Error(`no payment ${label}`);
    return entry[0];
  }

  // ------------------------------------------------------------------------------------------
  // Processes and the recording proxy.

  #open(name: Proc, incarnation: number): ProcState {
    const payer = new this.lab.PayerStore(join(this.dir, 'payer.db'));
    const receiver = new this.lab.ReceiverStore(join(this.dir, 'receiver.db'));
    // The harness kills processes, not machines: what a store committed is in the file whether or not it was fsynced.
    for (const store of [payer, receiver]) (store.db as { exec(sql: string): void }).exec('PRAGMA synchronous = OFF');
    const state = { name, incarnation, payer, receiver, workflows: new Set<Workflow>() } as ProcState;
    state.payerDeps = { api: this.lnd.payerApi(name), store: this.#proxy(state, 'payer', payer), emit: quiet };
    state.receiverDeps = { api: this.lnd.invoiceApi(name), store: this.#proxy(state, 'receiver', receiver), emit: quiet };
    return state;
  }

  /** The store as a process sees it: dead once the process is killed, and every write recorded for the oracle. */
  #proxy(state: ProcState, side: 'payer' | 'receiver', real: Store): Store {
    const incarnation = state.incarnation;
    return new Proxy(real, {
      get: (target, property) => {
        if (state.incarnation !== incarnation) throw new Error(`process ${state.name} was killed`);
        const value = Reflect.get(target, property, target) as unknown;
        if (typeof value !== 'function') return value;
        // The connection belongs to the harness (cli.ts's main closes its store when it is done).
        if (property === 'close') return quiet;
        if (typeof property !== 'string' || !MUTATING[side].has(property)) return (value as (...args: unknown[]) => unknown).bind(target);
        return (...args: unknown[]) => this.#record(state, side, property, args, () => (value as (...args: unknown[]) => unknown).apply(target, args));
      },
    }) as Store;
  }

  #record(state: ProcState, side: 'payer' | 'receiver', method: string, args: unknown[], work: () => unknown): unknown {
    const workflow = this.#delivering?.workflow ?? this.#als.getStore();
    const submission = side === 'payer' ? (this.#delivering ?? workflow?.lastCall)?.submission : undefined;
    const before = side === 'payer' ? this.oracle.payerSnap() : this.oracle.receiverSnap();
    let result: unknown;
    let error: unknown;
    try { result = work(); } catch (thrown) { error = thrown ?? new Error('undefined thrown'); }
    this.#progress += 1;
    const after = side === 'payer' ? this.oracle.payerSnap() : this.oracle.receiverSnap();
    if (method === 'claimForSubmission' && result === true && workflow !== undefined && side === 'payer') {
      workflow.submission = (after as ReturnType<Oracle['payerSnap']>).payments.get(String(args[0]))?.subs;
    }
    const call: StoreCall = { proc: state.name, side, method, args, before, after, result, error, submission };
    this.oracle.afterCall(call);
    if (error !== undefined) {
      if (typeof error === 'object') this.#storeErrors.add(error as object);
      throw error;
    }
    return result;
  }

  /** Payment streams speak for a submission: a send for its claim, a track opened by submit for that claim, a reconcile's track for the record's current one. */
  #callCreated(call: Call): void {
    if (call.kind === 'send') call.submission = call.workflow?.submission;
    if (call.kind === 'track') {
      call.submission = call.workflow?.kind === 'submit' ? call.workflow.submission : this.oracle.payerSnap().payments.get(call.hash)?.subs;
    }
    if (this.#autoAnswer && call.kind !== 'send' && call.kind !== 'track' && call.kind !== 'sub') {
      queueMicrotask(() => this.lnd.answer(call, 'ok'));
    }
  }

  #start(proc: Proc, kind: string, label: string, body: (signal: AbortSignal) => Promise<unknown>, onDone?: (result: unknown) => void): Workflow {
    const state = this.procs[proc];
    const workflow: Workflow = { id: ++this.#workflowSeq, proc, incarnation: state.incarnation, kind, label, controller: new AbortController(), done: false };
    state.workflows.add(workflow);
    const alive = (): boolean => this.procs[proc].incarnation === workflow.incarnation;
    const promise = this.#als.run(workflow, () => body((workflow.controller as AbortController).signal));
    promise.then(result => {
      workflow.done = true;
      workflow.result = result;
      this.#progress += 1;
      if (alive()) onDone?.(result);
    }, (error: unknown) => {
      workflow.done = true;
      workflow.error = error;
      this.#progress += 1;
      if (alive()) this.oracle.fail('no-internal-error', `${kind} ${label} on ${proc} threw: ${String((error as Error)?.message ?? error)}`);
    });
    return workflow;
  }

  /** Lets every workflow run until it waits on LND again. */
  async drain(): Promise<void> {
    let last = -1;
    let still = 0;
    for (let turn = 0; turn < 1000 && still < 3; turn += 1) {
      await settleTurn();
      if (this.#progress === last) still += 1;
      else { still = 0; last = this.#progress; }
    }
  }

  /** Kills a process: its store is dead at once, its calls are cut, and it restarts from the files. */
  async kill(proc: Proc, restart = true): Promise<void> {
    const state = this.procs[proc];
    state.incarnation += 1;
    for (const workflow of state.workflows) workflow.controller?.abort();
    for (const call of this.lnd.openCalls(proc)) this.lnd.cut(call, new this.lab.TransportError('connection reset: process killed', 'response'));
    await this.drain();
    closeQuietly(state);
    if (restart) this.procs[proc] = this.#open(proc, state.incarnation);
  }

  #abort(proc: Proc): void {
    for (const workflow of this.procs[proc].workflows) if (!workflow.done) workflow.controller?.abort();
  }

  #listening(proc: Proc): boolean {
    return [...this.procs[proc].workflows].some(item => item.kind === 'listen' && !item.done);
  }

  // ------------------------------------------------------------------------------------------
  // Candidates (the generator chooses among them; a replayed event picks by position).

  calls(kind: Call['kind'], filter: (call: Call) => boolean = call => call.open): Call[] {
    return this.lnd.calls.filter(call => call.kind === kind && filter(call));
  }

  /** SendPaymentV2 requests that can still reach LND (send.arrive). */
  arrivable(): Call[] {
    return this.calls('send', item => !item.arrived && (item.open || item.inTransit));
  }

  /** Streams with a message to deliver (send.deliver, track.deliver, sub.deliver). */
  queued(kind: 'send' | 'track' | 'sub'): Call[] {
    return this.calls(kind, item => item.open && item.queue.length > 0);
  }

  /** Create requests in transit that have not reached LND (create.arrive). */
  creatable(): Call[] {
    return this.calls('create', item => item.inTransit && !item.arrived);
  }

  inFlightPayments(): string[] {
    return [...this.lnd.payments.values()].filter(item => item.status === 'IN_FLIGHT').map(item => item.hash);
  }

  invoicesIn(states: string[]): string[] {
    return [...this.lnd.invoices.values()].filter(item => states.includes(item.state)).map(item => item.hash);
  }

  // ------------------------------------------------------------------------------------------
  // Events.

  async step(event: HarnessEvent): Promise<boolean> {
    let applied: boolean;
    try {
      applied = await this.#execute(event);
    } catch (error) {
      // A store call that threw was judged by the oracle when it happened; anything else is a harness defect.
      if (typeof error !== 'object' || error === null || !this.#storeErrors.has(error)) throw error;
      applied = true;
    }
    await this.drain();
    await this.oracle.afterStep();
    const key = `${event.t}${applied ? '' : ' (no-op)'}`;
    this.counts[key] = (this.counts[key] ?? 0) + 1;
    return applied;
  }

  async #execute(event: HarnessEvent): Promise<boolean> {
    const pick = <T>(items: T[]): T | undefined => (items.length === 0 ? undefined
      : items[Math.min(items.length - 1, Math.floor(Number(event.pick ?? 0) * items.length))]);
    const proc = (event.p ?? 'p0') as Proc;
    const state = this.procs[proc];
    switch (event.t) {
      case 'intent': {
        const op = Number(event.op);
        const inv = Number(event.inv);
        const config = this.ops[op] as OperationConfig;
        const hash = this.hashOf(op, inv);
        this.lab.recordIntent(state.payerDeps, { operationId: `op${op}`, kind: 'payout', paymentRequest: `lnbcrt-op${op}/i${inv}`,
          invoice: { destination: DESTINATION, paymentHash: hash, amountMsat: config.amount, timestamp: BigInt(Math.floor(Date.now() / 1000)),
            expirySeconds: 3600n, description: `op${op}` }, feeLimitMsat: config.fee, maxParts: 1, budgetId: this.config.budget ? 'B' : undefined });
        return true;
      }
      case 'submit': {
        const hash = this.hashOf(Number(event.op), Number(event.inv));
        this.#start(proc, 'submit', this.lnd.labelOf(hash), signal => this.lab.submit(state.payerDeps, hash, { timeoutSeconds: 60, fault: 'none', signal }));
        return true;
      }
      case 'retry':
        (state.payerDeps.store.prepareRetry as (op: string) => unknown)(`op${Number(event.op)}`);
        return true;
      case 'reconcile': {
        const hash = this.hashOf(Number(event.op), Number(event.inv));
        this.#start(proc, 'reconcile', this.lnd.labelOf(hash), signal => this.lab.reconcile(state.payerDeps, hash, signal));
        return true;
      }
      case 'send.arrive': {
        const call = pick(this.arrivable());
        return call !== undefined && this.lnd.arrive(call);
      }
      case 'send.deliver':
      case 'track.deliver':
      case 'sub.deliver': {
        const kind = event.t === 'send.deliver' ? 'send' : event.t === 'track.deliver' ? 'track' : 'sub';
        const call = pick(this.queued(kind));
        if (call === undefined) return false;
        this.#delivering = call;
        try { this.lnd.deliver(call); } finally { this.#delivering = undefined; }
        return true;
      }
      case 'send.end': {
        const call = pick(this.calls('send'));
        return call !== undefined && this.lnd.endSend(call, String(event.mode));
      }
      case 'track.end': {
        const call = pick(this.calls('track'));
        if (call === undefined || !this.lnd.endTrack(call, String(event.mode))) return false;
        // A reconcile whose stream ended waits out a backoff before tracking again; the harness has no clock, so
        // it lets the reconcile see the end (track-interrupted, track-ended-early) and then stops it: the deadline.
        if (call.workflow?.kind === 'reconcile') {
          await this.drain();
          call.workflow.controller?.abort();
        }
        return true;
      }
      case 'lnd.payment': {
        const hash = pick(this.inFlightPayments());
        return hash !== undefined && this.lnd.paymentEvent(hash, event.what as 'attempt' | 'attempt-fail' | 'fail' | 'succeed', event.amount as AmountVariant | undefined);
      }
      case 'create': {
        const order = ORDERS[Number(event.order)] as string;
        this.#start(proc, 'create', order, () => this.lab.createInvoice(state.receiverDeps, { orderId: order,
          amountMsat: ORDER_AMOUNTS[Number(event.order)] as bigint, hold: event.hold === true, memo: order, expirySeconds: 3600 }));
        return true;
      }
      case 'answer': {
        const call = pick(this.calls(event.kind as Call['kind']));
        return call !== undefined && this.lnd.answer(call, String(event.mode));
      }
      case 'create.arrive': {
        const call = pick(this.creatable());
        return call !== undefined && this.lnd.arriveLate(call);
      }
      case 'invoice': {
        if (event.what === 'foreign') { this.lnd.foreignInvoice(); return true; }
        const what = event.what as 'pay' | 'htlc-timeout' | 'expire' | 'misreport' | 'resettle';
        const hash = pick(this.invoicesIn(what === 'htlc-timeout' ? ['ACCEPTED'] : what === 'misreport' ? ['OPEN', 'ACCEPTED'] : what === 'resettle' ? ['SETTLED'] : ['OPEN']));
        return hash !== undefined && this.lnd.invoiceEvent(hash, what, event.amount as AmountVariant | undefined);
      }
      case 'settle':
      case 'cancel': {
        const order = ORDERS[Number(event.order)] as string;
        this.#start(proc, event.t, order, () => (event.t === 'settle' ? this.lab.settleHoldInvoice : this.lab.cancelHoldInvoice)(state.receiverDeps, order));
        return true;
      }
      case 'rreconcile': {
        const order = event.order === null || event.order === undefined ? undefined : ORDERS[Number(event.order)];
        const targets = this.oracle.reconcileTargets(order);
        if (event.cli === true && this.lab.cliMain !== undefined && !this.#cliBusy) {
          this.#startCliReconcile(proc, order, targets);
          return true;
        }
        const workflow = this.#start(proc, 'rreconcile', order ?? 'all', signal => this.lab.reconcileInvoices(state.receiverDeps, order, signal),
          result => this.oracle.reconcileDone(targets, result as { resolved: number; open: number; unknown: number }, undefined, this.#answers(workflow)));
        return true;
      }
      case 'listen':
        if (this.#listening(proc)) return false;
        this.#start(proc, 'listen', 'invoices', signal => this.lab.listen(state.receiverDeps, { reconcileIntervalMs: 2 ** 31 - 1, signal }));
        return true;
      case 'cursor-set': {
        const index = pick([0n, ...this.lnd.settleIndexes()]) ?? 0n;
        const adds = [0n, ...this.lnd.addIndexes()];
        const add = event.add === undefined ? 0n : adds[Math.min(adds.length - 1, Math.floor(Number(event.add) * adds.length))] ?? 0n;
        (state.receiverDeps.store.setCursor as (settle: bigint, add: bigint) => void)(index, add);
        return true;
      }
      case 'age':
        // The clock moves three minutes on: invoice intents pass the 120 s creation window (still within the 24 h recheck).
        (state.receiver.db as { exec(sql: string): void }).exec(`UPDATE invoices SET created_at = strftime('%Y-%m-%dT%H:%M:%fZ', created_at, '-180 seconds')`);
        return true;
      case 'kill':
        await this.kill(proc);
        return true;
      case 'abort':
        this.#abort(proc);
        return true;
      case 'outbox':
        if (this.lab.outbox === undefined) return false;
        await this.#work(proc, event.side === 'payer' ? 'payer' : 'receiver', String(event.crash ?? 'none'));
        return true;
      default:
        throw new Error(`unknown event ${event.t}`);
    }
  }

  /** The lookup answers a reconcile workflow received, per invoice (see Oracle.reconcileDone). */
  #answers(workflow: Workflow): Map<string, Set<string>> {
    const answers = new Map<string, Set<string>>();
    for (const call of this.lnd.calls) {
      if (call.kind !== 'lookup' || call.workflow !== workflow || call.answered === undefined) continue;
      answers.set(call.hash, (answers.get(call.hash) ?? new Set()).add(call.answered));
    }
    return answers;
  }

  /**
   * One outbox worker pass (src/outbox/worker.ts) on a process, over the side's database, writing the
   * lab's effect files in the case directory. `crash` kills the process at that point of the first row it
   * reaches: its connection is closed there, so nothing after the point is written, and it restarts.
   * Each row's effect is counted as written when its file did not exist at the claim and exists after it.
   */
  async #work(proc: Proc, side: 'payer' | 'receiver', crash: string): Promise<void> {
    const outbox = this.lab.outbox;
    if (outbox === undefined) return;
    const state = this.procs[proc];
    const store = side === 'payer' ? state.payer : state.receiver;
    const target = this.#effectTarget(side);
    this.#clockMs += WORKER_STEP_MS;
    const existed = new Map<number, boolean>();
    let crashed = false;
    const die = (point: string): void => {
      if (crash !== point || crashed) return;
      crashed = true;
      store.close();
      throw new Error(`process ${proc} was killed in the outbox worker (${point})`);
    };
    const hooks = {
      afterClaim: (row: OutboxRowView): void => { existed.set(row.outboxId, existsSync(outbox.effectPath(target, row.subject))); die('after-claim'); },
      duringWrite: (): void => die('during-write'),
      afterEffect: (row: OutboxRowView): void => {
        if (existed.get(row.outboxId) === false && existsSync(outbox.effectPath(target, row.subject))) {
          this.oracle.written.set(row.idempotencyKey, (this.oracle.written.get(row.idempotencyKey) ?? 0) + 1);
        }
        die('after-effect');
      },
      afterAck: (): void => die('after-ack'),
    };
    try {
      outbox.runPass(store.db, target, { emit: quiet, clock: () => this.#clockMs, hooks });
    } catch (error) {
      if (!crashed) {
        this.oracle.fail('no-internal-error', `the ${side}'s outbox worker on ${proc} threw: ${String((error as Error)?.message ?? error)}`);
        return;
      }
    }
    if (crashed) await this.kill(proc);
  }

  /** receiver reconcile through cli.ts's main, so its exit code is checked as well as its counts. */
  #startCliReconcile(proc: Proc, order: string | undefined, targets: Map<string, InvoiceRow>): void {
    const main = this.lab.cliMain;
    if (main === undefined) return;
    this.#cliBusy = true;
    const workflow = this.#start(proc, 'rreconcile-cli', order ?? 'all', async () => {
      const lines: string[] = [];
      const write = process.stdout.write;
      const listeners = { SIGINT: process.listeners('SIGINT'), SIGTERM: process.listeners('SIGTERM') };
      process.stdout.write = ((chunk: unknown) => { lines.push(String(chunk)); return true; }) as typeof process.stdout.write;
      let exit: number;
      try {
        exit = await main(['receiver', 'reconcile', '--as', 'merchant', ...(order === undefined ? [] : ['--order', order])], {
          payer: () => { throw new Error('the harness drives the payer directly'); }, receiver: () => this.procs[proc].receiverDeps });
      } finally {
        process.stdout.write = write;
        // cli.ts registers SIGINT and SIGTERM handlers for its stop signal; a test process must not keep them.
        for (const signal of ['SIGINT', 'SIGTERM'] as const) {
          for (const listener of process.listeners(signal)) if (!listeners[signal].includes(listener)) process.removeListener(signal, listener);
        }
        this.#cliBusy = false;
      }
      const events = lines.flatMap(line => line.split('\n')).filter(Boolean).map(line => { try { return JSON.parse(line) as Record<string, unknown>; } catch { return {}; } });
      return { exit, outcome: events.find(item => item.event === 'outcome'), error: events.find(item => item.event === 'error') };
    }, done => {
      const { exit, outcome, error } = done as { exit: number; outcome?: { resolved: number; open: number; unknown: number }; error?: { error: string } };
      if (outcome !== undefined) this.oracle.reconcileDone(targets, outcome, exit, this.#answers(workflow));
      else this.oracle.fail('no-internal-error', `receiver reconcile exited ${exit}: ${error?.error ?? 'no outcome'}`);
    });
  }

  /**
   * The end of a case: both processes are killed, the clock passes the creation window, and a fresh process
   * reconciles twice with every call answered at once. Then no order may have two payable invoices.
   */
  async quiesce(): Promise<void> {
    await this.kill('p0');
    await this.kill('p1');
    (this.procs.p0.receiver.db as { exec(sql: string): void }).exec(`UPDATE invoices SET created_at = strftime('%Y-%m-%dT%H:%M:%fZ', created_at, '-180 seconds')`);
    this.#autoAnswer = true;
    for (let pass = 0; pass < 2; pass += 1) {
      const targets = this.oracle.reconcileTargets(undefined);
      const workflow = this.#start('p0', 'rreconcile', 'quiescence', signal => this.lab.reconcileInvoices(this.procs.p0.receiverDeps, undefined, signal),
        result => this.oracle.reconcileDone(targets, result as { resolved: number; open: number; unknown: number }, undefined, this.#answers(workflow)));
      await this.drain();
      await this.oracle.afterStep();
    }
    this.oracle.quiescent();
    if (this.lab.outbox !== undefined) {
      // The worker runs until every row is done: past any backoff (at most 5 minutes) and any lease.
      this.#clockMs += 10 * 60_000;
      for (let pass = 0; pass < 2; pass += 1) for (const side of ['receiver', 'payer'] as const) await this.#work('p0', side, 'none');
      await this.oracle.afterStep();
      this.oracle.effectsQuiescent();
    }
  }

  async dispose(): Promise<void> {
    this.#autoAnswer = false;
    await this.kill('p0', false);
    await this.kill('p1', false);
    process.stdout.write = this.#stdoutWrite;
    this.oracle.close();
    // A directory Windows still holds open is left in the scratch directory (removed with it); it never hides a result.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try { rmSync(this.dir, { recursive: true, force: true }); return; } catch { await new Promise(done => setTimeout(done, 20)); }
    }
  }

  // ------------------------------------------------------------------------------------------
  // Plans: short scripted sequences toward paths random events reach only rarely (a payment that succeeds
  // after it was recorded failed, a withdrawn replacement, a double payment, a FAILED that arrives after
  // the success, a refusal after a NotFound revert; an invoice created late that is paid second, paid first
  // so its order's other invoice is superseded and its cancel fails or is cut off, seen canceled and then
  // settled or reported OPEN again). A plan is a list of steps, each producing one ordinary event from the
  // state at that moment (picks by position, as every event), so a case with a plan replays and shrinks like
  // any other. A step returns null to be skipped and undefined to abandon the plan (the state went elsewhere).

  #plan: { name: string; steps: PlanStep[]; at: number } | undefined;
  #planCount = 0;

  #planned(rng: Rng): HarnessEvent | undefined {
    if (this.#plan === undefined && this.#planCount < MAX_PLANS) {
      const plan = this.#startPlan(rng);
      if (plan !== undefined) {
        this.#plan = { ...plan, at: 0 };
        this.#planCount += 1;
        this.counts[`plan ${plan.name}`] = (this.counts[`plan ${plan.name}`] ?? 0) + 1;
      }
    }
    while (this.#plan !== undefined) {
      const step = this.#plan.steps[this.#plan.at];
      this.#plan.at += 1;
      const event = step === undefined ? undefined : step();
      if (event === null) continue;
      if (event === undefined) {
        this.#plan = undefined;
        break;
      }
      return event;
    }
    return undefined;
  }

  /** Starts a plan whose precondition holds now, each kind with its own chance per generated event (a payer plan's precondition is brief). */
  #startPlan(rng: Rng): { name: string; steps: PlanStep[] } | undefined {
    const snap = this.oracle.payerSnap();
    const invoices = this.oracle.receiverSnap();
    const builders: [number, () => { name: string; steps: PlanStep[] } | undefined][] = [];
    const sending = this.arrivable().filter(call => call.open && call.workflow?.kind === 'submit' && this.procs[call.proc].incarnation === call.workflow.incarnation
      && snap.payments.get(call.hash)?.state === 'submitting' && snap.payments.get(call.hash)?.subs === call.submission);
    if (sending.length > 0) builders.push([PAYER_PLAN_CHANCE, () => this.#revertPlan(rng, rng.pick(sending))]);
    const refailable = [...snap.payments].filter(([hash, row]) => row.state === 'failed' && this.lnd.payments.get(hash)?.status === 'FAILED'
      && snap.operations.get(row.op) !== 'completed' && ![...snap.payments.values()].some(other => other.op === row.op && PENDING_STATES.has(other.state)));
    if (refailable.length > 0) builders.push([PAYER_PLAN_CHANCE, () => this.#staleTrackPlan(rng, rng.pick(refailable)[0])]);
    const free = ORDERS.map((order, index) => ({ order, index })).filter(({ order }) => (invoices.orders.get(order) ?? 'awaiting-payment') === 'awaiting-payment'
      && ![...invoices.invoices.values()].some(row => row.order === order && ['creating', 'open', 'accepted'].includes(row.state)));
    if (free.length > 0) builders.push([RECEIVER_PLAN_CHANCE, () => this.#lateInvoicePlan(rng, rng.pick(free).index)]);
    if (free.length > 0) builders.push([RECEIVER_PLAN_CHANCE / 2, () => this.#canceledAcceptedPlan(rng, rng.pick(free).index)]);
    let point = rng.next();
    for (const [chance, build] of builders) {
      if (point < chance) return build();
      point -= chance;
    }
    return undefined;
  }

  /** The newest call of a kind by a process for a hash (or, for creates, an order's label). */
  #newest(kind: Call['kind'], proc: Proc, match: (call: Call) => boolean): Call | undefined {
    for (let index = this.lnd.calls.length - 1; index >= 0; index -= 1) {
      const call = this.lnd.calls[index] as Call;
      if (call.kind === kind && call.proc === proc && match(call)) return call;
    }
    return undefined;
  }

  #answerStep(proc: Proc, kind: 'lookup' | 'create' | 'cancel' | 'settle', mode: string, match: (call: Call) => boolean = () => true): PlanStep {
    return () => {
      const open = this.calls(kind);
      const call = open.find(item => item.proc === proc && match(item));
      return call === undefined ? null : { t: 'answer', kind, pick: pickAt(open, call), mode };
    };
  }

  #deliverSteps(kind: 'send' | 'track' | 'sub', match: (call: Call) => boolean, times = 3): PlanStep[] {
    return Array.from({ length: times }, () => (): HarnessEvent | null => {
      const queued = this.queued(kind);
      const call = queued.find(match);
      return call === undefined ? null : { t: `${kind}.deliver`, pick: pickAt(queued, call) };
    });
  }

  #arriveStep(id: () => number | undefined): PlanStep {
    return () => {
      const list = this.arrivable();
      const call = list.find(item => item.id === id());
      return call === undefined ? undefined : { t: 'send.arrive', pick: pickAt(list, call) };
    };
  }

  #paymentStep(hash: () => string | undefined, what: 'fail' | 'succeed', amount?: AmountVariant): PlanStep {
    return (): HarnessEvent | undefined => {
      const list = this.inFlightPayments();
      const target = hash();
      if (target === undefined || !list.includes(target)) return undefined;
      return what === 'succeed' ? { t: 'lnd.payment', pick: pickAt(list, target), what, amount: amount ?? 'exact' } : { t: 'lnd.payment', pick: pickAt(list, target), what };
    };
  }

  #payStep(hash: () => string | undefined): PlanStep {
    return () => {
      const list = this.invoicesIn(['OPEN']);
      const target = hash();
      return target === undefined || !list.includes(target) ? undefined : { t: 'invoice', what: 'pay', pick: pickAt(list, target), amount: 'exact' };
    };
  }

  /**
   * A submission's request is on its way when the other process's TrackPaymentV2 answers NotFound and the record
   * returns to intent. Then: the request is refused, or reaches LND and fails (the live submission's FAILED or
   * refusal must still apply); or the other process submits again, LND fails that, a replacement may be recorded
   * (and paid), and the first request reaches LND and succeeds: success after a recorded failure, a withdrawn
   * replacement, a double payment.
   */
  #revertPlan(rng: Rng, first: Call): { name: string; steps: PlanStep[] } {
    const hash = first.hash;
    const { op, inv } = parseLabel(this.lnd.labelOf(hash));
    const a = first.proc;
    const b: Proc = a === 'p0' ? 'p1' : 'p0';
    const variant = rng.pick(['revert-then-refused', 'revert-then-failed', 'success-after-failure', 'withdrawn', 'double-payment'] as const);
    const record = (target = hash): PaymentRowView | undefined => this.oracle.payerSnap().payments.get(target);
    let second: number | undefined;
    let replacement: string | undefined;
    let third: number | undefined;
    const steps: PlanStep[] = [
      () => ({ t: 'reconcile', p: b, op, inv }),
      ...this.#deliverSteps('track', call => call.hash === hash && call.proc === b, 1),
      () => (record()?.state === 'intent' ? null : undefined),
    ];
    if (variant === 'revert-then-refused') {
      steps.push(() => {
        const sends = this.calls('send');
        const call = sends.find(item => item.id === first.id);
        return call === undefined ? undefined : { t: 'send.end', pick: pickAt(sends, call), mode: 'definite' };
      });
    } else if (variant === 'revert-then-failed') {
      steps.push(this.#arriveStep(() => first.id), this.#paymentStep(() => hash, 'fail'), ...this.#deliverSteps('send', call => call.id === first.id));
    } else {
      steps.push(
        () => ({ t: 'submit', p: b, op, inv }),
        () => { second = this.#newest('send', b, call => call.hash === hash)?.id; return second === undefined || second === first.id ? undefined : null; },
        this.#arriveStep(() => second), this.#paymentStep(() => hash, 'fail'), ...this.#deliverSteps('send', call => call.id === second),
        () => (record()?.state === 'failed' ? null : undefined),
      );
      if (variant !== 'success-after-failure') {
        steps.push(() => {
          const used = [...this.oracle.payerSnap().payments.values()].filter(row => row.op === `op${op}`).length;
          if (used >= INVOICES_PER_OPERATION) return undefined;
          replacement = this.hashOf(op, used);
          return { t: 'intent', p: b, op, inv: used };
        });
      }
      if (variant === 'double-payment') {
        steps.push(
          () => (replacement === undefined ? undefined : { t: 'submit', p: b, ...parseLabel(this.lnd.labelOf(replacement)) }),
          () => { third = replacement === undefined ? undefined : this.#newest('send', b, call => call.hash === replacement)?.id; return third === undefined ? undefined : null; },
          this.#arriveStep(() => third), this.#paymentStep(() => replacement, 'succeed'), ...this.#deliverSteps('send', call => call.id === third),
        );
      }
      steps.push(this.#arriveStep(() => first.id), this.#paymentStep(() => hash, 'succeed', rng.pick(['exact', 'exact', 'over', 'under'] as const)),
        ...this.#deliverSteps('send', call => call.id === first.id));
    }
    return { name: `payer ${variant}`, steps };
  }

  /**
   * A failed payment is retried and submitted again; before the new request reaches LND, the other process's
   * TrackPaymentV2 reads the old FAILED. The new request succeeds, and then the track's FAILED arrives for the
   * live submission of a payment already succeeded.
   */
  #staleTrackPlan(rng: Rng, hash: string): { name: string; steps: PlanStep[] } {
    const { op, inv } = parseLabel(this.lnd.labelOf(hash));
    const a = rng.pick(PROCS);
    const b: Proc = a === 'p0' ? 'p1' : 'p0';
    let send: number | undefined;
    return { name: 'payer failed-after-success', steps: [
      () => ({ t: 'retry', p: a, op }),
      () => (this.oracle.payerSnap().payments.get(hash)?.state === 'intent' ? null : undefined),
      () => ({ t: 'submit', p: a, op, inv }),
      () => { send = this.#newest('send', a, call => call.hash === hash)?.id; return send === undefined ? undefined : null; },
      () => ({ t: 'reconcile', p: b, op, inv }),
      this.#arriveStep(() => send), this.#paymentStep(() => hash, 'succeed'), ...this.#deliverSteps('send', call => call.id === send),
      ...this.#deliverSteps('track', call => call.hash === hash && call.proc === b, 1),
    ] };
  }

  /**
   * An order's invoice A is created, its create call gives up (in transit), the clock passes the creation window
   * and a reconciliation records it not created; a replacement B is created, and A's request reaches LND after
   * all. Then: both are paid (one of them is a second payment); or A is paid first and fulfils the order while
   * B (a hold invoice, accepted) is superseded, its cancel failing or cut off by an abort, and B is settled
   * (before or after the fulfillment); or A is seen canceled and then paid (SETTLED outranks it), or seen
   * canceled while an earlier lookup still reports it OPEN.
   */
  #lateInvoicePlan(rng: Rng, order: number): { name: string; steps: PlanStep[] } {
    const label = `${ORDERS[order] as string}#`;
    const a = rng.pick(PROCS);
    const b: Proc = a === 'p0' ? 'p1' : 'p0';
    const variant = rng.pick(['second-payment', 'superseded', 'canceled-then-settled', 'canceled-then-open'] as const);
    let first: number | undefined;
    let late: string | undefined;
    let other: string | undefined;
    const answerAll = (proc: Proc, times: number, match: (call: Call) => boolean = () => true): PlanStep[] =>
      Array.from({ length: times }, () => this.#answerStep(proc, 'lookup', 'ok', match));
    const steps: PlanStep[] = [
      () => ({ t: 'create', p: a, order, hold: false }),
      () => {
        const call = this.#newest('create', a, item => item.label.startsWith(label));
        if (call === undefined || !call.open) return undefined;
        first = call.id;
        late = call.hash;
        return { t: 'answer', kind: 'create', pick: pickAt(this.calls('create'), call), mode: 'in-transit' };
      },
      ...answerAll(a, 2, call => call.hash === late),
      () => ({ t: 'age' }),
      () => ({ t: 'rreconcile', p: b, order: null, cli: false }),
      ...answerAll(b, 4),
      () => (late !== undefined && this.oracle.receiverSnap().invoices.get(late)?.state === 'not-created' ? null : undefined),
      () => ({ t: 'create', p: a, order, hold: variant === 'superseded' }),
      () => {
        const call = this.#newest('create', a, item => item.label.startsWith(label));
        if (call === undefined || !call.open || call.id === first) return undefined;
        other = call.hash;
        return { t: 'answer', kind: 'create', pick: pickAt(this.calls('create'), call), mode: 'ok' };
      },
      () => {
        const list = this.creatable();
        const call = list.find(item => item.id === first);
        return call === undefined ? undefined : { t: 'create.arrive', pick: pickAt(list, call) };
      },
    ];
    const misreport: PlanStep = () => {
      const list = this.invoicesIn(['OPEN', 'ACCEPTED']);
      return late === undefined || !list.includes(late) ? undefined : { t: 'invoice', what: 'misreport', pick: pickAt(list, late) };
    };
    if (variant === 'second-payment') {
      steps.push(this.#payStep(() => other), this.#payStep(() => late), () => ({ t: 'rreconcile', p: b, order: null, cli: false }),
        ...answerAll(b, 4), this.#answerStep(b, 'cancel', 'ok'), ...answerAll(b, 2));
    } else if (variant === 'superseded') {
      const early = rng.chance(0.5);
      const cut = rng.pick(['definite', 'connect', 'in-transit', 'ambiguous-pending', 'abort-at-lookup', 'abort-at-cancel'] as const);
      let handled = false;
      const advance: PlanStep = (): HarnessEvent | null => {
        if (handled) return null;
        const cancels = this.calls('cancel');
        const cancel = cancels.find(item => item.proc === b && item.hash === other);
        const lookups = this.calls('lookup');
        const lookup = lookups.find(item => item.proc === b);
        if (cancel !== undefined) {
          handled = true;
          return cut === 'abort-at-cancel' || cut === 'abort-at-lookup' ? { t: 'abort', p: b } : { t: 'answer', kind: 'cancel', pick: pickAt(cancels, cancel), mode: cut };
        }
        if (lookup !== undefined && lookup.hash === other && cut === 'abort-at-lookup'
          && this.oracle.receiverSnap().fulfillments.some(item => item.hash === late)) {
          handled = true;
          return { t: 'abort', p: b };
        }
        return lookup === undefined ? null : { t: 'answer', kind: 'lookup', pick: pickAt(lookups, lookup), mode: 'ok' };
      };
      steps.push(this.#payStep(() => other));
      if (early) steps.push(() => ({ t: 'settle', p: a, order }));
      steps.push(this.#payStep(() => late), () => ({ t: 'rreconcile', p: b, order: null, cli: false }), advance, advance, advance, advance, advance, advance);
      if (!early) steps.push(() => ({ t: 'settle', p: a, order }));
      steps.push(...answerAll(a, 2, call => call.hash === other), this.#answerStep(a, 'settle', 'ok'), ...answerAll(a, 1, call => call.hash === other));
    } else if (variant === 'canceled-then-settled') {
      steps.push(misreport, () => ({ t: 'rreconcile', p: b, order: null, cli: false }), ...answerAll(b, 4),
        () => (late !== undefined && this.oracle.receiverSnap().invoices.get(late)?.late === 'CANCELED' ? null : undefined),
        () => (this.#listening(a) ? null : { t: 'listen', p: a }), ...answerAll(a, 3), this.#payStep(() => late),
        ...this.#deliverSteps('sub', call => call.proc === a, 4));
    } else {
      steps.push(() => ({ t: 'rreconcile', p: a, order, cli: false }),
        ...Array.from({ length: 3 }, (): PlanStep => () => {
          const lookups = this.calls('lookup');
          if (lookups.some(item => item.proc === a && item.hash === late)) return null;
          const lookup = lookups.find(item => item.proc === a);
          return lookup === undefined ? null : { t: 'answer', kind: 'lookup', pick: pickAt(lookups, lookup), mode: 'ok' };
        }),
        () => (this.calls('lookup').some(item => item.proc === a && item.hash === late) ? null : undefined),
        misreport, () => ({ t: 'rreconcile', p: b, order: null, cli: false }), ...answerAll(b, 4),
        () => (late !== undefined && this.oracle.receiverSnap().invoices.get(late)?.late === 'CANCELED' ? null : undefined),
        this.#answerStep(a, 'lookup', 'stale', call => call.hash === late));
    }
    return { name: `receiver ${variant}`, steps };
  }

  /**
   * A hold invoice is paid (ACCEPTED) and looked up by one process; before that answer arrives LND misreports it
   * canceled to the other process's lookup, which records it canceled; then the first answer, ACCEPTED for the full
   * amount, is delivered late. Canceled is final for it.
   */
  #canceledAcceptedPlan(rng: Rng, order: number): { name: string; steps: PlanStep[] } {
    const label = `${ORDERS[order] as string}#`;
    const a = rng.pick(PROCS);
    const b: Proc = a === 'p0' ? 'p1' : 'p0';
    let hash: string | undefined;
    return { name: 'receiver canceled-then-accepted', steps: [
      () => ({ t: 'create', p: a, order, hold: true }),
      () => {
        const call = this.#newest('create', a, item => item.label.startsWith(label));
        if (call === undefined || !call.open) return undefined;
        hash = call.hash;
        return { t: 'answer', kind: 'create', pick: pickAt(this.calls('create'), call), mode: 'ok' };
      },
      this.#payStep(() => hash),
      () => ({ t: 'rreconcile', p: a, order, cli: false }),
      () => (this.calls('lookup').some(item => item.proc === a && item.hash === hash) ? null : undefined),
      () => {
        const list = this.invoicesIn(['OPEN', 'ACCEPTED']);
        return hash === undefined || !list.includes(hash) ? undefined : { t: 'invoice', what: 'misreport', pick: pickAt(list, hash) };
      },
      () => ({ t: 'rreconcile', p: b, order, cli: false }),
      this.#answerStep(b, 'lookup', 'ok', call => call.hash === hash),
      () => (hash !== undefined && this.oracle.receiverSnap().invoices.get(hash)?.state === 'canceled' ? null : undefined),
      this.#answerStep(a, 'lookup', 'stale', call => call.hash === hash),
    ] };
  }

  // ------------------------------------------------------------------------------------------
  // The generator: one applicable event, weighted, drawn from the current state.

  generate(rng: Rng): HarnessEvent {
    const planned = this.#planned(rng);
    if (planned !== undefined) return planned;
    const p = rng.pick(PROCS);
    const options: [number, () => HarnessEvent][] = [];
    const at = <T>(items: T[]): { item: T; pick: number } => {
      const index = rng.int(0, items.length - 1);
      return { item: items[index] as T, pick: Number(((index + 0.5) / items.length).toFixed(4)) };
    };
    const snap = this.oracle.payerSnap();
    const invoices = this.oracle.receiverSnap();
    const recorded = [...snap.payments].map(([hash, row]) => ({ hash, row, label: this.lnd.labelOf(hash) }));
    const used = (op: number): number => recorded.filter(item => item.row.op === `op${op}`).length;
    // Payer.
    options.push([3, () => {
      const op = rng.int(0, this.ops.length - 1);
      return { t: 'intent', p, op, inv: rng.chance(0.8) ? Math.min(used(op), INVOICES_PER_OPERATION - 1) : rng.int(0, INVOICES_PER_OPERATION - 1) };
    }]);
    const intents = recorded.filter(item => item.row.state === 'intent');
    if (intents.length > 0) options.push([5, () => ({ t: 'submit', p, ...parseLabel(at(intents).item.label) })]);
    else if (recorded.length > 0) options.push([0.5, () => ({ t: 'submit', p, ...parseLabel(at(recorded).item.label) })]);
    const unresolved = recorded.filter(item => ['submitting', 'in_flight', 'uncertain'].includes(item.row.state));
    if (unresolved.length > 0) options.push([2.5, () => ({ t: 'reconcile', p, ...parseLabel(at(unresolved).item.label) })]);
    const failed = recorded.filter(item => item.row.state === 'failed');
    if (failed.length > 0) options.push([2, () => ({ t: 'retry', p, op: parseLabel(at(failed).item.label).op })]);
    // Toward success after a recorded failure, withdrawn and double payments: a replacement for an operation whose payment
    // failed while it is not completed, a NotFound revert while a request is still on its way, and that request arriving.
    const replaceable = failed.filter(item => snap.operations.get(item.row.op) !== 'completed' && used(parseLabel(item.label).op) < INVOICES_PER_OPERATION);
    if (replaceable.length > 0) {
      options.push([3, () => { const op = parseLabel(at(replaceable).item.label).op; return { t: 'intent', p, op, inv: Math.min(used(op), INVOICES_PER_OPERATION - 1) }; }]);
    }
    const arriving = this.arrivable();
    if (arriving.length > 0) options.push([4, () => ({ t: 'send.arrive', pick: at(arriving).pick })]);
    const late = arriving.filter(call => this.lnd.payments.get(call.hash)?.status === 'FAILED' || ['failed', 'intent'].includes(snap.payments.get(call.hash)?.state ?? ''));
    if (late.length > 0) options.push([4, () => ({ t: 'send.arrive', pick: pickAt(arriving, at(late).item) })]);
    const waiting = unresolved.filter(item => arriving.some(call => call.hash === item.hash));
    if (waiting.length > 0) options.push([2, () => ({ t: 'reconcile', p, ...parseLabel(at(waiting).item.label) })]);
    const sendQueued = this.queued('send');
    if (sendQueued.length > 0) options.push([6, () => ({ t: 'send.deliver', pick: at(sendQueued).pick })]);
    const sends = this.calls('send');
    if (sends.length > 0) {
      options.push([2, () => ({ t: 'send.end', pick: at(sends).pick,
        mode: weighted(rng, [['transport', 2], ['ambiguous-504', 1.5], ['ambiguous-502', 0.7], ['definite', 1], ['connect', 1], ['eof', 1]]) })]);
    }
    const trackQueued = this.queued('track');
    if (trackQueued.length > 0) options.push([5, () => ({ t: 'track.deliver', pick: at(trackQueued).pick })]);
    const tracks = this.calls('track');
    if (tracks.length > 0) options.push([0.8, () => ({ t: 'track.end', pick: at(tracks).pick, mode: rng.chance(0.6) ? 'transport' : 'eof' })]);
    const inFlight = this.inFlightPayments();
    const payment = (what: string): HarnessEvent => what === 'succeed'
      ? { t: 'lnd.payment', pick: at(inFlight).pick, what, amount: weighted<AmountVariant>(rng, [['exact', 8], ['over', 1], ['under', 1]]) }
      : { t: 'lnd.payment', pick: at(inFlight).pick, what };
    if (inFlight.length > 0) {
      options.push([5, () => payment(weighted(rng, [['attempt', 1.2], ['attempt-fail', 0.5], ['fail', 1.5], ['succeed', 2]]))]);
    }
    const revived = inFlight.filter(hash => snap.payments.get(hash)?.state === 'failed' || snap.payments.get(hash)?.state === 'intent');
    if (revived.length > 0) options.push([4, () => ({ t: 'lnd.payment', pick: pickAt(inFlight, at(revived).item), what: 'succeed', amount: 'exact' })]);
    // Receiver.
    const superseded = (hash: string): boolean => {
      const row = invoices.invoices.get(hash);
      return row !== undefined && ['creating', 'open', 'accepted'].includes(row.state)
        && invoices.fulfillments.some(item => item.order === row.order && item.hash !== hash);
    };
    const notCreated = (hash: string): boolean => invoices.invoices.get(hash)?.state === 'not-created';
    options.push([2.5, () => ({ t: 'create', p, order: rng.int(0, ORDERS.length - 1), hold: rng.chance(0.5) })]);
    for (const kind of ['create', 'lookup', 'settle', 'cancel'] as const) {
      const open = this.calls(kind);
      if (open.length === 0) continue;
      const modes: [string, number][] = kind === 'lookup' ? [['ok', 6], ['stale', 1], ['in-transit', 1], ['ambiguous-pending', 1]]
        : [['ok', 6], ['lost-answer', 1], ['in-transit', 1], ['ambiguous-done', 0.7], ['ambiguous-pending', 1], ['definite', 0.5], ['connect', 0.4]];
      options.push([kind === 'lookup' ? 6 : 3, () => ({ t: 'answer', kind, pick: at(open).pick, mode: weighted(rng, modes) })]);
    }
    // CancelInvoice failing for a superseded invoice, so its order keeps two live invoices for a while.
    const cancels = this.calls('cancel');
    const supersededCancels = cancels.filter(call => superseded(call.hash) || notCreated(call.hash));
    if (supersededCancels.length > 0) {
      options.push([2, () => ({ t: 'answer', kind: 'cancel', pick: pickAt(cancels, at(supersededCancels).item),
        mode: weighted(rng, [['definite', 1], ['connect', 1], ['in-transit', 1], ['ambiguous-pending', 1]]) })]);
    }
    // A lookup's earlier view delivered late: an OPEN or ACCEPTED answer for an invoice LND has canceled or settled since.
    const lookups = this.calls('lookup');
    const outdated = lookups.filter(call => call.request.seen !== undefined && call.request.seen !== null
      && (call.request.seen.state !== this.lnd.invoices.get(call.hash)?.state || invoices.invoices.get(call.hash)?.state === 'canceled'
        || invoices.invoices.get(call.hash)?.late === 'CANCELED'));
    if (outdated.length > 0) options.push([2, () => ({ t: 'answer', kind: 'lookup', pick: pickAt(lookups, at(outdated).item), mode: 'stale' })]);
    const transit = this.creatable();
    if (transit.length > 0) options.push([1.5, () => ({ t: 'create.arrive', pick: at(transit).pick })]);
    const lateCreates = transit.filter(call => notCreated(call.hash));
    if (lateCreates.length > 0) options.push([3, () => ({ t: 'create.arrive', pick: pickAt(transit, at(lateCreates).item) })]);
    const openInvoices = this.invoicesIn(['OPEN']);
    const amount = (): AmountVariant => weighted<AmountVariant>(rng, [['exact', 8], ['over', 1], ['under', 1]]);
    if (openInvoices.length > 0) {
      options.push([3, () => ({ t: 'invoice', what: 'pay', pick: at(openInvoices).pick, amount: amount() })]);
      options.push([0.4, () => ({ t: 'invoice', what: 'expire', pick: at(openInvoices).pick })]);
    }
    // A second payment: an invoice of an order fulfilled by another, or one recorded not created, paid in LND.
    const secondPayable = openInvoices.filter(hash => superseded(hash) || notCreated(hash));
    if (secondPayable.length > 0) options.push([3, () => ({ t: 'invoice', what: 'pay', pick: pickAt(openInvoices, at(secondPayable).item), amount: 'exact' })]);
    const accepted = this.invoicesIn(['ACCEPTED']);
    if (accepted.length > 0) options.push([0.6, () => ({ t: 'invoice', what: 'htlc-timeout', pick: at(accepted).pick })]);
    const live = this.invoicesIn(['OPEN', 'ACCEPTED']);
    if (live.length > 0) options.push([0.25, () => ({ t: 'invoice', what: 'misreport', pick: at(live).pick })]);
    const liveLate = live.filter(hash => notCreated(hash) && this.lnd.invoices.get(hash)?.misreported !== true);
    if (liveLate.length > 0) options.push([1.5, () => ({ t: 'invoice', what: 'misreport', pick: pickAt(live, at(liveLate).item) })]);
    const settledInLnd = this.invoicesIn(['SETTLED']);
    if (settledInLnd.length > 0) options.push([0.5, () => ({ t: 'invoice', what: 'resettle', pick: at(settledInLnd).pick })]);
    options.push([0.15, () => ({ t: 'invoice', what: 'foreign' })]);
    options.push([accepted.length > 0 ? 3 : 0.8, () => ({ t: 'settle', p, order: rng.int(0, ORDERS.length - 1) })]);
    options.push([0.6, () => ({ t: 'cancel', p, order: rng.int(0, ORDERS.length - 1) })]);
    options.push([1.5, () => ({ t: 'rreconcile', p, order: rng.chance(0.4) ? rng.int(0, ORDERS.length - 1) : null, cli: rng.chance(0.3) })]);
    if (!this.#listening(p)) options.push([0.6, () => ({ t: 'listen', p })]);
    const subQueued = this.queued('sub');
    if (subQueued.length > 0) options.push([4, () => ({ t: 'sub.deliver', pick: at(subQueued).pick })]);
    options.push([0.3, () => ({ t: 'cursor-set', p, pick: Number(rng.next().toFixed(4)), add: Number(rng.next().toFixed(4)) })]);
    options.push([0.6, () => ({ t: 'age' })]);
    // The outbox worker, killed now and then at a point of a row.
    options.push([1.2, () => ({ t: 'outbox', p, side: rng.chance(0.5) ? 'payer' : 'receiver',
      crash: weighted(rng, [['none', 5], ['after-claim', 1], ['during-write', 1], ['after-effect', 1], ['after-ack', 0.5]]) })]);
    // Both.
    options.push([0.5, () => ({ t: 'kill', p })]);
    options.push([0.5, () => ({ t: 'abort', p })]);
    // An abort that lands in the middle of a supersede: the process waits on a lookup or CancelInvoice for a superseded invoice.
    const midSupersede = [...lookups, ...cancels].filter(call => superseded(call.hash) && call.workflow !== undefined && !call.workflow.done);
    if (midSupersede.length > 0) options.push([2, () => ({ t: 'abort', p: at(midSupersede).item.proc })]);
    return weighted(rng, options.map(([weight, make]): [() => HarnessEvent, number] => [make, weight]))();
  }
}

type PlanStep = () => HarnessEvent | null | undefined;
type PaymentRowView = ReturnType<Oracle['payerSnap']>['payments'] extends Map<string, infer Row> ? Row : never;
/** A plan whose precondition holds starts with this chance per generated event while none runs, at most MAX_PLANS per case. */
const PAYER_PLAN_CHANCE = 0.08;
const RECEIVER_PLAN_CHANCE = 0.01;
const MAX_PLANS = 2;
const PENDING_STATES = new Set(['intent', 'submitting', 'in_flight', 'uncertain']);

/** The pick that selects `item` from `items` (an event picks its target by position). */
function pickAt<T>(items: T[], item: T): number {
  return Number(((items.indexOf(item) + 0.5) / items.length).toFixed(4));
}

function parseLabel(label: string): { op: number; inv: number } {
  const match = /^op(\d+)\/i(\d+)$/.exec(label);
  return { op: Number(match?.[1]), inv: Number(match?.[2]) };
}

/** Closes a process's stores; one a killed worker already closed is left as it is. */
function closeQuietly(state: ProcState): void {
  for (const store of [state.payer, state.receiver]) {
    try { store?.close(); } catch { /* already closed */ }
  }
}

/** One of the [value, weight] rows (as weighted in scripts/payment-fuzz.mjs). */
function weighted<T>(rng: Rng, rows: [T, number][]): T {
  let total = 0;
  for (const [, weight] of rows) total += weight;
  let point = rng.next() * total;
  for (const [value, weight] of rows) if ((point -= weight) < 0) return value;
  return (rows[rows.length - 1] as [T, number])[0];
}

// ---------------------------------------------------------------------------------------------
// Running cases, shrinking, replay files.

export type StepViolation = Violation & { step: number; event: HarnessEvent | null };

export interface CaseResult {
  config: CaseConfig;
  events: HarnessEvent[];
  /** The violation the case stopped at (or, run to the end, the first one). */
  violation: StepViolation | undefined;
  /** The first violation of each predicate, in order (one predicate's failure can precede another's in the same call). */
  violations: StepViolation[];
  counts: Record<string, number>;
  ms: number;
}

export interface CaseOptions {
  lab: Lab;
  config: CaseConfig;
  /** Replay these events; without them, `steps` events are generated from `rng`. */
  events?: HarnessEvent[];
  rng?: Rng;
  steps?: number;
  scratch: string;
  /** 'first' (default): stop at the first violation; a predicate: stop when it is violated; 'never': run to the end. */
  stop?: 'first' | 'never' | PredicateName;
}

export async function runCase(options: CaseOptions): Promise<CaseResult> {
  const began = performance.now();
  let run: Run | undefined;
  const events: HarnessEvent[] = [];
  const total = options.events?.length ?? options.steps ?? 60;
  const stop = options.stop ?? 'first';
  const violations: StepViolation[] = [];
  let seen = 0;
  const collect = (oracle: Oracle, step: number, event: HarnessEvent | null): boolean => {
    for (const item of oracle.violations.slice(seen)) {
      if (!violations.some(known => known.predicate === item.predicate)) violations.push({ ...item, step, event });
    }
    seen = oracle.violations.length;
    return stop === 'first' ? violations.length > 0 : violations.some(item => item.predicate === stop);
  };
  let stopped = false;
  try {
    run = new Run(options.lab, options.config, options.scratch);
    for (let step = 0; step < total && !stopped; step += 1) {
      const event = options.events?.[step] ?? run.generate(options.rng as Rng);
      events.push(event);
      await run.step(event);
      stopped = collect(run.oracle, step, event);
    }
    if (!stopped) {
      await run.quiesce();
      collect(run.oracle, events.length, null);
    }
  } finally {
    await run?.dispose();
  }
  const violation = stop in PREDICATES ? violations.find(item => item.predicate === stop) ?? violations[0] : violations[0];
  return { config: options.config, events, violation, violations, counts: run.counts, ms: performance.now() - began };
}

/**
 * Delta debugging (ddmin over complements) of a failing event list: the smallest list found that still
 * violates the same predicate. Every candidate is run from scratch; `budget` bounds the runs.
 */
export async function shrink(options: Omit<CaseOptions, 'events' | 'rng' | 'steps'>, events: HarnessEvent[], predicate: PredicateName,
  budget = 300): Promise<{ events: HarnessEvent[]; result: CaseResult; runs: number }> {
  let current = events;
  let best = await runCase({ ...options, events: current, stop: predicate });
  let runs = 1;
  const fails = (result: CaseResult): boolean => result.violations.some(item => item.predicate === predicate);
  if (!fails(best)) return { events, result: best, runs };
  // Everything after the violating step is irrelevant.
  current = best.events;
  let granularity = 2;
  while (current.length >= 2 && runs < budget) {
    const chunk = Math.ceil(current.length / granularity);
    let reduced = false;
    for (let start = 0; start < current.length && runs < budget; start += chunk) {
      const candidate = [...current.slice(0, start), ...current.slice(start + chunk)];
      const result = await runCase({ ...options, events: candidate, stop: predicate });
      runs += 1;
      if (fails(result)) {
        current = result.events;
        best = result;
        granularity = Math.max(granularity - 1, 2);
        reduced = true;
        break;
      }
    }
    if (!reduced) {
      if (granularity >= current.length) break;
      granularity = Math.min(current.length, granularity * 2);
    }
  }
  return { events: current, result: best, runs };
}

export interface Replay {
  schema: 1;
  kind: 'macwarden-payment-lab-harness-replay';
  predicate: PredicateName;
  rule: string;
  message: string;
  seed: number | null;
  case: number | null;
  config: CaseConfig;
  /** The step at which the predicate was violated when the file was recorded; -1 for a hand-written scenario that records none. */
  failingStep: number;
  originalSteps: number;
  events: HarnessEvent[];
  states: Record<string, unknown>;
  note?: string;
  /**
   * The mutant (a file in test/harness/mutants/) this replay was recorded on, for a predicate the 1.2.0 lab did not
   * break or could not be checked on: the replay violates its predicate on that mutant and nothing on the current lab.
   */
  mutant?: string;
}

/** A replay file that is not one: the file, the step (when an event is at fault) and what is wrong. Exit code 2 in run.mjs. */
export class ReplayError extends Error {
  readonly file: string;
  readonly step: number | undefined;
  constructor(file: string, step: number | undefined, problem: string) {
    super(`${file}: ${step === undefined ? '' : `step ${step}: `}${problem}`);
    this.file = file;
    this.step = step;
  }
}

type FieldCheck = (value: unknown) => string | undefined;
const integer = (low: number, high: number): FieldCheck => value => (Number.isInteger(value) && (value as number) >= low && (value as number) <= high ? undefined
  : `an integer from ${low} to ${high}`);
const oneOf = (...values: readonly unknown[]): FieldCheck => value => (values.includes(value) ? undefined : `one of ${values.map(item => JSON.stringify(item)).join(', ')}`);
const PICK: FieldCheck = value => (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value < 1 ? undefined : 'a number from 0 to below 1');
const BOOLEAN: FieldCheck = value => (typeof value === 'boolean' ? undefined : 'true or false');
const PROC = oneOf(...PROCS);
const OP = integer(0, 1);
const INV = integer(0, INVOICES_PER_OPERATION - 1);
const ORDER = integer(0, ORDERS.length - 1);
const AMOUNT = oneOf('exact', 'over', 'under');
const UNARY_MODES = ['ok', 'lost-answer', 'in-transit', 'ambiguous-done', 'ambiguous-pending', 'definite', 'connect'] as const;
/** Every event kind with its fields: [required, optional]. A field not listed is refused. */
const EVENTS: Record<string, [Record<string, FieldCheck>, Record<string, FieldCheck>]> = {
  intent: [{ op: OP, inv: INV }, { p: PROC }],
  submit: [{ op: OP, inv: INV }, { p: PROC }],
  retry: [{ op: OP }, { p: PROC }],
  reconcile: [{ op: OP, inv: INV }, { p: PROC }],
  'send.arrive': [{}, { pick: PICK }],
  'send.deliver': [{}, { pick: PICK }],
  'send.end': [{ mode: oneOf('transport', 'ambiguous-504', 'ambiguous-502', 'definite', 'connect', 'eof') }, { pick: PICK }],
  'track.deliver': [{}, { pick: PICK }],
  'track.end': [{ mode: oneOf('transport', 'eof') }, { pick: PICK }],
  'lnd.payment': [{ what: oneOf('attempt', 'attempt-fail', 'fail', 'succeed') }, { pick: PICK, amount: AMOUNT }],
  create: [{ order: ORDER, hold: BOOLEAN }, { p: PROC }],
  answer: [{ kind: oneOf('create', 'lookup', 'settle', 'cancel'), mode: oneOf(...UNARY_MODES, 'stale') }, { pick: PICK }],
  'create.arrive': [{}, { pick: PICK }],
  invoice: [{ what: oneOf('pay', 'htlc-timeout', 'expire', 'misreport', 'resettle', 'foreign') }, { pick: PICK, amount: AMOUNT }],
  settle: [{ order: ORDER }, { p: PROC }],
  cancel: [{ order: ORDER }, { p: PROC }],
  rreconcile: [{}, { p: PROC, order: value => (value === null ? undefined : ORDER(value) === undefined ? undefined : `null or ${ORDER(value) ?? ''}`), cli: BOOLEAN }],
  listen: [{}, { p: PROC }],
  'sub.deliver': [{}, { pick: PICK }],
  'cursor-set': [{}, { p: PROC, pick: PICK, add: PICK }],
  age: [{}, {}],
  kill: [{}, { p: PROC }],
  abort: [{}, { p: PROC }],
  outbox: [{ side: oneOf('payer', 'receiver'), crash: oneOf(...OUTBOX_CRASH_POINTS) }, { p: PROC }],
};
const MAX_EVENTS = 10_000;

/** Checks a replay's configuration and every event before anything runs; throws ReplayError naming the file and the step. */
export function validateReplay(file: string, value: unknown): Replay {
  const fail = (problem: string, step?: number): never => { throw new ReplayError(file, step, problem); };
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('not a JSON object');
  const replay = value as Replay;
  if (replay.kind !== 'macwarden-payment-lab-harness-replay' || replay.schema !== 1) fail('not a payment-lab harness replay (schema 1)');
  if (typeof replay.predicate !== 'string' || !(replay.predicate in PREDICATES)) fail(`predicate ${JSON.stringify(replay.predicate)} is not one of the oracle's`);
  const config = replay.config as unknown as Record<string, unknown> | null;
  if (config === null || typeof config !== 'object' || Array.isArray(config)) fail('config is not an object');
  const configProblem = Object.keys(config as object).find(key => !['scale', 'budget', 'limit'].includes(key)) !== undefined ? 'config has a field other than scale, budget and limit'
    : !['small', 'huge'].includes(String(config?.scale)) || typeof config?.scale !== 'string' ? 'config.scale is neither "small" nor "huge"'
      : typeof config.budget !== 'boolean' ? 'config.budget is neither true nor false'
        : typeof config.limit !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(config.limit) || BigInt(config.limit) > MAX_INT64 ? 'config.limit is not a decimal from 0 to 2^63 - 1'
          : undefined;
  if (configProblem !== undefined) fail(configProblem);
  if (!Array.isArray(replay.events)) fail('events is not an array');
  if (replay.events.length > MAX_EVENTS) fail(`${replay.events.length} events, more than ${MAX_EVENTS}`);
  if (!Number.isInteger(replay.failingStep) || replay.failingStep < -1 || replay.failingStep > replay.events.length) {
    fail(`failingStep ${JSON.stringify(replay.failingStep)} is not -1 or a step from 0 to ${replay.events.length}`);
  }
  if (replay.mutant !== undefined && (typeof replay.mutant !== 'string' || !/^[a-z0-9-]+\.cjs$/.test(replay.mutant))) fail('mutant is not a file name in test/harness/mutants/');
  replay.events.forEach((event: unknown, step: number) => {
    if (event === null || typeof event !== 'object' || Array.isArray(event)) fail('the event is not an object', step);
    const fields = event as Record<string, unknown>;
    const spec = typeof fields.t === 'string' ? EVENTS[fields.t] : undefined;
    if (spec === undefined) fail(`unknown event kind ${JSON.stringify(fields.t)}`, step);
    const [required, optional] = spec as [Record<string, FieldCheck>, Record<string, FieldCheck>];
    for (const [name, check] of Object.entries(required)) {
      if (!(name in fields)) fail(`${String(fields.t)} needs ${name}`, step);
      const problem = check(fields[name]);
      if (problem !== undefined) fail(`${String(fields.t)}.${name} is ${JSON.stringify(fields[name])}, not ${problem}`, step);
    }
    for (const [name, item] of Object.entries(fields)) {
      if (name === 't' || name in required) continue;
      const check = optional[name];
      if (check === undefined) fail(`${String(fields.t)} has no field ${name}`, step);
      const problem = (check as FieldCheck)(item);
      if (problem !== undefined) fail(`${String(fields.t)}.${name} is ${JSON.stringify(item)}, not ${problem}`, step);
    }
    if (fields.t === 'answer' && fields.mode === 'stale' && fields.kind !== 'lookup') fail('answer mode "stale" is for a lookup only', step);
    if (fields.t === 'answer' && fields.kind === 'lookup' && !['ok', 'stale', 'in-transit', 'ambiguous-pending'].includes(String(fields.mode))) {
      fail(`answer mode ${JSON.stringify(fields.mode)} does not apply to a lookup`, step);
    }
    if (fields.amount !== undefined && !(fields.t === 'lnd.payment' ? fields.what === 'succeed' : fields.what === 'pay')) {
      fail(`${String(fields.t)}.amount applies only to ${fields.t === 'lnd.payment' ? 'what "succeed"' : 'what "pay"'}`, step);
    }
  });
  return replay;
}

export function replayOf(result: CaseResult, predicate: PredicateName, origin: { seed: number | null; case: number | null; originalSteps: number }): Replay {
  const violation = result.violations.find(item => item.predicate === predicate);
  if (violation === undefined) throw new Error('no violation to record');
  return { schema: 1, kind: 'macwarden-payment-lab-harness-replay', predicate: violation.predicate, rule: PREDICATES[violation.predicate],
    message: violation.message, seed: origin.seed, case: origin.case, config: result.config, failingStep: violation.step,
    originalSteps: origin.originalSteps, events: result.events, states: violation.states };
}

export function readReplay(path: string): Replay {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new ReplayError(path, undefined, `not readable JSON: ${String((error as Error).message)}`);
  }
  return validateReplay(path, value);
}

export function replayFiles(path: string): string[] {
  return statSync(path).isDirectory() ? readdirSync(path).filter(name => name.endsWith('.json')).sort().map(name => join(path, name)) : [path];
}

/** A replay run to its end: every predicate it violates (none, on a correct lab). */
export interface ReplayOutcome {
  file: string;
  predicate: PredicateName;
  /** Whether the file records a violation (a shrunk failing case); a hand-written scenario records none (failingStep -1). */
  recorded: boolean;
  violations: StepViolation[];
  counts: Record<string, number>;
  ms: number;
  /** The mutant the replay was recorded on, if it names one. */
  mutant?: string;
  /** Why the file was refused (ReplayError): nothing of it ran. */
  invalid?: string;
}

/** Runs replay files (a file or a directory of them) against a lab source. */
export async function replay(options: { path: string; labSrc?: string; scratch?: string }): Promise<ReplayOutcome[]> {
  const lab = await loadLab(options.labSrc ?? DEFAULT_LAB_SRC);
  const scratch = options.scratch ?? mkdtempSync(join(tmpdir(), 'macwarden-lab-harness-'));
  const outcomes: ReplayOutcome[] = [];
  try {
    for (const file of replayFiles(options.path)) {
      let recorded: Replay;
      try {
        recorded = readReplay(file);
      } catch (error) {
        // One bad file is reported and the others still run.
        if (!(error instanceof ReplayError)) throw error;
        outcomes.push({ file, predicate: 'no-internal-error', recorded: false, violations: [], counts: {}, ms: 0, invalid: error.message });
        continue;
      }
      const result = await runCase({ lab, config: recorded.config, events: recorded.events, scratch, stop: 'never' });
      outcomes.push({ file, predicate: recorded.predicate, recorded: recorded.failingStep >= 0, violations: result.violations, counts: result.counts, ms: result.ms,
        ...(recorded.mutant === undefined ? {} : { mutant: recorded.mutant }) });
    }
  } finally {
    if (options.scratch === undefined) {
      try { rmSync(scratch, { recursive: true, force: true }); } catch { /* a scratch directory Windows still holds is left in the temp directory */ }
    }
  }
  return outcomes;
}

export interface CampaignOptions {
  seed: number;
  cases: number;
  start?: number;
  steps?: number;
  labSrc?: string;
  /** Directory for replay files of violations (created when needed). */
  replayOut?: string;
  shrink?: boolean;
  shrinkBudget?: number;
  /** Run every case to its end and record each predicate it violates (default: stop a case at its first violation). */
  collect?: boolean;
  onProgress?(done: number, total: number): void;
}

export interface CampaignResult {
  seed: number;
  start: number;
  cases: number;
  stepsPerCase: number;
  events: number;
  seconds: number;
  labSrc: string;
  /** `message` is the case's; `replayMessage` the shrunk replay's (what the replay file reproduces). */
  violations: { case: number; predicate: PredicateName; message: string; step: number; replay?: string; shrunkSteps?: number; replayMessage?: string }[];
  /** How often each event ran (applied, or a no-op when its target was gone). */
  coverage: Record<string, number>;
  configs: Record<string, number>;
}

export async function campaign(options: CampaignOptions): Promise<CampaignResult> {
  const began = performance.now();
  const labSrc = resolve(options.labSrc ?? DEFAULT_LAB_SRC);
  const lab = await loadLab(labSrc);
  const start = options.start ?? 0;
  const steps = options.steps ?? 60;
  const scratch = mkdtempSync(join(tmpdir(), 'macwarden-lab-harness-'));
  const result: CampaignResult = { seed: options.seed, start, cases: options.cases, stepsPerCase: steps, events: 0, seconds: 0, labSrc,
    violations: [], coverage: {}, configs: {} };
  const shrunk = new Set<PredicateName>();
  try {
    for (let index = start; index < start + options.cases; index += 1) {
      const rng = xorshift(caseSeed(options.seed, index));
      const config = randomConfig(rng);
      const key = `${config.scale}${config.budget ? `, budget ${config.limit}` : ', no budget'}`;
      result.configs[key] = (result.configs[key] ?? 0) + 1;
      const outcome = await runCase({ lab, config, rng, steps, scratch, stop: options.collect === true ? 'never' : 'first' });
      result.events += outcome.events.length;
      for (const [name, count] of Object.entries(outcome.counts)) result.coverage[name] = (result.coverage[name] ?? 0) + count;
      for (const violation of outcome.violations) {
        const entry: CampaignResult['violations'][number] = { case: index, predicate: violation.predicate, message: violation.message, step: violation.step };
        if (options.replayOut !== undefined && !shrunk.has(violation.predicate)) {
          shrunk.add(violation.predicate);
          let recorded = outcome;
          if (options.shrink !== false) recorded = (await shrink({ lab, config, scratch }, outcome.events, violation.predicate, options.shrinkBudget)).result;
          mkdirSync(options.replayOut, { recursive: true });
          const file = join(options.replayOut, `${violation.predicate}-seed${options.seed}-case${index}.json`);
          writeFileSync(file, `${JSON.stringify(replayOf(recorded, violation.predicate, { seed: options.seed, case: index, originalSteps: outcome.events.length }), null, 2)}\n`);
          entry.replay = file;
          entry.shrunkSteps = recorded.events.length;
          entry.replayMessage = recorded.violations.find(item => item.predicate === violation.predicate)?.message ?? violation.message;
        }
        result.violations.push(entry);
      }
      options.onProgress?.(index - start + 1, options.cases);
    }
  } finally {
    try { rmSync(scratch, { recursive: true, force: true }); } catch { /* a scratch directory Windows still holds is left in the temp directory */ }
  }
  result.seconds = Number(((performance.now() - began) / 1000).toFixed(1));
  return result;
}

// ---------------------------------------------------------------------------------------------
// Mutants: scripted source mutations that prove a predicate the 1.2.0 lab did not break.

/** test/harness/mutants/<predicate>.cjs: the predicate it breaks, what it does, and its edits (file under src/, text, replacement). */
export interface Mutant { predicate: PredicateName; description: string; edits: [string, string, string][] }

export const MUTANTS = resolve(dirname(fileURLToPath(import.meta.url)), 'mutants');

export function readMutant(path: string): Mutant {
  const mutant = createRequire(import.meta.url)(resolve(path)) as Mutant;
  if (!(mutant.predicate in PREDICATES) || !Array.isArray(mutant.edits) || mutant.edits.length === 0) throw new Error(`${path} is not a harness mutant`);
  return mutant;
}

/**
 * Copies the lab source (default: the lab's src/) to `dest`/src, applies the mutant's edits (each must match
 * exactly once) and returns the mutated source directory, for --lab-src.
 */
export function buildMutant(path: string, dest: string, labSrc: string = DEFAULT_LAB_SRC): string {
  const mutant = readMutant(path);
  const src = join(dest, 'src');
  rmSync(src, { recursive: true, force: true });
  cpSync(labSrc, src, { recursive: true });
  writeFileSync(join(dest, 'package.json'), '{"type":"module"}\n');
  for (const [relative, find, replace] of mutant.edits) {
    const target = join(src, relative);
    const text = readFileSync(target, 'utf8').replace(/\r\n/g, '\n');
    const count = text.split(find).length - 1;
    if (count !== 1) throw new Error(`${path}: ${relative}: the edit matches ${count} times, not once: ${JSON.stringify(find.slice(0, 80))}`);
    writeFileSync(target, text.replace(find, () => replace));
  }
  return src;
}

export { PREDICATES };
export type { PredicateName };
