import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { DEFAULT_LAB_SRC, loadLab, type Lab, type PayerDeps, type ReceiverDeps, type Store } from './lab.ts';
import { FakeLnd, sha256Hex, type Call, type Proc, type Workflow } from './lnd.ts';
import { MAX_INT64, Oracle, PREDICATES, type PredicateName, type StoreCall, type Violation } from './oracle.ts';

/**
 * Model-based harness for the payment lab's state machines (design brief 1.3.0, item 1).
 *
 * A case is a sequence of events: workflow starts on two processes (p0, p1) sharing one payer and one
 * receiver database file, LND's answers and stream messages in any order, LND's own progress (HTLC
 * attempts, a payment failing or succeeding, an invoice paid, a held HTLC timing out), requests that
 * reach LND late, clock steps past the invoice creation window, graceful aborts and process kills
 * (the store is closed and reopened from its file; nothing the killed process still had in flight is
 * written). The real stores and workflows run against the scripted LND in lnd.ts, and the oracle in
 * oracle.ts checks every README rule after every store call and every step.
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
  readonly lnd: FakeLnd;
  readonly oracle: Oracle;
  readonly dir: string;
  readonly procs: Record<Proc, ProcState>;
  readonly counts: Record<string, number> = {};
  readonly #als = new AsyncLocalStorage<Workflow>();
  readonly #storeErrors = new WeakSet<object>();
  #progress = 0;
  #workflowSeq = 0;
  #delivering: Call | undefined;
  #autoAnswer = false;
  #cliBusy = false;
  readonly #stdoutWrite = process.stdout.write;

  constructor(lab: Lab, config: CaseConfig, scratch: string) {
    this.lab = lab;
    this.config = config;
    this.ops = operations(config);
    this.dir = mkdtempSync(join(scratch, 'case-'));
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
    state.payer.close();
    state.receiver.close();
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
    this.oracle.afterStep();
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
        const call = pick(this.calls('send', item => !item.arrived && (item.open || item.inTransit)));
        return call !== undefined && this.lnd.arrive(call);
      }
      case 'send.deliver':
      case 'track.deliver':
      case 'sub.deliver': {
        const kind = event.t === 'send.deliver' ? 'send' : event.t === 'track.deliver' ? 'track' : 'sub';
        const call = pick(this.calls(kind, item => item.open && item.queue.length > 0));
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
        return hash !== undefined && this.lnd.paymentEvent(hash, event.what as 'attempt' | 'attempt-fail' | 'fail' | 'succeed');
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
        const call = pick(this.calls('create', item => item.inTransit && !item.arrived));
        return call !== undefined && this.lnd.arriveLate(call);
      }
      case 'invoice': {
        const what = event.what as 'pay' | 'htlc-timeout' | 'expire' | 'misreport';
        const hash = pick(this.invoicesIn(what === 'htlc-timeout' ? ['ACCEPTED'] : what === 'misreport' ? ['OPEN', 'ACCEPTED'] : ['OPEN']));
        return hash !== undefined && this.lnd.invoiceEvent(hash, what);
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
        this.#start(proc, 'rreconcile', order ?? 'all', signal => this.lab.reconcileInvoices(state.receiverDeps, order, signal),
          result => this.oracle.reconcileDone(targets, result as { resolved: number; open: number; unknown: number }, undefined));
        return true;
      }
      case 'listen':
        if (this.#listening(proc)) return false;
        this.#start(proc, 'listen', 'invoices', signal => this.lab.listen(state.receiverDeps, { reconcileIntervalMs: 2 ** 31 - 1, signal }));
        return true;
      case 'cursor-set': {
        const index = pick([0n, ...this.lnd.settleIndexes()]) ?? 0n;
        (state.receiverDeps.store.setCursor as (settle: bigint, add: bigint) => void)(index, 0n);
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
      default:
        throw new Error(`unknown event ${event.t}`);
    }
  }

  /** receiver reconcile through cli.ts's main, so its exit code is checked as well as its counts. */
  #startCliReconcile(proc: Proc, order: string | undefined, targets: Set<string>): void {
    const main = this.lab.cliMain;
    if (main === undefined) return;
    this.#cliBusy = true;
    this.#start(proc, 'rreconcile-cli', order ?? 'all', async () => {
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
      if (outcome !== undefined) this.oracle.reconcileDone(targets, outcome, exit);
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
      this.#start('p0', 'rreconcile', 'quiescence', signal => this.lab.reconcileInvoices(this.procs.p0.receiverDeps, undefined, signal),
        result => this.oracle.reconcileDone(targets, result as { resolved: number; open: number; unknown: number }, undefined));
      await this.drain();
      this.oracle.afterStep();
    }
    this.oracle.quiescent();
  }

  async dispose(): Promise<void> {
    this.#autoAnswer = false;
    await this.kill('p0', false);
    await this.kill('p1', false);
    process.stdout.write = this.#stdoutWrite;
    this.oracle.close();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try { rmSync(this.dir, { recursive: true, force: true }); return; } catch { await new Promise(done => setTimeout(done, 20)); }
    }
  }

  // ------------------------------------------------------------------------------------------
  // The generator: one applicable event, weighted, drawn from the current state.

  generate(rng: Rng): HarnessEvent {
    const p = rng.pick(PROCS);
    const options: [number, () => HarnessEvent][] = [];
    const at = <T>(items: T[]): { item: T; pick: number } => {
      const index = rng.int(0, items.length - 1);
      return { item: items[index] as T, pick: Number(((index + 0.5) / items.length).toFixed(4)) };
    };
    const snap = this.oracle.payerSnap();
    const recorded = [...snap.payments].map(([hash, row]) => ({ hash, row, label: this.lnd.labelOf(hash) }));
    const parse = (label: string): { op: number; inv: number } => {
      const match = /^op(\d+)\/i(\d+)$/.exec(label);
      return { op: Number(match?.[1]), inv: Number(match?.[2]) };
    };
    // Payer.
    options.push([3, () => {
      const op = rng.int(0, this.ops.length - 1);
      const used = recorded.filter(item => item.row.op === `op${op}`).length;
      return { t: 'intent', p, op, inv: rng.chance(0.8) ? Math.min(used, INVOICES_PER_OPERATION - 1) : rng.int(0, INVOICES_PER_OPERATION - 1) };
    }]);
    const intents = recorded.filter(item => item.row.state === 'intent');
    if (intents.length > 0) options.push([5, () => ({ t: 'submit', p, ...parse(at(intents).item.label) })]);
    else if (recorded.length > 0) options.push([0.5, () => ({ t: 'submit', p, ...parse(at(recorded).item.label) })]);
    const unresolved = recorded.filter(item => ['submitting', 'in_flight', 'uncertain'].includes(item.row.state));
    if (unresolved.length > 0) options.push([2.5, () => ({ t: 'reconcile', p, ...parse(at(unresolved).item.label) })]);
    const failed = recorded.filter(item => item.row.state === 'failed');
    if (failed.length > 0) options.push([2, () => ({ t: 'retry', p, op: parse(at(failed).item.label).op })]);
    const arriving = this.calls('send', item => !item.arrived && (item.open || item.inTransit));
    if (arriving.length > 0) options.push([4, () => ({ t: 'send.arrive', pick: at(arriving).pick })]);
    const sendQueued = this.calls('send', item => item.open && item.queue.length > 0);
    if (sendQueued.length > 0) options.push([6, () => ({ t: 'send.deliver', pick: at(sendQueued).pick })]);
    const sends = this.calls('send');
    if (sends.length > 0) {
      options.push([2, () => ({ t: 'send.end', pick: at(sends).pick,
        mode: weighted(rng, [['transport', 2], ['ambiguous-504', 1.5], ['ambiguous-502', 0.7], ['definite', 1], ['connect', 1], ['eof', 1]]) })]);
    }
    const trackQueued = this.calls('track', item => item.open && item.queue.length > 0);
    if (trackQueued.length > 0) options.push([5, () => ({ t: 'track.deliver', pick: at(trackQueued).pick })]);
    const tracks = this.calls('track');
    if (tracks.length > 0) options.push([0.8, () => ({ t: 'track.end', pick: at(tracks).pick, mode: rng.chance(0.6) ? 'transport' : 'eof' })]);
    const inFlight = this.inFlightPayments();
    if (inFlight.length > 0) {
      options.push([5, () => ({ t: 'lnd.payment', pick: at(inFlight).pick,
        what: weighted(rng, [['attempt', 1.2], ['attempt-fail', 0.5], ['fail', 1.5], ['succeed', 2]]) })]);
    }
    // Receiver.
    options.push([2.5, () => ({ t: 'create', p, order: rng.int(0, ORDERS.length - 1), hold: rng.chance(0.5) })]);
    for (const kind of ['create', 'lookup', 'settle', 'cancel'] as const) {
      const open = this.calls(kind);
      if (open.length === 0) continue;
      const modes: [string, number][] = kind === 'lookup' ? [['ok', 6], ['stale', 1], ['in-transit', 1], ['ambiguous-pending', 1]]
        : [['ok', 6], ['lost-answer', 1], ['in-transit', 1], ['ambiguous-done', 0.7], ['ambiguous-pending', 1], ['definite', 0.5], ['connect', 0.4]];
      options.push([kind === 'lookup' ? 6 : 3, () => ({ t: 'answer', kind, pick: at(open).pick, mode: weighted(rng, modes) })]);
    }
    const transit = this.calls('create', item => item.inTransit && !item.arrived);
    if (transit.length > 0) options.push([1.5, () => ({ t: 'create.arrive', pick: at(transit).pick })]);
    const openInvoices = this.invoicesIn(['OPEN']);
    if (openInvoices.length > 0) {
      options.push([3, () => ({ t: 'invoice', what: 'pay', pick: at(openInvoices).pick })]);
      options.push([0.4, () => ({ t: 'invoice', what: 'expire', pick: at(openInvoices).pick })]);
    }
    const accepted = this.invoicesIn(['ACCEPTED']);
    if (accepted.length > 0) options.push([0.6, () => ({ t: 'invoice', what: 'htlc-timeout', pick: at(accepted).pick })]);
    const live = this.invoicesIn(['OPEN', 'ACCEPTED']);
    if (live.length > 0) options.push([0.25, () => ({ t: 'invoice', what: 'misreport', pick: at(live).pick })]);
    options.push([accepted.length > 0 ? 3 : 0.8, () => ({ t: 'settle', p, order: rng.int(0, ORDERS.length - 1) })]);
    options.push([0.6, () => ({ t: 'cancel', p, order: rng.int(0, ORDERS.length - 1) })]);
    options.push([1.5, () => ({ t: 'rreconcile', p, order: rng.chance(0.4) ? rng.int(0, ORDERS.length - 1) : null, cli: rng.chance(0.3) })]);
    if (!this.#listening(p)) options.push([0.6, () => ({ t: 'listen', p })]);
    const subQueued = this.calls('sub', item => item.open && item.queue.length > 0);
    if (subQueued.length > 0) options.push([4, () => ({ t: 'sub.deliver', pick: at(subQueued).pick })]);
    options.push([0.3, () => ({ t: 'cursor-set', p, pick: Number(rng.next().toFixed(4)) })]);
    options.push([0.6, () => ({ t: 'age' })]);
    // Both.
    options.push([0.5, () => ({ t: 'kill', p })]);
    options.push([0.5, () => ({ t: 'abort', p })]);
    return weighted(rng, options.map(([weight, make]): [() => HarnessEvent, number] => [make, weight]))();
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
  const run = new Run(options.lab, options.config, options.scratch);
  const events: HarnessEvent[] = [];
  const total = options.events?.length ?? options.steps ?? 60;
  const stop = options.stop ?? 'first';
  const violations: StepViolation[] = [];
  let seen = 0;
  const collect = (step: number, event: HarnessEvent | null): boolean => {
    for (const item of run.oracle.violations.slice(seen)) {
      if (!violations.some(known => known.predicate === item.predicate)) violations.push({ ...item, step, event });
    }
    seen = run.oracle.violations.length;
    return stop === 'first' ? violations.length > 0 : violations.some(item => item.predicate === stop);
  };
  let stopped = false;
  try {
    for (let step = 0; step < total && !stopped; step += 1) {
      const event = options.events?.[step] ?? run.generate(options.rng as Rng);
      events.push(event);
      await run.step(event);
      stopped = collect(step, event);
    }
    if (!stopped) {
      await run.quiesce();
      collect(events.length, null);
    }
  } finally {
    await run.dispose();
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
}

export function replayOf(result: CaseResult, predicate: PredicateName, origin: { seed: number | null; case: number | null; originalSteps: number }): Replay {
  const violation = result.violations.find(item => item.predicate === predicate);
  if (violation === undefined) throw new Error('no violation to record');
  return { schema: 1, kind: 'macwarden-payment-lab-harness-replay', predicate: violation.predicate, rule: PREDICATES[violation.predicate],
    message: violation.message, seed: origin.seed, case: origin.case, config: result.config, failingStep: violation.step,
    originalSteps: origin.originalSteps, events: result.events, states: violation.states };
}

export function readReplay(path: string): Replay {
  const replay = JSON.parse(readFileSync(path, 'utf8')) as Replay;
  if (replay.kind !== 'macwarden-payment-lab-harness-replay' || replay.schema !== 1 || !Array.isArray(replay.events) || !(replay.predicate in PREDICATES)) {
    throw new Error(`${path} is not a payment-lab harness replay (schema 1)`);
  }
  return replay;
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
}

/** Runs replay files (a file or a directory of them) against a lab source. */
export async function replay(options: { path: string; labSrc?: string; scratch?: string }): Promise<ReplayOutcome[]> {
  const lab = await loadLab(options.labSrc ?? DEFAULT_LAB_SRC);
  const scratch = options.scratch ?? mkdtempSync(join(tmpdir(), 'macwarden-lab-harness-'));
  const outcomes: ReplayOutcome[] = [];
  try {
    for (const file of replayFiles(options.path)) {
      const recorded = readReplay(file);
      const result = await runCase({ lab, config: recorded.config, events: recorded.events, scratch, stop: 'never' });
      outcomes.push({ file, predicate: recorded.predicate, recorded: recorded.failingStep >= 0, violations: result.violations, counts: result.counts, ms: result.ms });
    }
  } finally {
    if (options.scratch === undefined) rmSync(scratch, { recursive: true, force: true });
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
  violations: { case: number; predicate: PredicateName; message: string; step: number; replay?: string; shrunkSteps?: number }[];
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
        }
        result.violations.push(entry);
      }
      options.onProgress?.(index - start + 1, options.cases);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  result.seconds = Number(((performance.now() - began) / 1000).toFixed(1));
  return result;
}

export { PREDICATES };
export type { PredicateName };
