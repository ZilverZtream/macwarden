import { spawn, type ChildProcess } from 'node:child_process';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { LAB_ROOT } from '../../src/config.ts';
import { command, say } from '../../lab/narrate.ts';

/**
 * Runs the payment service as separate OS processes, as a deployment would,
 * so a scenario can kill one mid-payment and start another against the same
 * durable store.
 */

const CLI = join(LAB_ROOT, 'src', 'cli.ts');

export type ServiceEvent = Record<string, unknown> & { event?: string };

export interface ServiceOptions {
  /** Keep stdin open for the `go` barrier. */
  stdin?: boolean;
  /** Print each event as it arrives. */
  echo?: (event: ServiceEvent) => string | undefined;
}

const running = new Set<ServiceProcess>();

/** Kills every service process a scenario started that is still running (used when a scenario stops early). */
export async function stopAll(): Promise<void> {
  await Promise.all([...running].map(child => child.kill()));
}

export class ServiceProcess {
  readonly events: ServiceEvent[] = [];
  readonly exited: Promise<number>;
  readonly #child: ChildProcess;
  readonly #waiters = new Set<() => void>();
  #stderr = '';
  #code: number | undefined;

  constructor(args: readonly string[], options: ServiceOptions = {}) {
    command(`node src/cli.ts ${args.join(' ')}`);
    this.#child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', CLI, ...args],
      { cwd: LAB_ROOT, stdio: [options.stdin ? 'pipe' : 'ignore', 'pipe', 'pipe'], windowsHide: true });
    const lines = createInterface({ input: this.#child.stdout as NodeJS.ReadableStream });
    lines.on('line', line => {
      let event: ServiceEvent;
      try { event = JSON.parse(line) as ServiceEvent; } catch { event = { event: 'unparsed-output', line }; }
      this.events.push(event);
      const text = options.echo?.(event);
      if (text !== undefined) say(text);
      for (const wake of this.#waiters) wake();
    });
    this.#child.stderr?.setEncoding('utf8');
    this.#child.stderr?.on('data', (chunk: string) => { if (this.#stderr.length < 65_536) this.#stderr += chunk; });
    running.add(this);
    this.exited = new Promise(resolve => {
      this.#child.on('close', (code, signal) => {
        running.delete(this);
        this.#code = code ?? (signal === null ? 1 : 128);
        for (const wake of this.#waiters) wake();
        resolve(this.#code);
      });
    });
  }

  get stderr(): string {
    return this.#stderr;
  }

  get pid(): number | undefined {
    return this.#child.pid;
  }

  /** Resolves with the first event (already received or future) matching `predicate`. */
  waitForEvent(description: string, predicate: (event: ServiceEvent) => boolean, timeoutMs: number): Promise<ServiceEvent> {
    return new Promise((resolve, reject) => {
      const check = (): void => {
        const found = this.events.find(predicate);
        if (found !== undefined) { done(); resolve(found); return; }
        if (this.#code !== undefined) {
          done();
          reject(new Error(`process exited ${this.#code} before ${description}${this.#stderr ? `: ${this.#stderr.trim()}` : ''}`));
        }
      };
      const timer = setTimeout(() => { done(); reject(new Error(`timed out after ${timeoutMs} ms waiting for ${description}`)); }, timeoutMs);
      const done = (): void => { clearTimeout(timer); this.#waiters.delete(check); };
      this.#waiters.add(check);
      check();
    });
  }

  send(line: string): void {
    this.#child.stdin?.write(`${line}\n`);
  }

  /** Ends the process at once, without letting it clean up: a crash, an OOM kill, a power cut. */
  async kill(): Promise<number> {
    this.#child.kill('SIGKILL');
    return this.exited;
  }

  /** Asks the process to stop (SIGTERM; on Windows the process is terminated). */
  async stop(): Promise<number> {
    this.#child.kill('SIGTERM');
    return this.exited;
  }

  async finished(timeoutMs: number, description: string): Promise<number> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`timed out after ${timeoutMs} ms waiting for ${description} to finish`)), timeoutMs);
    });
    try { return await Promise.race([this.exited, timeout]); } finally { clearTimeout(timer); }
  }

  last(name: string): ServiceEvent | undefined {
    return [...this.events].reverse().find(item => item.event === name);
  }
}

/** Runs one service command to completion. */
export async function runService(args: readonly string[], options: ServiceOptions & { timeoutMs?: number } = {}): Promise<{ code: number; events: ServiceEvent[]; process: ServiceProcess }> {
  const child = new ServiceProcess(args, options);
  const code = await child.finished(options.timeoutMs ?? 180_000, `node src/cli.ts ${args[0] ?? ''} ${args[1] ?? ''}`);
  return { code, events: child.events, process: child };
}

/** A short description of service events for the narration. */
export function describeEvent(event: ServiceEvent): string | undefined {
  switch (event.event) {
    case 'intent-recorded': return `recorded intent: operation ${String(event.operationId)} -> payment ${String(event.paymentHash).slice(0, 16)}...`;
    case 'submitted': return 'SendPaymentV2 called (submission counted in the record)';
    case 'payment-update':
      return `${String(event.source)}: ${String(event.status)} (attempts ${String(event.htlcAttempts)}: ${String(event.attemptsInFlight)} in flight, `
        + `${String(event.attemptsSucceeded)} succeeded, ${String(event.attemptsFailed)} failed; fee ${String(event.feeMsat)} msat) -> record ${String(event.recordState)}`;
    case 'uncertain': return `record marked uncertain: ${String(event.reason)}`;
    case 'fault-injected': return 'fault injected: the HTTP connection to LND is destroyed';
    case 'track-started': return `TrackPaymentV2 started (record ${String(event.recordState)})`;
    case 'track-interrupted': return `TrackPaymentV2 interrupted: ${String(event.error)}`;
    case 'intent-refused': return `refused: ${String(event.reason)}`;
    case 'invoice-refused': return `invoice refused: ${String(event.reason)}`;
    case 'invoice-created': return `invoice created with ${String(event.rpc)} for ${String(event.orderId)}`;
    case 'invoice-delivery': return `invoice update via ${String(event.source)}: ${String(event.lndState)} (settle index ${String(event.settleIndex)}) -> ${String(event.outcome)}`;
    case 'settle-called': return 'SettleInvoice called with the stored preimage';
    case 'cancel-called': return 'CancelInvoice called';
    case 'subscribing': return `SubscribeInvoices from settle index ${String(event.settleIndex)}`;
    case 'subscription-lost': return `subscription lost: ${String(event.error)}`;
    case 'outcome': return `outcome: ${String(event.kind ?? '')}${event.reason === undefined ? '' : ` (${String(event.reason)})`}`;
    case 'error': return `error: ${String(event.error)}`;
    default: return undefined;
  }
}
