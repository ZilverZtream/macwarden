import { paymentsForHash } from '../../src/analysis/payments.ts';
import {
  NODE_NAMES, PAYER_PROFILES, RECEIVER_PROFILES, databasePath, loadLab, readApi,
  type Lab, type NodeName, type PayerProfile, type ReceiverProfile,
} from '../../src/config.ts';
import type { ReadApi } from '../../src/lnd/api.ts';
import type { Payment } from '../../src/lnd/types.ts';
import { PayerStore } from '../../src/payer/store.ts';
import { ReceiverStore } from '../../src/receiver/store.ts';
import { fact, say, step, title, Verdict, warn } from '../../lab/narrate.ts';
import { describeEvent, runService, stopAll, type ServiceEvent } from './service.ts';

/** Shared scenario plumbing: the lab, read-only evidence, durable records and cleanup. */

export interface Context {
  lab: Lab;
  read: Record<NodeName, ReadApi>;
  tag: string;
  /** Runs before exit when the scenario stops early, for example to cancel a hold invoice it left accepted. */
  onAbort: (cleanup: () => Promise<void>) => void;
}

/** A run tag keeps business IDs unique across repeated runs against one lab. */
function runTag(): string {
  return new Date().toISOString().replace(/[-:]/g, '').replace(/\.(\d{3})Z$/, '$1').slice(4);
}

export function withPayer<T>(context: Context, profile: PayerProfile, work: (store: PayerStore) => T): T {
  const store = new PayerStore(databasePath(context.lab, PAYER_PROFILES[profile].database));
  try { return work(store); } finally { store.close(); }
}

export function withReceiver<T>(context: Context, profile: ReceiverProfile, work: (store: ReceiverStore) => T): T {
  const store = new ReceiverStore(databasePath(context.lab, RECEIVER_PROFILES[profile].database));
  try { return work(store); } finally { store.close(); }
}

/** Every payment the node holds for a hash, from ListPayments with the read-only credential. */
export async function lndPayments(context: Context, node: NodeName, paymentHash: string): Promise<{ payments: Payment[]; complete: boolean }> {
  const result = await paymentsForHash(context.read[node], paymentHash);
  return { payments: result.payments, complete: result.complete };
}

export async function createInvoice(profile: ReceiverProfile, orderId: string, amountMsat: bigint, hold: boolean): Promise<{ paymentHash: string; paymentRequest: string }> {
  const args = ['receiver', 'create-invoice', '--as', profile, '--order', orderId, '--amount-msat', amountMsat.toString(), '--memo', orderId];
  if (hold) args.push('--hold');
  const { code, events } = await runService(args, { echo: describeEvent });
  const outcome = events.find(item => item.event === 'outcome');
  if (code !== 0 || outcome?.kind !== 'created') throw new Error(`invoice for ${orderId} was not created (exit ${code})`);
  return { paymentHash: String(outcome.paymentHash), paymentRequest: String(outcome.paymentRequest) };
}

export function payArgs(profile: PayerProfile, operationId: string, kind: string, paymentRequest: string, feeLimitMsat: bigint,
  extra: readonly string[] = []): string[] {
  return ['payer', 'pay', '--as', profile, '--operation', operationId, '--kind', kind, '--invoice', paymentRequest,
    '--fee-limit-msat', feeLimitMsat.toString(), ...extra];
}

export function eventsNamed(events: readonly ServiceEvent[], name: string): ServiceEvent[] {
  return events.filter(item => item.event === name);
}

/** Runs a scenario body with narration, a verdict and cleanup. */
export async function scenario(name: string, summary: string, body: (context: Context) => Promise<Verdict>): Promise<void> {
  title(name);
  say(summary);
  const cleanups: (() => Promise<void>)[] = [];
  let lab: Lab;
  try {
    lab = loadLab();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
    return;
  }
  const read = Object.fromEntries(NODE_NAMES.map(node => [node, readApi(lab, node)])) as Record<NodeName, ReadApi>;
  const context: Context = { lab, read, tag: runTag(), onAbort: cleanup => { cleanups.push(cleanup); } };
  fact('lab run', lab.dir);
  fact('run tag', context.tag);
  try {
    for (const node of NODE_NAMES) {
      const info = await read[node].getInfo();
      if (!info.syncedToChain) throw new Error(`${node} is not synced to chain`);
    }
    const verdict = await body(context);
    process.exitCode = verdict.finish();
  } catch (error) {
    process.stdout.write(`\nscenario stopped: ${error instanceof Error ? error.message : String(error)}\nVERDICT ${name}: FAIL (did not complete)\n`);
    process.exitCode = 1;
    await stopAll();
    if (cleanups.length > 0) step('Clean up what this run left open');
    for (const cleanup of cleanups.reverse()) {
      try { await cleanup(); } catch (cleanupError) { warn(`cleanup failed: ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`); }
    }
  }
}

/** Cancels a hold invoice the scenario created if it is still open or accepted, so no HTLC stays locked. */
export async function cancelIfOpen(profile: ReceiverProfile, orderId: string): Promise<void> {
  await runService(['receiver', 'cancel', '--as', profile, '--order', orderId], { echo: describeEvent, timeoutMs: 60_000 });
}
