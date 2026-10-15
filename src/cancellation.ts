import { AsyncLocalStorage } from 'node:async_hooks';
export class Cancelled extends Error { constructor() { super('operation interrupted'); } }
const current = new AsyncLocalStorage<AbortSignal>();
export function withCancellation<T>(signal: AbortSignal, action: () => T): T { return current.run(signal, action); }
export function checkCancellation(): void { if (current.getStore()?.aborted) throw new Cancelled(); }
export function cancellable<T>(operation: () => Promise<T>): Promise<T> {
  const signal = current.getStore();
  if (!signal) return operation();
  if (signal.aborted) return Promise.reject(new Cancelled());
  return new Promise<T>((resolve, reject) => {
    const cancel = () => reject(new Cancelled());
    signal.addEventListener('abort', cancel, { once: true });
    let started: Promise<T>;
    // An operation that throws before returning its promise still removes the listener (audit 1.3.2).
    try { started = operation(); } catch (error) { started = Promise.reject(error); }
    started.then(resolve, reject).finally(() => signal.removeEventListener('abort', cancel));
  });
}

export function cancellationSignal(): AbortSignal | undefined { return current.getStore(); }


export type CleanupState = { mutationSent: boolean; inspection?: string; cleanupFailures: string[] };
export async function cleanup(state: CleanupState, name: string, action: () => Promise<void>): Promise<void> {
  try { await action(); } catch { state.cleanupFailures.push(name); }
}
export function cleanupOutcome<T extends { ok: boolean; result: unknown; error: { code: number; step: string | null; message: string } | null }>(result: T, state: CleanupState): T {
  if (!state.cleanupFailures.length) return result;
  const message = `cleanup failed: ${state.cleanupFailures.join(', ')}; owned files may remain; stop registry writers and inspect state before recovery`;
  if (result.error) return { ...result, error: { ...result.error, message: `${result.error.message}; ${message}` } };
  return { ...result, ok: false, result: null, error: { code: state.mutationSent ? 7 : 3, step: 'cleanup', message: `${message}; ${state.inspection ?? 'run macwarden inventory to inspect the completed operation'}` } };
}
