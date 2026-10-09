import { AsyncLocalStorage } from 'node:async_hooks';

export type ProcessErrorContext = { mutationSent: boolean };
const context = new AsyncLocalStorage<ProcessErrorContext>();

export function withProcessErrorContext<T>(state: ProcessErrorContext, action: () => T): T {
  return context.run(state, action);
}

export function markMutationSent(): void {
  const state = context.getStore();
  if (state) state.mutationSent = true;
}

export function internalErrorMessage(state?: ProcessErrorContext): string {
  return 'unexpected failure' + (state?.mutationSent
    ? '; LND may have changed — run macwarden inventory' : '');
}
