import type * as nodeFs from 'node:fs/promises';
import { Cancelled, cancellable, checkCancellation } from '../../cancellation.js';

// The --out checks (bake B4, rotate S5, inventory N7, attenuate A3) and the --out creation call
// race the command's cancellation signal, as scan's agent-config checks do: Node cannot cancel a
// file system call that does not return (a stalled mount), so an interrupt abandons it and the
// command reports exit 6, step `cancelled`, after releasing its lock (1.2.1). Kept apart from
// write-out.ts, whose exports the build graph limits to the credential-writing reservation.

type PathChecks = Pick<typeof nodeFs, 'realpath' | 'lstat'>;
type Call = (...args: unknown[]) => Promise<unknown>;

/** `realpath` and `lstat` of `fs`, each abandoned (rejecting with Cancelled) on an interrupt. */
export function interruptibleChecks(fs: PathChecks): PathChecks {
  return {
    realpath: ((...args: unknown[]) => cancellable(() => (fs.realpath as unknown as Call)(...args))) as unknown as typeof nodeFs.realpath,
    lstat: ((...args: unknown[]) => cancellable(() => (fs.lstat as unknown as Call)(...args))) as unknown as typeof nodeFs.lstat,
  };
}

/** Rethrows an interrupt so a caller's "cannot check output path" never hides it. */
export function rethrowCancelled(error: unknown): void {
  if (error instanceof Cancelled) throw error;
}

/**
 * The step result for an interrupt that abandoned the --out creation call: that call may still
 * create the file (on Windows the owner-only helper creates it before the exclusive open), which
 * nothing can then remove before the process exits. Such a file is empty and owner-only.
 */
export const OUT_CREATION_INTERRUPTED = 'interrupted while the output file was being created; nothing was written to it, ' +
  'but if the file now exists (empty and owner-only) remove it before running again';

/**
 * Runs the --out reservation against the cancellation signal. On an interrupt the reservation is
 * abandoned (Cancelled); if it completes later while the process is still alive, it is discarded.
 */
export async function interruptibleReserve<T extends { reservation: { discard(): Promise<void> } }>(
  reserve: () => Promise<T>): Promise<T> {
  checkCancellation();
  const pending = reserve();
  try { return await cancellable(() => pending); }
  catch (error) {
    if (error instanceof Cancelled) pending.then(late => late.reservation.discard()).catch(() => undefined);
    throw error;
  }
}
