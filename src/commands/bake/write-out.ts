import { revealSecret } from '../../secret-capability.js';
import * as nodeFs from 'node:fs/promises';
import type { Secret } from '../../secret.js';
import { outputNameProblem } from '../../protected-path.js';
import { PrivateFileError, reserveOwnerOnly } from '../../private-file.js';
import { OutputReserveError } from './out-errors.js';

export type ReservedOut = { write(mac: Secret): Promise<void>; discard(): Promise<void> };

class OutputShareError extends OutputReserveError {
  constructor() { super('output file was opened or replaced by another process before it was written'); this.name = 'OutputShareError'; }
}

/**
 * Creates `path` exclusively for one credential (or report) and returns a reservation that
 * writes it through a handle no other process holds. The file is owner-only before any byte
 * is written, and that is verified (POSIX mode 0600 through the open descriptor; on Windows an
 * owner-only protected DACL set in the creating call, see src/private-file.ts); anything else
 * fails before writing. `aclWarning` is true only on a Windows volume that stores no
 * permissions (FAT, exFAT).
 */
export async function reserveOut(path: string, fs: typeof nodeFs = nodeFs): Promise<{
  reservation: ReservedOut;
  aclWarning: boolean;
}> {
  const nameProblem = outputNameProblem(path);
  if (nameProblem) throw new OutputReserveError(nameProblem);
  let reserved: Awaited<ReturnType<typeof reserveOwnerOnly>>;
  try { reserved = await reserveOwnerOnly(path, fs); }
  catch (error) {
    if (error instanceof PrivateFileError && error.kind === 'share') throw new OutputShareError();
    if (error instanceof PrivateFileError && error.code) throw error; // EEXIST and other open errors keep their code for the caller
    if (error instanceof PrivateFileError) throw new OutputReserveError(error.message);
    throw error;
  }
  const handle = reserved.handle;
  let written = false;
  return {
    aclWarning: reserved.aclWarning,
    reservation: {
      async write(mac) {
        await handle.writeFile(revealSecret(mac));
        await handle.sync();
        await handle.close();
        written = true;
      },
      async discard() {
        if (written) return;
        // The exclusive handle refuses deletion, so close before unlinking.
        try { await handle.close(); } finally { await fs.unlink(path); }
      },
    },
  };
}
