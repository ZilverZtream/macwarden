import { revealSecret } from '../../secret-capability.js';
import * as nodeFs from 'node:fs/promises';
import { dirname, normalize } from 'node:path';
import type { Secret } from '../../secret.js';
import { outputNameProblem } from '../../protected-path.js';
import { openRegistry } from '../../registry/index.js';
import { PrivateFileError, reserveOwnerOnly } from '../../private-file.js';
import { OutputReserveError } from './out-errors.js';

export const REGISTRY_OUT_REFUSAL = 'output path refused: it names the registry file or a file named after it ' +
  '(<registry>.*: its lock, claim, temporary, canary or usage file), which macwarden writes itself';

/**
 * The registry file the command will use, resolved as openRegistry resolves it (realpath of the
 * existing part of the path), without reading it; null when it cannot be resolved, in which case
 * the command's registry step refuses it before anything is written.
 */
export async function registryPath(path: string | undefined, fs: Pick<typeof nodeFs, 'realpath' | 'lstat'>,
  env: Record<string, string | undefined>): Promise<string | null> {
  // openRegistry treats a missing file as an empty registry: a stat that reports ENOENT yields
  // its resolved location without opening the file.
  const stat = async (): Promise<never> => { throw Object.assign(new Error('location only'), { code: 'ENOENT' }); };
  try { return (await openRegistry(path, { fs: { ...fs, stat } as unknown as typeof nodeFs, env })).location; }
  catch { return null; }
}

/**
 * True when `out` is the registry file or a file named after it (`<registry>.*`): the lock, the
 * lock claim, the save's temporary files and the canary and usage sidecars. A credential written
 * there would be overwritten by the next registry save (or break the lock). Both paths must be
 * resolved (resolveUnprotectedPath); the comparison ignores letter case where the file system
 * usually does (Windows, macOS).
 */
export function namesRegistryFile(out: string, registry: string, platform: NodeJS.Platform = process.platform): boolean {
  const fold = (path: string) => platform === 'win32' || platform === 'darwin' ? normalize(path).toLowerCase() : normalize(path);
  const target = fold(out), file = fold(registry);
  return target === file || target.startsWith(`${file}.`);
}

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
        await syncDirectory(path, fs);
      },
      async discard() {
        if (written) return;
        // The exclusive handle refuses deletion, so close before unlinking.
        try { await handle.close(); } finally { await fs.unlink(path); }
      },
    },
  };
}

// The new name is durable only once its directory entry is, as for the registry save
// (src/registry/index.ts): POSIX needs the directory synced. Best effort: some file systems
// refuse to sync a directory, and Windows has no such call. The file itself is already synced.
async function syncDirectory(path: string, fs: typeof nodeFs): Promise<void> {
  if (process.platform === 'win32') return;
  let directory: nodeFs.FileHandle | undefined;
  try {
    directory = await fs.open(dirname(path), 'r');
    await directory.sync();
  } catch { /* EISDIR, EINVAL, EPERM and similar: nothing more can be done. */ }
  finally { await directory?.close().catch(() => {}); }
}
