import * as nodeFs from 'node:fs/promises';
import { normalize } from 'node:path';
import { openRegistry } from '../../registry/index.js';

// Where an --out may not go: the registry file and the files named after it. Kept apart from
// write-out.ts, whose exports the build graph limits to the credential-writing reservation.

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
