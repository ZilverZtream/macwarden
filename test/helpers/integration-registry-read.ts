// Fault and change injection for the registry read. openRegistry reads registry.json through
// readBoundedFile (resolve with realpath, stat, then one read-only open of the checked file), so a
// test that used to intercept fs.readFile intercepts one of those calls instead.
import { constants, realpathSync } from 'node:fs';
import type * as fs from 'node:fs/promises';

const WRITE_FLAGS = constants.O_WRONLY | constants.O_RDWR | constants.O_CREAT | constants.O_TRUNC | constants.O_APPEND;

function readOnly(flags: unknown): boolean {
  if (flags === undefined) return true;
  if (typeof flags === 'number') return (flags & WRITE_FLAGS) === 0;
  return typeof flags === 'string' && /^rs?$/.test(flags);
}

function samePath(path: unknown, registry: string): boolean {
  try { return realpathSync.native(String(path)) === realpathSync.native(registry); } catch { return false; }
}

/**
 * Returns `io.open` wrapped so that the read-only open of `registry` (the registry read itself) first
 * runs `before`, which throws to inject a read failure. Every other open is passed through unchanged.
 */
export function onRegistryOpen(io: Pick<typeof fs, 'open'>, registry: string, before: () => void): typeof fs.open {
  const original = io.open;
  return (async (...params: Parameters<typeof fs.open>) => {
    if (readOnly(params[1]) && samePath(params[0], registry)) before();
    return original(...params);
  }) as typeof fs.open;
}

/**
 * Returns `io.realpath` wrapped so that resolving `registry` first runs `before`: a change made
 * there lands before the read checks and opens the file, as a change made before fs.readFile did.
 */
export function onRegistryResolve(io: Pick<typeof fs, 'realpath'>, registry: string, before: () => void): typeof fs.realpath {
  const original = io.realpath;
  return (async (...params: Parameters<typeof fs.realpath>) => {
    if (samePath(params[0], registry)) before();
    return original(...params);
  }) as typeof fs.realpath;
}
