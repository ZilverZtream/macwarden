// Bounded regular-file reads for files macwarden reads by path: TLS certificates, the
// sidecars kept next to the registry and lock owner records. The path (and, except for lock
// records, which must not be symlinks, its resolved target) is checked against the
// protected names (SAFE-02) before anything is opened, the opened file must be the
// regular file that was checked, and at most `limit` bytes are accepted: a larger file fails
// before its content is parsed, and allocation follows the file's size, never the limit.
import { constants } from 'node:fs';
import type * as fs from 'node:fs/promises';
import { isProtectedPath } from './protected-path.js';

export type BoundedReadIO = Pick<typeof fs, 'realpath' | 'stat' | 'open'>;

/** Why a bounded read was refused before any content was read or accepted. */
export class BoundedFileError extends Error {
  constructor(message: 'protected file' | 'not a regular file' | 'file changed' | 'file too large') {
    super(message); this.name = 'BoundedFileError';
  }
}

export const DEFAULT_FILE_LIMIT = 1_048_576;

/**
 * Reads at most limit + 1 bytes from an open handle. The buffer starts at the size fstat
 * reported plus one byte (to notice growth) and doubles only while the file keeps yielding
 * data, so a small file never costs a limit-sized allocation.
 */
export async function readBounded(handle: Pick<fs.FileHandle, 'read'>, limit: number, size: number | bigint): Promise<Buffer> {
  const hinted = typeof size === 'bigint' ? (size > BigInt(limit) ? limit : Number(size)) : Math.min(Math.max(size, 0), limit);
  let bytes = Buffer.allocUnsafe(hinted + 1);
  let total = 0;
  for (;;) {
    if (total === bytes.length) {
      if (bytes.length >= limit + 1) break;
      const grown = Buffer.allocUnsafe(Math.min(limit + 1, bytes.length * 2));
      bytes.copy(grown, 0, 0, total);
      bytes = grown;
    }
    const { bytesRead } = await handle.read(bytes, total, bytes.length - total, total);
    if (bytesRead === 0) break;
    total += bytesRead;
  }
  return bytes.subarray(0, total);
}

/**
 * Reads a regular file of at most `limit` bytes. A missing path rejects with the file
 * system's ENOENT error (so callers can treat an optional file as absent); a protected path
 * or target, anything but a regular file, a file replaced between check and open, or one
 * larger than `limit` rejects with BoundedFileError before any content is read.
 */
export async function readBoundedFile(path: string, io: BoundedReadIO, limit = DEFAULT_FILE_LIMIT): Promise<Buffer> {
  if (isProtectedPath(path)) throw new BoundedFileError('protected file');
  const resolved = await io.realpath(path);
  if (isProtectedPath(resolved)) throw new BoundedFileError('protected file');
  const before = await io.stat(resolved);
  if (!before.isFile()) throw new BoundedFileError('not a regular file');
  if (before.size > limit) throw new BoundedFileError('file too large');
  const handle = await io.open(resolved, constants.O_RDONLY | constants.O_NONBLOCK | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) throw new BoundedFileError('file changed');
    if (opened.size > limit) throw new BoundedFileError('file too large');
    const bytes = await readBounded(handle, limit, opened.size);
    if (bytes.length > limit) throw new BoundedFileError('file too large');
    return bytes;
  } finally { await handle.close(); }
}

/** Largest lock owner record read: a few fields (pid, host name, start time, process domain). */
export const LOCK_FILE_LIMIT = 64 * 1024;

/**
 * Reads a file that must stay in place (lock owner records, whose reads are part of the lock
 * protocol) through one descriptor: the path itself must be a regular file, not a symlink,
 * under no protected name and at most `limit` bytes when checked; the opened file must be
 * that same regular file (device and inode, compared as bigints so Windows file indexes stay
 * exact; no-follow is used where the platform has it, and Windows has none, so the identity
 * check is what binds the read to the checked file), and at most limit + 1 bytes are read
 * from it. A symlink or protected path is refused before any open; a file replaced after the
 * check is refused before its content is read; one that grew past `limit` fails once
 * limit + 1 bytes have been read.
 */
export async function readPlainFile(path: string, io: Pick<typeof fs, 'lstat' | 'open'>, limit: number): Promise<string> {
  if (isProtectedPath(path)) throw new BoundedFileError('protected file');
  const meta = await io.lstat(path, { bigint: true });
  if (!meta.isFile() || meta.isSymbolicLink()) throw new BoundedFileError('not a regular file');
  if (meta.size > BigInt(limit)) throw new BoundedFileError('file too large');
  const handle = await io.open(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.dev !== meta.dev || opened.ino !== meta.ino) throw new BoundedFileError('file changed');
    if (opened.size > BigInt(limit)) throw new BoundedFileError('file too large');
    const bytes = await readBounded(handle, limit, opened.size);
    if (bytes.length > limit) throw new BoundedFileError('file too large');
    return bytes.toString('utf8');
  } finally { await handle.close(); }
}
