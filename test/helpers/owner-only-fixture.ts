import * as fs from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { reserveOwnerOnly } from '../../src/private-file.js';

/**
 * Writes a fixture file the way the product creates its own private files: `0600` on POSIX,
 * and on Windows through the owner-only helper, so the file is owned by this account with a
 * protected DACL. A fixture written with plain `writeFileSync` is owned by the Administrators
 * group on an elevated session (GitHub's Windows runners), which the product's owner-only check
 * rightly refuses (1.2.1). The path must not exist yet.
 */
export async function writeOwnerOnly(path: string, data: string | Buffer): Promise<void> {
  if (process.platform !== 'win32') { writeFileSync(path, data, { mode: 0o600 }); return; }
  const { handle } = await reserveOwnerOnly(path, fs);
  try { await handle.writeFile(data); } finally { await handle.close(); }
}
