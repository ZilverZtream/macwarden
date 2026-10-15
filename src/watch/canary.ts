// Canary macaroons: decoys on their own root key ID that carry an LND custom caveat
// `lnd-custom <name> <condition>`. LND accepts such a macaroon only while a middleware
// registered for <name> is connected, so without `macwarden watch` a canary fails
// closed (rejected, but silently). The name is per installation, random and
// innocuous because `lncli printmacaroon` shows it; each canary has its own condition.
import * as nodeFs from 'node:fs/promises';
import { reserveOwnerOnly } from '../private-file.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import type { RegistryEntry } from '../registry/index.js';
import { readBoundedFile, type BoundedReadIO } from '../bounded-file.js';

export type CanaryConfig = { caveatName: string };

const words = ['tenant', 'scope', 'profile', 'policy', 'region', 'cluster'];
const namePattern = /^(?:tenant|scope|profile|policy|region|cluster)-[0-9a-f]{8}$/;
const conditionPattern = /^[0-9a-f]{16}$/;

/** Largest canary configuration read: the format holds one short name (about 50 bytes). */
export const CANARY_FILE_LIMIT = 4096;

export function canaryConfigPath(registryPath: string): string { return `${registryPath}.canary.json`; }

export function newCaveatName(random: (size: number) => Buffer = randomBytes): string {
  const bytes = random(5);
  return `${words[bytes[0] % words.length]}-${bytes.subarray(1).toString('hex')}`;
}

export function newCondition(random: (size: number) => Buffer = randomBytes): string {
  return random(8).toString('hex');
}

export function canaryCondition(caveatName: string, condition: string): string {
  return `lnd-custom ${caveatName} ${condition}`;
}

function parse(text: string): CanaryConfig {
  let value: unknown;
  try { value = JSON.parse(text); } catch (error) { throw new Error('invalid canary configuration', { cause: error }); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid canary configuration');
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join() !== 'caveatName,schema' || record.schema !== 1
    || typeof record.caveatName !== 'string' || !namePattern.test(record.caveatName))
    throw new Error('invalid canary configuration');
  return { caveatName: record.caveatName };
}

/**
 * Reads the configuration through the bounded regular-file reader: a protected path or
 * target (SAFE-02), anything but a regular file, or a file over CANARY_FILE_LIMIT is refused
 * before its content is read. A missing file is null.
 */
export async function readCanaryConfig(path: string, fs: BoundedReadIO = nodeFs): Promise<CanaryConfig | null> {
  let text: string;
  try { text = (await readBoundedFile(path, fs, CANARY_FILE_LIMIT)).toString('utf8'); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new Error('cannot read canary configuration', { cause: error });
  }
  return parse(text);
}

export type CanaryIO = BoundedReadIO & Pick<typeof nodeFs, 'link' | 'unlink'>;

/** Creates `path` owner-only (1.2.1) with `text`, synced; on any failure the file is removed. */
async function writeNewPrivate(path: string, text: string, fs: CanaryIO): Promise<void> {
  const { handle } = await reserveOwnerOnly(path, fs);
  try {
    await handle.writeFile(text, 'utf8');
    await handle.sync();
    await handle.close();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await fs.unlink(path).catch(() => undefined);
    throw error;
  }
}

/**
 * Returns the existing configuration or creates it, never replacing one. Written like the
 * registry (audit 1.3.2): a complete, synced temp file is put in place with link(), which
 * fails on an existing name. Writing the file in place left a 0-byte configuration after a
 * failed write (ENOSPC), and every later watch and bake --canary refused it as invalid.
 */
export async function ensureCanaryConfig(path: string, fs: CanaryIO = nodeFs,
  random: (size: number) => Buffer = randomBytes): Promise<CanaryConfig> {
  const existing = await readCanaryConfig(path, fs);
  if (existing) return existing;
  const config = { caveatName: newCaveatName(random) };
  const text = `${JSON.stringify({ schema: 1, caveatName: config.caveatName })}\n`;
  const temp = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  let code: string | undefined;
  try {
    await writeNewPrivate(temp, text, fs);
    try { await fs.link(temp, path); return config; }
    catch (error) {
      code = (error as NodeJS.ErrnoException).code;
      // A volume without hard links (FAT, exFAT): created in place exclusively, removed if the write fails.
      if (code !== 'EEXIST') { await writeNewPrivate(path, text, fs); return config; }
    }
  } catch (error) {
    code = (error as NodeJS.ErrnoException).code;
    if (code !== 'EEXIST') throw new Error('cannot create canary configuration', { cause: error });
  } finally { await fs.unlink(temp).catch(() => undefined); }
  // Another invocation created it first: use that one.
  const raced = await readCanaryConfig(path, fs);
  if (raced) return raced;
  throw new Error('cannot create canary configuration');
}

/** Active canary entries for this node, keyed by their caveat condition. */
export function canaryEntries(entries: RegistryEntry[], config: CanaryConfig | null, nodePubkey: string): Map<string, RegistryEntry> {
  const result = new Map<string, RegistryEntry>();
  if (!config) return result;
  const prefix = `${config.caveatName} `;
  for (const entry of entries) {
    if (entry.status !== 'active' || entry.nodePubkey.toLowerCase() !== nodePubkey.toLowerCase()) continue;
    for (const caveat of entry.caveats) {
      if (caveat.type !== 'lnd-custom' || !caveat.value.startsWith(prefix)) continue;
      const condition = caveat.value.slice(prefix.length);
      if (conditionPattern.test(condition)) result.set(condition, entry);
    }
  }
  return result;
}

export function isCanary(entry: RegistryEntry, config: CanaryConfig | null): boolean {
  return config !== null && entry.caveats.some(caveat => caveat.type === 'lnd-custom'
    && caveat.value.startsWith(`${config.caveatName} `));
}
