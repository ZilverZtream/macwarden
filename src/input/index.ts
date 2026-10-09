import { constants } from 'node:fs';
import type { BigIntStats } from 'node:fs';
import type * as fs from 'node:fs/promises';
import type { Readable } from 'node:stream';
import { Secret } from '../secret.js';
import { isProtectedPath } from '../protected-path.js';
import { parseLndconnect } from './lndconnect.js';
import { InputError, UsageError } from '../errors.js';

export { InputError, UsageError } from '../errors.js';
export type { InputStage } from '../errors.js';

export type InputIO = {
  stdin: Readable & { isTTY?: boolean };
  fs: Pick<typeof fs, 'stat' | 'lstat' | 'realpath' | 'open' | 'readFile'>;
};

const literalRefusal = 'pass a file path or - (stdin); literal credentials end up in shell history and process listings';

function invalidForm(): never {
  throw new InputError('input-form');
}

function decodeBase64(value: string): Buffer {
  const standard = /^[A-Za-z0-9+/]+={0,2}$/.test(value);
  const url = /^[A-Za-z0-9_-]+={0,2}$/.test(value);
  if ((!standard && !url) || value.length % 4 === 1) return invalidForm();
  const padding = value.length - value.replace(/=+$/, '').length;
  if ((padding > 0 && value.length % 4 !== 0) ||
      (padding === 1 && value.at(-2) === '=') ||
      (padding === 2 && value.at(-3) === '=')) return invalidForm();
  const decoded = Buffer.from(value, standard ? 'base64' : 'base64url');
  if (decoded.length === 0) return invalidForm();
  const canonical = decoded.toString(standard ? 'base64' : 'base64url');
  if (canonical.replace(/=+$/, '') !== value.replace(/=+$/, '')) return invalidForm();
  return decoded;
}

// NIP-47 canonical and legacy schemes; decode/index.ts validates the rest.
const nwcScheme = /^(?:nostr\+walletconnect|nostrwalletconnect):/i;
// L402 text forms (inspect only): an Authorization value or WWW-Authenticate challenge, with or
// without the header name, or a bare "<base64 macaroon>:<hex preimage>" pair. decode/index.ts
// validates the rest.
const l402Scheme = /^(?:(?:authorization|www-authenticate)[ \t]*:[ \t]*)?(?:l402|lsat)[ \t]/i;
const l402Pair = /^[A-Za-z0-9+/_=-]{16,}:[0-9a-f]*$/i;

function isL402Text(trimmed: string): boolean {
  return l402Scheme.test(trimmed) || l402Pair.test(trimmed);
}

/**
 * Aperture's token store framing (l402/token.go serializeToken): a uint32 macaroon length of 1
 * to 65,536, the macaroon (first byte 2), then 88 bytes of payment hash, preimage, amounts and time.
 */
function isTokenStoreFile(bytes: Buffer): boolean {
  if (bytes.length < 4 + 1 + 88 || bytes[0] !== 0x00) return false;
  const length = bytes.readUInt32BE(0);
  return length >= 1 && length <= 65_536 && bytes.length >= 4 + length + 88 && bytes[4] === 0x02;
}

/** Credential forms beyond macaroons that a command accepts: NWC URIs, L402 credentials. */
type Forms = { nwc?: boolean; l402?: boolean };

function parseText(text: string, forms: Forms = {}): Buffer {
  const trimmed = text.trim();
  // An NWC URI is kept verbatim inside the Secret container; decode/index.ts parses it.
  if (forms.nwc && nwcScheme.test(trimmed)) return /\s/.test(trimmed) ? invalidForm() : Buffer.from(trimmed, 'utf8');
  // An L402 Authorization value, challenge or pair is kept verbatim too, as one line.
  if (forms.l402 && isL402Text(trimmed)) return /[\r\n]/.test(trimmed) ? invalidForm() : Buffer.from(trimmed, 'latin1');
  if (/^lndconnect:\/\//i.test(trimmed)) return parseLndconnect(trimmed) ?? invalidForm();
  const value = text.replace(/\s/g, '');
  if (!value) return invalidForm();

  if (/^(?:0x)?[0-9a-f]+$/i.test(value)) {
    const digits = /^0x/i.test(value) ? value.slice(2) : value;
    if (digits.length % 2 !== 0) return invalidForm();
    return Buffer.from(digits, 'hex');
  }

  return decodeBase64(value);
}

function parseBytes(bytes: Buffer, forms: Forms = {}): Buffer {
  if (bytes[0] === 0x02) return bytes;
  // An Aperture L402 token store file is binary and starts with its macaroon length, a
  // big-endian uint32 below 2^24: decode/index.ts checks its framing.
  if (forms.l402 && isTokenStoreFile(bytes)) return bytes;
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    if ((bytes.length - 2) % 2 !== 0) return invalidForm();
    return parseText(bytes.subarray(2).toString('utf16le'), forms);
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    if ((bytes.length - 2) % 2 !== 0) return invalidForm();
    const swapped = Buffer.from(bytes.subarray(2));
    swapped.swap16();
    return parseText(swapped.toString('utf16le'), forms);
  }
  const start = bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])) ? 3 : 0;
  return parseText(bytes.subarray(start).toString('utf8'), forms);
}

async function stdinBytes(stream: Readable): Promise<Buffer> {
  const parts: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const remaining = RAW_INPUT_LIMIT + 1 - total;
      stream.read(0);
      // Object-mode Readables return an entire object even when read(size)
      // requests fewer bytes. Inspect the queued object before consuming it.
      if (stream.readableObjectMode) {
        const queued = (stream as Readable & { readableBuffer?: Array<Buffer | string> }).readableBuffer;
        if (!queued) throw new InputError('input-read');
        if (queued.length && Buffer.byteLength(queued[0]) > remaining) throw new InputError('input-read');
      }
      const available = stream.readableLength;
      const part: Buffer | string | null = available > 0
        ? stream.read(stream.readableObjectMode ? 1 : Math.min(remaining, available)) : null;
      if (part === null) {
        if (stream.readableEnded) break;
        await new Promise<void>((resolve, reject) => {
          const cleanup = () => {
            stream.off('readable', ready);
            stream.off('end', ready);
            stream.off('error', failed);
          };
          const ready = () => { cleanup(); resolve(); };
          const failed = () => { cleanup(); reject(new InputError('input-read')); };
          stream.once('readable', ready);
          stream.once('end', ready);
          stream.once('error', failed);
        });
        continue;
      }
      const bytes = Buffer.isBuffer(part) ? part : Buffer.from(part);
      total += bytes.length;
      if (total > RAW_INPUT_LIMIT) throw new InputError('input-read');
      parts.push(bytes);
    }
  } catch {
    stream.destroy();
    throw new InputError('input-read');
  }
  return Buffer.concat(parts);
}

const RAW_INPUT_LIMIT = 1_048_576;

async function fileBytes(handle: fs.FileHandle): Promise<Buffer> {
  const bytes = Buffer.allocUnsafe(RAW_INPUT_LIMIT + 1);
  let total = 0;
  while (total < bytes.length) {
    const result = await handle.read(bytes, total, bytes.length - total, null);
    if (!result.bytesRead) break;
    total += result.bytesRead;
  }
  if (total > RAW_INPUT_LIMIT) throw new InputError('input-read');
  return bytes.subarray(0, total);
}

export async function readCredential(
  arg: string,
  io: InputIO,
  opts: { unsafeArg: boolean; nwc?: boolean; l402?: boolean },
): Promise<{ secret: Secret; literal: boolean }> {
  const forms: Forms = { nwc: opts.nwc === true, l402: opts.l402 === true };
  if (arg === '-') {
    if (io.stdin.isTTY) throw new UsageError('stdin is a TTY');
    return { secret: new Secret(parseBytes(await stdinBytes(io.stdin), forms)), literal: false };
  }

  let sourceStat: BigIntStats | undefined;
  try {
    sourceStat = await io.fs.stat(arg, { bigint: true });
  } catch (error) {
    // A path probe can reject credential text as an invalid path on either OS.
    // Only failures that can describe an existing but inaccessible path stop here.
    if (!['ENOENT', 'ENAMETOOLONG', 'ENOTDIR', 'EINVAL'].includes((error as NodeJS.ErrnoException).code || '')) {
      throw new InputError('input-read');
    }
  }
  if (sourceStat) {
    if (isProtectedPath(arg)) throw new InputError('input-read');
    if (!sourceStat.isFile()) throw new InputError('input-read');
    let handle: fs.FileHandle | undefined;
    let bytes: Buffer | undefined;
    let readFailed = false;
    try {
      const filePath = await io.fs.realpath(arg);
      if (isProtectedPath(filePath)) throw new InputError('input-read');
      const pathStat = await io.fs.lstat(filePath);
      if (!pathStat.isFile() || pathStat.isSymbolicLink()) throw new InputError('input-read');
      handle = await io.fs.open(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const openedStat = await handle.stat({ bigint: true });
      if (!openedStat.isFile() || openedStat.dev !== sourceStat.dev || openedStat.ino !== sourceStat.ino) {
        throw new InputError('input-read');
      }
      bytes = await fileBytes(handle);
    } catch {
      readFailed = true;
    } finally {
      if (handle) {
        try {
          await handle.close();
        } catch {
          readFailed = true;
        }
      }
    }
    if (readFailed || !bytes) throw new InputError('input-read');
    return { secret: new Secret(parseBytes(bytes, forms)), literal: false };
  }

  // An encoded literal can contain a protected-looking path component. Only
  // an established file path takes precedence over literal classification.
  let supportedLiteral = /^lndconnect:\/\//i.test(arg) || (forms.nwc && nwcScheme.test(arg)) || (forms.l402 && isL402Text(arg.trim()));
  if (!supportedLiteral) {
    try {
      supportedLiteral = parseText(arg)[0] === 0x02;
    } catch { /* An unparseable argument is not a supported credential literal. */ }
  }
  if (isProtectedPath(arg) && !supportedLiteral) throw new InputError('input-read');
  if (!opts.unsafeArg) {
    if (supportedLiteral) throw new UsageError(literalRefusal);
    throw new InputError('input-read', 'no such file');
  }
  return { secret: new Secret(parseText(arg, forms)), literal: true };
}
