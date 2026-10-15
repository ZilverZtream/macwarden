import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { canonicalMacaroonForm } from './decode/index.js';

// Capture the built-ins this module touches with credential bytes once, at load.
// Code that later replaces Buffer.from, Buffer.prototype.subarray or the hash
// methods therefore never observes the bytes held here. Hooks installed before
// this module loads (preloads) are out of scope; see docs/architecture.md.
const bufferFrom = Buffer.from.bind(Buffer) as (data: Uint8Array) => Buffer;
const subarray = Buffer.prototype.subarray.call.bind(Buffer.prototype.subarray) as
  (buffer: Buffer, start?: number, end?: number) => Buffer;
const newHash = createHash;
const probe = newHash('sha256');
const hashUpdate = probe.update.call.bind(probe.update) as (hash: unknown, data: Uint8Array) => unknown;
const hashDigest = probe.digest.call.bind(probe.digest) as (hash: unknown, encoding: 'hex') => string;

export let revealSecret: (secret: Secret) => Buffer;

export class Secret {
  #bytes: Buffer;

  static {
    revealSecret = (secret: Secret): Buffer => bufferFrom(secret.#bytes);
  }

  #fingerprint: string | undefined;

  constructor(bytes: Uint8Array) {
    this.#bytes = bufferFrom(bytes);
  }

  /**
   * Computed on first read and kept: watch wraps every intercepted macaroon in a Secret while it
   * answers LND, and needs only its identifier (macaroonId reads the header alone). Parsing every
   * caveat and hashing up to 64 KiB there cost a padded macaroon about 50 times the header read,
   * outside the attribution budget (audit 1.3.2).
   */
  get fingerprint(): string {
    if (this.#fingerprint === undefined) {
      // A valid macaroon hashes its canonical form (see canonicalMacaroonForm), anything else its bytes.
      const stored = this.#bytes;
      const canonical = canonicalMacaroonForm(stored);
      const hash = newHash('sha256');
      hashUpdate(hash, canonical?.reencoded ?? subarray(stored, 0, canonical?.length ?? stored.length));
      this.#fingerprint = `fp:${hashDigest(hash, 'hex').slice(0, 16)}`;
    }
    return this.#fingerprint;
  }

  toString(): string {
    return `[redacted ${this.fingerprint}]`;
  }

  toJSON(): string {
    return this.toString();
  }

  [inspect.custom](): string {
    return this.toString();
  }
}
