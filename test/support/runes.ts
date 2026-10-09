// Synthetic Core Lightning runes for unit tests (1.2.0). A rune is URL-safe base64 of a 32-byte
// authenticator followed by the restriction text; these use a fixed or random authenticator, so
// they carry no authority on any node. Expected values are built here independently of the parser.
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

export const repo = resolve();
export const FIXED_AUTHENTICATOR = Buffer.alloc(32, 0x5a);

/** rune_altern_encode: '\', '|' and '&' in a value are escaped. */
export function escapeValue(value: string): string {
  return value.replace(/[\\|&]/g, match => `\\${match}`);
}

/** Restriction text from restrictions given as alternatives "field<condition>value" with raw values. */
export function restrictionText(restrictions: [string, string, string][][]): string {
  return restrictions.map(restriction => restriction.map(([field, condition, value]) =>
    `${field}${condition}${escapeValue(value)}`).join('|')).join('&');
}

/** A rune as Core Lightning writes it: padded URL-safe base64 of authenticator + restriction bytes. */
export function rune(text: string, authenticator: Buffer = FIXED_AUTHENTICATOR, encoding: 'latin1' | 'utf8' = 'utf8'): string {
  const raw = Buffer.concat([authenticator, Buffer.from(text, encoding)]).toString('base64url');
  return raw + '='.repeat((4 - raw.length % 4) % 4);
}

/** The bytes a rune's fingerprint covers: authenticator and restriction text. */
export function runeBytes(text: string, authenticator: Buffer = FIXED_AUTHENTICATOR): Buffer {
  return Buffer.concat([authenticator, Buffer.from(text, 'utf8')]);
}

export function runeFingerprint(text: string, authenticator: Buffer = FIXED_AUTHENTICATOR): string {
  return `fp:${createHash('sha256').update(runeBytes(text, authenticator)).digest('hex').slice(0, 16)}`;
}

/** A rune with a fresh random authenticator, for leak tests that register it as a sentinel. */
export function freshRune(text: string): { rune: string; bytes: Buffer; authenticator: Buffer } {
  const authenticator = randomBytes(32);
  return { rune: rune(text, authenticator), bytes: runeBytes(text, authenticator), authenticator };
}

export type CcanVector = { kind: string; fields: string[] };

/** The vendored ccan rune test vectors (test/vendor/README.md), one row per line. */
export function ccanVectors(): CcanVector[] {
  return readFileSync(join(repo, 'test/vendor/ccan-rune-test-vectors.csv'), 'utf8').split(/\r?\n/).filter(Boolean)
    .map(line => { const fields = line.split(','); return { kind: fields[0], fields }; });
}
