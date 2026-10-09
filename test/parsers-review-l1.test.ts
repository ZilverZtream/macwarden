// Parser review 2026-10-08, LOW-1: every redaction layer recognised credentials only after
// decoding escapes, so a hex macaroon right after "\" or "%" lost its anchor ("\020" read as
// an octal escape, "%02" as a percent escape) and passed through output unredacted.
import { createHmac, randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { redactEncodedCredentials } from '../src/credential-recognition.js';
import { render } from '../src/output/index.js';
import { redactDecoded } from '../src/scan/redact.js';

// A structurally valid synthetic macaroon with a random signature (no node's credential).
const field = (number: number, value: Buffer) => Buffer.concat([Buffer.from([number << 3 | 2, value.length]), value]);
const identifier = Buffer.concat([Buffer.from([3]), field(1, Buffer.alloc(16, 5)), field(2, Buffer.from('0')),
  field(3, Buffer.concat([field(1, Buffer.from('offchain')), field(2, Buffer.from('write'))]))]);
const signature = createHmac('sha256', randomBytes(32)).update(identifier).digest();
const macaroon = Buffer.concat([Buffer.from([2, 1, 3]), Buffer.from('lnd'), Buffer.from([2, identifier.length]), identifier,
  Buffer.from([0, 0, 6, 32]), signature]);
const hex = macaroon.toString('hex');
const B = '\\';

const forms: Record<string, string> = {
  hex,
  'upper-case hex': hex.toUpperCase(),
  'spaced hex': hex.match(/../g)!.join(' '),
  'wrapped hex': hex.replace(/(.{64})/g, '$1\n'),
};
const prefixes = [B, '%', `x${B}x`, `C:${B}k${B}`, `C:${B}keys${B}`, 'path%', `${B}${B}`, ' ', ''];

/** True when any 24-hex-digit window of the signature survives, ignoring case and separators. */
function leaks(output: string): boolean {
  const digits = output.toLowerCase().replace(/[^0-9a-f]/g, '');
  const secret = signature.toString('hex');
  for (let at = 0; at + 24 <= secret.length; at++) if (digits.includes(secret.slice(at, at + 24))) return true;
  return false;
}

const cases = prefixes.flatMap(prefix => Object.entries(forms).map(([form, text]) => ({ prefix, form, text: `${prefix}${text}` })));

it.each(cases)('PARSERS-L1/$form after $prefix is redacted by every output path', ({ form, text }) => {
  expect(leaks(text)).toBe(true);
  expect(leaks(redactEncodedCredentials(text))).toBe(false);
  expect(leaks(redactDecoded(text))).toBe(false);
  const json = render({ schema: 1, command: 'inspect', ok: true, warnings: [], error: null, result: { caveat: text } } as never, 'json');
  const plain = render({ schema: 1, command: null, ok: true, warnings: [], error: null, result: { text } } as never, 'text');
  expect(leaks(json)).toBe(false);
  // A plain text result is rendered line by line, so only single-line forms apply to it.
  if (form !== 'wrapped hex') expect(leaks(plain)).toBe(false);
});

it('PARSERS-L1/a stray backslash before a \\x-escaped credential does not hide its first byte', () => {
  // Found by the review's redaction fuzzer after the literal pass: "\" + "\x02\x02..." reads
  // as an escaped backslash, then "x02" as text, so the version byte was lost; the next layer
  // recovers it only when no decoded byte is itself a backslash (0x5c) starting an escape.
  const id = Buffer.concat([Buffer.from([3]), field(1, Buffer.from([0x5c, 0x34, 0x5c, 0x78, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])),
    field(2, Buffer.from('0')), field(3, Buffer.concat([field(1, Buffer.from('offchain')), field(2, Buffer.from('write'))]))]);
  const tricky = Buffer.concat([Buffer.from([2, 2, id.length]), id, Buffer.from([0, 0, 6, 32]), signature]);
  for (const bytes of [macaroon, tricky]) {
    const escaped = [...bytes].map(byte => `${B}x${byte.toString(16).padStart(2, '0')}`).join('');
    for (const prefix of [B, `a${B}`, `${B}${B}${B}`]) {
      const text = `${prefix}${escaped}A`;
      expect(leaks(redactEncodedCredentials(text)), prefix).toBe(false);
      expect(leaks(redactDecoded(text)), prefix).toBe(false);
    }
  }
  expect(redactEncodedCredentials(`C:${B}${B}dir${B}${B}file.txt`)).toBe(`C:${B}${B}dir${B}${B}file.txt`);
});

it('PARSERS-L1/the literal pass keeps surrounding text and still decodes real escapes', () => {
  expect(redactEncodedCredentials(`C:${B}keys${B}${hex} done`)).toBe(`C:${B}keys${B}[redacted] done`);
  expect(redactEncodedCredentials(`%${hex}`)).toBe('%[redacted]');
  // An escaped credential (each byte as \xNN) is still found by the decoding layers.
  const escaped = [...macaroon].map(byte => `${B}x${byte.toString(16).padStart(2, '0')}`).join('');
  expect(leaks(redactEncodedCredentials(`a${escaped}b`))).toBe(false);
  // Ordinary text with escapes is untouched.
  expect(redactEncodedCredentials(`path${B}to%20file ${B}x41 0201abcdef`)).toBe(`path${B}to%20file ${B}x41 0201abcdef`);
});
