import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { decodeMacaroon } from '../src/decode/index.js';
import { render } from './helpers/render-adversarial.js';
import { Secret } from '../src/secret.js';

const repo = resolve();
const malformedHex = '0201036c6e6402' + 'a'.repeat(40);
const malformedBase64 = 'AgEDbG5kA' + 'A'.repeat(40);
const marker = 'ordinary-output-marker';
const envelope = (message: string) => ({ schema: 1 as const, command: 'inspect', ok: true,
  warnings: [], result: { message }, error: null });

function escapedText(value: string): string {
  return [...value].map(character => {
    const code = character.charCodeAt(0);
    return code < 32 || code === 127 || (code >= 128 && code <= 159)
      ? `\\x${code.toString(16).padStart(2, '0')}` : character;
  }).join('');
}

function expectExactRendering(message: string, expected: string): void {
  const json = JSON.parse(render(envelope(message), 'json')) as ReturnType<typeof envelope>;
  expect.soft(JSON.stringify(json) === JSON.stringify(envelope(expected)), 'whole JSON envelope').toBe(true);

  const template = render(envelope(marker), 'text');
  expect(template.split(marker).length, 'text marker occurs exactly once').toBe(2);
  const expectedText = template.replace(marker, escapedText(expected));
  expect.soft(render(envelope(message), 'text') === expectedText, 'whole escaped text output').toBe(true);
}

it('CP-037/C-ordinary-text-identity preserves the rejected macaroon-shaped hex string', () => {
  expect(() => decodeMacaroon(new Secret(Buffer.from(malformedHex, 'hex'))),
    'the pattern cannot decode as a macaroon').toThrow();
  const message = `prefix ${malformedHex} suffix`;
  expectExactRendering(message, message);
});

it('CP-037/C-ordinary-text-identity preserves Unicode and escaped controls beside rejected hex', () => {
  expect(() => decodeMacaroon(new Secret(Buffer.from(malformedHex, 'hex'))),
    'the pattern cannot decode as a macaroon').toThrow();
  const message = `préfixe Ω\x1b ${malformedHex} \x7f\x9b suffix`;
  expectExactRendering(message, message);
});

it('CP-037/C-ordinary-text-identity preserves a rejected base64-shaped string', () => {
  expect(() => decodeMacaroon(new Secret(Buffer.from(malformedBase64, 'base64'))),
    'the pattern cannot decode as a macaroon').toThrow();
  const message = `prefix ${malformedBase64} suffix`;
  expectExactRendering(message, message);
});

it('CP-037/C-ordinary-text-identity preserves a caveat with an ordinary lndconnect URL', () => {
  const url = 'lndconnect://node.example/?foo=bar';
  expect(new URL(url).searchParams.has('macaroon'), 'the URL has no credential parameter').toBe(false);
  const message = `unknown caveat préfixe Ω\x1b ${url} \x7f\x9b suffix`;
  expectExactRendering(message, message);
});

it('CP-037/C-ordinary-text-identity preserves an lndconnect URL with a rejected macaroon parameter', () => {
  expect(() => decodeMacaroon(new Secret(Buffer.from(malformedHex, 'hex'))),
    'the parameter cannot decode as a macaroon').toThrow();
  const url = `lndconnect://node.example/?foo=bar&macaroon=${malformedHex}&label=safe`;
  expect(new URL(url).searchParams.get('macaroon') === malformedHex,
    'the URL carries the rejected parameter').toBe(true);
  const message = `unknown caveat préfixe ${url} suffix Ω`;
  expectExactRendering(message, message);
});

it('CP-037/C-ordinary-text-identity redacts a fixture credential in an lndconnect URL', () => {
  const bytes = readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
  expect(() => decodeMacaroon(new Secret(bytes)), 'fixture must decode').not.toThrow();
  const credential = bytes.toString('hex');
  const url = `lndconnect://node.example/?foo=bar&macaroon=${credential}&label=safe`;
  const message = `unknown caveat préfixe ${url} suffix Ω`;
  const json = render(envelope(message), 'json');
  const text = render(envelope(message), 'text');
  const parsed = JSON.parse(json) as ReturnType<typeof envelope>;
  expect(json.includes(credential), 'JSON excludes the credential').toBe(false);
  expect(text.includes(credential), 'text excludes the credential').toBe(false);
  expect(json.includes(credential.slice(-24)), 'JSON excludes the signature tail').toBe(false);
  expect(text.includes(credential.slice(-24)), 'text excludes the signature tail').toBe(false);
  expect(parsed.result?.message.startsWith('unknown caveat préfixe '), 'JSON keeps the safe prefix').toBe(true);
  expect(parsed.result?.message.endsWith(' suffix Ω'), 'JSON keeps the safe suffix').toBe(true);
  expect(parsed.result?.message.includes('[redacted]'), 'JSON marks the credential').toBe(true);
  expect(text.includes('préfixe '), 'text keeps the safe prefix').toBe(true);
  expect(text.includes(' suffix Ω'), 'text keeps the safe suffix').toBe(true);
  expect(text.includes('[redacted]'), 'text marks the credential').toBe(true);
});

it('CP-037/C-ordinary-text-identity still redacts a confirmed fixture credential', () => {
  const bytes = readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
  expect(() => decodeMacaroon(new Secret(bytes)), 'fixture must decode').not.toThrow();
  expectExactRendering(`prefix ${bytes.toString('hex')} suffix`, 'prefix [redacted] suffix');
});
