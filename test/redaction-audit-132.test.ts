// Redaction findings of audit 1.3.2: credential text that scan, inspect and the output layer
// recognise but printed in part. Synthetic credentials only (test/vectors, fixed seeds).
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeRuneText } from '../src/decode/rune.js';
import { redactCredentialText } from '../src/output/index.js';
import { runeReport, shownRuneText } from '../src/rune-report.js';
import { collectNwcSecrets, redactDecoded, redactKnownSecrets, redactPath } from '../src/scan/redact.js';
import { LINEAR_4X, growth } from './helpers/growth.js';
import { rune } from './support/runes.js';

const MACAROON = readFileSync('test/vectors/default-admin.macaroon');
const BASE64 = MACAROON.toString('base64');
const seeded = (label: string) => createHash('sha256').update(label).digest();
const PREIMAGE = seeded('audit-132 preimage').toString('hex');
const WALLET = seeded('audit-132 wallet').toString('hex');
const SECRET = seeded('audit-132 nwc secret').toString('hex');

/** Every `size`-character window of `value` found in `text`. */
function fragments(text: string, value: string, size: number): string[] {
  const found = new Set<string>();
  for (let i = 0; i + size <= value.length; i++) if (text.includes(value.slice(i, i + size))) found.add(value.slice(i, i + size));
  return [...found];
}

describe('AUDIT-132/L402 pairs in paths and decoded text', () => {
  // Before: encoded-credential redaction ran first, turned the macaroon into [redacted], and the
  // pair no longer matched, so the preimage was printed (a directory named <macaroon>:<preimage>).
  for (const [name, text] of [
    ['pair in a path', `/srv/${BASE64}:${PREIMAGE}/data.txt`],
    ['L402 header', `Authorization: L402 ${BASE64}:${PREIMAGE}`],
  ]) {
    it(`AUDIT-132/${name} has no preimage after redactPath or redactDecoded`, () => {
      for (const redact of [redactPath, redactDecoded]) {
        const safe = redact(text);
        expect(safe).not.toContain(PREIMAGE.slice(0, 16));
        expect(fragments(safe, BASE64, 16)).toEqual([]);
      }
    });
  }
});

describe('AUDIT-132/macaroon in a rune restriction', () => {
  const hex = MACAROON.toString('hex');
  const groups = (text: string, size: number, separator: string) => text.match(new RegExp(`.{1,${size}}`, 'g'))!.join(separator);
  const tail = (encoded: string) => encoded.replace(/\s/g, '').slice(-64);
  // Before: long tokens were replaced first, each hex group or base64 line on its own, and the
  // short last group or line (signature bytes) was no longer part of a recognised macaroon.
  for (const [name, encoded] of [
    ['hex in 64-character space-separated groups', groups(hex, 64, ' ')],
    ['base64 wrapped at 64 characters', groups(BASE64, 64, '\n')],
    ['base64 wrapped at 76 characters', groups(BASE64, 76, '\n')],
    ['base64 wrapped at 76 characters with CRLF', groups(BASE64, 76, '\r\n')],
  ]) {
    it(`AUDIT-132/${name} shows no fragment of the macaroon tail`, () => {
      const shown = shownRuneText(Buffer.from(encoded, 'latin1').toString('latin1'));
      expect(fragments(shown, tail(encoded), 8)).toEqual([]);
      expect(shown).toContain('[redacted]');
    });
  }

  it('AUDIT-132/a restriction value holding grouped hex is reported without the macaroon tail', () => {
    const decoded = decodeRuneText(rune(`=1&note=${groups(hex, 64, ' ')}`));
    if (!decoded.ok) throw new Error(decoded.reason);
    const rendered = JSON.stringify(runeReport(decoded.facts, 1_790_000_000n).report);
    expect(fragments(rendered, hex.slice(-64), 8)).toEqual([]);
  });
});

describe('AUDIT-132/NWC secrets', () => {
  const uri = (separator: string) => `nostr+walletconnect://${WALLET}?relay=wss://relay.example${separator}secret=${SECRET}`;
  const spaced = SECRET.match(/.{8}/g)!.join(' ');

  // Before: collection required "?" or "&" right before secret=, while the scanner and redaction
  // accept any separator, so the URI was redacted but the same secret elsewhere was printed.
  for (const separator of ['&amp;', ';']) {
    it(`AUDIT-132/a URI with ${separator}secret= has its secret collected and redacted elsewhere`, () => {
      const secrets = new Set<string>();
      collectNwcSecrets(uri(separator), secrets);
      expect([...secrets]).toEqual([SECRET]);
      expect(redactKnownSecrets(`caveat ${spaced} end`, secrets)).toBe('caveat [redacted] end');
    });
  }

  // Before: the scanner found these (nwcUnescaped) but redaction and collection did not.
  const escaped: [string, string][] = [
    ['JSON-escaped', uri('&').replace(/\//g, '\\/')],
    ['percent-encoded', encodeURIComponent(uri('&'))],
    ['"+" as a space', uri('&').replace('+', ' ')],
    ['percent-encoded "&amp;"', encodeURIComponent(uri('&amp;'))],
  ];
  for (const [name, text] of escaped) {
    it(`AUDIT-132/a ${name} URI is redacted and its secret collected`, () => {
      const line = `{"wallet": "${text}", "next": 1}`;
      for (const safe of [redactDecoded(line), redactPath(line), redactCredentialText(line)]) {
        expect(safe).not.toContain(SECRET);
        expect(safe).not.toContain(SECRET.slice(-16));
        expect(safe).toContain('[redacted]');
        expect(safe.endsWith('", "next": 1}')).toBe(true);
      }
      const secrets = new Set<string>();
      collectNwcSecrets(line, secrets);
      expect([...secrets]).toEqual([SECRET]);
    });
  }

  it('AUDIT-132/the delimiter after an escaped secret is kept as written', () => {
    const text = `${encodeURIComponent(uri('&'))}%26lud16%3Dx`;
    expect(redactCredentialText(text)).toBe('[redacted]%26lud16%3Dx');
  });

  // The escaped copy is matched with the same linear matcher: repeated prefixes stay linear.
  it('AUDIT-132/repeated escaped NWC prefixes four times longer are collected and redacted at about four times the cost', async () => {
    for (const prefix of [`nostr%2Bwalletconnect%3A%2F%2F${WALLET}%3F`, `nostr+walletconnect:\\/\\/${WALLET}?`, `nostr walletconnect://${WALLET}?`]) {
      const repeated = (size: number) => prefix.repeat(Math.ceil(size / prefix.length));
      const collect = (size: number) => {
        const text = repeated(size);
        return () => { const secrets = new Set<string>(); collectNwcSecrets(text, secrets); expect(secrets.size).toBe(0); };
      };
      const redact = (size: number) => { const text = repeated(size); return () => redactCredentialText(`${text}x`); };
      for (const [name, work, n] of [['collect', collect, 512 * 1024], ['redact', redact, 64 * 1024]] as const) {
        const timing = await growth(work, n, 4, 5);
        expect(timing.ratio, `${prefix.slice(0, 12)} ${name}: ${timing.summary}`).toBeLessThan(LINEAR_4X);
      }
    }
  }, 120_000);
});

describe('AUDIT-132/a known NWC secret inside a longer base64 run', () => {
  // Before: only the standalone base64 and base64url forms were needles, so a secret at byte
  // alignment 1 or 2, or followed by more bytes, inside a longer run was not matched.
  const secret = Buffer.from(SECRET, 'hex');
  const secrets = new Set([SECRET]);
  for (const prefixLength of [0, 1, 2, 4, 5]) {
    for (const encoding of ['base64', 'base64url'] as const) {
      it(`AUDIT-132/${encoding} after ${prefixLength} byte(s) and before more bytes is redacted`, () => {
        const before = Buffer.alloc(prefixLength, 0xa5);
        const run = Buffer.concat([before, secret, Buffer.from([0x5a, 0x5a, 0x5a, 0x01])]).toString(encoding);
        const safe = redactKnownSecrets(`x ${run} y`, secrets);
        expect(safe).toContain('[redacted]');
        // The characters that depend on the secret alone are gone: no 12-character window remains.
        const first = Math.ceil(prefixLength * 8 / 6);
        const last = Math.floor((prefixLength + 32) * 8 / 6);
        expect(fragments(safe, run.slice(first, last), 12)).toEqual([]);
      });
    }
  }

  it('AUDIT-132/a wrapped base64 run holding the secret at alignment 1 is redacted', () => {
    const run = Buffer.concat([Buffer.from([1, 2, 3, 4]), secret, Buffer.from([9, 9])]).toString('base64');
    const wrapped = run.match(/.{1,20}/g)!.join('\n');
    const safe = redactKnownSecrets(wrapped, secrets);
    expect(fragments(safe.replace(/\n/g, ''), run.slice(8, 50), 12)).toEqual([]);
  });
});
