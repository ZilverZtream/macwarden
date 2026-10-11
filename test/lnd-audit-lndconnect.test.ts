import { expect, it } from 'vitest';
import { parseLndconnect } from '../src/input/lndconnect.js';

// Audit 1.4.0 (LND section): exactly one `macaroon` parameter, its key compared percent-decoded.
// Synthetic bytes 02 01 03 04 05, not a credential.
const m = Buffer.from([2, 1, 3, 4, 5]).toString('base64url');
it('LND-audit lndconnect refuses a percent-encoded second macaroon key', () => {
  for (const uri of [`lndconnect://h:1?%6Dacaroon=AAAA&macaroon=${m}`, `lndconnect://h:1?macaroon=${m}&%6d%61caroon=AAAA`,
    `lndconnect://h:1?%6Dacaroon=${m}&macaroon=${m}`, `lndconnect://h:1?%6Dacaroon&macaroon=${m}`])
    expect(parseLndconnect(uri), uri).toBeNull();
  for (const uri of [`lndconnect://h:1?%6Dacaroon=AAAA&macaroon=${m}`])
    expect(parseLndconnect(uri, { standardBase64: true }), uri).toBeNull();
});

it('LND-audit lndconnect still reads one macaroon parameter, however its key is written', () => {
  expect(parseLndconnect(`lndconnect://h:1?cert=x&macaroon=${m}`)?.toString('hex')).toBe('0201030405');
  expect(parseLndconnect(`lndconnect://h:1?%6Dacaroon=${m}`)?.toString('hex')).toBe('0201030405');
  // A key with a malformed escape is not the macaroon parameter, and does not hide the real one.
  expect(parseLndconnect(`lndconnect://h:1?x%ZZ=1&macaroon=${m}`)?.toString('hex')).toBe('0201030405');
  expect(parseLndconnect(`lndconnect://h:1?macaroon`)).toBeNull();
  expect(parseLndconnect(`lndconnect://h:1?macaroon&macaroon=${m}`)).toBeNull();
});
