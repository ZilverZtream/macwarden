import { expect, it } from 'vitest';
import { buildAccessReview, formatAccessReview, REPORT_FORMATS } from '../src/report/access-review.js';
import { token } from './helpers/l402-vectors.js';
import { rune } from './support/runes.js';

// Audit 1.3.2: the access review redacted encoded macaroons only, and before anything else, so an
// L402 value kept its preimage (macaroon redacted, ':<preimage>' left), and NWC secrets and runes in
// key context were written as they are. `inventory --report --out` writes this text straight to a
// file. Synthetic values only: a token from the L402 test vectors, a fixed-authenticator rune.
it('REPORT/redaction every format redacts L402 preimages, NWC secrets and runes in every field', () => {
  const paid = token(303);
  const preimage = paid.preimage.toString('hex');
  const walletSecret = 'e'.repeat(64);
  const nwc = `nostr+walletconnect://${'b'.repeat(64)}?relay=wss%3A%2F%2Frelay.example&secret=${walletSecret}`;
  const cln = rune('=0&method=getinfo');
  const node = { pubkey: '02'.padEnd(66, 'a'), alias: `L402 ${paid.base64}:${preimage}`, network: 'regtest',
    version: `${nwc} rune=${cln} again ${walletSecret}` };
  const review = buildAccessReview({ node, entries: [], ownRootKeyId: '1', now: new Date(0), version: '0.0.0', ids: [] });
  for (const format of REPORT_FORMATS) {
    const text = formatAccessReview(review, format).toLowerCase();
    expect(text, format).not.toContain(preimage);
    expect(text, format).not.toContain(walletSecret);
    expect(text, format).not.toContain(cln.toLowerCase());
    expect(text, format).not.toContain(paid.base64.slice(8, 40).toLowerCase());
    // CSV rows hold credentials only, not the node's alias and version.
    if (format !== 'csv') expect(text, format).toMatch(/redacted/);
  }
});
