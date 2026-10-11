import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { redactEncodedCredentials } from '../src/credential-recognition.js';
import { macaroonEnds } from '../src/decode/recognition.js';
import { LINEAR_4X, compare } from './helpers/growth.js';
import { nestedCandidates } from './helpers/decode-audit-vectors.js';

// Audit 1.4.0: identifier validity was cached only per start offset, so nested candidate headers
// sharing one long identifier tail were each parsed to its end and recognition cost n * m.
// Synthetic bytes only; the vectors under test/vectors are read by path.

it('DECODE-AUDIT/recognition nested candidates four times larger cost about four times as much', async () => {
  const text = (n: number) => `x ${nestedCandidates(n, 4 * n).toString('base64')}`;
  const small = text(2_000), large = text(8_000);
  const work = (value: string) => () => redactEncodedCredentials(value);
  const timing = await compare(work(small), work(large), 3);
  console.log(`DECODE-AUDIT/recognition nested n=2,000 and n=8,000: ${timing.summary}`);
  expect(timing.ratio, timing.summary).toBeLessThan(LINEAR_4X);
}, 120_000);

it('DECODE-AUDIT/recognition the parse budget never stops a real credential being recognised', () => {
  for (const name of ['default-admin', 'default-readonly']) {
    const bytes = readFileSync(resolve(`test/vectors/${name}.macaroon`));
    expect(macaroonEnds(bytes)(0), name).toBe(bytes.length);
    for (const encoded of [bytes.toString('hex'), bytes.toString('base64')]) {
      // Many real credentials in one value: each is still found and redacted whole.
      const value = Array.from({ length: 64 }, () => encoded).join(' ');
      expect(redactEncodedCredentials(value)).toBe(Array.from({ length: 64 }, () => '[redacted]').join(' '));
    }
  }
  // After a nested-candidate corpus that spends the parse budget, a real credential is still
  // redacted, separate or adjacent, in hex and base64.
  const corpus = nestedCandidates(2_000, 8_000);
  const readonly = readFileSync(resolve('test/vectors/default-readonly.macaroon'));
  for (const encoding of ['hex', 'base64'] as const) {
    const credential = readonly.toString(encoding);
    for (const value of [`${corpus.toString(encoding)} ${credential}`, Buffer.concat([corpus, readonly]).toString(encoding)]) {
      const out = redactEncodedCredentials(value);
      expect(out.includes(credential.slice(-24)), encoding).toBe(false);
      expect(out).toContain('[redacted]');
    }
  }
  // Text that only looks like a macaroon start is left alone.
  expect(macaroonEnds(Buffer.from([2, 2, 1, 3, 0, 0, 6, 32, ...Buffer.alloc(32)]))(0)).toBeNull();
});
