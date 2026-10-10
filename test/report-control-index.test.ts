import { expect, it } from 'vitest';
import { buildAccessReview, formatAccessReview } from '../src/report/access-review.js';
import { growth, LINEAR_4X } from './helpers/growth.js';

const node = { pubkey: '02'.padEnd(66, 'a'), alias: 'synthetic', network: 'regtest', version: '0.21.4-beta' };
const review = (count: number) => buildAccessReview({ node, entries: [], ownRootKeyId: '1', now: new Date(0), version: '0.0.0',
  ids: Array.from({ length: count }, (_, index) => String(1000 + index)) });

// Audit O04: every CSV row searched each control's root key ID list, so N unknown IDs that
// one control names cost N(N+1) comparisons. The membership index is built once per report.
it('REPORT/csv names each row\'s controls in control order and grows linearly with the credential count', async () => {
  const lines = formatAccessReview(review(3), 'csv').trimEnd().split('\r\n');
  const header = lines[0].split(',');
  const at = header.indexOf('controls');
  expect(at).toBeGreaterThan(0);
  expect(lines.slice(1).map(line => line.split(',')[at])).toEqual(Array(3).fill('Periodic access review'));
  // Root key ID 0 used as macwarden's own credential is named by two controls, in report order.
  const shared = buildAccessReview({ node, entries: [], ownRootKeyId: '0', now: new Date(0), version: '0.0.0', ids: ['5', '0'] });
  const rows = formatAccessReview(shared, 'csv').trimEnd().split('\r\n').slice(1).map(line => line.split(',')[at]);
  expect(rows).toEqual(['Least privilege; Periodic access review', 'Periodic access review']);

  const timing = await growth(size => {
    const built = review(size);
    return () => formatAccessReview(built, 'csv');
  }, 10_000, 4);
  expect(timing.ratio, timing.summary).toBeLessThan(LINEAR_4X);
}, 120_000);
