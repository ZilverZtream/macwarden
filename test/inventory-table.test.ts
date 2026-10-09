import { expect, it } from 'vitest';
import { inventoryResult, render } from '../src/output/index.js';

const created = '2026-09-01T00:00:00Z';
const entry = (label: string, grade: string) => ({ label, grade, permissions: [], caveats: [], createdAt: created,
  status: 'active', fingerprint: null, outPath: null, replaces: null, replacedBy: null });

it('UX/inventory-table text columns line up under their headers', () => {
  const result = inventoryResult({ node: { pubkey: '02' + 'ab'.repeat(32), alias: 'node', network: 'regtest', version: '0.21.4-beta' },
    rootKeys: [
      { rootKeyId: '0', inLnd: true, flags: ['default-root-key'], verify: 'not-checked', expires: null, entry: null },
      { rootKeyId: '4294967341', inLnd: true, flags: [], verify: 'not-checked', expires: null, entry: entry('btcpay', 'RECEIVE') },
      { rootKeyId: '18446744073709551615', inLnd: true, flags: [], verify: 'not-checked', expires: '2026-12-31T00:00:00Z',
        entry: entry('a-much-longer-label', 'SPEND') },
    ] } as never, [], new Date('2026-10-08T00:00:00Z'));
  const lines = render(result, 'text').trimEnd().split('\n').slice(1);
  // Every column starts at the same offset as its header on every row.
  const starts = (line: string) => [...line.matchAll(/(?:^|\s{2})(\S)/g)].map(match => match.index! + match[0].length - 1);
  const header = lines[0];
  const columns = ['ROOT KEY ID', 'LABEL', 'GRADE', 'AGE', 'EXPIRES', 'STATUS'].map(name => header.indexOf(name));
  expect(columns.every(index => index >= 0)).toBe(true);
  for (const line of lines.slice(1)) expect(starts(line).slice(0, 6)).toEqual(columns);
});
