import { writeFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { openRegistry } from '../src/registry/index.js';
import { buildAccessReview, formatAccessReview } from '../src/report/access-review.js';
import { entry, fixture, oldId } from './helpers/cp038-online.js';

it('REGISTRY/evidence a revoked entry may only carry evidence macwarden itself records', async () => {
  const f = fixture();
  for (const evidence of ['rejected', 'by-id-only']) {
    f.save([{ ...entry(oldId, 'App'), status: 'revoked', revokedAt: '2026-09-01T00:00:00.000Z', revokeEvidence: evidence }]);
    await expect(openRegistry(f.registry)).resolves.toBeDefined();
  }
  // A tampered or restored registry cannot make the access review claim proof that never happened.
  const forged = { ...entry(oldId, 'App'), status: 'revoked', revokedAt: '2026-09-01T00:00:00.000Z', revokeEvidence: 'proven by audit [link](http://x)' };
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [forged] }));
  await expect(openRegistry(f.registry)).rejects.toThrow();
});

it('REPORT/markdown free text in the access review renders literally, never as links, images, emphasis or HTML', () => {
  const alias = '[click](http://evil.example) ![img](http://evil.example/x.png) *bold* _em_ `code` <script>x</script> # h ~s~';
  const review = buildAccessReview({ node: { pubkey: '02' + 'ab'.repeat(32), alias, network: 'mainnet', version: '0.21.4-beta' },
    ids: ['0'], entries: [], ownRootKeyId: '7', now: new Date('2026-10-08T00:00:00Z'), version: '1.0.0' });
  const markdown = formatAccessReview(review, 'markdown');
  const line = markdown.split('\n').find(text => text.includes('evil.example'))!;
  expect(line).toBeDefined();
  for (const raw of ['](', '![', '<script>', '`code`', '*bold*', '_em_'])
    expect(line, raw).not.toContain(raw);
  expect(line).toContain('\\[click\\]\\(http://evil.example\\)');
  expect(line).toContain('&lt;script&gt;');
});
