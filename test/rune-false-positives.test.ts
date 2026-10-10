import { join } from 'node:path';
import { expect, it } from 'vitest';
import { repo, root } from './support/cp039-audit.js';

// The false-positive and recall measurement (scripts/rune-false-positives.mjs) on a reduced corpus.
// Only the properties that hold by design are asserted here: without rune context nothing is
// reported, a value in rune context is never dropped silently, and a rune in any supported context
// and variant (quoting, blanks, CRLF, CR, BOM, UTF-16) is found. The measured rates are reported by
// the script itself (docs/spec.md, Core Lightning runes > Measured false-positive and false-negative rates).
type Row = { values: number; rune: number; runeInvalid: number };
type Script = {
  measure(options: { perClass: number; seed: number; distRoot: string; scratchRoot: string }): Promise<{
    settings: Record<string, Row & { falsePositives: number; classes: Record<string, Row> }> }>;
  measureRecall(options: { perContext: number; seed: number; distRoot: string; scratchRoot: string }): Promise<{
    runes: number; found: number; missed: unknown[]; contexts: Record<string, { runes: number; found: number }> }>;
};

it('RUNE/false-positives no rune finding without rune context; every rune-context value is reported', async () => {
  const { measure } = await import('../scripts/rune-false-positives.mjs') as unknown as Script;
  const report = await measure({ perClass: 200, seed: 7, distRoot: join(repo, 'dist'), scratchRoot: root() });
  expect(report.settings['no-context'].falsePositives).toBe(0);
  // Classes whose every value is one run of at least 43 base64 characters: a rune candidate in rune context.
  for (const name of ['random-base64url', 'random-base64url-padded', 'random-base64', 'random-alphabet-text', 'hex-sha256',
    'hex-node-id', 'stripe-key', 'bolt11-invoice', 'ssh-public-key', 'pem-body-line', 'lnd-macaroon-hex', 'lnd-macaroon-base64',
    'lnd-macaroon-base64url', 'l402-pair']) {
    const row = report.settings.key.classes[name];
    expect(row.rune + row.runeInvalid, name).toBe(row.values);
  }
}, 60_000);

it('RUNE/false-positives a rune is found in every supported context and variant', async () => {
  const { measureRecall } = await import('../scripts/rune-false-positives.mjs') as unknown as Script;
  const recall = await measureRecall({ perContext: 18, seed: 7, distRoot: join(repo, 'dist'), scratchRoot: root() });
  expect(recall.missed).toEqual([]);
  expect(recall.found).toBe(recall.runes);
  expect(Object.keys(recall.contexts).length).toBeGreaterThanOrEqual(30);
}, 60_000);
