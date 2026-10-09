import { join } from 'node:path';
import { expect, it } from 'vitest';
import { repo, root } from './support/cp039-audit.js';

// The false-positive measurement (scripts/rune-false-positives.mjs) on a reduced corpus. Only the
// properties that hold by design are asserted here: without rune context nothing is reported, and
// a value in rune context is never dropped silently. The measured rates are reported by the
// script itself (docs/spec.md, Core Lightning runes > Measured false-positive rate).
it('RUNE/false-positives no rune finding without rune context; every rune-context value is reported', async () => {
  const { measure } = await import('../scripts/rune-false-positives.mjs') as {
    measure(options: { perClass: number; seed: number; distRoot: string; scratchRoot: string }): Promise<{
      settings: Record<string, { values: number; rune: number; runeInvalid: number; falsePositives: number;
        classes: Record<string, { values: number; rune: number; runeInvalid: number }> }> }> };
  const report = await measure({ perClass: 200, seed: 7, distRoot: join(repo, 'dist'), scratchRoot: root() });
  expect(report.settings['no-context'].falsePositives).toBe(0);
  // Classes whose every value is one run of at least 43 base64 characters: a rune candidate in rune context.
  for (const name of ['random-base64url', 'random-base64url-padded', 'random-base64', 'random-alphabet-text', 'hex-sha256',
    'hex-node-id', 'stripe-key', 'bolt11-invoice', 'ssh-public-key', 'pem-body-line']) {
    const row = report.settings.key.classes[name];
    expect(row.rune + row.runeInvalid, name).toBe(row.values);
  }
}, 60_000);
