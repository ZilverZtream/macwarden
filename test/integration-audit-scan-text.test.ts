import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { render } from '../src/output/index.js';
import { scan } from '../src/scan/index.js';
import { scratch, vector } from './support/cp039-audit.js';

// Audit 1.4.0: files never opened because their names look like wallet secrets (SAFE-02) are named
// in the plain text output too, before the summary, so a reader sees what the scan did not check.
it('scan text output lists each never-opened file before the summary', async () => scratch(async dir => {
  const admin = vector('default-admin').bytes.toString('hex');
  mkdirSync(join(dir, 'prisma'));
  writeFileSync(join(dir, 'prisma', 'seed.ts'), `export const m = '${admin}';\n`);
  writeFileSync(join(dir, 'app.ts'), 'const ok = 1;\n');
  const result = await scan([dir]);
  const text = render({ command: 'scan', ok: true, warnings: [], error: null, result }, 'text');
  const lines = text.split('\n');
  const never = lines.findIndex(line => line.startsWith('never-opened  '));
  expect(lines[never]).toMatch(/^never-opened {2}.*prisma[\\/]seed\.ts {2}\(name matches a protected pattern; not scanned\)$/);
  expect(lines.filter(line => line.startsWith('never-opened  '))).toHaveLength(1);
  const summary = lines.findIndex(line => /^\d+ findings \(/.test(line));
  expect(never).toBeGreaterThanOrEqual(0);
  expect(never).toBeLessThan(summary);
  expect(text).not.toContain(admin);
}));
