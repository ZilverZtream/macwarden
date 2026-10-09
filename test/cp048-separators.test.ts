import { expect, it } from 'vitest';
import { render, type OutputResult } from '../src/output/index.js';
import { sentinel } from './support/cp041-controls.js';
import { auditedForms } from './support/cp048-separators.js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { leakStatus, scratch } from './support/cp041-controls.js';
for (const form of auditedForms) it(`CP-048/B1 peer error redacts ${form.name} in text and one JSON envelope`, () => {
  const echo = String(form.encode(sentinel()));
  const envelope: OutputResult = { schema: 1, command: 'inventory', ok: false, warnings: [], result: null,
    error: { code: 5, step: 'N4', message: `safe-left ${echo} safe-right` } };
  for (const mode of ['text', 'json'] as const) {
    const output = render(envelope, mode);
    expect(output.includes(echo), 'encoded sentinel absent').toBe(false);
    expect(output.includes('safe-left') && output.includes('safe-right')).toBe(true);
    if (mode === 'json') expect(JSON.parse(output).error.code).toBe(5);
  }
});
it('CP-048/B2 standing leak oracle detects every exact audited encoding and preserves benign control', () => scratch(dir => {
  mkdirSync(join(dir, 'runtime')); const path = join(dir, 'capture.txt');
  writeFileSync(path, 'safe benign output'); expect(leakStatus(path, dir)).toBe(0);
  for (const form of auditedForms) {
    writeFileSync(path, form.encode(sentinel()));
    expect.soft(leakStatus(path, dir), `${form.name} planted control detected`).toBe(1);
  }
}));
for (const form of auditedForms.filter(form => form.name.startsWith('decimal separator ')))
  it(`CP-048/B1 peer error redacts ${form.name} between out-of-range numeric context`, () => {
    const separator = form.name.slice(-1);
    const echo = String(form.encode(sentinel()));
    const left = `safe-left 999${separator}`, right = `${separator}999 safe-right`;
    const envelope: OutputResult = { schema: 1, command: 'inventory', ok: false, warnings: [], result: null,
      error: { code: 5, step: 'N4', message: `${left}${echo}${right}` } };
    for (const mode of ['text', 'json'] as const) {
      const output = render(envelope, mode);
      expect(output.includes(echo), 'encoded sentinel absent').toBe(false);
      const message = mode === 'json' ? JSON.parse(output).error.message : output;
      expect(message.includes(left), 'safe prefix retained').toBe(true);
      expect(message.includes(right), 'safe suffix retained').toBe(true);
    }
  });
