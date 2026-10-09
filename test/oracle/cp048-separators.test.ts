import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { leakStatus, scratch, sentinel } from '../support/cp041-controls.js';
import { auditedForms } from '../support/cp048-separators.js';
for (const form of auditedForms) it(`CP-048/separator-ground-truth standing oracle detects planted ${form.name}`, () => scratch(dir => {
  mkdirSync(join(dir, 'runtime'));
  const path = join(dir, 'capture.txt');
  writeFileSync(path, 'safe benign output');
  expect(leakStatus(path, dir), 'benign control passes').toBe(0);
  writeFileSync(path, form.encode(sentinel()));
  expect(leakStatus(path, dir), 'independently encoded planted sentinel is detected').toBe(1);
}));
for (const form of auditedForms.filter(form => form.name.startsWith('decimal separator ')))
  it(`CP-048/separator-ground-truth standing oracle detects ${form.name} between out-of-range numeric context`, () => scratch(dir => {
    mkdirSync(join(dir, 'runtime'));
    const path = join(dir, 'capture.txt');
    const separator = form.name.slice(-1);
    const left = `safe-left 999${separator}`, right = `${separator}999 safe-right`;
    writeFileSync(path, `${left}ordinary text${right}`);
    expect(leakStatus(path, dir), 'benign numeric context passes').toBe(0);
    writeFileSync(path, `${left}${String(form.encode(sentinel()))}${right}`);
    expect(leakStatus(path, dir), 'independently encoded planted sentinel is detected').toBe(1);
  }));
