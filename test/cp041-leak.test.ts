import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { leakForms, leakStatus, scratch, sentinel } from './support/cp041-controls.js';

for (const form of leakForms) it(`CP-041/B4-independent-leak-controls detects ${form.name} in gate output and neighboring scratch`, () => scratch(dir => {
  mkdirSync(join(dir, 'runtime')); const capture = join(dir, 'gate-output.txt'), neighbor = join(dir, 'neighbor.json');
  writeFileSync(capture, form.encode(sentinel()));
  expect.soft(leakStatus(capture, dir), 'planted independent encoding fails public leak CLI').toBe(1);
  writeFileSync(capture, 'safe output');
  writeFileSync(neighbor, form.encode(sentinel()));
  expect.soft(leakStatus(dir, dir), 'neighboring non-output files remain scanned').toBe(1);
}));
it('CP-041/B4-independent-leak-controls excludes exactly declared product output and passes clean redacted captures', () => scratch(dir => {
  mkdirSync(join(dir, 'runtime')); const product = join(dir, 'issued.macaroon'), capture = join(dir, 'capture.txt');
  writeFileSync(product, sentinel()); writeFileSync(capture, 'safe-left [redacted] safe-right');
  writeFileSync(join(dir, 'declared-out.txt'), product + '\n');
  expect(leakStatus(dir, dir), 'clean output with exactly declared credential file').toBe(0);
  const neighboring = join(dir, 'issued.macaroon.log'); writeFileSync(neighboring, sentinel());
  expect(leakStatus(dir, dir), 'same prefix is not an output exemption').toBe(1);
}));
for (const kind of ['empty list', 'empty file', 'missing file'] as const) {
  it(`CP-041/B4-independent-leak-controls refuses ${kind} sentinel authority`, () => scratch(dir => {
    mkdirSync(join(dir, 'runtime')); const capture = join(dir, 'capture.txt'), list = join(dir, 'list.json');
    const empty = join(dir, 'empty.macaroon'); writeFileSync(empty, Buffer.alloc(0)); writeFileSync(capture, 'safe output');
    writeFileSync(list, JSON.stringify(kind === 'empty list' ? [] : [kind === 'empty file' ? empty : join(dir, 'missing.macaroon')]));
    expect(leakStatus(capture, dir, list) !== 0, 'nonempty registered bytes required for PASS').toBe(true);
  }));
}
