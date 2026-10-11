import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { scan } from '../src/scan/index.js';
import { scratch, vector } from './support/cp039-audit.js';

for (const name of ['default-admin', 'default-readonly', 'default-invoice']) {
  it(`a percent-encoded standard base64 macaroon is found and decoded: ${name}`, async () => scratch(async dir => {
    const v = vector(name);
    const path = join(dir, 'request.log');
    writeFileSync(path, `POST /x body: macaroon=${encodeURIComponent(v.bytes.toString('base64'))}&a=1\n`);
    const result = await scan([path]);
    expect(result.findings.map(f => [f.column, f.kind, f.fingerprint, f.grade]))
      .toEqual([['POST /x body: macaroon='.length + 1, 'macaroon-base64', v.fingerprint, v.expectedGrade]]);
  }));
}

it('an explicit node_modules or .git argument is scanned, not skipped as an excluded directory', async () => scratch(async dir => {
  const admin = vector('default-admin');
  for (const name of ['node_modules', '.git']) {
    mkdirSync(join(dir, name));
    writeFileSync(join(dir, name, 'a.env'), `A=${admin.bytes.toString('hex')}\n`);
    const result = await scan([join(dir, name)]);
    expect(result.findings.map(f => f.fingerprint), name).toEqual([admin.fingerprint]);
    expect(result.skipped, name).toEqual([]);
  }
  // Below an argument the names are still excluded.
  const walked = await scan([dir]);
  expect(walked.findings).toEqual([]);
  expect(walked.skipped.map(item => item.reason)).toEqual(['excluded-dir', 'excluded-dir']);
}));
