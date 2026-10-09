import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from '../scripts/leak-check.mjs';
import { auditEncodings, noCredential, repo, scratch, sentinel, sentinelList } from './support/cp039-audit.js';

const bytes = sentinel();
for (const [name, encoded] of auditEncodings(bytes)) {
  it(`CP-039/A3-leak-encodings detects ${name} in independent captures`, async () => scratch(dir => {
    const path = join(dir, 'capture.txt');
    writeFileSync(path, encoded);
    const hit = findLeaks({ sentinels: sentinelList, root: repo, paths: [path] });
    expect.soft(hit !== null, `${name} positive control`).toBe(true);
    noCredential(JSON.stringify(hit));
    if (typeof encoded === 'string') {
      expect.soft(findLeaks({ sentinels: sentinelList, root: repo, commandOutput: encoded }) !== null,
        `${name} command output control`).toBe(true);
    }
    const changed = Buffer.from(bytes); changed[changed.length - 1] ^= 1;
    const control = auditEncodings(changed).find(([label]) => label === name)![1];
    writeFileSync(path, control);
    expect(findLeaks({ sentinels: sentinelList, root: repo, paths: [path] }) === null,
      `${name} negative control`).toBe(true);
  }));
}
it('CP-039/A3-leak-encodings rejects zero nonempty sentinels and accepts benign output', async () => scratch(dir => {
  const list = join(dir, 'sentinels.json'); writeFileSync(list, '[]');
  let refused: boolean;
  try { refused = findLeaks({ sentinels: list, root: repo, commandOutput: 'ordinary safe output' }) !== null; }
  catch { refused = true; }
  expect(refused, 'missing sentinels must fail closed').toBe(true);
  expect(findLeaks({ sentinels: sentinelList, root: repo, commandOutput: 'ordinary safe output' })).toBeNull();
}));
