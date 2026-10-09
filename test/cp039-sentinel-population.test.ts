import { mkdirSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from '../scripts/leak-check.mjs';
import { repo, scratch } from './support/cp039-audit.js';

it('CP-039/A3-leak-encodings rejects a matching empty sentinel file', async () => scratch(dir => {
  const file = join(dir, 'empty.macaroon'), list = join(dir, 'sentinels.json'), emptyDirectory = join(dir, 'empty-sentinels');
  mkdirSync(emptyDirectory); writeFileSync(file, '');
  writeFileSync(list, JSON.stringify([relative(repo, file).split(sep).join('/')]));
  let refused: boolean;
  try { refused = findLeaks({ sentinels: list, sentinelDir: emptyDirectory, root: repo, commandOutput: 'safe output' }) !== null; }
  catch { refused = true; }
  expect(refused, 'zero nonempty sentinels fail closed').toBe(true);
}));
