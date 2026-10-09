import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { scratch } from '../support/cp039-audit.js';
import { command, extractPackedArtifact } from './artifact.js';

it('CP-043/B4-clean-platform-suite actual packed files extract from platform absolute checkout path', async () => scratch(async dir => {
  const source = join(dir, 'package source'), extracted = join(dir, 'extracted files');
  mkdirSync(source); mkdirSync(extracted);
  writeFileSync(join(source, 'package.json'), JSON.stringify({ name: 'cp043-independent-package', version: '1.0.0', files: ['proof.txt'] }));
  const expected = 'independently planted packed contents\n'; writeFileSync(join(source, 'proof.txt'), expected);
  const packed = command(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['pack', '--json', '--ignore-scripts'], source);
  expect(packed.status).toBe(0);
  const filename = (JSON.parse(packed.stdout) as Array<{ filename: string }>)[0].filename;
  extractPackedArtifact(filename, source, extracted);
  expect(readFileSync(join(extracted, 'package', 'proof.txt'), 'utf8')).toBe(expected);
  expect(JSON.parse(readFileSync(join(extracted, 'package', 'package.json'), 'utf8'))).toMatchObject({ name: 'cp043-independent-package', version: '1.0.0' });
}), 30_000);
