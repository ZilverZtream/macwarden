import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect } from 'vitest';
import { scratch } from '../support/cp039-audit.js';
import { command, extractPackedArtifact, files } from './artifact.js';

export const packedArtifactControl = () => scratch(dir => {
  const source = join(dir, 'package source'), extracted = join(dir, 'extracted files'), installed = join(dir, 'installed');
  mkdirSync(source); mkdirSync(join(source, 'bin')); mkdirSync(extracted); mkdirSync(installed);
  const expected = 'independent packed and installed command proof\n';
  writeFileSync(join(source, 'proof.txt'), expected);
  writeFileSync(join(source, 'bin/reader.cjs'), '#!/usr/bin/env node\n' +
    "process.stdout.write(require('node:fs').readFileSync(require('node:path').join(__dirname,'../proof.txt'),'utf8'));\n");
  writeFileSync(join(source, 'package.json'), JSON.stringify({ name: 'cp049-independent-package', version: '1.0.0',
    files: ['proof.txt','bin/reader.cjs'], bin: { cp049Proof: 'bin/reader.cjs' } }));
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const packed = command(npm, ['pack','--json','--ignore-scripts'], source);
  expect(packed.status).toBe(0);
  const filename = (JSON.parse(packed.stdout) as Array<{ filename: string }>)[0].filename;
  const tar = process.platform === 'win32' ? join(process.env.ProgramFiles || 'C:/Program Files', 'Git/usr/bin/tar.exe') : 'tar';
  if (process.platform === 'win32') expect(existsSync(tar), 'real Git GNU tar is required').toBe(true);
  expect(command(tar, ['--version'], source).stdout.includes('GNU tar')).toBe(true);
  if (process.platform === 'linux') expect(process.getuid!() > 0, 'Linux artifact evidence requires an unprivileged caller').toBe(true);
  extractPackedArtifact(filename, source, extracted, tar);
  expect(files(join(extracted, 'package'))).toEqual(['bin/reader.cjs','package.json','proof.txt']);
  expect(readFileSync(join(extracted, 'package/proof.txt'), 'utf8')).toBe(expected);
  expect(readFileSync(join(extracted, 'package/bin/reader.cjs')).equals(readFileSync(join(source,'bin/reader.cjs')))).toBe(true);
  const installation = command(npm, ['install','--prefix',installed,'./' + filename,'--ignore-scripts','--no-audit','--no-fund'], source);
  expect(installation.status).toBe(0);
  const shim = join(installed, 'node_modules/.bin', process.platform === 'win32' ? 'cp049Proof.cmd' : 'cp049Proof');
  expect(existsSync(shim)).toBe(true);
  const run = command(shim, [], installed);
  expect(run.status).toBe(0); expect(run.stdout).toBe(expected);
});
