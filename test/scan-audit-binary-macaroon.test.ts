import { mkdirSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { scan } from '../src/scan/index.js';
import { token, tokenFile } from './helpers/l402-vectors.js';
import { scratch, vector } from './support/cp039-audit.js';

const facts = (result: Awaited<ReturnType<typeof scan>>) =>
  result.findings.map(finding => [finding.path.split('/').pop(), finding.kind, finding.fingerprint, finding.grade]);

it('a raw binary LND macaroon is read as a macaroon file whatever its name', async () => scratch(async dir => {
  const admin = vector('default-admin');
  const names = ['admin.macaroon.bak', 'admin.mac', 'macaroon'];
  for (const name of names) writeFileSync(join(dir, name), admin.bytes);
  const result = await scan([dir]);
  expect(facts(result)).toEqual(names.sort().map(name => [name, 'macaroon-file', admin.fingerprint, 'ADMIN']));
  expect(result.skipped).toEqual([]);
}));

it('a raw L402 macaroon and an Aperture token store file are read as credential files whatever their names', async () => scratch(async dir => {
  const stored = token(201);
  const bare = token(202);
  mkdirSync(join(dir, 'named'));
  writeFileSync(join(dir, 'named', 'bare.macaroon'), bare.macaroon);
  writeFileSync(join(dir, 'named', 'l402.token'), tokenFile(stored));
  const named = await scan([join(dir, 'named')]);
  mkdirSync(join(dir, 'renamed'));
  writeFileSync(join(dir, 'renamed', 'bare.bin'), bare.macaroon);
  writeFileSync(join(dir, 'renamed', 'l402.token.bak'), tokenFile(stored));
  const renamed = await scan([join(dir, 'renamed')]);
  expect(named.findings.map(f => [f.kind, f.fingerprint])).toHaveLength(2);
  expect(renamed.findings.map(f => [f.kind, f.fingerprint]).sort()).toEqual(named.findings.map(f => [f.kind, f.fingerprint]).sort());
  expect(renamed.skipped).toEqual([]);
}));

it('other binary files are still skipped as binary', async () => scratch(async dir => {
  writeFileSync(join(dir, 'blob.bin'), Buffer.from([2, 1, 3, 0x6c, 0x6e, 0x64, 3, 0, 0]));
  writeFileSync(join(dir, 'zeros.bin'), Buffer.from([0, 0, 0, 9, 1, 2, 3, 4, 5, 0]));
  const result = await scan([dir]);
  expect(result.findings).toEqual([]);
  expect(result.skipped.map(item => item.reason)).toEqual(['binary', 'binary']);
}));

it('an explicit argument that resolves to a *.macaroon file is read as a macaroon file', async () => scratch(async dir => {
  const admin = vector('default-admin');
  // A hex text macaroon file: as text it is found as macaroon-hex, as a macaroon file as macaroon-file.
  const real = join(dir, 'real.macaroon');
  writeFileSync(real, admin.bytes.toString('hex'));
  const link = join(dir, 'link.txt');
  // The link is simulated by the injected file system: realpath resolves it to the macaroon file.
  const io = { ...fs,
    realpath: (async (path: Parameters<typeof fs.realpath>[0]) => String(path) === link ? fs.realpath(real) : fs.realpath(path)) as typeof fs.realpath,
    stat: (async (path: Parameters<typeof fs.stat>[0], options?: Parameters<typeof fs.stat>[1]) =>
      fs.stat(String(path) === link ? real : path, options)) as typeof fs.stat,
    lstat: (async (path: Parameters<typeof fs.lstat>[0], options?: Parameters<typeof fs.lstat>[1]) =>
      fs.lstat(String(path) === link ? real : path, options)) as typeof fs.lstat };
  const result = await scan([link], { fs: io });
  expect(result.findings.map(f => [f.kind, f.fingerprint, f.grade])).toEqual([['macaroon-file', admin.fingerprint, 'ADMIN']]);
}));
