// Windows variant of the 1.1.1 scan walk fixes (robustness review RR-07, RR-08). On Windows
// '\' is a path separator and file names are case-insensitive. The Linux counterpart is
// test/rr111-walk.linux-fs.test.ts.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { scan } from '../src/scan/index.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as
  { vectors: { name: string; file: string; fingerprint: string; expectedGrade: string }[] };
const readonly = manifest.vectors.find(vector => vector.name === 'default-readonly')!;
const readonlyHex = readFileSync(join(repo, 'test/vectors', readonly.file)).toString('hex');

async function temp<T>(body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'rr111-windows-'));
  try { return await body(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

it('RR-111/walk-windows RR-07 backslash separators in an argument and its walk are reported as /', async () => temp(async dir => {
  mkdirSync(join(dir, 'sub'));
  writeFileSync(join(dir, 'sub', 'a.env'), `X=${readonlyHex}\n`);
  const result = await scan([`${dir}\\sub\\`]);
  expect(result.findings.map(finding => finding.path)).toEqual([`${dir.replace(/\\/g, '/')}/sub/a.env`]);
}));

it('RR-111/walk-windows RR-08 case variants of .git and node_modules are excluded on a case-insensitive file system', async () => temp(async dir => {
  for (const name of ['.GIT', 'Node_Modules']) {
    mkdirSync(join(dir, name));
    writeFileSync(join(dir, name, 'x.env'), `X=${readonlyHex}\n`);
  }
  const result = await scan([dir]);
  const root = dir.replace(/\\/g, '/');
  expect(result.findings).toEqual([]);
  expect(result.skipped).toEqual([{ path: `${root}/.GIT`, reason: 'excluded-dir' }, { path: `${root}/Node_Modules`, reason: 'excluded-dir' }]);
}));
