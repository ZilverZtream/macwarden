import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { expect, it } from 'vitest';

type Result = { findings: { path: string }[]; skipped: { path: string; reason: string }[] };
type Scanner = { scan: (paths: string[], options: object) => Promise<Result> };

const scanner = (): Promise<Scanner> => import('../src/scan/index.js') as Promise<Scanner>;
const vectorRoot = join(resolve(), 'test/vectors');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const slash = (path: string) => path.split(sep).join('/');
async function temp<T>(body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp010-real-'));
  try { return await body(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

it('CP-010/B8 real file, directory and loop symlinks stay outside the walk', async () => temp(async dir => {
  const tree = join(dir, 'T');
  mkdirSync(tree);
  const own = join(tree, 'own.env');
  writeFileSync(own, readFileSync(join(vectorRoot, 'default-readonly.macaroon')).toString('hex'));
  const target = join(dir, 'target.env');
  writeFileSync(target, readFileSync(join(vectorRoot, 'default-readonly.macaroon')).toString('hex'));
  const targetDir = join(dir, 'target-dir');
  mkdirSync(targetDir);
  writeFileSync(join(targetDir, 'hidden.env'), readFileSync(target));
  const fileLink = join(tree, 'file-link');
  const dirLink = join(tree, 'dir-link');
  const loop = join(tree, 'loop');
  const rootLink = join(dir, 'root-link');
  symlinkSync(target, fileLink, 'file');
  symlinkSync(targetDir, dirLink, process.platform === 'win32' ? 'junction' : 'dir');
  symlinkSync(tree, loop, process.platform === 'win32' ? 'junction' : 'dir');
  symlinkSync(tree, rootLink, process.platform === 'win32' ? 'junction' : 'dir');
  const { scan } = await scanner();
  const walked = await scan([tree], {});
  expect(walked.findings.map(item => slash(item.path))).toEqual([slash(own)]);
  expect(walked.skipped).toEqual([dirLink, fileLink, loop].map(path =>
    ({ path: slash(path), reason: 'symlink' })).sort((a, b) => a.path.localeCompare(b.path)));
  const named = await scan([rootLink], {});
  expect(named.findings.map(item => slash(item.path))).toEqual([slash(join(rootLink, 'own.env'))]);
}));
