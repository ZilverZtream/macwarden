import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
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

it('CP-010/B11 real permission-denied directory is skipped without stopping siblings', async () => temp(async dir => {
  const a = join(dir, 'a.env');
  writeFileSync(a, readFileSync(join(vectorRoot, 'default-readonly.macaroon')).toString('hex'));
  const denied = join(dir, 'D');
  mkdirSync(denied);
  writeFileSync(join(denied, 'hidden.env'), readFileSync(a));
  const user = process.env.USERNAME;
  if (process.platform === 'win32') {
    expect(user).toBeTruthy();
    expect(spawnSync('icacls', [denied, '/deny', `${user}:(R)`], { encoding: 'utf8' }).status).toBe(0);
  } else chmodSync(denied, 0o000);
  try {
    const result = await (await scanner()).scan([dir], {});
    expect(result.findings.map(item => slash(item.path))).toEqual([slash(a)]);
    expect(result.skipped).toContainEqual({ path: slash(denied), reason: 'unreadable' });
  } finally {
    if (process.platform === 'win32')
      spawnSync('icacls', [denied, '/remove:d', user!], { encoding: 'utf8' });
    else chmodSync(denied, 0o700);
  }
}));
