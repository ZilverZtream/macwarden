import { childEnvironment } from './helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

const repo = resolve();
const tempRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp-cp012-glob-budget');
process.env.MACWARDEN_TEST_TMP = tempRoot;
const bin = join(repo, 'dist/bin.js');
const fixture = join(repo, 'test/scan-fixtures/ignore/a.env');
const manifest = JSON.parse(readFileSync(join(repo, 'test/scan-fixtures/ignore/manifest.json'), 'utf8')) as {
  files: { path: string; findings: { fingerprint: string; grade: string }[] }[];
};
const expected = manifest.files.find(file => file.path === 'a.env')?.findings[0];
if (!expected) throw new Error('ignore fixture manifest is missing a.env');

type ScanResult = {
  ok: boolean;
  result: {
    findings: { path: string; fingerprint: string; grade: string }[];
    summary: { ignored: number; findings: number; distinct: number };
    failOn: { threshold: string; count: number };
  } | null;
  error: { code: number; step: string | null } | null;
};

function inTemp(work: (dir: string) => void): void {
  mkdirSync(tempRoot, { recursive: true });
  const dir = mkdtempSync(join(tempRoot, 'glob-budget-'));
  try { work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function runScan(dir: string, args: string[]): ScanResult {
  const child = spawnSync(process.execPath, [bin, 'scan', ...args, '--json', '--fail-on', 'READ'], {
    cwd: dir,
    env: childEnvironment({ MACWARDEN_TEST_TMP: tempRoot  }),
    encoding: 'utf8',
    timeout: 3_000,
    maxBuffer: 1_048_576,
  });
  expect((child.error as NodeJS.ErrnoException | undefined)?.code, 'scan must finish within the child-process deadline').toBeUndefined();
  expect(child.signal).toBeNull();
  expect(child.stderr).toBe('');
  expect(child.stdout, 'scan must emit one JSON document').toBeTruthy();
  const output = JSON.parse(child.stdout) as ScanResult;
  expect(child.status).toBe(output.ok && output.result?.failOn.count ? 1 : 0);
  return output;
}

for (const mode of ['local', 'explicit'] as const) {
  it(`CP-012/B2 ${mode} repeated globstars with a failing suffix finish and retain the finding`, () => inTemp(dir => {
    const path = `${'a'.repeat(24)}.env`;
    const target = join(dir, 'tree', ...path.split('/'));
    mkdirSync(resolve(target, '..'), { recursive: true });
    copyFileSync(fixture, target);
    const pattern = `${'**'.repeat(11)}z`;
    const ignore = mode === 'local' ? join(dir, 'tree', '.macwardenignore') : join(dir, 'rules.txt');
    writeFileSync(ignore, `${expected.fingerprint} ${mode === 'local' ? pattern : `tree/${pattern}`}\n`);
    const args = mode === 'local' ? ['tree'] : ['tree', '--ignore-file', 'rules.txt'];
    const output = runScan(dir, args);
    expect(output).toMatchObject({ ok: true, error: null, result: {
      findings: [{ path: `tree/${path}`, fingerprint: expected.fingerprint, grade: expected.grade }],
      summary: { ignored: 0, findings: 1, distinct: 1 },
      failOn: { threshold: 'READ', count: 1 },
    } });
  }));
}

it('CP-012/B2 ordinary star, globstar and question mark retain directory semantics', () => inTemp(dir => {
  const tree = join(dir, 'tree');
  mkdirSync(join(tree, 'sub', 'deep'), { recursive: true });
  for (const path of ['a.env', 'sub/b.env', 'sub/deep/c.env']) {
    copyFileSync(fixture, join(tree, ...path.split('/')));
  }
  const ignore = join(tree, '.macwardenignore');
  for (const [pattern, paths] of [
    ['*.env', ['tree/sub/b.env', 'tree/sub/deep/c.env']],
    ['sub/?.env', ['tree/a.env', 'tree/sub/deep/c.env']],
    ['sub/**/*.env', ['tree/a.env']],
  ] as const) {
    writeFileSync(ignore, `${expected.fingerprint} ${pattern}\n`);
    const output = runScan(dir, ['tree']);
    expect(output).toMatchObject({ ok: true, error: null, result: {
      findings: paths.map(path => ({ path, fingerprint: expected.fingerprint, grade: expected.grade })),
      summary: { ignored: 3 - paths.length, findings: paths.length, distinct: 1 },
      failOn: { threshold: 'READ', count: paths.length },
    } });
  }
}));
