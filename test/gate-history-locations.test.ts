import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { expect, it } from 'vitest';
import { inventoryResult, render } from '../src/output/index.js';
import { captureMain } from './support/capture.js';

// Final release gate, 2026-10-08: a credential already reported at a blob's first path must
// still be reported at the other paths that added it, so an ignore entry for one path can
// never hide it everywhere.
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string }[] };
const fp = (name: string) => manifest.vectors.find(item => item.name === name)!.fingerprint;
const hex = (name: string) => readFileSync(join(vectors, `${name}.macaroon`)).toString('hex');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const posix = (path: string) => path.split(sep).join('/');

function git(dir: string, ...args: string[]): void {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr}`);
}
function commit(dir: string, message: string): void { git(dir, 'add', '-A'); git(dir, 'commit', '-q', '--allow-empty', '-m', message); }

type Finding = { path: string; fingerprint: string; commit?: string; alsoAt?: { count: number; paths: string[] } };

async function withRepo(body: (dir: string) => Promise<void>): Promise<void> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'gate-history-'));
  try {
    git(dir, 'init', '-q');
    mkdirSync(join(dir, 'a')); mkdirSync(join(dir, 'z'));
    // Commit 1: X at a/p1.txt.
    writeFileSync(join(dir, 'a', 'p1.txt'), `x=${hex('default-readonly')}\n`);
    commit(dir, 'c1');
    // Commit 2: the same new content (X and Y) at a/p1.txt and z/p2.txt.
    const both = `x=${hex('default-readonly')}\ny=${hex('default-invoice')}\n`;
    writeFileSync(join(dir, 'a', 'p1.txt'), both);
    writeFileSync(join(dir, 'z', 'p2.txt'), both);
    commit(dir, 'c2');
    // Commit 3: both removed, so only history holds them.
    rmSync(join(dir, 'a'), { recursive: true }); rmSync(join(dir, 'z'), { recursive: true });
    commit(dir, 'c3');
    await body(dir);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const located = (findings: Finding[], dir: string) => findings
  .map(finding => [finding.fingerprint, posix(finding.path).slice(posix(dir).length + 1), finding.alsoAt?.count ?? 0])
  .sort((left, right) => String(left).localeCompare(String(right)));

it('GATE/history-locations a credential already reported at the first path is still reported at its other path', async () => withRepo(async dir => {
  const { scan } = await import('../src/scan/index.js');
  const result = await scan([dir], { gitHistory: true }) as unknown as { findings: Finding[] };
  expect(located(result.findings, dir)).toEqual([
    [fp('default-invoice'), 'a/p1.txt', 1],   // Y: first added at a/p1.txt, also at z/p2.txt
    [fp('default-readonly'), 'a/p1.txt', 0],  // X: commit 1
    [fp('default-readonly'), 'z/p2.txt', 0],  // X: commit 2, the location the old code lost
  ].sort((left, right) => String(left).localeCompare(String(right))));
}));

it('GATE/history-locations an ignore entry for one path never hides the credential at another, and fail-on still fails', async () => withRepo(async dir => {
  writeFileSync(join(dir, '.macwardenignore'), `${fp('default-readonly')} a/p1.txt\n`);
  const { scan } = await import('../src/scan/index.js');
  const result = await scan([dir], { gitHistory: true }) as unknown as { findings: Finding[] };
  expect(result.findings.some(finding => finding.fingerprint === fp('default-readonly')
    && posix(finding.path).endsWith('z/p2.txt'))).toBe(true);
  const { main } = await import('../src/cli.js');
  const run = await captureMain(main, ['scan', dir, '--git-history', '--fail-on', 'READ']);
  expect(run.code).toBe(1);
}));

it('GATE/inventory-status each row shows its base status once, with no contradictory status appended', () => {
  const entry = (status: string) => ({ label: 'app', grade: 'READ', permissions: [], caveats: [], createdAt: '2026-10-01T00:00:00Z',
    status, fingerprint: null, outPath: null, replaces: null, replacedBy: null });
  const result = inventoryResult({ node: { pubkey: '02' + 'ab'.repeat(32), alias: 'node', network: 'regtest', version: '0.21.4-beta' },
    rootKeys: [
      { rootKeyId: '0', inLnd: true, flags: ['default-root-key'], verify: 'not-checked', expires: null, entry: null },
      { rootKeyId: '7', inLnd: true, flags: ['unknown'], verify: 'not-checked', expires: null, entry: null },
      { rootKeyId: '8', inLnd: false, flags: ['missing-in-lnd'], verify: 'not-checked', expires: null, entry: entry('active') },
      { rootKeyId: '9', inLnd: true, flags: ['revoked-but-present'], verify: 'not-checked', expires: null, entry: entry('revoked') },
      { rootKeyId: '10', inLnd: true, flags: [], verify: 'not-checked', expires: null, entry: entry('active') },
    ] } as never, [], new Date('2026-10-08T00:00:00Z'));
  const statuses = render(result, 'text').trimEnd().split('\n').slice(2).map(line => line.split(/\s{2,}/).at(-1));
  expect(statuses).toEqual([
    'default root key: cannot be individually revoked',
    'unknown — not in this registry (another tool or operator may own it)',
    'missing in LND (registry says active)',
    'revoked but present in LND',
    'active',
  ]);
});
