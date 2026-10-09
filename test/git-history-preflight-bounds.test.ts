import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { captureMain } from './support/capture.js';

// MW102-06: the repository-location preflight walks include and alternates graphs that the
// scanned repository controls. Its own work must scale with the distinct files and edges,
// and the work git would do expanding the graph (git re-reads an include every time it is
// named) must be bounded by cumulative budgets that fail closed with exit 3.
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
const UNREADABLE = { code: 3, step: 'git-history', message: 'git history could not be read' };
const unlimited = { files: Infinity, bytes: Infinity, edges: Infinity };

function git(dir: string, ...args: string[]): void {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr}`);
}

async function withRepo<T>(body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'git-preflight-'));
  try {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, 'README'), 'synthetic\n');
    git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'add');
    return await body(dir);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

/** `count` configs c0..; each includes the next one `fanout` times; .git/config includes c0. */
function sharedIncludeGraph(dir: string, count = 8, fanout = 8): void {
  for (let index = 0; index < count; index++) {
    const body = index < count - 1 ? `[include]\n${`\tpath = c${index + 1}.cfg\n`.repeat(fanout)}` : '[core]\n';
    writeFileSync(join(dir, `c${index}.cfg`), body);
  }
  const config = join(dir, '.git', 'config');
  writeFileSync(config, `${readFileSync(config, 'utf8')}[include]\n\tpath = ../c0.cfg\n`);
}

async function scanJson(path: string) {
  const { main } = await import('../src/cli.js');
  const run = await captureMain(main, ['scan', path, '--git-history', '--json']);
  return { code: run.code, document: JSON.parse(run.stdout) as { error: { code: number; step: string; message: string } | null } };
}

it('git-history/preflight a shared include graph is read once per distinct file and edge', async () => {
  await withRepo(async dir => {
    sharedIncludeGraph(dir);
    const { locateRepository } = await import('../src/scan/git-history.js');
    const stats: Record<string, number> = {};
    const started = performance.now();
    await locateRepository(dir, { limits: unlimited, stats });
    // .git/config (1 edge) + c0..c6 (8 edges each) = 57 distinct edges; commondir, alternates,
    // config.worktree (absent), .git/config and c0..c7 are each looked at once.
    expect(stats.edges).toBe(57);
    expect(stats.files).toBe(12);
    // What git would traverse: 1 + E(c0) with E(c7) = 0 and E(k) = 8 * (1 + E(k + 1)).
    expect(stats.expandedEdges).toBe(2_396_745);
    expect(performance.now() - started).toBeLessThan(2_000);
  });
});

it('git-history/preflight a shared include graph beyond the budget fails closed with exit 3, quickly', async () => {
  await withRepo(async dir => {
    sharedIncludeGraph(dir);
    const started = performance.now();
    const run = await scanJson(dir);
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(run.document.error).toEqual(UNREADABLE);
    expect(run.code).toBe(3);
  });
});

it('git-history/preflight a shared include graph within the budget is scanned', async () => {
  await withRepo(async dir => {
    // 1 + 4 + 16 + 64 + 256 = 341 include edges as git expands them.
    sharedIncludeGraph(dir, 5, 4);
    const run = await scanJson(dir);
    expect(run.document.error).toBeNull();
    expect(run.code).toBe(0);
  });
});

it('git-history/preflight exceeding the edge budget with one repeated include fails closed with exit 3', async () => {
  await withRepo(async dir => {
    writeFileSync(join(dir, 'leaf.cfg'), '[core]\n');
    const config = join(dir, '.git', 'config');
    // 5,000 include entries fit in a 64 KiB config and stay at depth 1.
    writeFileSync(config, `${readFileSync(config, 'utf8')}[include]\n${'path=../leaf.cfg\n'.repeat(5_000)}`);
    const run = await scanJson(dir);
    expect(run.document.error).toEqual(UNREADABLE);
    expect(run.code).toBe(3);
  });
});

it('git-history/preflight file, byte, edge and alternates budgets are cumulative and fail closed', async () => {
  await withRepo(async dir => {
    sharedIncludeGraph(dir, 3, 2);
    const { locateRepository, GitHistoryError, PREFLIGHT_LIMITS } = await import('../src/scan/git-history.js');
    expect(PREFLIGHT_LIMITS).toEqual({ files: 256, bytes: 1024 * 1024, edges: 4096 });
    const stats: Record<string, number> = {};
    await locateRepository(dir, { stats });
    // .git/config → c0 (1), c0 → c1 twice (2 + 0), c1 → c2 twice each time c1 is read (2 × 2).
    expect(stats.edges).toBe(1 + 2 + 2);
    expect(stats.expandedEdges).toBe(1 + 2 + 4);
    await expect(locateRepository(dir, { limits: { files: 5 } })).rejects.toBeInstanceOf(GitHistoryError);
    await expect(locateRepository(dir, { limits: { bytes: stats.expandedBytes - 1 } })).rejects.toBeInstanceOf(GitHistoryError);
    await expect(locateRepository(dir, { limits: { edges: 6 } })).rejects.toBeInstanceOf(GitHistoryError);
    await expect(locateRepository(dir, { limits: { edges: 7 } })).resolves.toBeTruthy();
    // Alternates count toward the same budget: two local alternates, one naming the other twice.
    const objects = join(dir, '.git', 'objects');
    const a = join(dir, 'alt-a'); const b = join(dir, 'alt-b');
    for (const path of [a, b]) mkdirSync(join(path, 'info'), { recursive: true });
    writeFileSync(join(objects, 'info', 'alternates'), `${a}\n${b}\n`);
    writeFileSync(join(a, 'info', 'alternates'), `${b}\n${b}\n`);
    await locateRepository(dir, { stats });
    expect(stats.edges).toBe(5 + 4);
    expect(stats.expandedEdges).toBe(7 + 4);
    await expect(locateRepository(dir, { limits: { edges: 10 } })).rejects.toBeInstanceOf(GitHistoryError);
  });
});

it('git-history/preflight an include cycle is refused without walking it repeatedly', async () => {
  await withRepo(async dir => {
    writeFileSync(join(dir, 'x.cfg'), '[include]\n\tpath = y.cfg\n\tpath = y.cfg\n');
    writeFileSync(join(dir, 'y.cfg'), '[include]\n\tpath = x.cfg\n\tpath = x.cfg\n');
    const config = join(dir, '.git', 'config');
    writeFileSync(config, `${readFileSync(config, 'utf8')}[include]\n\tpath = ../x.cfg\n`);
    const { locateRepository, GitHistoryError } = await import('../src/scan/git-history.js');
    const stats: Record<string, number> = {};
    await expect(locateRepository(dir, { stats })).rejects.toBeInstanceOf(GitHistoryError);
    expect(stats.edges).toBe(3);
  });
});

it('git-history/preflight observes cancellation between location checks', async () => {
  await withRepo(async dir => {
    sharedIncludeGraph(dir);
    const { locateRepository } = await import('../src/scan/git-history.js');
    const { Cancelled, withCancellation } = await import('../src/cancellation.js');
    const controller = new AbortController();
    controller.abort();
    await expect(withCancellation(controller.signal, () => locateRepository(dir))).rejects.toBeInstanceOf(Cancelled);
  });
});
