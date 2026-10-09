import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, posix, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';

type Envelope = { ok: boolean; result: { summary: { ignored: number; findings: number } } | null;
  error: { code: number; step: string | null } | null };
type Command = { run: (args: string[], deps: { fs: typeof fs }) => Promise<Envelope> };

const command = (): Promise<Command> => import('../src/commands/scan.js') as Promise<Command>;
const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp-cp012-system-ignore');
process.env.MACWARDEN_TEST_TMP = testTmp;

async function inTemp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'ignore-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function virtualPath(path: string): string {
  const slash = path.replaceAll('\\', '/').replace(/^[A-Za-z]:/, '');
  return posix.normalize(slash.startsWith('/') ? slash : `/${slash}`);
}

function injectedFs(supplied: string, resolved: string, harmless: string) {
  const isSupplied = (path: string) => resolve(path) === resolve(supplied);
  const isVirtual = (path: string) => /^\/(?:proc|sys|dev)(?:\/|$)/.test(virtualPath(path));
  const isTarget = (path: string) => isSupplied(path) || isVirtual(path);
  const physical = (path: string) => isTarget(path) ? harmless : path;
  const attempted = vi.fn((path: string) => path);
  const fileSystem = {
    ...fs,
    stat: vi.fn((path: string, options?: { bigint?: boolean }) =>
      fs.stat(physical(path), options as never)),
    lstat: vi.fn((path: string, options?: { bigint?: boolean }) =>
      fs.lstat(physical(path), options as never)),
    realpath: vi.fn((path: string) =>
      isSupplied(path) ? Promise.resolve(resolved) : isVirtual(path)
        ? Promise.resolve(virtualPath(path)) : fs.realpath(path)),
    access: vi.fn((path: string, mode?: number) => fs.access(physical(path), mode)),
    readdir: vi.fn((path: string, options?: Parameters<typeof fs.readdir>[1]) =>
      fs.readdir(physical(path), options as never)),
    opendir: vi.fn((path: string, options?: Parameters<typeof fs.opendir>[1]) =>
      fs.opendir(physical(path), options)),
    readlink: vi.fn((path: string, options?: Parameters<typeof fs.readlink>[1]) =>
      fs.readlink(physical(path), options as never)),
    open: vi.fn((path: string, flags: string | number, mode?: number) => {
      if (isTarget(path)) attempted(path);
      return fs.open(physical(path), flags, mode);
    }),
    readFile: vi.fn((path: string, options?: Parameters<typeof fs.readFile>[1]) => {
      if (isTarget(path)) attempted(path);
      return fs.readFile(physical(path), options as never);
    }),
  } as unknown as typeof fs;
  return { fileSystem, attempted };
}

it.each(['/proc', '/sys', '/dev'])(
  'CP-012/B3 rejects supplied ignore files beneath %s before opening',
  async directory => inTemp(async dir => {
    const tree = join(dir, 'tree'); mkdirSync(tree);
    const harmless = join(dir, 'ordinary-ignore.txt'); writeFileSync(harmless, '# ordinary\n');
    const supplied = `${directory}/nested/ignore.txt`;
    const { fileSystem, attempted } = injectedFs(supplied, supplied, harmless);
    const result = await (await command()).run([tree, '--ignore-file', supplied, '--json'], { fs: fileSystem });
    expect.soft(result).toMatchObject({ ok: false, result: null,
      error: { code: 3, step: 'input-read' } });
    expect(attempted, 'excluded ignore content must remain unopened').not.toHaveBeenCalled();
  }),
);

it.each(['/proc', '/sys', '/dev'])(
  'CP-012/B3 rejects ignore files resolved beneath %s before opening',
  async directory => inTemp(async dir => {
    const tree = join(dir, 'tree'); mkdirSync(tree);
    const harmless = join(dir, 'ordinary-ignore.txt'); writeFileSync(harmless, '# ordinary\n');
    const supplied = join(dir, 'ordinary-link.txt');
    const { fileSystem, attempted } = injectedFs(supplied, `${directory}/nested/ignore.txt`, harmless);
    const result = await (await command()).run([tree, '--ignore-file', supplied, '--json'], { fs: fileSystem });
    expect.soft(result).toMatchObject({ ok: false, result: null,
      error: { code: 3, step: 'input-read' } });
    expect(fileSystem.realpath).toHaveBeenCalled();
    expect(attempted, 'resolved excluded ignore content must remain unopened').not.toHaveBeenCalled();
  }),
);

it.each(['/process', '/sysadmin', '/device'])(
  'CP-012/B3 allows ordinary ignore file paths under %s',
  async directory => inTemp(async dir => {
    const tree = join(dir, 'tree'); mkdirSync(tree);
    const harmless = join(dir, 'ordinary-ignore.txt'); writeFileSync(harmless, '# ordinary\n');
    const supplied = `${directory}/nested/ignore.txt`;
    const { fileSystem, attempted } = injectedFs(supplied, supplied, harmless);
    const result = await (await command()).run([tree, '--ignore-file', supplied, '--json'], { fs: fileSystem });
    expect(result).toMatchObject({ ok: true, error: null,
      result: { summary: { ignored: 0, findings: 0 } } });
    expect(attempted).toHaveBeenCalled();
  }),
);
