import { createHash } from 'node:crypto';
import { constants, chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { expect, it, vi } from 'vitest';

type Finding = { path: string; line: number | null; column: number | null; kind: string;
  fingerprint: string; grade: string | null; warnings: string[] };
type Result = { findings: Finding[]; skipped: { path: string; reason: string }[];
  summary: { filesScanned: number; filesSkipped: number; findings: number; distinct: number } };
type Scanner = { scan: (paths: string[], options: object) => Promise<Result> };

const scanner = (): Promise<Scanner> => import('../src/scan/index.js') as Promise<Scanner>;
const repo = resolve();
const vectorRoot = join(repo, 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectorRoot, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const reference = (name: string) => manifest.vectors.find(item => item.name === name)!;
const vector = (name: string) => readFileSync(join(vectorRoot, `${name}.macaroon`));
const slash = (path: string) => path.split(sep).join('/');
const fp = (bytes: Buffer) => `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
async function scan(paths: string[], options: object = {}): Promise<Result> {
  return (await scanner()).scan(paths, options);
}
async function temp<T>(body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp010-'));
  try { return await body(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function put(dir: string, path: string, bytes: Buffer | string): string {
  const full = join(dir, path);
  mkdirSync(join(full, '..'), { recursive: true });
  writeFileSync(full, bytes);
  return full;
}
function projected(result: Result) {
  return result.findings.map(({ path, line, column, kind, fingerprint, grade }) =>
    ({ path: slash(path), line, column, kind, fingerprint, grade }));
}
function finding(path: string, kind: string, name: string, line: number | null, column: number | null) {
  return { path: slash(path), line, column, kind,
    fingerprint: reference(name).fingerprint, grade: reference(name).expectedGrade };
}
function skipped(result: Result, path: string, reason: string) {
  expect(result.skipped).toContainEqual({ path: slash(path), reason });
}
function trackedFs() {
  const reads = new Map<string, number>();
  const opens: { path: string; flags: string | number }[] = [];
  const record = (path: string, count: number) => reads.set(path, (reads.get(path) || 0) + count);
  const fileSystem = {
    ...fs,
    open: vi.fn(async (path: string, flags: string | number, mode?: number) => {
      opens.push({ path, flags });
      const handle = await fs.open(path, flags, mode);
      return new Proxy(handle, { get(target, key) {
        if (key === 'read') return async (...args: Parameters<typeof handle.read>) => {
          const outcome = await handle.read(...args);
          record(path, outcome.bytesRead);
          return outcome;
        };
        if (key === 'readFile') return async (...args: Parameters<typeof handle.readFile>) => {
          const outcome = await handle.readFile(...args);
          record(path, Buffer.byteLength(outcome));
          return outcome;
        };
        const value = Reflect.get(target, key, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }),
    readFile: vi.fn(async (path: string) => {
      const bytes = await fs.readFile(path);
      record(path, bytes.length);
      return bytes;
    }),
  };
  return { fileSystem, reads, opens };
}

it('CP-010/B1 walks a mixed tree and reports files, text and undecodable bytes', async () => temp(async dir => {
  const a = put(dir, 'a.env', vector('default-readonly').toString('hex'));
  const b = put(dir, 'sub/b.yml', vector('default-invoice').toString('base64'));
  const admin = put(dir, 'admin.macaroon', vector('default-admin'));
  const ro = put(dir, 'ro.macaroon', vector('default-readonly').toString('hex'));
  const inv = put(dir, 'inv.MACAROON', vector('default-invoice').toString('base64'));
  const bad = put(dir, 'bad.macaroon', 'garbage');
  const result = await scan([dir]);
  expect(projected(result)).toEqual([
    finding(a, 'macaroon-hex', 'default-readonly', 1, 1),
    finding(admin, 'macaroon-file', 'default-admin', null, null),
    { path: slash(bad), line: null, column: null, kind: 'undecodable',
      fingerprint: fp(Buffer.from('garbage')), grade: null },
    finding(inv, 'macaroon-file', 'default-invoice', null, null),
    finding(ro, 'macaroon-file', 'default-readonly', null, null),
    finding(b, 'macaroon-base64', 'default-invoice', 1, 1),
  ]);
  expect(result.skipped).toEqual([]);
  expect(result.summary).toMatchObject({ filesScanned: 6, filesSkipped: 0, findings: 6, distinct: 4 });
}));

it('CP-010/B2 macaroon file limits include trailing bytes and cap reads', async () => temp(async dir => {
  const base = vector('default-readonly');
  const x = put(dir, 'x.macaroon', Buffer.concat([base, Buffer.alloc(65_536 - base.length)]));
  const y = put(dir, 'y.macaroon', Buffer.concat([base, Buffer.alloc(65_537 - base.length)]));
  const observed = trackedFs();
  const result = await scan([x, y], { fs: observed.fileSystem });
  expect(result.findings.map(f => [slash(f.path), f.kind])).toEqual([
    [slash(x), 'macaroon-file'], [slash(y), 'undecodable']]);
  expect(result.findings[0].fingerprint).toBe(reference('default-readonly').fingerprint);
  expect(result.findings[0].warnings).toContain('trailing-bytes');
  expect(result.findings[1].grade).toBeNull();
  expect(result.findings[1].fingerprint).toBe(fp(readFileSync(y)));
  expect(observed.reads.get(x) || 0).toBeGreaterThan(0);
  expect(observed.reads.get(x) || 0).toBeLessThanOrEqual(65_537);
  expect(observed.reads.get(y) || 0).toBeLessThanOrEqual(65_537);
}));

it('CP-010/B3 text file size boundary includes the last line', async () => temp(async dir => {
  const hex = vector('default-readonly').toString('hex');
  const make = (size: number) => Buffer.from('.'.repeat(size - hex.length - 1) + '\n' + hex);
  const p = put(dir, 'p.txt', make(5_242_880));
  const q = put(dir, 'q.txt', make(5_242_881));
  const observed = trackedFs();
  const result = await scan([p, q], { fs: observed.fileSystem });
  expect(projected(result)).toEqual([finding(p, 'macaroon-hex', 'default-readonly', 2, 1)]);
  skipped(result, q, 'size');
  expect(result.summary).toMatchObject({ filesScanned: 1, filesSkipped: 1 });
  expect(observed.reads.get(p) || 0).toBeGreaterThan(0);
  for (const path of [p, q])
    expect(observed.reads.get(path) || 0).toBeLessThanOrEqual(5_242_881);
}));

it('CP-010/B4 a file growing after stat is capped and skipped', async () => temp(async dir => {
  const path = put(dir, 'g.txt', Buffer.alloc(10_000_000, 46));
  const observed = trackedFs();
  const actualStat = fs.stat;
  const fileSystem = { ...observed.fileSystem,
    stat: vi.fn(async (entry: string, options?: { bigint?: boolean }) => {
      const stat = await actualStat(entry, options as never);
      return entry === path ? Object.assign(Object.create(stat) as object,
        { size: typeof stat.size === 'bigint' ? 1_000n : 1_000 }) : stat;
    }),
    lstat: vi.fn(async (entry: string, options?: { bigint?: boolean }) => {
      const stat = await fs.lstat(entry, options as never);
      return entry === path ? Object.assign(Object.create(stat) as object,
        { size: typeof stat.size === 'bigint' ? 1_000n : 1_000 }) : stat;
    }),
    open: vi.fn(async (entry: string, flags: string | number, mode?: number) => {
      const handle = await observed.fileSystem.open(entry, flags, mode);
      return new Proxy(handle, { get(target, key) {
        if (key === 'stat') return async (options?: { bigint?: boolean }) => {
          const stat = await target.stat(options as never);
          return entry === path ? Object.assign(Object.create(stat) as object,
            { size: typeof stat.size === 'bigint' ? 1_000n : 1_000 }) : stat;
        };
        const value = Reflect.get(target, key, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }),
  };
  const result = await scan([path], { fs: fileSystem });
  expect(fileSystem.stat.mock.calls.length + fileSystem.lstat.mock.calls.length +
    fileSystem.open.mock.calls.length).toBeGreaterThan(0);
  skipped(result, path, 'size');
  expect(observed.reads.get(path) || 0).toBeLessThanOrEqual(5_242_881);
}));

it('CP-010/B5 binary probe ends before offset 8192 and exempts macaroon files', async () => temp(async dir => {
  const hex = vector('default-readonly').toString('hex');
  const n1 = put(dir, 'n1.txt', Buffer.concat([Buffer.alloc(8_191, 46), Buffer.from([0]), Buffer.from(`\n${hex}`)]));
  const n2 = put(dir, 'n2.txt', Buffer.concat([Buffer.alloc(8_192, 46), Buffer.from([0]), Buffer.from(`\n${hex}`)]));
  const n3 = put(dir, 'n3.macaroon', vector('default-admin'));
  const u16 = put(dir, 'u16.txt', Buffer.from(hex, 'utf16le'));
  const result = await scan([n1, n2, n3, u16]);
  skipped(result, n1, 'binary');
  skipped(result, u16, 'binary');
  expect(projected(result)).toEqual([
    finding(n2, 'macaroon-hex', 'default-readonly', 2, 1),
    finding(n3, 'macaroon-file', 'default-admin', null, null)]);
}));

it('CP-010/B6 excluded directories are listed once and includeDirs enters them', async () => temp(async dir => {
  const hex = vector('default-readonly').toString('hex');
  const git = put(dir, '.git/config', hex);
  const modules = put(dir, 'node_modules/x/.env', hex);
  const ordinary = await scan([dir]);
  expect(ordinary.findings).toEqual([]);
  expect(ordinary.skipped).toEqual([
    { path: slash(join(dir, '.git')), reason: 'excluded-dir' },
    { path: slash(join(dir, 'node_modules')), reason: 'excluded-dir' }]);
  const included = await scan([dir], { includeDirs: true });
  expect(projected(included)).toEqual([
    finding(git, 'macaroon-hex', 'default-readonly', 1, 1),
    finding(modules, 'macaroon-hex', 'default-readonly', 1, 1)]);
}));

it('CP-010/B7 protected names are never opened or descended into', async () => temp(async dir => {
  const hex = vector('default-readonly').toString('hex');
  const protectedFiles = ['MACAROONS.DB', 'wallet.db', 'tls.key', 'ADMIN.KEY',
    'db-password.txt', 'seed.txt', 'my_passwd', 'Password'];
  const protectedDirs = ['seed', 'keys.KEY'];
  for (const name of protectedFiles) put(dir, name, hex);
  for (const name of protectedDirs) put(dir, `${name}/hidden.env`, hex);
  const allowed = ['seedling.txt', 'passwords.txt'].map(name => put(dir, name, hex));
  const observed = trackedFs();
  const readDirs: string[] = [];
  const fileSystem = { ...observed.fileSystem,
    readdir: vi.fn(async (...args: Parameters<typeof fs.readdir>) => {
      readDirs.push(String(args[0]));
      return fs.readdir(...args);
    }),
  };
  const result = await scan([dir], { fs: fileSystem });
  expect(result.skipped).toEqual([...protectedFiles, ...protectedDirs]
    .map(name => ({ path: slash(join(dir, name)), reason: 'never-open' }))
    .sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))));
  expect(projected(result)).toEqual(allowed.map(path =>
    finding(path, 'macaroon-hex', 'default-readonly', 1, 1))
    .sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))));
  expect(observed.opens.map(item => item.path)).toEqual(expect.arrayContaining(allowed));
  for (const name of [...protectedFiles, ...protectedDirs]) {
    const path = join(dir, name);
    expect(observed.opens.map(item => item.path)).not.toContain(path);
    expect([...observed.reads.keys()]).not.toContain(path);
    expect(readDirs).not.toContain(path);
  }
}));

function pretendSymlink(stat: Awaited<ReturnType<typeof fs.lstat>>) {
  return Object.assign(Object.create(stat) as object, {
    isSymbolicLink: () => true, isFile: () => false, isDirectory: () => false,
  }) as Awaited<ReturnType<typeof fs.lstat>>;
}

it('CP-010/B8 walk links are skipped while an explicit symlink argument is followed once', async () => temp(async dir => {
  const hex = vector('default-readonly').toString('hex');
  const tree = join(dir, 'T');
  const file = put(tree, 'own.env', hex);
  const linkedFile = put(tree, 'linked.env', hex);
  const linkedDir = join(tree, 'linked-dir');
  put(linkedDir, 'only.env', hex);
  const loop = join(tree, 'loop');
  mkdirSync(loop);
  const rootLink = join(dir, 'L');
  const rootFile = put(rootLink, 'own.env', hex);
  const links = new Set([linkedFile, linkedDir, loop, rootLink]);
  const fileSystem = { ...fs,
    lstat: vi.fn(async (path: string, options?: { bigint?: boolean }) => {
      const stat = await fs.lstat(path, options as never);
      return links.has(path) ? pretendSymlink(stat) : stat;
    }),
  };
  const result = await scan([tree], { fs: fileSystem });
  expect(projected(result)).toEqual([finding(file, 'macaroon-hex', 'default-readonly', 1, 1)]);
  expect(result.skipped).toEqual([linkedDir, linkedFile, loop].map(path =>
    ({ path: slash(path), reason: 'symlink' })).sort((a, b) =>
    Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))));
  const named = await scan([rootLink], { fs: fileSystem });
  expect(projected(named)).toEqual([finding(rootFile, 'macaroon-hex', 'default-readonly', 1, 1)]);
}));

it('CP-010/B9 special entries are never opened and system root directories stay excluded', async () => temp(async dir => {
  const hex = vector('default-readonly').toString('hex');
  const tree = join(dir, 'T');
  const special = ['pipe', 'device', 'socket'].map(name => put(tree, name, hex));
  const opened: string[] = [];
  const fileSystem = { ...fs,
    lstat: vi.fn(async (path: string, options?: { bigint?: boolean }) => {
      const stat = await fs.lstat(path, options as never);
      if (!special.includes(path)) return stat;
      return Object.assign(Object.create(stat) as object, {
        isFile: () => false, isDirectory: () => false,
        isFIFO: () => path === special[0],
        isCharacterDevice: () => path === special[1],
        isSocket: () => path === special[2],
      }) as Awaited<ReturnType<typeof fs.lstat>>;
    }),
    open: vi.fn(async (...args: Parameters<typeof fs.open>) => {
      opened.push(String(args[0]));
      return fs.open(...args);
    }),
  };
  const result = await scan([tree], { fs: fileSystem });
  for (const path of special) skipped(result, path, 'not-regular');
  expect(opened.filter(path => special.includes(path))).toEqual([]);

  const virtual = join(dir, 'virtual-root');
  for (const name of ['proc', 'sys', 'dev']) put(virtual, `${name}/hidden.env`, hex);
  put(virtual, 'home/a.env', hex);
  const map = (path: string) => {
    const normalized = path.replaceAll('\\', '/').replace(/^[A-Za-z]:/, '');
    return join(virtual, normalized.replace(/^\/+/, ''));
  };
  const entered: string[] = [];
  const rootFs = {
    ...fs,
    stat: (path: string, options?: { bigint?: boolean }) => fs.stat(map(path), options as never),
    lstat: (path: string, options?: { bigint?: boolean }) => fs.lstat(map(path), options as never),
    readdir: vi.fn(async (...args: Parameters<typeof fs.readdir>) => {
      entered.push(String(args[0]));
      return fs.readdir(map(String(args[0])), args[1]);
    }),
    open: vi.fn((path: string, flags: string | number) => fs.open(map(path), flags)),
    readFile: vi.fn((path: string) => fs.readFile(map(path))),
    realpath: vi.fn(async (path: string) => path),
  };
  const rootResult = await scan(['/'], { fs: rootFs });
  expect(projected(rootResult)).toEqual([finding('/home/a.env', 'macaroon-hex', 'default-readonly', 1, 1)]);
  for (const name of ['proc', 'sys', 'dev']) {
    skipped(rootResult, `/${name}`, 'excluded-dir');
    expect(entered).not.toContain(`/${name}`);
  }
}));

it('CP-010/B10 overlapping directory and file arguments scan each file once', async () => temp(async dir => {
  const hex = vector('default-readonly').toString('hex');
  const a = put(dir, 'a.env', hex);
  const b = put(dir, 'sub/b.env', hex);
  const result = await scan([dir, join(dir, 'sub'), a]);
  expect(projected(result)).toEqual([
    finding(a, 'macaroon-hex', 'default-readonly', 1, 1),
    finding(b, 'macaroon-hex', 'default-readonly', 1, 1)]);
  expect(result.summary.filesScanned).toBe(2);
}));

it('CP-010/B10 distinct exact file identities survive a numeric inode collision', async () => temp(async dir => {
  const hex = vector('default-readonly').toString('hex');
  const first = put(dir, 'a.env', hex);
  const second = put(dir, 'b.env', hex);
  const identities = new Map([[first, 9_851_624_198_645_556n], [second, 9_851_624_198_645_557n]]);
  expect(Number(identities.get(first))).toBe(Number(identities.get(second)));
  const identity = (stat: { dev: number | bigint; ino: number | bigint; nlink: number | bigint }, path: string) => {
    const ino = identities.get(path);
    if (ino === undefined) return stat;
    const big = typeof stat.ino === 'bigint';
    return Object.assign(Object.create(stat) as object, {
      dev: big ? 3_974_765_067n : 3_974_765_067,
      ino: big ? ino : Number(ino),
      nlink: big ? 1n : 1,
    });
  };
  const fileSystem = { ...fs,
    stat: vi.fn(async (path: string, options?: { bigint?: boolean }) =>
      identity(options?.bigint ? await fs.stat(path, { bigint: true }) : await fs.stat(path), path)),
    lstat: vi.fn(async (path: string, options?: { bigint?: boolean }) =>
      identity(options?.bigint ? await fs.lstat(path, { bigint: true }) : await fs.lstat(path), path)),
    open: vi.fn(async (path: string, flags: string | number, mode?: number) => {
      const handle = await fs.open(path, flags, mode);
      return new Proxy(handle, { get(target, key) {
        if (key === 'stat') return async (options?: { bigint?: boolean }) =>
          identity(options?.bigint ? await target.stat({ bigint: true }) : await target.stat(), path);
        const value = Reflect.get(target, key, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }),
  };
  const result = await scan([dir, first], { fs: fileSystem });
  expect(projected(result)).toEqual([
    finding(first, 'macaroon-hex', 'default-readonly', 1, 1),
    finding(second, 'macaroon-hex', 'default-readonly', 1, 1)]);
  expect(result.summary.filesScanned).toBe(2);
}));

it('CP-010/B11 an unreadable descendant is skipped while siblings continue', async () => temp(async dir => {
  const a = put(dir, 'a.env', vector('default-readonly').toString('hex'));
  const denied = join(dir, 'D');
  put(denied, 'hidden.env', vector('default-readonly').toString('hex'));
  const fileSystem = { ...fs,
    readdir: vi.fn(async (...args: Parameters<typeof fs.readdir>) => {
      if (args[0] === denied) throw Object.assign(new Error('denied'), { code: 'EACCES' });
      return fs.readdir(...args);
    }),
  };
  const result = await scan([dir], { fs: fileSystem });
  expect(projected(result)).toEqual([finding(a, 'macaroon-hex', 'default-readonly', 1, 1)]);
  skipped(result, denied, 'unreadable');
}));

it('CP-010/B12 missing and unreadable path arguments reject at input-read', async () => temp(async dir => {
  const absent = join(dir, 'missing');
  const file = put(dir, 'unreadable.env', vector('default-readonly').toString('hex'));
  const denied = Object.assign(new Error('denied'), { code: 'EACCES' });
  const fileSystem = { ...fs,
    stat: vi.fn(async (path: string, options?: { bigint?: boolean }) =>
      path === file ? Promise.reject(denied) : fs.stat(path, options as never)),
    lstat: vi.fn(async (path: string, options?: { bigint?: boolean }) =>
      path === file ? Promise.reject(denied) : fs.lstat(path, options as never)),
  };
  for (const [path, options] of [[absent, {}], [file, { fs: fileSystem }]] as const)
    await expect(scan([path], options)).rejects.toMatchObject({ name: 'InputError', stage: 'input-read' });
}));

it('CP-010/B13 read-only trees remain byte and mtime identical with read-only opens', async () => temp(async dir => {
  const a = put(dir, 'a.env', vector('default-readonly').toString('hex'));
  const b = put(dir, 'sub/b.env', vector('default-invoice').toString('base64'));
  const before = [a, b].map(path => ({ path, bytes: readFileSync(path), mtime: statSync(path).mtimeMs }));
  for (const path of [a, b]) chmodSync(path, 0o444);
  for (const path of [join(dir, 'sub'), dir]) chmodSync(path, 0o555);
  try {
    const observed = trackedFs();
    const result = await scan([dir], { fs: observed.fileSystem });
    expect(result.summary.filesScanned).toBe(2);
    expect(observed.opens.length).toBeGreaterThanOrEqual(2);
    for (const { flags } of observed.opens) {
      if (typeof flags === 'number') expect(flags & (constants.O_WRONLY | constants.O_RDWR)).toBe(0);
      else expect(flags).toMatch(/^r/);
    }
    for (const item of before) {
      expect(readFileSync(item.path).equals(item.bytes)).toBe(true);
      expect(statSync(item.path).mtimeMs).toBe(item.mtime);
    }
  } finally {
    for (const path of [join(dir, 'sub'), dir]) chmodSync(path, 0o755);
    for (const path of [a, b]) chmodSync(path, 0o644);
  }
}));

it('CP-010/B14 trailing and Windows separators normalize finding paths', async () => temp(async dir => {
  const path = put(dir, 'sub/b.env', vector('default-readonly').toString('hex'));
  const args = [dir + sep];
  if (process.platform === 'win32') args.push(join(dir, 'sub').replaceAll('/', '\\'));
  for (const arg of args) {
    const result = await scan([arg]);
    expect(projected(result)).toEqual([finding(path, 'macaroon-hex', 'default-readonly', 1, 1)]);
  }
}));
