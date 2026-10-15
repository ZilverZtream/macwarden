import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { CANARY_FILE_LIMIT, ensureCanaryConfig, readCanaryConfig } from '../src/watch/canary.js';
import { readUsage, USAGE_FILE_LIMIT, UsageFileError, UsageStore, USAGE_LIMIT, CANARY_LIMIT, COVERAGE_LIMIT, SPAN_LIMIT } from '../src/watch/usage.js';

// MW102-07: the usage and canary sidecars next to the registry are read through a bounded
// regular-file reader. A sidecar that resolves to a protected name (SAFE-02) is refused before
// any open or read, and a sidecar larger than its format allows fails before it is parsed.
// Real symlinks on the real file system, created the way the required walk test creates them.
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function scratch(): string {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'sidecar-'));
  dirs.push(dir);
  return dir;
}

/** node:fs/promises with every content access (open, readFile) recorded. */
function recordingFs() {
  const opened: string[] = [];
  const io = { ...fs,
    open: vi.fn(async (...args: Parameters<typeof fs.open>) => { opened.push(String(args[0])); return fs.open(...args); }),
    readFile: vi.fn(async (...args: Parameters<typeof fs.readFile>) => { opened.push(String(args[0])); return fs.readFile(...args); }),
  } as unknown as typeof fs;
  return { io, opened };
}

const usageText = JSON.stringify({ schema: 1, dropped: 0, entries: [] });
const canaryText = JSON.stringify({ schema: 1, caveatName: 'tenant-0011aabb' });

it('SIDECAR/protected a usage sidecar symlinked to a synthetic seed.json is refused before reading', async () => {
  const dir = scratch();
  const target = join(dir, 'seed.json');
  writeFileSync(target, usageText);
  const link = join(dir, 'registry.json.usage.json');
  symlinkSync(target, link, 'file');
  const { io, opened } = recordingFs();
  const parse = vi.spyOn(UsageStore, 'parse');
  try {
    await expect(readUsage(link, io)).rejects.toBeInstanceOf(UsageFileError);
    expect(opened).toEqual([]);
    expect(parse).not.toHaveBeenCalled();
  } finally { parse.mockRestore(); }
});

it('SIDECAR/protected a canary sidecar symlinked to a synthetic tls.key is refused before reading', async () => {
  const dir = scratch();
  const target = join(dir, 'tls.key');
  writeFileSync(target, canaryText);
  const link = join(dir, 'registry.json.canary.json');
  symlinkSync(target, link, 'file');
  const { io, opened } = recordingFs();
  await expect(readCanaryConfig(link, io)).rejects.toThrow('cannot read canary configuration');
  expect(opened).toEqual([]);
});

it('SIDECAR/protected a sidecar under a protected directory name is refused before reading', async () => {
  const dir = scratch();
  const keyDir = join(dir, 'node.key');
  mkdirSync(keyDir);
  writeFileSync(join(keyDir, 'registry.json.usage.json'), usageText);
  const { io, opened } = recordingFs();
  await expect(readUsage(join(keyDir, 'registry.json.usage.json'), io)).rejects.toBeInstanceOf(UsageFileError);
  expect(opened).toEqual([]);
});

it('SIDECAR/regular a sidecar that is a directory is refused, a missing one is absent, a plain one is read', async () => {
  const dir = scratch();
  mkdirSync(join(dir, 'r.json.usage.json'));
  mkdirSync(join(dir, 'r.json.canary.json'));
  await expect(readUsage(join(dir, 'r.json.usage.json'))).rejects.toBeInstanceOf(UsageFileError);
  await expect(readCanaryConfig(join(dir, 'r.json.canary.json'))).rejects.toThrow('cannot read canary configuration');
  expect((await readUsage(join(dir, 'absent.usage.json'))).size).toBe(0);
  expect(await readCanaryConfig(join(dir, 'absent.canary.json'))).toBeNull();
  writeFileSync(join(dir, 'ok.usage.json'), usageText);
  writeFileSync(join(dir, 'ok.canary.json'), canaryText);
  expect((await readUsage(join(dir, 'ok.usage.json'))).size).toBe(0);
  expect(await readCanaryConfig(join(dir, 'ok.canary.json'))).toEqual({ caveatName: 'tenant-0011aabb' });
  // A symlink to an ordinary sidecar elsewhere is still followed.
  const link = join(dir, 'linked.canary.json');
  symlinkSync(join(dir, 'ok.canary.json'), link, 'file');
  expect(await readCanaryConfig(link)).toEqual({ caveatName: 'tenant-0011aabb' });
});

it('SIDECAR/size limits are derived from the record caps and leave room for a full store', () => {
  // 1 KiB per usage record bounds what watch writes (a method name over 256 bytes is
  // recorded as /unknown/Unknown); 512 bytes per canary use or coverage record; 64 bytes
  // per coverage span.
  expect(USAGE_FILE_LIMIT).toBe(4096 + USAGE_LIMIT * 1024 + (CANARY_LIMIT + COVERAGE_LIMIT) * 512
    + COVERAGE_LIMIT * SPAN_LIMIT * 64);
  const store = new UsageStore();
  const node = `02${'ab'.repeat(32)}`;
  const method = `/${'a'.repeat(120)}.Service/${'M'.repeat(120)}`;
  const at = (index: number) => new Date(Date.UTC(2026, 9, 8) + index);
  for (let index = 0; index < USAGE_LIMIT; index++)
    store.record(node, `id:${index.toString(16).padStart(16, '0')}`, '18446744073709551615', method, at(index), true);
  for (let index = 0; index < CANARY_LIMIT; index++)
    store.recordCanary(node, String(10_000_000_000_000_000_000n + BigInt(index)), Number.MAX_SAFE_INTEGER, at(index));
  for (let index = 0; index < COVERAGE_LIMIT; index++) {
    const other = `03${index.toString(16).padStart(64, 'f')}`;
    // A full span list per node: disjoint registrations, each one second apart.
    for (let span = 0; span < SPAN_LIMIT; span++) {
      store.beginCoverage(other, at(span * 2_000));
      store.endCoverage(other, at(span * 2_000 + 1_000));
    }
  }
  const text = store.toText();
  expect(store.size).toBe(USAGE_LIMIT);
  expect(UsageStore.parse(text).size).toBe(USAGE_LIMIT);
  expect(Buffer.byteLength(text)).toBeLessThan(USAGE_FILE_LIMIT);
  expect(Buffer.byteLength(`${canaryText}\n`)).toBeLessThan(CANARY_FILE_LIMIT);
});

it('SIDECAR/size an oversized usage or canary sidecar fails before it is parsed', async () => {
  const dir = scratch();
  const usage = join(dir, 'r.json.usage.json');
  writeFileSync(usage, `${usageText}${' '.repeat(USAGE_FILE_LIMIT + 1 - usageText.length)}`);
  const canary = join(dir, 'r.json.canary.json');
  writeFileSync(canary, `${canaryText}${' '.repeat(CANARY_FILE_LIMIT + 1 - canaryText.length)}`);
  const { io } = recordingFs();
  const parse = vi.spyOn(UsageStore, 'parse');
  try {
    await expect(readUsage(usage, io)).rejects.toMatchObject({ code: 3, message: 'usage file too large' });
    expect(parse).not.toHaveBeenCalled();
  } finally { parse.mockRestore(); }
  expect(vi.mocked(io.readFile)).not.toHaveBeenCalled();
  await expect(readCanaryConfig(canary, io)).rejects.toThrow('cannot read canary configuration');
  // Exactly at the limit is accepted (trailing whitespace is valid JSON).
  writeFileSync(usage, `${usageText}${' '.repeat(USAGE_FILE_LIMIT - usageText.length)}`);
  expect((await readUsage(usage)).size).toBe(0);
  writeFileSync(canary, `${canaryText}${' '.repeat(CANARY_FILE_LIMIT - canaryText.length)}`);
  expect(await readCanaryConfig(canary)).toEqual({ caveatName: 'tenant-0011aabb' });
});

it('SIDECAR/lock a registry lock or watch lock symlinked to a synthetic seed.json is refused before reading', async () => {
  const dir = scratch();
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }));
  const seed = join(dir, 'seed.json');
  writeFileSync(seed, JSON.stringify({ pid: 2_147_483_000, hostname: 'elsewhere', startedAt: '2026-10-08T00:00:00.000Z' }));
  symlinkSync(seed, `${registry}.lock`, 'file');
  const { io, opened } = recordingFs();
  const { openRegistry } = await import('../src/registry/index.js');
  const view = await openRegistry(registry, { fs: io });
  opened.length = 0;
  await expect(view.lock()).rejects.toMatchObject({ code: 3, step: 'registry-lock', message: 'invalid registry lock' });
  // Only the exclusive create was attempted on the lock path; nothing was read through it.
  const reads = () => vi.mocked(io.readFile).mock.calls.map(call => String(call[0]));
  expect(reads().filter(path => path.includes('seed') || path.endsWith('.lock'))).toEqual([]);
  expect(opened.filter(path => path.includes('seed'))).toEqual([]);

  const watchLock = join(dir, 'registry.json.watch.lock');
  const watchSeed = join(dir, 'watch-seed.json');
  writeFileSync(watchSeed, `${JSON.stringify({ pid: 2_147_483_000, hostname: 'elsewhere' })}\n`);
  symlinkSync(watchSeed, watchLock, 'file');
  const { acquireLock } = await import('../src/commands/watch.js');
  const before = opened.length;
  await expect(acquireLock(watchLock, { fs: io, env: {}, clock: () => new Date(), emit: () => undefined,
    hostname: () => 'here', pid: 1_000_001, processDomain: async () => null } as never)).rejects.toThrow('watch lock without owner record');
  expect(opened.slice(before).filter(path => path.includes('seed'))).toEqual([]);
  expect(reads().filter(path => path === watchLock)).toEqual([]);
});

// Audit 1.3.2: the canary configuration was written in place, so a failed write (ENOSPC) left a
// 0-byte file that every later watch (W4) and bake --canary (B6) refused as invalid, for good.
it('SIDECAR/canary-create a failed write leaves no canary configuration or temp file behind, and a later run creates it', async () => {
  const dir = scratch();
  const canary = join(dir, 'r.json.canary.json');
  const full = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    handle.writeFile = async () => { throw Object.assign(new Error('no space left on device'), { code: 'ENOSPC' }); };
    return handle;
  } } as typeof fs;
  await expect(ensureCanaryConfig(canary, full)).rejects.toThrow('cannot create canary configuration');
  expect(readdirSync(dir)).toEqual([]);
  const created = await ensureCanaryConfig(canary);
  expect(await readCanaryConfig(canary)).toEqual(created);
  expect(readdirSync(dir)).toEqual(['r.json.canary.json']);
}, 60_000);

it('SIDECAR/canary-create a configuration another run created first is used, never replaced; concurrent runs agree', async () => {
  const dir = scratch();
  const canary = join(dir, 'r.json.canary.json');
  const theirs = `${JSON.stringify({ schema: 1, caveatName: 'policy-00112233' })}\n`;
  // The other run places its file after this one found none and wrote its own temp file.
  const racing = { ...fs, link: async (...args: Parameters<typeof fs.link>) => { writeFileSync(canary, theirs); return fs.link(...args); } } as typeof fs;
  expect(await ensureCanaryConfig(canary, racing)).toEqual({ caveatName: 'policy-00112233' });
  expect(readFileSync(canary, 'utf8')).toBe(theirs);
  expect(readdirSync(dir)).toEqual(['r.json.canary.json']);
  const other = join(dir, 'other.json.canary.json');
  const results = await Promise.all([1, 2, 3, 4].map(() => ensureCanaryConfig(other)));
  expect(new Set(results.map(result => result.caveatName)).size).toBe(1);
  expect(await readCanaryConfig(other)).toEqual(results[0]);
  expect(readdirSync(dir).sort()).toEqual(['other.json.canary.json', 'r.json.canary.json']);
}, 60_000);
