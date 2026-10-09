import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { deadProductLock } from './helpers/cp042-lock-process.js';
import { ownProcessDomain } from '../src/registry/process-domain.js';
import { expect, it, vi } from 'vitest';

type Entry = {
  nodePubkey: string; label: string | null; rootKeyId: string; permissions: string[];
  caveats: { type: string; value: string; requested?: string }[]; grade: string;
  fingerprint: string; outPath: string | null; createdAt: string; verified: boolean;
  status: 'active' | 'revoked'; revokedAt: string | null; revokeEvidence: string | null;
  replaces: string | null; replacedBy: string | null;
};
type Registry = {
  entries: Entry[];
  find: (nodePubkey: string, rootKeyId: string) => Entry | undefined;
  add: (entry: Entry) => void | Promise<void>;
  markRevoked: (nodePubkey: string, rootKeyId: string, revokedAt: string, evidence: string) => void | Promise<void>;
  lock: (options?: { breakLock?: boolean }) => Promise<void>;
  save: () => Promise<void>;
  unlock: () => Promise<void>;
};
type RegistryDeps = {
  fs?: typeof fs; platform?: NodeJS.Platform; env?: NodeJS.ProcessEnv; homedir?: () => string;
  hostname?: () => string; pidAlive?: (pid: number) => boolean; sleep?: (ms: number) => Promise<void>;
};
type RegistryModule = {
  openRegistry: (path?: string, deps?: RegistryDeps) => Promise<Registry>;
};
const repo = resolve();
const fixture = JSON.parse(readFileSync(join(repo, 'test/registry-fixtures/registry.json'), 'utf8')) as {
  schema: number; entries: Entry[];
};
const base = join(repo, 'node_modules/.cp017-tests');

const registry = (): Promise<RegistryModule> => import('../src/registry/index.js') as Promise<RegistryModule>;
const clone = <T>(value: T): T => structuredClone(value);
const failing = async (action: () => unknown | Promise<unknown>) => {
  try { await action(); } catch (error) { return error as Error & { code?: number; exitCode?: number }; }
  throw new Error('Expected registry rejection');
};
function inputError(error: Error & { code?: number; exitCode?: number }): void {
  expect(error.name).toBe('RegistryInputError');
  if (typeof error.code === 'number') expect(error.code).toBe(3);
  if (typeof error.exitCode === 'number') expect(error.exitCode).toBe(3);
}
function usageError(error: Error & { code?: number; exitCode?: number }): void {
  expect(error.name).toBe('RegistryUsageError');
  if (typeof error.code === 'number') expect(error.code).toBe(2);
  if (typeof error.exitCode === 'number') expect(error.exitCode).toBe(2);
}
async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'registry-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function copied(dir: string): string {
  const path = join(dir, 'registry.json');
  writeFileSync(path, JSON.stringify(fixture));
  return path;
}
function allFiles(dir: string): string[] { return readdirSync(dir).sort(); }

it('CP-017/B1 absent registry opens empty without creating the file or lock', async () => temp(async dir => {
  const path = join(dir, 'missing', 'registry.json');
  const view = await (await registry()).openRegistry(path);
  expect(view.entries).toEqual([]);
  expect(existsSync(path)).toBe(false);
  expect(existsSync(`${path}.lock`)).toBe(false);
  expect(existsSync(join(dir, 'missing'))).toBe(false);
}));

it.each([
  ['malformed JSON', '{'],
  ['unknown schema', JSON.stringify({ ...fixture, schema: 2 })],
  ['unknown root field', JSON.stringify({ ...fixture, credential: 'forbidden' })],
  ['unknown entry field', JSON.stringify({ ...fixture, entries: [{ ...fixture.entries[0], credential: 'forbidden' }] })],
  ['missing entry field', JSON.stringify({ ...fixture, entries: [{ ...fixture.entries[0], fingerprint: undefined }] })],
  ['numeric root ID', JSON.stringify({ ...fixture, entries: [{ ...fixture.entries[0], rootKeyId: 42 }] })],
  ['out of range root ID', JSON.stringify({ ...fixture, entries: [{ ...fixture.entries[0], rootKeyId: '18446744073709551616' }] })],
  ['duplicate identity', JSON.stringify({ ...fixture, entries: [fixture.entries[0], fixture.entries[0]] })],
])('CP-017/B2 %s fails as input without changing original bytes', async (_case, content) => temp(async dir => {
  const path = join(dir, 'registry.json');
  writeFileSync(path, content);
  const before = readFileSync(path);
  const module = await registry();
  const error = await failing(() => module.openRegistry(path));
  inputError(error);
  expect(error.message).not.toContain('forbidden');
  expect(readFileSync(path).equals(before)).toBe(true);
  expect(existsSync(`${path}.lock`)).toBe(false);
}));

it('CP-017/B3 exact node and uint64 identity, label and revoked rules round-trip', async () => temp(async dir => {
  const path = copied(dir);
  const view = await (await registry()).openRegistry(path);
  const first = fixture.entries[0];
  expect(view.find(first.nodePubkey, first.rootKeyId)).toEqual(first);
  expect(view.find(fixture.entries[2].nodePubkey, first.rootKeyId)).toEqual(fixture.entries[2]);
  expect(view.find(first.nodePubkey, '18446744073709551614')).toBeUndefined();
  const newEntry = { ...clone(first), rootKeyId: '18446744073709551614', label: 'merchant',
    fingerprint: 'fp:8c142f8ae9cf05d7' };
  await view.lock();
  try {
    await view.add(newEntry);
    await view.markRevoked(first.nodePubkey, newEntry.rootKeyId, '2026-10-04T12:00:00Z', 'rejected');
    await view.save();
  } finally { await view.unlock(); }
  const loaded = await (await registry()).openRegistry(path);
  expect(loaded.find(first.nodePubkey, newEntry.rootKeyId)).toMatchObject({ status: 'revoked',
    revokedAt: '2026-10-04T12:00:00Z', revokeEvidence: 'rejected' });
  expect(loaded.find(first.nodePubkey, first.rootKeyId)).toEqual(first);
  await loaded.lock();
  try {
    usageError(await failing(() => loaded.add(newEntry)));
    usageError(await failing(() => loaded.add({ ...clone(first), rootKeyId: '91' })));
    usageError(await failing(() => loaded.add({ ...clone(first), rootKeyId: '92', label: null })));
    const pending = { ...clone(first), rootKeyId: '93', replaces: first.rootKeyId };
    await loaded.add(pending);
    expect(loaded.find(first.nodePubkey, '93')).toMatchObject({ replaces: first.rootKeyId });
  } finally { await loaded.unlock(); }
}));

it('CP-017/B4 injected rename failures preserve old bytes and retry Windows sharing errors', async () => temp(async dir => {
  const path = copied(dir);
  const original = readFileSync(path);
  let attempts = 0;
  const blockedFs = { ...fs, rename: vi.fn(async () => {
    attempts++;
    throw Object.assign(new Error('private rename detail'), { code: 'EPERM' });
  }) } as typeof fs;
  const delays: number[] = [];
  const view = await (await registry()).openRegistry(path, { fs: blockedFs, platform: 'win32',
    sleep: async ms => { delays.push(ms); } });
  await view.lock();
  try {
    inputError(await failing(() => view.save()));
    expect(attempts).toBe(10);
    expect(delays.length).toBe(9);
    expect(delays.reduce((sum, ms) => sum + ms, 0)).toBeGreaterThanOrEqual(800);
    expect(readFileSync(path).equals(original)).toBe(true);
  } finally { await view.unlock(); }
  attempts = 0;
  const transientFs = { ...fs, rename: vi.fn(async (from: string, to: string) => {
    attempts++;
    if (attempts < 3) throw Object.assign(new Error('busy'), { code: 'EBUSY' });
    await fs.rename(from, to);
  }) } as typeof fs;
  const transient = await (await registry()).openRegistry(path, { fs: transientFs, platform: 'win32', sleep: async () => {} });
  await transient.lock();
  try { await transient.save(); } finally { await transient.unlock(); }
  expect(attempts).toBe(3);
  expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual(fixture);
}));

it('CP-017/B5 new file and directory are owner-only on POSIX; Windows uses best effort', async () => temp(async dir => {
  const path = join(dir, 'private', 'registry.json');
  const view = await (await registry()).openRegistry(path);
  await view.lock();
  try { await view.save(); } finally { await view.unlock(); }
  if (process.platform !== 'win32') {
    expect(statSync(join(dir, 'private')).mode & 0o777).toBe(0o700);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  } else {
    expect(existsSync(path)).toBe(true);
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({ schema: 1, entries: [] });
  }
}));

it('CP-017/B6 an exclusive held lock names its owner and survives the rejected caller', async () => temp(async dir => {
  const path = join(dir, 'registry.json');
  const module = await registry();
  const holder = await module.openRegistry(path);
  await holder.lock();
  try {
    const lock = JSON.parse(readFileSync(`${path}.lock`, 'utf8')) as { pid: number; hostname: string; startedAt: string };
    expect(lock).toMatchObject({ pid: process.pid, hostname: hostname() });
    expect(Number.isNaN(Date.parse(lock.startedAt))).toBe(false);
    const before = readFileSync(`${path}.lock`);
    const contender = await module.openRegistry(path);
    const error = await failing(() => contender.lock());
    inputError(error);
    expect(error.message).toBe(`registry locked by pid ${lock.pid} on ${lock.hostname} since ${lock.startedAt}`);
    expect(readFileSync(`${path}.lock`).equals(before)).toBe(true);
    expect(existsSync(path)).toBe(false);
  } finally { await holder.unlock(); }
  expect(existsSync(`${path}.lock`)).toBe(false);
}));

it('CP-017/B7 break-lock recovers dead same-host owner and unlock owns only its own lock', async () => temp(async dir => {
  const path = join(dir, 'registry.json');
  const module = await registry();
  const lockPath = `${path}.lock`;
  const startedAt = '2026-10-04T00:00:00Z';
  for (const [host, alive, allowed] of [
    [hostname(), true, false], ['another-host', false, false],
  ] as const) {
    const processDomain = await ownProcessDomain();
    expect(processDomain).not.toBeNull();
    writeFileSync(lockPath, JSON.stringify({ pid: 911111, hostname: host, startedAt, processDomain }));
    const view = await module.openRegistry(path, { hostname, pidAlive: () => alive });
    if (allowed) {
      await view.lock({ breakLock: true });
      expect(JSON.parse(readFileSync(lockPath, 'utf8')).pid).toBe(process.pid);
      await view.unlock();
      expect(existsSync(lockPath)).toBe(false);
    } else {
      const refused = await failing(() => view.lock({ breakLock: true }));
      inputError(refused);
      expect((refused as Error).message).toBe(`registry locked by pid 911111 on ${host} since ${startedAt}`);
      await view.unlock();
      expect(JSON.parse(readFileSync(lockPath, 'utf8')).pid).toBe(911111);
    }
  }
  const productPath = join(dir, 'product-registry.json'), productLock = productPath + '.lock';
  await deadProductLock(productPath);
  const view = await module.openRegistry(productPath);
  await view.lock({ breakLock: true });
  expect(JSON.parse(readFileSync(productLock, 'utf8')).pid).toBe(process.pid);
  await view.unlock();
  expect(existsSync(productLock)).toBe(false);
  expect(JSON.parse(readFileSync(lockPath, 'utf8')).pid).toBe(911111);
}));

it('CP-017/B8 injected OS defaults and explicit path select only their registry', async () => temp(async dir => {
  const module = await registry();
  const fakeHome = join(dir, 'home');
  const xdg = join(dir, 'xdg');
  const appdata = join(dir, 'appdata');
  const cases: Array<[NodeJS.Platform, NodeJS.ProcessEnv, string]> = [
    ['linux', { XDG_CONFIG_HOME: xdg }, join(xdg, 'macwarden/registry.json')],
    ['linux', {}, join(fakeHome, '.config/macwarden/registry.json')],
    ['darwin', {}, join(fakeHome, 'Library/Application Support/macwarden/registry.json')],
    ['win32', { APPDATA: appdata }, join(appdata, 'macwarden/registry.json')],
  ];
  for (const [platform, env, expected] of cases) {
    mkdirSync(resolve(expected, '..'), { recursive: true });
    writeFileSync(expected, JSON.stringify(fixture));
    const deps = { platform, env, homedir: () => fakeHome };
    expect((await module.openRegistry(undefined, deps)).entries).toEqual(fixture.entries);
    const override = join(dir, `${platform}-${Object.keys(env).length}`, 'override.json');
    const empty = await module.openRegistry(override, deps);
    expect(empty.entries).toEqual([]);
    expect(existsSync(override)).toBe(false);
  }
}));

it('CP-017/B9 serialization and failures never expose a sentinel credential', async () => temp(async dir => {
  const path = join(dir, 'registry.json');
  const bytes = readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
  const encoded = [bytes.toString('latin1'), bytes.toString('hex'), bytes.toString('base64'),
    bytes.toString('base64url')];
  const view = await (await registry()).openRegistry(path);
  const offered = { ...clone(fixture.entries[0]), credential: bytes.toString('base64') } as Entry;
  const error = await failing(() => view.add(offered));
  inputError(error);
  for (const representation of encoded) expect(error.message).not.toContain(representation);
  const hostilePath = join(dir, 'hostile.json');
  writeFileSync(hostilePath, JSON.stringify({ ...fixture, credential: bytes.toString('base64') }));
  let openError: Error;
  try { openError = await failing(() => registry().then(module => module.openRegistry(hostilePath))); }
  finally { rmSync(hostilePath); }
  inputError(openError);
  for (const representation of encoded) expect(openError.message).not.toContain(representation);
  expect(existsSync(path)).toBe(false);
  expect(allFiles(dir)).toEqual([]);
}));

it('CP-017/B10 a read ignores a held mutation lock and preserves bytes and mtime', async () => temp(async dir => {
  const path = copied(dir);
  const module = await registry();
  const holder = await module.openRegistry(path);
  await holder.lock();
  try {
    const before = readFileSync(path);
    const mtime = statSync(path).mtimeMs;
    const reader = await module.openRegistry(path);
    expect(reader.entries).toEqual(fixture.entries);
    expect(readFileSync(path).equals(before)).toBe(true);
    expect(statSync(path).mtimeMs).toBe(mtime);
  } finally { await holder.unlock(); }
}));
