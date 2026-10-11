// An --out (bake, rotate) or inventory --report --out that names the registry file or a file
// named after it (its lock, claim, temporary and sidecar files) is refused before any lock, file
// or LND call (1.2.1). Before, bake wrote the credential to a registry path that did not exist
// yet and the registry save then renamed its temp file over it: bake reported success and the
// credential was lost.
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as fsPromises from 'node:fs/promises';
import { Readable } from 'node:stream';
import { afterEach, expect, it, vi } from 'vitest';
import { run as bake } from '../src/commands/bake/index.js';
import { namesRegistryFile } from '../src/commands/bake/out-registry.js';
import { Secret } from '../src/secret.js';
import { directory, fixture } from './helpers/cp025-bake-support.mjs';
import { invoke as rotate, failure as rotateFailure, scratch as rotateScratch, unchanged } from './helpers/cp028-rotate-support.js';
import { scratch as finishScratch } from './helpers/cp029-rotate-support.js';
import { run as inventory } from '../src/commands/inventory.js';
import { run as attenuate } from '../src/commands/attenuate.js';
import { REGISTRY_OUT_REFUSAL } from '../src/commands/bake/out-registry.js';

const uuid = '0123abcd-0123-4abc-8def-0123456789ab';
const sidecars = (registry: string) => ({ registry, lock: `${registry}.lock`, claim: `${registry}.lock.claim`,
  temp: `${registry}.${uuid}.tmp`, canary: `${registry}.canary.json`, usage: `${registry}.usage.json`,
  dotted: join(registry, '..', 'sub', '..', 'registry.json') });

afterEach(() => { vi.unstubAllEnvs(); });
/**
 * Points the default registry location into `dir` on this platform and returns its folder
 * (created, empty) and the environment the command gets: APPDATA on Windows, XDG_CONFIG_HOME
 * on Linux, and on macOS the home directory itself (~/Library/Application Support), which
 * os.homedir() reads from HOME.
 */
function defaultRegistryFolder(dir: string): { folder: string; env: Record<string, string> } {
  if (process.platform === 'darwin') vi.stubEnv('HOME', dir);
  const folder = process.platform === 'win32' ? join(dir, 'macwarden')
    : process.platform === 'darwin' ? join(dir, 'Library', 'Application Support', 'macwarden') : join(dir, 'macwarden');
  mkdirSync(folder, { recursive: true });
  return { folder, env: process.platform === 'win32' ? { APPDATA: dir } : process.platform === 'darwin' ? {} : { XDG_CONFIG_HOME: dir } };
}

function withOut(args: string[], out: string): string[] {
  const copy = [...args]; copy[copy.indexOf('--out') + 1] = out; return copy;
}

for (const kind of Object.keys(sidecars('r')) as Array<keyof ReturnType<typeof sidecars>>) {
  it(`bake refuses --out naming the ${kind} file of a registry that does not exist yet, at B4`, async () => {
    const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'out-registry-'));
    const f = fixture(dir, Secret);
    const out = sidecars(f.registry)[kind];
    const result = await bake(withOut(f.args, out), f.deps);
    expect(result.error).toMatchObject({ code: 3, step: 'B4' });
    expect(result.error!.message).toMatch(/registry/);
    expect(f.state.calls).toEqual([]);
    expect(readdirSync(dir).filter(name => name.startsWith('registry.json'))).toEqual([]);
  });
}

// The rule itself, on every platform: folded on Windows and macOS, exact elsewhere. A real bake on
// a case-folding file system is the Windows variant test/out-registry-case.windows-fs.test.ts.
it('OUT-REGISTRY/case-rule --out naming the registry in another letter case is the registry where the file system folds case', () => {
  const dir = join(directory('MACWARDEN_TEST_TMP'), 'case-rule');
  expect(namesRegistryFile(join(dir, 'REGISTRY.JSON'), join(dir, 'registry.json'), 'win32')).toBe(true);
  expect(namesRegistryFile(join(dir, 'REGISTRY.JSON'), join(dir, 'registry.json'), 'darwin')).toBe(true);
  expect(namesRegistryFile(join(dir, 'REGISTRY.JSON'), join(dir, 'registry.json'), 'linux')).toBe(false);
});

it('bake refuses --out naming the default registry in an empty directory', async () => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'out-registry-'));
  const f = fixture(dir, Secret);
  const at = f.args.indexOf('--registry'); const args = [...f.args]; args.splice(at, 2);
  const { folder, env } = defaultRegistryFolder(dir);
  const result = await bake(withOut(args, join(folder, 'registry.json')), { ...f.deps, env });
  expect(result.error).toMatchObject({ code: 3, step: 'B4' }); expect(f.state.calls).toEqual([]);
  expect(readdirSync(folder)).toEqual([]);
});

it('bake --out naming an existing registry exits 3 at B4 and leaves the registry unchanged', async () => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'out-registry-'));
  const f = fixture(dir, Secret);
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [] }), { mode: 0o600 });
  const before = readFileSync(f.registry);
  const result = await bake(withOut(f.args, f.registry), f.deps);
  expect(result.error).toMatchObject({ code: 3, step: 'B4' }); expect(f.state.calls).toEqual([]);
  expect(readFileSync(f.registry).equals(before)).toBe(true); expect(existsSync(`${f.registry}.lock`)).toBe(false);
});

// rotate runs the command in process and then the leak check over the scratch tree (findLeaks,
// cp028-rotate-support invoke); under a loaded full suite that passed the 15 s default, so these get 90 s
// (as RECONCILE/bounds did in 1.2.1).
for (const kind of ['registry', 'lock', 'claim', 'temp', 'canary', 'usage'] as const) {
  it(`rotate refuses --out naming the registry ${kind} file at S5`, async () => rotateScratch(async f => {
    const out = sidecars(f.registry)[kind];
    f.args.splice(0, f.args.length, ...withOut(f.args, out));
    const before = readFileSync(f.registry), result = await rotate(f);
    rotateFailure(f, result, 3, 'S5'); expect(f.calls).toEqual([]);
    if (kind !== 'registry') expect(existsSync(out)).toBe(false);
    unchanged(f, before);
  }), 90_000);
}

for (const kind of ['registry', 'lock', 'claim', 'temp', 'canary', 'usage'] as const) {
  it(`inventory refuses --report --out naming the registry ${kind} file at N7`, async () => finishScratch(async f => {
    const out = sidecars(f.registry)[kind];
    const before = readFileSync(f.registry);
    const result = await inventory([...f.args.slice(2), '--report', 'json', '--out', out], f.deps);
    expect(result.error).toMatchObject({ code: 3, step: 'N7' }); expect(f.calls).toEqual([]);
    if (kind !== 'registry') expect(existsSync(out)).toBe(false);
    expect(readFileSync(f.registry).equals(before)).toBe(true);
  }));
}

// 1.2.1: attenuate --out (A3) gets the same refusal, against the default registry location
// (attenuate has no --registry). Before, `attenuate x --out <registry>.lock` exited 0 and left a
// fake lock that blocked every later registry writer.
for (const kind of ['registry', 'lock', 'claim', 'temp', 'canary', 'usage'] as const) {
  it(`attenuate refuses --out naming the default registry ${kind} file at A3`, async () => {
    const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'out-registry-'));
    const { folder, env } = defaultRegistryFolder(dir);
    const out = sidecars(join(folder, 'registry.json'))[kind];
    const result = await attenuate([join(resolve(), 'test/vectors/default-admin.macaroon'), '--out', out, '--expires', '1d'],
      { stdin: Object.assign(Readable.from([]), { isTTY: true }), fs: fsPromises, env, clock: () => new Date('2026-10-05T09:00:00Z') });
    expect(result.error).toEqual({ code: 3, step: 'A3', message: REGISTRY_OUT_REFUSAL });
    expect(readdirSync(folder)).toEqual([]);
  });
}

it('attenuate --out next to the default registry under another name is still written', async () => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'out-registry-'));
  mkdirSync(join(dir, 'macwarden'));
  const env = process.platform === 'win32' ? { APPDATA: dir } : { XDG_CONFIG_HOME: dir };
  const out = join(dir, 'macwarden', 'registry.jsonx.lock');
  const result = await attenuate([join(resolve(), 'test/vectors/default-admin.macaroon'), '--out', out, '--expires', '1d'],
    { stdin: Object.assign(Readable.from([]), { isTTY: true }), fs: fsPromises, env, clock: () => new Date('2026-10-05T09:00:00Z') });
  expect(result.ok).toBe(true); expect(existsSync(out)).toBe(true);
});
