// An --out (bake, rotate) or inventory --report --out that names the registry file or a file
// named after it (its lock, claim, temporary and sidecar files) is refused before any lock, file
// or LND call (1.2.1). Before, bake wrote the credential to a registry path that did not exist
// yet and the registry save then renamed its temp file over it: bake reported success and the
// credential was lost.
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { run as bake } from '../src/commands/bake/index.js';
import { Secret } from '../src/secret.js';
import { directory, fixture } from './helpers/cp025-bake-support.mjs';
import { invoke as rotate, failure as rotateFailure, scratch as rotateScratch, unchanged } from './helpers/cp028-rotate-support.js';
import { scratch as finishScratch } from './helpers/cp029-rotate-support.js';
import { run as inventory } from '../src/commands/inventory.js';

const uuid = '0123abcd-0123-4abc-8def-0123456789ab';
const sidecars = (registry: string) => ({ registry, lock: `${registry}.lock`, claim: `${registry}.lock.claim`,
  temp: `${registry}.${uuid}.tmp`, canary: `${registry}.canary.json`, usage: `${registry}.usage.json`,
  dotted: join(registry, '..', 'sub', '..', 'registry.json') });
const caseFolding = process.platform === 'win32' || process.platform === 'darwin';

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

it.runIf(caseFolding)('bake refuses --out naming the registry in another letter case', async () => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'out-registry-'));
  const f = fixture(dir, Secret);
  const result = await bake(withOut(f.args, join(dir, 'REGISTRY.JSON')), f.deps);
  expect(result.error).toMatchObject({ code: 3, step: 'B4' }); expect(f.state.calls).toEqual([]);
  expect(readdirSync(dir).filter(name => name.toLowerCase().startsWith('registry.json'))).toEqual([]);
});

it.skipIf(process.platform === 'darwin')('bake refuses --out naming the default registry in an empty directory', async () => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'out-registry-'));
  const f = fixture(dir, Secret);
  const at = f.args.indexOf('--registry'); const args = [...f.args]; args.splice(at, 2);
  mkdirSync(join(dir, 'macwarden'));
  const env = process.platform === 'win32' ? { APPDATA: dir } : { XDG_CONFIG_HOME: dir };
  const result = await bake(withOut(args, join(dir, 'macwarden', 'registry.json')), { ...f.deps, env });
  expect(result.error).toMatchObject({ code: 3, step: 'B4' }); expect(f.state.calls).toEqual([]);
  expect(readdirSync(join(dir, 'macwarden'))).toEqual([]);
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

for (const kind of ['registry', 'lock', 'claim', 'temp', 'canary', 'usage'] as const) {
  it(`rotate refuses --out naming the registry ${kind} file at S5`, async () => rotateScratch(async f => {
    const out = sidecars(f.registry)[kind];
    f.args.splice(0, f.args.length, ...withOut(f.args, out));
    const before = readFileSync(f.registry), result = await rotate(f);
    rotateFailure(f, result, 3, 'S5'); expect(f.calls).toEqual([]);
    if (kind !== 'registry') expect(existsSync(out)).toBe(false);
    unchanged(f, before);
  }));
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
