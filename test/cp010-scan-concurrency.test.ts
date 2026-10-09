import { linkSync, mkdirSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { basename, join } from 'node:path';
import { expect, it } from 'vitest';
import * as scanner from '../src/scan/index.js';
import { scratch, vector } from './support/cp039-audit.js';

// Opens are delayed by a per-path amount so file scans complete out of walk
// order. Open handles are counted from open until close.
function delayedFs(delay: (path: string) => number) {
  const state = { open: 0, peak: 0, opened: [] as string[] };
  const io = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const path = String(args[0]);
    await new Promise(resume => setTimeout(resume, delay(path)));
    const handle = await fs.open(...args);
    state.open++; state.peak = Math.max(state.peak, state.open); state.opened.push(path);
    let closed = false;
    return new Proxy(handle, { get(target, key) {
      if (key === 'close') return async () => { if (!closed) { closed = true; state.open--; } return target.close(); };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs;
  return { io, state };
}

function seeded(seed: number) {
  let value = seed;
  return () => { value = (value * 1103515245 + 12345) % 2147483648; return value / 2147483648; };
}

function tree(dir: string): void {
  const admin = vector('default-admin'), readonly = vector('default-readonly'), invoice = vector('default-invoice');
  for (const [index, sub] of ['a', join('a', 'b'), join('a', 'b', 'c'), 'd', 'e'].entries()) {
    mkdirSync(join(dir, sub), { recursive: true });
    for (let i = 0; i < 12; i++) {
      const base = join(dir, sub, `f${index}-${i}`);
      if (i % 4 === 0) writeFileSync(`${base}.macaroon`, [admin, readonly, invoice][i % 3]!.bytes);
      else if (i % 4 === 1) writeFileSync(`${base}.env`, `X=1\nTOKEN=${readonly.bytes.toString('hex')}\n`);
      else if (i % 4 === 2) writeFileSync(`${base}.bin`, Buffer.from([1, 0, 2, 3]));
      else writeFileSync(`${base}.txt`, `nothing here ${i}\nAgEDbG5kAtoo-short\n`);
    }
  }
  writeFileSync(join(dir, 'a', 'broken.macaroon'), 'not a macaroon');
  linkSync(join(dir, 'a', 'f0-0.macaroon'), join(dir, 'd', 'alias.macaroon'));
}

it('CP-010/scan-concurrency results are identical whatever order concurrent file scans complete in', async () => scratch(async dir => {
  tree(dir);
  const baseline = await scanner.scan([dir], { includeDirs: false });
  expect(baseline.summary.filesScanned).toBeGreaterThan(40);
  for (const seed of [1, 7, 42]) {
    const random = seeded(seed), delays = new Map<string, number>();
    const { io } = delayedFs(path => { if (!delays.has(path)) delays.set(path, Math.floor(random() * 12)); return delays.get(path)!; });
    expect(await scanner.scan([dir], { includeDirs: false, fs: io })).toEqual(baseline);
  }
  // Earlier files finish last: the strongest reordering.
  let countdown = 400;
  const { io } = delayedFs(() => Math.max(0, (countdown -= 5)));
  expect(await scanner.scan([dir], { includeDirs: false, fs: io })).toEqual(baseline);
}), 60_000);

it('CP-010/scan-concurrency open files never exceed the bound and reads overlap', async () => scratch(async dir => {
  for (let i = 0; i < 80; i++) writeFileSync(join(dir, `file-${i}.txt`), `line ${i}\n`);
  const { io, state } = delayedFs(() => 5);
  const result = await scanner.scan([dir], { includeDirs: false, fs: io });
  expect(result.summary.filesScanned).toBe(80);
  expect(scanner.SCAN_CONCURRENCY).toBeGreaterThan(1);
  expect(state.peak).toBeLessThanOrEqual(scanner.SCAN_CONCURRENCY);
  expect(state.peak).toBeGreaterThan(1);
  expect(state.open).toBe(0);
}), 60_000);

it('CP-010/scan-concurrency a file reached twice is reported once under the first walk position even when the later scan finishes first', async () => scratch(async dir => {
  const v = vector('default-readonly');
  const one = join(dir, 'one'), two = join(dir, 'two');
  mkdirSync(one); mkdirSync(two);
  writeFileSync(join(one, 'x.macaroon'), v.bytes);
  linkSync(join(one, 'x.macaroon'), join(one, 'y.macaroon'));
  linkSync(join(one, 'x.macaroon'), join(two, 'z.macaroon'));
  const names = await fs.readdir(one);
  const first = join(one, names.find(name => name.endsWith('.macaroon'))!);
  // Within one argument: delay the first-listed link so its twin completes first.
  const slowFirst = delayedFs(path => basename(path) === basename(first) ? 60 : 0).io;
  const within = await scanner.scan([one], { includeDirs: false, fs: slowFirst });
  expect(within.findings).toHaveLength(1);
  expect(basename(within.findings[0]!.path)).toBe(basename(first));
  expect(within.summary.filesScanned).toBe(1);
  // Across arguments: the first argument wins.
  const across = await scanner.scan([two, one], { includeDirs: false, fs: delayedFs(path => path.includes('z.macaroon') ? 60 : 0).io });
  expect(across.findings).toHaveLength(1);
  expect(across.findings[0]!.path.endsWith('two/z.macaroon')).toBe(true);
  expect(across.summary.filesScanned).toBe(1);
}), 60_000);
