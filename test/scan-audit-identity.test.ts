import { linkSync, writeFileSync } from 'node:fs';
import type { BigIntStats, PathLike, Stats } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { scan } from '../src/scan/index.js';
import { scratch, vector } from './support/cp039-audit.js';

// ReFS and Dev Drive have 128-bit file IDs that Node truncates to 64 bits: two distinct files
// can show the same device and file index. The injected file system presents that collision.
function collidingFs(names: Set<string>) {
  const same = <T extends Stats | BigIntStats>(stat: T, path: string): T =>
    names.has(String(path)) && stat.isFile() ? Object.assign(stat, { dev: typeof stat.dev === 'bigint' ? 5n : 5,
      ino: typeof stat.ino === 'bigint' ? 77n : 77 }) : stat;
  return { ...fs,
    lstat: async (path: PathLike, options?: object) => same(await fs.lstat(path, options as never), String(path)),
    stat: async (path: PathLike, options?: object) => same(await fs.stat(path, options as never), String(path)),
    open: async (...args: Parameters<typeof fs.open>) => {
      const handle = await fs.open(...args);
      return { stat: async (options?: object) => same(await handle.stat(options as never), String(args[0])),
        read: (...readArgs: Parameters<typeof handle.read>) => handle.read(...readArgs), close: () => handle.close() };
    } } as unknown as typeof fs;
}

it('two distinct single-name files with the same file index are both scanned', async () => scratch(async dir => {
  const admin = vector('default-admin'), readonly = vector('default-readonly');
  const first = join(dir, 'a.env'), second = join(dir, 'b.env');
  writeFileSync(first, `A=${admin.bytes.toString('hex')}\n`);
  writeFileSync(second, `B=${readonly.bytes.toString('hex')}\n`);
  const result = await scan([dir], { fs: collidingFs(new Set([first, second])) });
  expect(result.findings.map(f => f.fingerprint)).toEqual([admin.fingerprint, readonly.fingerprint]);
  expect(result.summary.filesScanned).toBe(2);
}));

it('hard links are still one file', async () => scratch(async dir => {
  const admin = vector('default-admin');
  const first = join(dir, 'a.env');
  writeFileSync(first, `A=${admin.bytes.toString('hex')}\n`);
  linkSync(first, join(dir, 'b.env'));
  const result = await scan([dir]);
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0].alsoAt?.count).toBe(1);
}));
