// Audit 1.4.0: openRegistry checked the size by path and then read the path whole with fs.readFile,
// so a file swapped in or grown after the check was read without a bound. The read now goes through
// the descriptor of the checked file and stops after REGISTRY_FILE_LIMIT + 1 bytes.
import * as fs from 'node:fs/promises';
import { expect, it, vi } from 'vitest';
import { REGISTRY_FILE_LIMIT, openRegistry } from '../src/registry/index.js';
import { fixture } from './helpers/cp038-online.js';

it('a registry reported small that yields more than the limit is refused after a bounded read', async () => {
  const f = fixture();
  f.save([]);
  let delivered = 0;
  // Every stat (by path and of the handle) reports the small file on disk; the handle's reads never
  // end, as a file that keeps growing (or one swapped in after the check) would.
  const open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'read') return async (buffer: Buffer, offset: number, length: number) => {
        buffer.fill(0x20, offset, offset + length);
        delivered += length;
        return { bytesRead: length, buffer };
      };
      const value = Reflect.get(target, key) as unknown;
      return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    } });
  }) as typeof fs.open;
  const readFile = vi.fn(fs.readFile) as unknown as typeof fs.readFile;
  await expect(openRegistry(f.registry, { fs: { ...fs, open, readFile } }))
    .rejects.toMatchObject({ code: 3, message: 'cannot read registry' });
  expect(readFile).not.toHaveBeenCalled();
  expect(delivered).toBeGreaterThan(REGISTRY_FILE_LIMIT);
  expect(delivered).toBeLessThanOrEqual(REGISTRY_FILE_LIMIT + 1);
});
