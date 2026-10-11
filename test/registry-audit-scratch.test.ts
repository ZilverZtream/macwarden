// Pre-1.4 audit, private scratch roots: a Windows root given by its 8.3 short name is accepted
// when no component is a link, and a new root that is not empty once restricted is refused.
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import type * as fsPromises from 'node:fs/promises';
import { join, resolve, win32 } from 'node:path';
import { expect, it, vi } from 'vitest';

const plant = vi.hoisted(() => ({ name: '' as string, made: [] as string[] }));
vi.mock('node:fs/promises', async importOriginal => {
  const original = await importOriginal<typeof fsPromises>();
  return { ...original, mkdtemp: (async (...args: Parameters<typeof original.mkdtemp>) => {
    const made = await original.mkdtemp(...args);
    plant.made.push(String(made));
    // Another account writing into the new directory before its permissions are replaced.
    if (plant.name) await original.writeFile(join(String(made), plant.name), 'planted');
    return made;
  }) as typeof original.mkdtemp };
});

const { createPrivateDirectory, realDirectory } = await import('../scripts/private-scratch.mjs');

type Node = { directory?: boolean; link?: boolean };
function windowsDisk(nodes: Record<string, Node>, canonical: string) {
  const stat = (node: Node | undefined) => {
    if (!node) throw Object.assign(new Error('absent'), { code: 'ENOENT' });
    return { isDirectory: () => node.directory === true, isSymbolicLink: () => node.link === true };
  };
  return { platform: 'win32' as const,
    lstat: (async (path: string) => stat(nodes[win32.resolve(path).toLowerCase()])) as unknown as typeof fsPromises.lstat,
    realpath: (async () => canonical) as unknown as typeof fsPromises.realpath };
}
const short = 'C:\\Users\\LONGNA~1\\Temp\\scratch';
const long = 'C:\\Users\\Long Name\\Temp\\scratch';

it('REGISTRY-AUDIT/scratch-short-name a Windows root given by its 8.3 short name and reached through no link is accepted', async () => {
  const nodes: Record<string, Node> = Object.fromEntries(['C:\\', 'C:\\Users', 'C:\\Users\\LONGNA~1', 'C:\\Users\\LONGNA~1\\Temp', short]
    .map(path => [path.toLowerCase(), { directory: true }]));
  await expect(realDirectory(short, windowsDisk(nodes, long))).resolves.toBeDefined();
});

it('REGISTRY-AUDIT/scratch-short-name a Windows root whose path passes through a junction or link is still refused', async () => {
  const nodes: Record<string, Node> = Object.fromEntries(['C:\\', 'C:\\Users', 'C:\\Users\\LONGNA~1', short]
    .map(path => [path.toLowerCase(), { directory: true }]));
  nodes['c:\\users\\longna~1\\temp'] = { directory: true, link: true };
  await expect(realDirectory(short, windowsDisk(nodes, long))).rejects.toThrow('scratch root must be a real directory');
  // The root itself as a link is refused whatever its canonical name.
  nodes['c:\\users\\longna~1\\temp'] = { directory: true };
  nodes[short.toLowerCase()] = { directory: true, link: true };
  await expect(realDirectory(short, windowsDisk(nodes, short))).rejects.toThrow('scratch root must be a real directory');
});

it('REGISTRY-AUDIT/scratch-empty a new scratch root that is not empty after it was restricted is refused and removed', async () => {
  const parent = resolve(process.env.MACWARDEN_TEST_TMP ?? join(resolve(), 'test/.tmp'));
  mkdirSync(parent, { recursive: true });
  plant.name = 'planted.txt'; plant.made.length = 0;
  try {
    await expect(createPrivateDirectory(parent, 'registry-audit-scratch-')).rejects.toThrow(/not empty/);
    expect(plant.made).toHaveLength(1);
    expect(existsSync(plant.made[0]), 'refused root removed').toBe(false);
  } finally { plant.name = ''; }
  // Without a planted file the root is created as before.
  const made = await createPrivateDirectory(parent, 'registry-audit-scratch-');
  try {
    writeFileSync(join(made, 'own.txt'), 'ok');
    expect(existsSync(join(made, 'own.txt'))).toBe(true);
  } finally { rmSync(made, { recursive: true, force: true }); }
}, 120_000);
