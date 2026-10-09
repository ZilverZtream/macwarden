import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

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
  lock: () => Promise<void>;
  save: () => Promise<void>;
  unlock: () => Promise<void>;
};
type RegistryModule = { openRegistry: (path: string) => Promise<Registry> };
type RegistryError = Error & { code?: number; exitCode?: number };

const repo = resolve();
const fixture = JSON.parse(readFileSync(join(repo, 'test/registry-fixtures/registry.json'), 'utf8')) as {
  schema: number; entries: Entry[];
};
const testTmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp-cp017-label-reference');
process.env.MACWARDEN_TEST_TMP = testTmp;

const registry = (): Promise<RegistryModule> => import('../src/registry/index.js') as Promise<RegistryModule>;

async function temp(work: (dir: string) => Promise<void>): Promise<void> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'registry-label-'));
  try { await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

async function rejection(action: () => unknown | Promise<unknown>): Promise<RegistryError | undefined> {
  try { await action(); } catch (error) { return error as RegistryError; }
  return undefined;
}

function safeError(error: RegistryError | undefined, name: string, exitCode: number, entry: Entry): void {
  expect(error).toBeDefined();
  if (!error) throw new Error('Expected registry refusal');
  expect(error.name).toBe(name);
  // Registry errors carry their exit code as code (exitCode is accepted as an alias); one must be present.
  expect(error.code ?? error.exitCode).toBe(exitCode);
  if (typeof error.code === 'number' && typeof error.exitCode === 'number') expect(error.exitCode).toBe(error.code);
  expect(error.message).not.toContain(JSON.stringify(entry));
  if (entry.label !== null) expect(error.message).not.toContain(entry.label);
}

// Labels come from the bake definition in docs/spec.md. All other
// fields come from the independently prepared, credential-free registry fixture.
it.each([
  ['dotted', 'Merchant.checkout_v2-1'],
  ['64-character', `M${'a'.repeat(63)}`],
])('CP-017/B3 valid %s label round-trips through add save and load', async (_case, label) => temp(async dir => {
  const path = join(dir, 'registry.json');
  const entry = { ...structuredClone(fixture.entries[0]), label };
  const view = await (await registry()).openRegistry(path);
  await view.lock();
  try {
    await view.add(entry);
    expect(view.find(entry.nodePubkey, entry.rootKeyId)).toEqual(entry);
    await view.save();
  } finally { await view.unlock(); }
  expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({ schema: 1, entries: [entry] });
  const loaded = await (await registry()).openRegistry(path);
  expect(loaded.entries).toEqual([entry]);
  expect(loaded.find(entry.nodePubkey, '18446744073709551615')).toEqual(entry);
  expect(existsSync(`${path}.lock`)).toBe(false);
}));

const invalidLabels = [
  ['digit-first', '1merchant'],
  ['numeric-only', '4831990234117'],
  ['65-character', `M${'a'.repeat(64)}`],
  ['space', 'merchant checkout'],
  ['slash', 'merchant/checkout'],
] as const;

for (const status of ['active', 'revoked'] as const) {
  it.each(invalidLabels)(`CP-017/B2 %s ${status} label is rejected on load with safe errors and unchanged bytes`,
    async (_case, label) => temp(async dir => {
      const path = join(dir, 'registry.json');
      const template = status === 'active' ? fixture.entries[0] : fixture.entries[1];
      const entry = { ...structuredClone(template), label };
      const content = `${JSON.stringify({ schema: 1, entries: [entry] }, null, 2)}\n`;
      writeFileSync(path, content);
      const before = readFileSync(path);
      const module = await registry();
      const error = await rejection(() => module.openRegistry(path));
      expect(readFileSync(path).equals(before)).toBe(true);
      expect(existsSync(`${path}.lock`)).toBe(false);
      safeError(error, 'RegistryInputError', 3, entry);
    }));
}

it('CP-017/B3 unregistered revoked null label round-trips through add save and load', async () => temp(async dir => {
  const path = join(dir, 'registry.json');
  const entry = structuredClone(fixture.entries[1]);
  expect(entry).toMatchObject({ label: null, status: 'revoked', replaces: null, replacedBy: null });
  const view = await (await registry()).openRegistry(path);
  await view.lock();
  try {
    await view.add(entry);
    await view.save();
  } finally { await view.unlock(); }
  expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({ schema: 1, entries: [entry] });
  const loaded = await (await registry()).openRegistry(path);
  expect(loaded.entries).toEqual([entry]);
  expect(loaded.find(entry.nodePubkey, entry.rootKeyId)).toEqual(entry);
}));

it('CP-017/B2 active null label is rejected on load with safe errors and unchanged bytes', async () => temp(async dir => {
  const path = join(dir, 'registry.json');
  const entry = { ...structuredClone(fixture.entries[0]), label: null };
  writeFileSync(path, JSON.stringify({ schema: 1, entries: [entry] }));
  const before = readFileSync(path);
  const module = await registry();
  const error = await rejection(() => module.openRegistry(path));
  expect(readFileSync(path).equals(before)).toBe(true);
  expect(existsSync(`${path}.lock`)).toBe(false);
  safeError(error, 'RegistryInputError', 3, entry);
}));

it('CP-017/B3 active null label is refused on add without changing the registry', async () => temp(async dir => {
  const path = join(dir, 'registry.json');
  const entry = { ...structuredClone(fixture.entries[0]), label: null };
  const view = await (await registry()).openRegistry(path);
  await view.lock();
  try {
    const error = await rejection(() => view.add(entry));
    safeError(error, 'RegistryUsageError', 2, entry);
    expect(view.entries).toEqual([]);
    expect(existsSync(path)).toBe(false);
    await view.save();
  } finally { await view.unlock(); }
  expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({ schema: 1, entries: [] });
}));
