import { childEnvironment } from './helpers/environment.js';
import { constants, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it, vi } from 'vitest';
import { Secret } from '../src/secret.js';
import { directory, entry, ownId, register, wireFixture } from './helpers/cp026-revoke-support.mjs';
import { fixture as bakeFixture } from './helpers/cp025-bake-support.mjs';
import { failure, invoke, scratch } from './helpers/cp029-rotate-support.js';
import { safe } from './helpers/cp028-rotate-support.js';

function cleanup(dir: string, root: string) {
  if (!resolve(dir).startsWith(root + sep)) throw new Error('Unsafe scratch cleanup');
  rmSync(dir, { recursive: true, force: true });
}

it('CP-031/batch-env dangerous NODE_DEBUG wildcards refuse before authority while fs remains allowed', async () => scratch(async f => {
  const open = vi.mocked(f.deps.fs.open);
  for (const category of ['*', 'h*', 't*', 'n*', 'fs,H*']) {
    f.deps.env.NODE_DEBUG = category; open.mockClear(); f.calls.length = 0;
    failure(await invoke(f), 2, 'F2'); expect(f.calls).toEqual([]); expect(open).not.toHaveBeenCalled();
  }
  f.deps.env.NODE_DEBUG = 'fs'; expect((await invoke(f, ['--dry-run'])).error).toBeNull();
}));

it.each(['unrelated entry', 'conflicting label'])('CP-031/batch-bake-reread delayed lock preserves %s and refuses new conflict before issuance', async kind => {
  const root = resolve(directory('MACWARDEN_TEST_TMP')), dir = mkdtempSync(join(root, 'cp031-reread-'));
  try {
    const f = bakeFixture(dir, Secret); writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [] }));
    const intervening = entry('preset-invoice-only', '4294967355', { label: kind === 'conflicting label' ? 'Alice' : 'Bob' });
    const open = f.deps.fs.open;
    f.deps.fs.open = async (...args: Parameters<typeof fs.open>) => {
      // The other writer finishes as this bake acquires the lock (its exclusive create). Later opens of the
      // lock path (the release check reads the owner record back) happen while this bake holds the lock,
      // when no other writer can change the registry.
      if (args[0] === `${f.registry}.lock` && args[1] === 'wx') writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [intervening] }));
      return open(...args);
    };
    const command = await import('../src/commands/bake/index.js');
    const result = await command.run(f.args, f.deps);
    const rows = JSON.parse(readFileSync(f.registry, 'utf8')).entries;
    expect(rows).toContainEqual(intervening);
    if (kind === 'conflicting label') {
      expect(result.error?.code).toBe(2); expect(f.state.calls).not.toContain('BakeMacaroon'); expect(rows).toEqual([intervening]);
    } else { expect(result.error).toBeNull(); expect(rows).toHaveLength(2); }
  } finally { cleanup(dir, root); }
});

it('CP-031/batch-registry forbidden supplied default and resolved paths refuse before content open', async () => {
  const command = await import('../src/registry/index.js');
  const root = directory('MACWARDEN_TEST_TMP');
  for (const kind of ['supplied', 'default', 'resolved']) {
    const ordinary = join(root, 'registry.json'), forbidden = join(root, 'wallet.db');
    const open = vi.fn(async () => { throw new Error('content open attempted'); });
    const readFile = vi.fn(async () => { throw new Error('content read attempted'); });
    const metadata = { isFile: () => true, isDirectory: () => false, isSymbolicLink: () => kind === 'resolved',
      dev: 1, ino: 1, mode: constants.S_IFREG | 0o600, size: 0 };
    const fileSystem = { ...fs, open, readFile, lstat: vi.fn(async () => metadata),
      stat: vi.fn(async () => metadata), realpath: vi.fn(async () => kind === 'resolved' ? forbidden : ordinary) };
    let error: unknown;
    try {
      await command.openRegistry(kind === 'default' ? undefined : kind === 'supplied' ? forbidden : ordinary,
        { fs: fileSystem as unknown as typeof fs, platform: 'linux',
          env: { XDG_CONFIG_HOME: join(root, 'seed') }, homedir: () => root });
    } catch (caught) { error = caught; }
    expect(error).toBeDefined(); expect(open).not.toHaveBeenCalled(); expect(readFile).not.toHaveBeenCalled();
  }
});

it('CP-031/batch-inventory URI-only listing authority cannot verify and makes zero LND calls', async () => scratch(async f => {
  const own = register(wireFixture('default-admin', ownId, [
    'uri:/lnrpc.Lightning/GetInfo', 'uri:/lnrpc.Lightning/ListPermissions', 'uri:/lnrpc.Lightning/ListMacaroonIDs',
  ]));
  const args = [...f.args.slice(2), '--verify']; args[args.indexOf('--macaroon') + 1] = own;
  const command = await import('../src/commands/inventory.js');
  const result = await command.run(args, f.deps);
  expect(result.error?.code).toBe(4); expect(f.calls).toEqual([]);
}));

it('CP-031/batch-process actual process event after sent mutation keeps exit 8 and inventory recovery while read-only stays safe', async () => scratch(async f => {
  const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
  for (const mode of ['read-only', 'mutation']) {
    const child = spawnSync(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning',
      '--import', pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href,
      resolve('test/helpers/cp031-process-child.mjs'), f.dir, mode],
      { env, encoding: 'utf8', timeout: 10_000 });
    expect(child.error).toBeUndefined(); expect(child.status).toBe(8);
    expect(child.stderr).toBe('');
    const document = JSON.parse(child.stdout);
    expect(document).toMatchObject({ schema: 1, command: mode === 'mutation' ? 'bake' : 'inventory',
      ok: false, result: null, error: { code: 8, step: 'internal' } });
    expect(child.stdout + child.stderr).not.toContain('credential-safe-process-event-marker');
    expect(child.stderr).not.toMatch(/^\s+at /m);
    if (mode === 'mutation') expect(document.error.message).toContain('macwarden inventory');
    safe(child.stdout + child.stderr, [f.dir]);
  }
}));
