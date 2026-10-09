import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { scenario, ids, probe, writeEntries } from '../helpers/cp038-live.js';

it.each(['bake', 'stage', 'revoke', 'finish'] as const)('CP-038/dry-run-state %s leaves live IDs registry bytes and output untouched', async mode => {
  await scenario(async f => {
    if (mode === 'bake') writeEntries(f, []);
    if (mode === 'finish') writeEntries(f, [f.old, f.next]);
    const before = readFileSync(f.registry), beforeIds = ids();
    const args = mode === 'bake' ? ['bake', '--label', 'Bob', '--preset', 'invoice-only', '--out', f.out] :
      mode === 'stage' ? ['rotate', 'Alice', '--out', f.out] : mode === 'finish' ? ['rotate', 'Alice', '--finish'] : ['revoke', 'Alice'];
    const actual = spawnSync(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
      pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, resolve('test/helpers/cp038-cli-child.mjs'),
      ...args, ...f.flags, '--dry-run', '--json'], { encoding: 'utf8', timeout: 20000, env: childEnvironment({ NODE_OPTIONS: '', NODE_DEBUG: ''  }) });
    expect(actual.error).toBeUndefined(); expect(actual.status).toBe(0);
    expect(JSON.parse(actual.stdout)).toMatchObject({ ok: true, error: null, result: { dryRun: true } });
    expect(ids()).toEqual(beforeIds); expect(readFileSync(f.registry).equals(before)).toBe(true);
    expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry + '.lock')).toBe(false);
    expect(probe(f.old.outPath!)).toBe('accepted');
  });
}, 60000);
it.each(['revoke', 'finish'] as const)('CP-038/dry-run-state %s missing confirmation leaves live state untouched', async mode => {
  await scenario(async f => {
    if (mode === 'finish') writeEntries(f, [f.old, f.next]);
    const before = readFileSync(f.registry), beforeIds = ids();
    const args = mode === 'finish' ? ['rotate', 'Alice', '--finish'] : ['revoke', 'Alice'];
    const actual = spawnSync(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
      pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, resolve('test/helpers/cp038-cli-child.mjs'),
      ...args, ...f.flags, '--json'], { encoding: 'utf8', input: '', timeout: 20000, env: childEnvironment({ NODE_OPTIONS: '', NODE_DEBUG: ''  }) });
    expect(actual.error).toBeUndefined(); expect(actual.status).toBe(6);
    expect(ids()).toEqual(beforeIds); expect(readFileSync(f.registry).equals(before)).toBe(true);
    expect(probe(f.old.outPath!)).toBe('accepted');
  });
}, 60000);
