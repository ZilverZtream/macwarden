import { statSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { fixture } from './helpers/cp038-online.js';
import { run } from '../src/commands/bake/index.js';

it('CP-040/B10-strict-platform unprivileged Linux writes output and registry 0600 in a new 0700 directory', async () => {
  if (process.platform !== 'linux' || !process.getuid || process.getuid() === 0)
    throw new Error('This explicit platform variant requires unprivileged Linux');
  const f = fixture();
  const directory = join(f.dir, 'private');
  const registry = join(directory, 'registry.json');
  f.flags[f.flags.indexOf('--registry') + 1] = registry;
  const result = await run(['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toBeNull();
  expect(statSync(f.out).mode & 0o777).toBe(0o600);
  expect(statSync(registry).mode & 0o777).toBe(0o600);
  expect(statSync(directory).mode & 0o777).toBe(0o700);
});
