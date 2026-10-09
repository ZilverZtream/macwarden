import { existsSync, readdirSync } from 'node:fs';
import { expect, it, vi } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { run as bake } from '../src/commands/bake/index.js';
import { run as revoke } from '../src/commands/revoke.js';
import { run as rotate } from '../src/commands/rotate.js';
import { context, scratch } from './support/cp039-audit.js';

const options = ['--tls-keylog=keylog.txt', '--inspect=127.0.0.1:0', '--heapsnapshot-signal=SIGUSR2',
  '--heapsnapshot-near-heap-limit=1', '--cpu-prof', '--require=./injection.cjs', '--import=./injection.mjs',
  '--loader=./injection.mjs', '--report-on-fatalerror', '--max-old-space-size=2048', ' ', 'unknown-option'];
for (const option of options) {
  it(`CP-039/A6-environment refuses nonempty NODE_OPTIONS ${option.split('=')[0].trim() || 'whitespace'} before access`,
    async () => scratch(async dir => {
      for (const [command, run, leading] of [
        ['inventory', inventory, []], ['bake', bake, ['--label', 'Alice', '--preset', 'invoice-only']],
        ['revoke', revoke, ['9001', '--unregistered', '--yes']], ['rotate', rotate, ['Alice']],
      ] as const) {
        const f = context(dir); f.deps.env.NODE_OPTIONS = option;
        const before = readdirSync(dir);
        const reads = [vi.spyOn(f.deps.fs, 'open'), vi.spyOn(f.deps.fs, 'readFile'),
          vi.spyOn(f.deps.fs, 'stat'), vi.spyOn(f.deps.fs, 'lstat'), vi.spyOn(f.deps.fs, 'realpath')];
        const args = [...leading, ...f.online, ...(['bake', 'rotate'].includes(command) ? ['--out', f.out] : [])];
        const result = await run(args, f.deps);
        expect.soft(result.error?.code, command).toBe(2);
        expect.soft(f.lnd.calls, command).toEqual([]);
        expect.soft(reads.map(spy => spy.mock.calls.length), command).toEqual([0, 0, 0, 0, 0]);
        expect.soft(readdirSync(dir), 'no report or keylog created').toEqual(before);
        expect.soft(existsSync(f.out)).toBe(false);
        for (const spy of reads) spy.mockRestore();
      }
    }));
}
it('CP-039/A6-environment retains unsafe NODE_DEBUG refusal and permits empty NODE_OPTIONS', async () => scratch(async dir => {
  for (const value of ['http', 'https', 'tls', 'net', 'HTTP,other']) {
    const f = context(dir); f.deps.env.NODE_DEBUG = value;
    const result = await inventory(f.online, f.deps);
    expect(result.error?.code, value).toBe(2); expect(f.lnd.calls).toEqual([]);
  }
  const f = context(dir); f.deps.env.NODE_OPTIONS = '';
  const result = await inventory(f.online, f.deps);
  expect(result.error).toBeNull();
  expect(f.lnd.calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
}));
