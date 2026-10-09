import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { fixture, root } from '../helpers/cp038-online.js';
import { run as inspect } from '../../src/commands/inspect.js';
import { run as scan } from '../../src/commands/scan.js';
import { run as inventory } from '../../src/commands/inventory.js';
import { run as bake } from '../../src/commands/bake/index.js';
import { run as revoke } from '../../src/commands/revoke.js';
import { run as rotate } from '../../src/commands/rotate.js';
import { render } from '../helpers/render-adversarial.js';
import { findLeaks } from "../helpers/leak-check.js";

it('CP-038/leak-check registered sentinels cover all six commands and registry recovery output', async () => {
  const f = fixture(); let captured = '';
  const out = vi.spyOn(process.stdout, 'write').mockImplementation((value => { captured += String(value); return true; }) as typeof process.stdout.write);
  const err = vi.spyOn(process.stderr, 'write').mockImplementation((value => { captured += String(value); return true; }) as typeof process.stderr.write);
  try {
    const results = [await inspect([f.own], { stdin: f.deps.stdin, fs: f.deps.fs, clock: f.deps.clock }), await scan([f.own]), await inventory(f.flags, f.deps),
      await bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags, '--dry-run'], f.deps),
      await revoke(['Alice', ...f.flags, '--dry-run'], f.deps),
      await rotate(['Alice', '--out', f.out, ...f.flags, '--dry-run'], f.deps)];
    for (const result of results) { expect(result.error).toBeNull(); captured += render(result, 'text') + render(result, 'json'); }
    f.lnd.verificationFault = new Error('private failure');
    const failure = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
    captured += render(failure, 'text') + render(failure, 'json') + readFileSync(f.registry, 'utf8');
  } finally { out.mockRestore(); err.mockRestore(); }
  expect(findLeaks({ root: resolve(), sentinels: resolve('test/sentinels.json'), sentinelDir: root('MACWARDEN_SENTINEL_DIR'),
    testTmp: root('MACWARDEN_TEST_TMP'), evidenceDir: f.dir, commandOutput: captured, paths: [] })).toBeNull();
});
