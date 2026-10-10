import { expect, it, vi } from 'vitest';
import { fixture } from './helpers/cp038-online.js';
import { existsSync } from 'node:fs';
const acl = vi.hoisted(() => ({ calls: 0 }));
// The owner-only creation helper reports a volume that stores no Windows permissions
// (FAT or exFAT), the only case SPEC B7 treats as best effort.
vi.mock('node:child_process', async importOriginal => {
  const real = await importOriginal<typeof import('node:child_process')>();
  const { EventEmitter } = await import('node:events');
  const { writeFileSync } = await import('node:fs');
  return { ...real, execFile: (file: string, args: string[], options: { env?: Record<string, string> },
    callback: (error: Error | null, stdout: string, stderr: string) => void) => {
    if (!file.toLowerCase().endsWith('\\powershell.exe') || !options?.env?.MACWARDEN_PRIVATE_OUT)
      return Reflect.apply(real.execFile, undefined, [file, args, options, callback]);
    acl.calls++;
    const stdout = new EventEmitter();
    const line = 'CREATED ' + JSON.stringify({ sid: 'S-1-5-21-1-2-3-1001', noAcl: true, acl: null }) + '\n';
    const stdin = Object.assign(new EventEmitter(), { write: () => true, end: () => queueMicrotask(() => callback(null, line, '')) });
    queueMicrotask(() => { writeFileSync(options.env!.MACWARDEN_PRIVATE_OUT, '', { flag: 'wx' }); stdout.emit('data', line); });
    return { stdout, stdin };
  } };
});
import { run as bake } from '../src/commands/bake/index.js';
import { run as rotate } from '../src/commands/rotate.js';
import { render } from './helpers/render-adversarial.js';
it.each(['bake', 'stage'] as const)('CP-038/B7-spec-output %s on a volume without permissions has one warning shape and no 0600 promise', async mode => {
  const f = fixture(); acl.calls = 0;
  const result = mode === 'bake' ? await bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags], f.deps) :
    await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  // The --out reservation is one helper call; registry saves go through the helper too (1.2.1).
  expect(result.error).toBeNull(); expect(acl.calls).toBeGreaterThanOrEqual(1);
  expect(existsSync(`${f.registry}.lock`), 'completed command releases its own lock').toBe(false);
  expect(result.warnings).toContainEqual({ code: 'acl-best-effort', message: 'the volume stores no Windows permissions (FAT or exFAT): anyone with access to the volume can read the file' });
  expect(result.warnings.filter(warning => typeof warning !== 'string' && warning.code === 'acl-best-effort')).toHaveLength(1);
  expect(render(result, 'text')).not.toMatch(/0600|owner-only Windows ACL/);
  expect(JSON.parse(render(result, 'json')).warnings).toContainEqual({ code: 'acl-best-effort', message: 'the volume stores no Windows permissions (FAT or exFAT): anyone with access to the volume can read the file' });
});
