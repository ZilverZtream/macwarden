import { execFile as actualExecFile } from 'node:child_process';
import { copyFileSync, existsSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { expect, it, vi } from 'vitest';
import { run as bake } from '../src/commands/bake/index.js';
import { context, scratch } from './support/cp039-audit.js';

const acl = vi.hoisted(() => ({ calls: [] as Array<{ file: string; args: string[]; options: unknown }> }));
vi.mock('node:child_process', async importOriginal => {
  const original = await importOriginal<typeof import('node:child_process')>();
  return { ...original, execFile: (...args: Parameters<typeof actualExecFile>) => {
    acl.calls.push({ file: args[0], args: args[1] as string[], options: args[2] });
    return Reflect.apply(original.execFile, undefined, args);
  } };
});
it('CP-039/B9-protected-limits Windows executes the absolute System32 owner-only helper with real ACL application', async () => scratch(async dir => {
  const f = context(dir); acl.calls.length = 0;
  f.deps.env.SystemRoot = process.env.SystemRoot!;
  // A PATH-selected Node executable cannot create an owner-only file. The system executable must win even with these shadows present.
  for (const name of ['powershell.exe', 'icacls.exe']) copyFileSync(process.execPath, join(dir, name));
  const previousPath = process.env.PATH; process.env.PATH = dir + delimiter + (previousPath ?? '');
  let result: Awaited<ReturnType<typeof bake>>;
  try { result = await bake(['--label', 'Alice', '--preset', 'invoice-only', '--out', f.out, ...f.online], f.deps); }
  finally { if (previousPath === undefined) delete process.env.PATH; else process.env.PATH = previousPath; }
  expect(result.error !== null, 'injected bake failure terminates after reservation').toBe(true);
  expect(result.error).not.toMatchObject({ step: 'B7' });
  const executable = join(process.env.SystemRoot!, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  // Every child is the System32 PowerShell (the registry lock's process-domain query uses it too);
  // exactly one is the owner-only creation helper for this output.
  for (const call of acl.calls) {
    expect(call.file.toLowerCase()).toBe(executable.toLowerCase());
    expect(call.options).toMatchObject({ shell: false });
  }
  const helper = acl.calls.filter(call => (call.options as { env?: Record<string, string> }).env?.MACWARDEN_PRIVATE_OUT === f.out);
  expect(helper).toHaveLength(1);
  const warnings = result.warnings.map(w => typeof w === 'string' ? w : w.code);
  expect(warnings.includes('acl-best-effort'), 'real owner-only creation succeeds').toBe(false);
  expect(existsSync(f.out)).toBe(false);
}));
