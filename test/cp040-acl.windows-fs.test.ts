import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it, vi } from 'vitest';
import { fixture } from './helpers/cp038-online.js';
import { childEnvironment } from './helpers/environment.js';
import { bootstrap } from './global-setup.js';
import { createPrivateDirectory } from '../scripts/private-scratch.mjs';
import { createFixture } from './fixture/fixture.mjs';

const executions = vi.hoisted(() => [] as string[]);
const argumentLists = vi.hoisted(() => [] as { file: string; args: readonly string[]; env?: Record<string, string> }[]);
vi.mock('node:child_process', async importOriginal => {
  const real = await importOriginal<typeof import('node:child_process')>();
  const tracked = ((...args: Parameters<typeof real.execFile>) => {
    executions.push(args[0]);
    argumentLists.push({ file: args[0], args: Array.isArray(args[1]) ? [...args[1] as string[]] : [],
      env: (args[2] as { env?: Record<string, string> } | undefined)?.env });
    return Reflect.apply(real.execFile, undefined, args);
  }) as typeof real.execFile;
  Object.defineProperties(tracked, Object.getOwnPropertyDescriptors(real.execFile));
  return { ...real, execFile: tracked };
});
import { run } from '../src/commands/bake/index.js';

it('CP-040/B10-strict-platform Windows executes the System32 owner-only helper and persists an owner-only output ACL', async () => {
  const f = fixture(); executions.length = 0; argumentLists.length = 0;
  const result = await run(['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toBeNull(); expect(existsSync(f.out)).toBe(true);
  const systemRoot = process.env.SystemRoot;
  if (!systemRoot) throw new Error('Windows SystemRoot is required');
  const executable = join(systemRoot, 'System32/icacls.exe');
  const powershell = join(systemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  // RO-1: the file is created owner-only by the System32 helper; no ACL is applied afterwards.
  for (const file of executions) expect(file.toLowerCase()).toBe(powershell.toLowerCase());
  expect(argumentLists.filter(call => call.env?.MACWARDEN_PRIVATE_OUT === f.out)).toHaveLength(1);
  expect(result.warnings.some(warning => typeof warning === 'string' ? warning === 'acl-best-effort' : warning.code === 'acl-best-effort')).toBe(false);
  const acl = join(f.dir, 'acl.txt');
  const checked = spawnSync(executable, [f.out, '/save', acl], { encoding: 'utf8', timeout: 10000, env: childEnvironment() });
  expect(checked.error).toBeUndefined(); expect(checked.status).toBe(0);
  const saved = readFileSync(acl).toString('utf16le');
  expect(saved).toContain('D:P');
  expect(saved.match(/\(A;[^)]*\)/g)).toHaveLength(1);
  expect(saved).not.toContain('(A;ID;');
  // Independent proof that the only grant names the current user by SID:
  // the test asks System32 whoami itself and compares with the saved ACE.
  const whoami = spawnSync(join(systemRoot, 'System32/whoami.exe'), ['/user', '/fo', 'csv', '/nh'],
    { encoding: 'utf8', timeout: 10000, env: childEnvironment() });
  expect(whoami.status).toBe(0);
  const sid = whoami.stdout.trim().split(',').at(-1)!.replaceAll('"', '');
  expect(sid).toMatch(/^S-1-5-21-\d+(?:-\d+)+$/);
  expect(saved.match(/\(A;[^)]*\)/g)![0]).toBe(`(A;;FA;;;${sid})`);
}, 20000);

it('CP-040/A8-clean-suite Windows refuses an unsafe existing fixture copy destination before any Docker call', async () => {
  const parent = process.env.MACWARDEN_TEST_TMP, systemRoot = process.env.SystemRoot;
  if (!parent || !systemRoot) throw new Error('Private Windows test setup is required');
  const root = await createPrivateDirectory(parent, 'unsafe-fixture-control-');
  const target = join(root, 'macwarden-fixture');
  renameSync(await createPrivateDirectory(root, 'destination-'), target);
  const executable = join(systemRoot, 'System32/icacls.exe');
  const acl = (args: string[]) => {
    const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 10000, env: childEnvironment() });
    expect(result.error).toBeUndefined(); expect(result.status).toBe(0);
  };
  const dummy = join(target, 'dummy.txt'); writeFileSync(dummy, 'noncredential copy destination');
  try {
    acl([target, '/grant', '*S-1-1-0:(OI)(CI)RX']);
    const before = join(root, 'before.txt'), after = join(root, 'after.txt');
    acl([target, '/save', before]);
    const docker = vi.fn(() => ({ status: 0, stdout: '' }));
    await expect(createFixture({ tempBase: root, docker }).up()).rejects.toThrow();
    expect(docker).not.toHaveBeenCalled();
    acl([target, '/save', after]);
    expect(readFileSync(after).equals(readFileSync(before))).toBe(true);
    expect(readFileSync(dummy, 'utf8')).toBe('noncredential copy destination');
  } finally { rmSync(root, { recursive: true, force: true }); }
}, 20000);

it('CP-040/A8-clean-suite Windows refuses Everyone-readable supplied scratch without changing its ACL or dummy contents', async () => {
  const parent = process.env.MACWARDEN_TEST_TMP;
  const systemRoot = process.env.SystemRoot;
  if (!parent || !systemRoot) throw new Error('Private Windows test setup is required');
  const root = await createPrivateDirectory(parent, 'unsafe-acl-control-');
  const executable = join(systemRoot, 'System32/icacls.exe');
  const dummy = join(root, 'dummy.txt');
  writeFileSync(dummy, 'noncredential ACL control');
  const acl = (args: string[]) => {
    const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 10000, env: childEnvironment() });
    expect(result.error).toBeUndefined(); expect(result.status).toBe(0);
  };
  try {
    acl([root, '/grant', '*S-1-1-0:(OI)(CI)RX']);
    const before = join(parent, 'unsafe-acl-before.txt'), after = join(parent, 'unsafe-acl-after.txt');
    acl([root, '/save', before]);
    await expect(bootstrap({ MACWARDEN_TEST_TMP: root })).rejects.toThrow();
    const docker = vi.fn(() => ({ status: 0, stdout: '' }));
    await expect(createFixture({ tempBase: root, docker }).up()).rejects.toThrow();
    expect(docker).not.toHaveBeenCalled();
    acl([root, '/save', after]);
    expect(readFileSync(after).equals(readFileSync(before))).toBe(true);
    expect(readFileSync(dummy, 'utf8')).toBe('noncredential ACL control');
  } finally { rmSync(root, { recursive: true, force: true }); }
}, 20000);
