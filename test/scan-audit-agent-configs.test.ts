import { mkdirSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { run } from '../src/commands/scan.js';
import { scratch } from './support/cp039-audit.js';

const errno = (code: string) => Object.assign(new Error(code), { code });
const environment = (home: string, cwd: string) => () => ({ platform: process.platform, home, cwd, env: {} });

it('--agent-configs: a dangling link at a well-known location is absent, not a failed scan', async () => scratch(async dir => {
  const home = join(dir, 'home'), cwd = join(dir, 'cwd');
  mkdirSync(home); mkdirSync(cwd);
  const link = join(home, '.claude.json');
  // The injected file system shows a symlink whose target is missing.
  const io = { ...fs,
    lstat: (async (path: string, options?: object) => String(path) === link
      ? { isSymbolicLink: () => true, isFile: () => false, isDirectory: () => false } : fs.lstat(path, options)) as unknown as typeof fs.lstat,
    stat: (async (path: string, options?: object) => {
      if (String(path) === link) throw errno('ENOENT');
      return fs.stat(path, options);
    }) as unknown as typeof fs.stat };
  const output = await run(['--agent-configs'], { fs: io, agentEnvironment: environment(home, cwd) });
  expect(output.error).toBeNull();
  expect(output.exitCode).toBe(0);
  const configs = (output.result as { summary: { agentConfigs: { found: unknown[]; absent: { path: string }[] } } }).summary.agentConfigs;
  expect(configs.found).toEqual([]);
  expect(configs.absent.map(item => item.path)).toContain(link);
}));

it('--agent-configs: a location that cannot be examined fails closed instead of being recorded as absent', async () => scratch(async dir => {
  const home = join(dir, 'home'), cwd = join(dir, 'cwd');
  mkdirSync(join(home, '.cursor'), { recursive: true }); mkdirSync(cwd);
  const denied = join(home, '.cursor', 'mcp.json');
  writeFileSync(denied, '{}');
  const io = { ...fs, lstat: (async (path: string, options?: object) => {
    if (String(path) === denied) throw errno('EACCES');
    return fs.lstat(path, options);
  }) as unknown as typeof fs.lstat };
  const output = await run(['--agent-configs'], { fs: io, agentEnvironment: environment(home, cwd) });
  expect(output.error).toMatchObject({ code: 3, step: 'input-read' });
}));

it('the unknown-flag message lists every scan flag', async () => {
  const output = await run(['--nope'], { fs });
  for (const flag of ['--fail-on', '--include-dirs', '--ignore-file', '--git-history', '--allow-shallow', '--agent-configs', '--format', '--json'])
    expect(output.error?.message).toContain(flag);
});
