import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { assertPrivateDirectory, createPrivateDirectory } from '../scripts/private-scratch.mjs';

export type TestEnvironment = Record<string, string | undefined>;
export async function bootstrap(env: TestEnvironment, workspace = resolve(),
  directories = { create: createPrivateDirectory, assert: assertPrivateDirectory }): Promise<{ root: string; teardown(): void }> {
  const base = resolve(workspace, 'test/.tmp/runs');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const root = await directories.create(base, 'run-');
  try {
  const supplied = [env.MACWARDEN_TEST_TMP, env.MACWARDEN_SENTINEL_DIR];
  const privateDirectory = async (value: string | undefined, name: string): Promise<string> => {
    const path = value ?? await directories.create(root, `${name}-`);
    if (!isAbsolute(path)) throw new Error('Test scratch directories must be absolute');
    await directories.assert(path);
    return resolve(path);
  };
    const tmp = await privateDirectory(supplied[0], 'tmp');
    const sentinels = await privateDirectory(supplied[1], 'sentinels');
    const contains = (a: string, b: string) => { const path = relative(a, b); return path === '' || (!path.startsWith('..') && !isAbsolute(path)); };
    if (contains(tmp, sentinels) || contains(sentinels, tmp)) throw new Error('Test scratch and sentinel roots must be disjoint');
    env.MACWARDEN_TEST_TMP = tmp;
    env.MACWARDEN_SENTINEL_DIR = sentinels;
    env.TMP = tmp; env.TEMP = tmp; env.TMPDIR = tmp;
    // Runner-owned scratch survives Vitest teardown so the standing leak scan
    // can inspect default-registry and configuration writes.
    const config = await directories.create(tmp, 'config-');
    env.HOME = config; env.USERPROFILE = config; env.APPDATA = config; env.LOCALAPPDATA = config; env.XDG_CONFIG_HOME = config;
    env.MACWARDEN_REGISTRY = join(config, 'macwarden/registry.json');
    delete env.MACWARDEN_LND_REST; delete env.MACWARDEN_TLS_CERT; delete env.MACWARDEN_MACAROON;
    env.NODE_OPTIONS = ''; env.NODE_DEBUG = '';
    const npmrc = join(config, 'npmrc'); writeFileSync(npmrc, '', { mode: 0o600 });
    env.NPM_CONFIG_USERCONFIG = npmrc; env.NPM_CONFIG_CACHE = join(tmp, 'npm-cache');
    const copies = await privateDirectory(undefined, 'fixture-root');
    if ([tmp, sentinels].some(path => contains(path, copies) || contains(copies, path)))
      throw new Error('Fixture copies must have a separate root');
    env.MACWARDEN_FIXTURE_COPY_ROOT = copies;
    delete env.MACWARDEN_FIXTURE_DIR;
    delete env.MACWARDEN_CP038_FIXTURE_TURN;
    delete env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE;
    return { root, teardown: () => rmSync(root, { recursive: true, force: true }) };
  } catch (error) { rmSync(root, { recursive: true, force: true }); throw error; }
}

export default async function setup(): Promise<() => void> {
  const state = await bootstrap(process.env);
  return state.teardown;
}
