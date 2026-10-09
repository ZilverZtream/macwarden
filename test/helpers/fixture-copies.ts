import { copyFileSync, lstatSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { assertPrivateDirectories, assertPrivateDirectory, createPrivateDirectory } from '../../scripts/private-scratch.mjs';
import { FixtureInvalidError } from './fixture-invalid.mjs';

type Environment = Record<string, string | undefined>;
type PrivateDirectories = {
  create: typeof createPrivateDirectory;
  assert: typeof assertPrivateDirectory;
  assertMany?: (paths: string[]) => Promise<void>;
};
const privateDirectories: PrivateDirectories = {
  create: createPrivateDirectory, assert: assertPrivateDirectory, assertMany: assertPrivateDirectories,
};
export function inside(parent: string, child: string): boolean {
  const path = relative(resolve(parent), resolve(child));
  return path === '' || (!isAbsolute(path) && path !== '..' && !path.startsWith('..' + sep));
}
async function copyRoot(env: Environment, workspace: string, directories: PrivateDirectories): Promise<string> {
  const root = env.MACWARDEN_FIXTURE_COPY_ROOT;
  if (!root || !isAbsolute(root) || !inside(join(workspace, 'test/.tmp/runs'), root))
    throw new FixtureInvalidError('Bootstrap-owned fixture copy root is required');
  const paths = [root];
  for (const name of ['MACWARDEN_TEST_TMP', 'MACWARDEN_SENTINEL_DIR']) {
    const path = env[name];
    if (!path || !isAbsolute(path)) throw new FixtureInvalidError('Private scratch setup was not installed');
    if (inside(path, root) || inside(root, path)) throw new FixtureInvalidError('Fixture copies must have a separate root');
    paths.push(path);
  }
  if (directories.assertMany) await directories.assertMany(paths);
  else for (const path of paths) await directories.assert(path);
  return root;
}
function privateFile(path: string): void {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0))
    throw new FixtureInvalidError('Unsafe fixture input copy');
}
async function checkedCopies(root: string, directory: string | undefined,
  directories: typeof privateDirectories): Promise<string> {
  if (!directory || !isAbsolute(directory) || resolve(root) === resolve(directory) || !inside(root, directory))
    throw new FixtureInvalidError('Fresh bootstrap-owned fixture copies are required');
  await directories.assert(directory);
  for (const name of ['tls.cert', 'admin.macaroon']) privateFile(join(directory, name));
  return directory;
}
export async function fixtureCopies(env: Environment = process.env, workspace = resolve(),
  directories = privateDirectories): Promise<string> {
  const root = await copyRoot(env, workspace, directories);
  return checkedCopies(root, env.MACWARDEN_FIXTURE_DIR, directories);
}
export function clearFixtureTurn(env: Environment): void {
  delete env.MACWARDEN_CP038_FIXTURE_TURN;
  delete env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE;
  delete env.MACWARDEN_FIXTURE_DIR;
}
// Validation and copying are one lifecycle. No caller ownership flag grants a
// turn; failed validation or copying leaves every consumer unassigned.
export async function prepareFixtureTurn(env: Environment, validate: () => void,
  read: (name: 'tls.cert' | 'admin.macaroon') => Buffer, workspace = resolve(),
  directories = privateDirectories): Promise<void> {
  clearFixtureTurn(env);
  const root = await copyRoot(env, workspace, directories);
  validate();
  const directory = await directories.create(root, 'copies-');
  const tmp = env.MACWARDEN_TEST_TMP!, sentinels = env.MACWARDEN_SENTINEL_DIR!;
  const compatibility = join(tmp, 'macwarden-fixture');
  // Older consumers use tmpdir()/macwarden-fixture. Keep that location private
  // and refresh its inputs without ever opening an existing linked file.
  try { lstatSync(compatibility); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    renameSync(await directories.create(tmp, 'fixture-compatibility-'), compatibility);
  }
  await directories.assert(compatibility);
  for (const name of ['tls.cert', 'admin.macaroon'] as const) {
    const path = join(directory, name), legacy = join(compatibility, name);
    writeFileSync(path, read(name), { flag: 'wx', mode: 0o600 });
    try { privateFile(legacy); unlinkSync(legacy); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    writeFileSync(legacy, readFileSync(path), { flag: 'wx', mode: 0o600 });
    if (name === 'admin.macaroon') {
      const registered = join(sentinels, `${directory.split(/[\\/]/).pop()}.macaroon`);
      copyFileSync(path, registered);
      writeFileSync(join(tmp, 'declared-out.txt'), `${path}\n${legacy}\n${registered}\n`, { flag: 'a', mode: 0o600 });
    }
  }
  await checkedCopies(root, directory, directories);
  env.MACWARDEN_FIXTURE_DIR = directory;
  env.MACWARDEN_CP038_FIXTURE_TURN = 'exclusive';
  env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE = '1';
}
