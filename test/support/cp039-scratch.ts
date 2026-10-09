import { lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';

function samePath(left: string, right: string): boolean {
  return relative(resolve(left), resolve(right)) === '';
}
function directory(path: string, privateRoot = false) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isDirectory() || !samePath(path, realpathSync(path)))
    throw new Error('CP-039 scratch must use real directories without symlinks');
  if (privateRoot && process.platform !== 'win32' &&
      ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))
    throw new Error('CP-039 scratch must be caller-owned and private');
  return stat;
}

export function root(name = 'MACWARDEN_TEST_TMP'): string {
  const value = process.env[name];
  if (!value || !isAbsolute(value)) throw new Error(`${name} must be an absolute scratch directory`);
  const path = resolve(value), base = parse(path).root;
  directory(base);
  let current = base;
  for (const part of relative(base, path).split(sep).filter(Boolean)) {
    current = join(current, part);
    try { lstatSync(current); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      // Only newly created components receive a mode; existing directories are never chmodded.
      mkdirSync(current, { mode: 0o700 });
    }
    directory(current);
  }
  directory(path, true);
  return path;
}

export function scratchDirectory(prefix = 'cp039-') {
  const parent = root(), parentStat = directory(parent, true);
  if (!/^[a-z0-9-]+$/i.test(prefix)) throw new Error('Unsafe scratch prefix');
  const dir = mkdtempSync(join(parent, prefix)), childStat = directory(dir, true);
  function contained() {
    const local = relative(parent, dir);
    if (!local || isAbsolute(local) || local === '..' || local.startsWith('..' + sep) ||
        !samePath(dirname(dir), parent)) throw new Error('Unsafe scratch cleanup target');
    const currentParent = directory(parent, true), currentChild = directory(dir, true);
    if (currentParent.dev !== parentStat.dev || currentParent.ino !== parentStat.ino ||
        currentChild.dev !== childStat.dev || currentChild.ino !== childStat.ino)
      throw new Error('Scratch directory identity changed before cleanup');
  }
  contained();
  return { dir, cleanup() { contained(); rmSync(dir, { recursive: true, force: true }); } };
}
