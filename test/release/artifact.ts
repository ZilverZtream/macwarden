import { spawnSync } from 'node:child_process';
import { chmodSync, closeSync, constants, copyFileSync, cpSync, existsSync, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, readlinkSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { childEnvironment } from '../helpers/environment.js';

export const repo = resolve();
const scratchRoot = resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'node_modules/.cp014-tests'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

type Result = { status: number | null; stdout: string; stderr: string };
export type Artifact = {
  root: string; source: string; tarball: string; extracted: string; installed: string;
  dryFiles: string[]; cleanDist: Map<string, Buffer>; packedDist: Map<string, Buffer>;
};

export function command(executable: string, args: string[], cwd: string, timeout = 120_000,
  env: NodeJS.ProcessEnv = childEnvironment()): Result {
  const result = spawnSync(executable, args, { cwd, env, encoding: 'utf8', timeout,
    maxBuffer: 4_000_000, shell: process.platform === 'win32' && executable.endsWith('.cmd') });
  return { status: result.status, stdout: result.stdout || '', stderr: result.stderr || '' };
}

function mustRun(executable: string, args: string[], cwd: string, timeout?: number,
  env: NodeJS.ProcessEnv = childEnvironment()): Result {
  const result = command(executable, args, cwd, timeout, env);
  if (result.status !== 0) throw new Error(
    `${JSON.stringify(executable)} ${args.map(arg => JSON.stringify(arg)).join(' ')} exited ${result.status}` +
    `\ncwd: ${JSON.stringify(cwd)}\nstderr (first 4096 characters):\n${result.stderr.slice(0, 4096)}`);
  return result;
}

export function extractPackedArtifact(filename: string, source: string, extracted: string, tar = 'tar'): void {
  if (filename.includes('/') || filename.includes('\\') || filename.includes(':'))
    throw new Error('Packed archive filename must be local to its source directory');
  // GNU tar (first on PATH under Git Bash) treats "C:\…" as a remote host; a path relative
  // to the source directory works with GNU tar and the Windows system bsdtar alike.
  const target = relative(source, extracted);
  if (isAbsolute(target)) throw new Error('Packed extraction directories must share a filesystem root');
  const env = childEnvironment();
  if (process.platform === 'win32' && isAbsolute(tar)) {
    // Explicit Git GNU tar needs its sibling gzip discoverable by the child.
    const pathKey = Object.keys(env).find(key => key.toLowerCase() === 'path') || 'PATH';
    env[pathKey] = dirname(tar) + (env[pathKey] ? delimiter + env[pathKey] : '');
  }
  mustRun(tar, ['-xzf', filename, '-C', target.split(sep).join('/') || '.'],
    source, undefined, env);
}

export function files(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? files(path).map(child => `${entry.name}/${child}`)
      : [entry.name];
  }).sort();
}

function distBytes(dir: string): Map<string, Buffer> {
  return new Map(files(dir).map(path => [path, readFileSync(join(dir, path))]));
}

function copySource(source: string): void {
  for (const name of ['src', 'scripts', 'rules', 'schemas']) {
    if (existsSync(join(repo, name))) cpSync(join(repo, name), join(source, name), { recursive: true });
  }
  for (const name of ['package.json', 'package-lock.json', ...readdirSync(repo).filter(name => /^tsconfig.*\.json$/.test(name)), 'README.md',
    'SECURITY.md', 'LICENSE', 'CHANGELOG.md']) {
    if (existsSync(join(repo, name))) copyFileSync(join(repo, name), join(source, name));
  }
}

let prepared: Artifact | undefined;
const retainedRoots = new Set<string>();

function ownedPath(root: string, path: string): void {
  const local = relative(root, path);
  if (!local || isAbsolute(local) || local === '..' || local.startsWith(`..${sep}`))
    throw new Error('Packaging artifact path is outside its owned fixture');
  // Check each component before realpath/open so an unrelated link is never followed.
  let current = root;
  const parts = local.split(sep);
  for (let index = 0; index < parts.length; index++) {
    current = join(current, parts[index]);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || (index < parts.length - 1 && !stat.isDirectory()))
      throw new Error('Packaging artifact contains an unexpected linked component');
  }
}

export function retainArtifactBytes(): void {
  // Run only after every installed-command assertion, including the broken-shim
  // control. Retain successful and failed preparations for the standing scan.
  const sourceBins = new Set(['acorn', 'eslint', 'nanoid', 'node-which', 'rolldown',
    'semver', 'tsc', 'tsserver', 'vite', 'vitest', 'why-is-node-running']);
  for (const root of retainedRoots) {
    const rootStat = lstatSync(root);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink())
      throw new Error('Packaging fixture root is no longer owned');
    const canonicalRoot = realpathSync(root);
    for (const installation of ['source', 'installed']) {
      const bin = join(root, installation, 'node_modules', '.bin');
      // A preparation may fail before npm creates this directory.
      try { ownedPath(root, bin); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
      if (!lstatSync(bin).isDirectory()) throw new Error('Packaging bin directory is not regular');
      for (const entry of readdirSync(bin, { withFileTypes: true })) {
        if (!entry.isSymbolicLink()) continue;
        if (!(installation === 'source' ? sourceBins.has(entry.name) : entry.name === 'macwarden'))
          throw new Error('Packaging bin directory contains an unexpected link');
        const link = join(bin, entry.name), original = lstatSync(link);
        const destination = readlinkSync(link), target = resolve(dirname(link), destination);
        ownedPath(root, target);
        const canonicalTarget = realpathSync(target);
        ownedPath(canonicalRoot, canonicalTarget);
        const targetStat = lstatSync(target);
        if (!targetStat.isFile()) throw new Error('Packaging bin target is not a regular file');
        const handle = openSync(target, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        let bytes: Buffer;
        try {
          const opened = fstatSync(handle);
          if (!opened.isFile() || opened.dev !== targetStat.dev || opened.ino !== targetStat.ino)
            throw new Error('Packaging bin target changed before retention');
          bytes = readFileSync(handle);
        } finally { closeSync(handle); }
        const materialized = join(bin, `.retained-${entry.name}`);
        writeFileSync(materialized, bytes, { flag: 'wx', mode: targetStat.mode & 0o777 });
        chmodSync(materialized, targetStat.mode & 0o777);
        const current = lstatSync(link);
        if (!current.isSymbolicLink() || current.dev !== original.dev || current.ino !== original.ino ||
            readlinkSync(link) !== destination)
          throw new Error('Packaging bin link changed before retention');
        // Rename replaces the link itself; the original target remains intact.
        renameSync(materialized, link);
      }
    }
  }
}

export function artifact(): Artifact {
  if (prepared) return prepared;
  mkdirSync(scratchRoot, { recursive: true });
  const root = mkdtempSync(join(scratchRoot, 'release-'));
  retainedRoots.add(root);
  const source = join(root, 'source');
  const extracted = join(root, 'extracted');
  const installed = join(root, 'installed');
  mkdirSync(source);
  // Failed preparation artifacts must also reach the standing leak scan.
  copySource(source);
  mustRun(npm, ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], source, 240_000);
  mustRun(npm, ['run', 'build'], source);
  const cleanDist = distBytes(join(source, 'dist'));
  if (!cleanDist.size) throw new Error('independent clean build produced no dist files');

  const stale = join(source, 'dist', 'obsolete-cp014.js');
  writeFileSync(stale, 'obsolete output must not ship\n');
  const firstJs = [...cleanDist.keys()].find(path => path.endsWith('.js'));
  if (firstJs) writeFileSync(join(source, 'dist', firstJs), 'stale compiled output\n');

  const dry = mustRun(npm, ['pack', '--dry-run', '--json'], source);
  const dryFiles = (JSON.parse(dry.stdout) as Array<{ files: Array<{ path: string }> }>)[0]
    .files.map(file => file.path).sort();
  writeFileSync(stale, 'obsolete output must not ship\n');
  if (firstJs) writeFileSync(join(source, 'dist', firstJs), 'stale compiled output\n');
  const packed = mustRun(npm, ['pack', '--json'], source);
  const filename = (JSON.parse(packed.stdout) as Array<{ filename: string }>)[0].filename;
  const tarball = join(source, filename);
  if (!existsSync(tarball)) throw new Error('npm pack reported no actual tarball');
  mkdirSync(extracted);
  // A relative archive name avoids GNU tar treating a Windows drive colon as
  // a remote host, and also works with Windows' bundled bsdtar.
  extractPackedArtifact(filename, source, extracted);
  mkdirSync(installed);
  mustRun(npm, ['install', '--prefix', installed, tarball, '--ignore-scripts', '--no-audit', '--no-fund'],
    source, 240_000);
  prepared = { root, source, tarball, extracted: join(extracted, 'package'), installed,
    dryFiles, cleanDist, packedDist: distBytes(join(extracted, 'package', 'dist')) };
  return prepared;
}

export function relativePaths(base: string): string[] {
  return files(base).map(path => relative(base, join(base, path)).split(sep).join('/'));
}

export function installedCommand(args: string[], workingDirectory?: string): Result {
  const a = artifact();
  const bin = join(a.installed, 'node_modules', '.bin');
  const windows = process.platform === 'win32';
  const shim = join(bin, windows ? 'macwarden.ps1' : 'macwarden');
  if (!existsSync(shim)) throw new Error('npm install did not create the macwarden command');
  let executable = shim;
  let launchArgs = args;
  if (windows) {
    // Invoke npm's PowerShell shim with literal array elements, avoiding cmd.exe parsing.
    const literal = (value: string) => `'${value.replace(/'/g, "''")}'`;
    // npm's shim uses Management cmdlets (Split-Path, Test-Path). Import them by name: autoloading
    // first analyses every module on the path, about 25 s on GitHub's Windows runners.
    const script = `$ErrorActionPreference = 'Stop'; ` +
      'Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility; ' +
      `$shimArgs = @(${args.map(literal).join(',')}); ` +
      `& ${literal(shim)} @shimArgs; exit $LASTEXITCODE`;
    executable = 'powershell.exe';
    launchArgs = ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')];
  }
  const run = spawnSync(executable, launchArgs, { cwd: workingDirectory || a.installed,
    env: childEnvironment(), encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
  return { status: run.status, stdout: run.stdout || '', stderr: run.stderr || '' };
}
