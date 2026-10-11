// Local git history access for `scan --git-history`. This is the only scan module that
// starts a process: `git` through `spawn` with an argument array, no shell, a minimal
// environment, no optional locks, no network transport and no lazy fetch, so scan stays
// offline and read-only (SAFE-07, SAFE-08).
//
// The scanned repository is untrusted input, and git still reads its own .git/config
// (system and global config are disabled). Command-line `-c` values outrank every config
// file, including include/includeIf targets, so each key that could make rev-parse, log or
// cat-file start a program or change the parsed output is pinned below. Audited keys:
// - started programs: core.fsmonitor; log.showSignature with gpg.program,
//   gpg.ssh.program and gpg.x509.program; core.hooksPath (no hook runs for these read-only
//   commands, pinned anyway); diff.external and diff.<driver>.command (--no-ext-diff);
//   diff.<driver>.textconv (--no-textconv); filter.<driver> clean/smudge (cat-file --batch
//   runs no filters); core.pager and pager.* (--no-pager).
// - network and credentials: protocol.allow=never, GIT_NO_LAZY_FETCH and
//   GIT_TERMINAL_PROMPT=0 keep core.sshCommand, core.askPass, credential.helper,
//   http.*, remote.*, core.gitProxy and uploadpack.* unreachable.
// - output shape: log.showRoot (--root), log.diffMerges (--diff-merges=separate),
//   log.follow, diff.renames (--no-renames), core.abbrev (--no-abbrev), color.* (--no-color),
//   core.quotePath (-z), format.pretty (--format), replace refs (GIT_NO_REPLACE_OBJECTS),
//   grafts (GIT_GRAFT_FILE names a path that does not exist) and pathspec magic
//   (GIT_LITERAL_PATHSPECS).
// - trace2.* is read only from system and global config, both disabled; safe.directory is
//   read only from those and the command line, so a repository owned by another account is
//   refused by git and reported as exit 3.
// - read paths: log.mailmap and mailmap.file/mailmap.blob (pinned off and empty).
//
//
// Repository location: git would follow a .git gitfile, commondir, objects/info/alternates,
// include/includeIf paths and symlinks or junctions inside the git directory anywhere,
// including UNC and device paths, so a tree could make an offline scan open SMB connections.
// locateRepository() resolves all of them in JavaScript first, one path component at a time
// (lstat and readlink only), refuses any that are not on a local file system before touching
// them, and the git processes then run with GIT_DIR and GIT_WORK_TREE pinned to the result.
// Every location is also checked against the protected names (SAFE-02) on its supplied path
// and resolved target before it is opened, because git would read the same files. Include
// values are parsed exactly as git's config parser reads them (quotes, escapes, comments).
import { spawn } from 'node:child_process';
import { constants, type Dirent } from 'node:fs';
import * as fs from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, delimiter, dirname, isAbsolute, join, resolve, win32 } from 'node:path';
import { BoundedFileError, readBoundedFile } from '../bounded-file.js';
import { Cancelled, cancellationSignal, checkCancellation } from '../cancellation.js';
import { isProtectedPath } from '../protected-path.js';

export class GitHistoryError extends Error {
  constructor(message: string) { super(message); this.name = 'GitHistoryError'; }
}

/**
 * Every blob added or modified on any ref, oldest commit first, stored column-wise so a
 * large history costs a few bytes per entry: commit, path and blob are indexes into
 * de-duplicated string tables, and mode is a small code (MODE_*). `commits` holds only
 * commits (or, for a tag naming a tree or blob, the ref's object) that added an entry.
 */
export type HistoryTable = {
  length: number;
  commits: string[]; paths: string[]; blobs: string[];
  commit: Uint32Array; path: Uint32Array; blob: Uint32Array; mode: Uint8Array;
};
export const MODE_REGULAR = 0;
export const MODE_SYMLINK = 1;
export const MODE_OTHER = 2;

const UNAVAILABLE = 'git history requires git on PATH';
const UNREADABLE = 'git history could not be read';
/** A git process that writes nothing for this long is killed and the scan fails closed. */
export const GIT_IDLE_TIMEOUT_MS = 120_000;
/** More added-blob entries than this fail closed instead of exhausting memory. */
export const MAX_HISTORY_ENTRIES = 1_000_000;
const NO_PROGRAM = '/nonexistent/macwarden-disabled';
const windows = process.platform === 'win32';

/** Configuration pinned on every git command line; exported so tests can assert it. */
export const PINNED_CONFIG = [
  'core.fsmonitor=false', `core.hooksPath=${NO_PROGRAM}`, 'protocol.allow=never',
  'log.showSignature=false', `gpg.program=${NO_PROGRAM}`, `gpg.ssh.program=${NO_PROGRAM}`,
  `gpg.x509.program=${NO_PROGRAM}`, 'log.showRoot=true', 'log.follow=false', 'diff.renames=false',
  'log.mailmap=false', 'mailmap.file=', 'mailmap.blob=',
].flatMap(setting => ['-c', setting]);

/** The validated repository a scan reads: git's directory and the work tree root. */
export type Repository = { gitDir: string; workTree: string };

const NOT_LOCAL = 'git history requires a repository on a local file system';
const PROTECTED = 'git history would open a protected file';
const NOT_WORK_TREE = 'path is not inside a git work tree';

/**
 * True when `path` (absolute) names a network or device location: on Windows a UNC
 * path (\\server\share, //server/share, \\?\UNC\...) or a device path (\\.\...,
 * \\?\ without a drive letter). POSIX paths are local.
 */
export function nonLocalPath(path: string, platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== 'win32') return false;
  const text = path.replace(/\//g, '\\');
  if (/^\\\\\?\\[A-Za-z]:\\/.test(text)) return false;
  if (text.startsWith('\\\\')) return true;
  return !/^[A-Za-z]:\\/.test(text);
}

const MAX_ALTERNATE_DEPTH = 5;
const MAX_INCLUDE_DEPTH = 10;
const MAX_LOCATION_FILE = 64 * 1024;
/** Symlinks followed while resolving one location (Linux's MAXSYMLINKS); more fails closed. */
const MAX_LINK_HOPS = 40;
/**
 * Directory entries the git-directory link check examines (refs, logs, packs, worktrees); a
 * git directory with more fails closed instead of making the check unbounded. Loose objects
 * are not listed (see checkGitDirectoryLinks), so this is far above any real repository.
 */
export const MAX_GIT_DIR_ENTRIES = 1_000_000;
/** Errors after which git cannot read a location either: it is treated as absent. */
const ABSENT = ['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM'];
const errorCode = (error: unknown) => (error as NodeJS.ErrnoException).code ?? '';

/**
 * The path git opens for a gitfile target, `commondir` or alternates entry at `base`: an
 * absolute path as written, a Windows rooted path (\x, no drive) on the work tree's drive (git
 * resolves it in its working directory, the work tree, whatever drive macwarden runs from),
 * and anything else relative to `base`.
 */
export function absoluteLocation(base: string, value: string, workTree: string): string {
  if (windows && /^[\\/](?![\\/])/.test(value)) return win32.resolve(win32.parse(workTree).root, value);
  return isAbsolute(value) || (windows && win32.isAbsolute(value)) ? resolve(value) : resolve(base, value);
}

/** The file system calls repository location uses; tests inject a recording wrapper. */
export type LocationIO = Pick<typeof fs, 'realpath' | 'stat' | 'lstat' | 'open' | 'readlink' | 'readdir'>;

/** An absolute path as its root and the names after it, in the form the platform opens it. */
function components(path: string): { root: string; names: string[] } {
  if (windows) {
    // Win32 normalises `.` and `..` in the text before the file system sees the path.
    const full = win32.resolve(path);
    const root = win32.parse(full).root;
    return { root, names: full.slice(root.length).split('\\') };
  }
  return { root: '/', names: path.split('/') };
}

/** A link target as an absolute path, checked before anything there is touched. */
function linkTarget(directory: string, target: string): string {
  const named = windows ? win32.resolve(directory, target) : isAbsolute(target) ? target : `${directory}/${target}`;
  if (nonLocalPath(named)) throw new GitHistoryError(NOT_LOCAL);
  if (isProtectedPath(named) || isProtectedPath(resolve(named))) throw new GitHistoryError(PROTECTED);
  return named;
}

/**
 * Resolves `path` (absolute) the way opening it would, one component at a time: each
 * component is lstat'ed and a symlink or junction is read with readlink, and its target is
 * checked (network or device path, protected component) before anything there is touched.
 * realpath, stat and open are never called on an unchecked location, so a link to a UNC path
 * makes no network connection. POSIX applies `..` after following a link, and so does this
 * walk. A missing or inaccessible component ends the walk: the rest is returned as written,
 * because git cannot read it either.
 */
async function resolveLinks(io: LocationIO, path: string): Promise<string> {
  let { root: current, names: pending } = components(path);
  let hops = 0;
  while (pending.length) {
    checkCancellation();
    const name = pending.shift()!;
    if (name === '' || name === '.') continue;
    if (name === '..') { current = dirname(current); continue; }
    const next = join(current, name);
    let stat;
    try { stat = await io.lstat(next); }
    catch (error) {
      if (ABSENT.includes(errorCode(error))) return join(next, ...pending);
      throw new GitHistoryError(UNREADABLE);
    }
    if (!stat.isSymbolicLink()) { current = next; continue; }
    if (++hops > MAX_LINK_HOPS) throw new GitHistoryError(UNREADABLE);
    let target: string;
    try { target = await io.readlink(next); } catch { throw new GitHistoryError(UNREADABLE); }
    const named = linkTarget(current, target);
    ({ root: current, names: pending } = components(windows ? win32.resolve(named, ...pending) : [named, ...pending].join('/')));
  }
  return current;
}

/**
 * Resolves a location git would read (absolute, as git forms it). Refuses a non-local one
 * before any I/O, and (SAFE-02) one whose supplied path, any link target on the way or
 * resolved target has a protected file or directory component, before anything there is
 * opened. Returns the resolved path.
 */
async function local(io: LocationIO, path: string): Promise<string> {
  if (nonLocalPath(path)) throw new GitHistoryError(NOT_LOCAL);
  if (isProtectedPath(path) || isProtectedPath(resolve(path))) throw new GitHistoryError(PROTECTED);
  const real = await resolveLinks(io, path);
  if (nonLocalPath(real)) throw new GitHistoryError(NOT_LOCAL);
  if (isProtectedPath(real)) throw new GitHistoryError(PROTECTED);
  // The text can still be an alias of a protected file: a Windows 8.3 short name
  // (MACARO~1.DB), a name with a trailing dot or space, or another spelling the file system
  // maps to it. Every component and link on the way was classified local above, so realpath
  // here touches no network location; its canonical result is checked again.
  let canonical: string;
  try { canonical = await io.realpath(real); }
  catch (error) {
    if ([...ABSENT, 'ELOOP'].includes(errorCode(error))) return real;
    throw new GitHistoryError(UNREADABLE);
  }
  if (nonLocalPath(canonical)) throw new GitHistoryError(NOT_LOCAL);
  if (isProtectedPath(canonical)) throw new GitHistoryError(PROTECTED);
  return real;
}

/**
 * Cumulative work allowed for one repository-location preflight. The include and alternates
 * graphs are repository input, and git re-reads an included file every time it is named, so
 * `edges` and `bytes` bound what git itself would traverse (every include or alternate it
 * follows, every config byte it parses), however the graph is shaped. `files` bounds the
 * distinct location files macwarden looks at.
 */
export type PreflightLimits = { files: number; bytes: number; edges: number };
export const PREFLIGHT_LIMITS: PreflightLimits = { files: 256, bytes: 1024 * 1024, edges: 4096 };
/**
 * Work done by one preflight: distinct location files looked at, bytes actually read and
 * distinct edges examined; `expandedEdges` and `expandedBytes` are what git would traverse.
 */
export type PreflightStats = { files: number; bytes: number; edges: number; expandedEdges: number; expandedBytes: number };

/** What git traverses below one location: the longest chain, the edges followed, the bytes read. */
type Expansion = { height: number; edges: number; bytes: number };

/** One preflight: budgets, counters, memoized results and the chain currently being walked. */
class Preflight {
  readonly stats: PreflightStats;
  readonly limits: PreflightLimits;
  /** Location key → its expansion, once validated. Each location is read at most once. */
  readonly done = new Map<string, Expansion>();
  readonly walking = new Set<string>();
  /** The work tree root; git resolves a rooted include path (\x) on its drive. */
  workTree = '';
  constructor(readonly io: LocationIO, limits: Partial<PreflightLimits> = {}, stats?: Partial<PreflightStats>) {
    this.limits = { ...PREFLIGHT_LIMITS, ...limits };
    this.stats = Object.assign(stats ?? {}, { files: 0, bytes: 0, edges: 0, expandedEdges: 0, expandedBytes: 0 });
  }
  key(path: string): string { return windows ? resolve(path).toLowerCase() : resolve(path); }
  /** Checks cancellation and the cumulative budgets; exceeding one fails like unreadable input. */
  step(): void {
    checkCancellation();
    const { stats, limits } = this;
    if (stats.files > limits.files || stats.bytes > limits.bytes || stats.edges > limits.edges
      || stats.expandedEdges > limits.edges || stats.expandedBytes > limits.bytes)
      throw new GitHistoryError(UNREADABLE);
  }
  edge(): void { this.stats.edges++; this.step(); }
  /**
   * Reads one location file, or null when it is absent or not a regular file. The path is
   * resolved link by link first, so a network, device or protected location (SAFE-02) is
   * refused before it is opened; the content is read through one descriptor checked to be the
   * regular, local file that was resolved, and at most MAX_LOCATION_FILE + 1 bytes are read.
   */
  async small(path: string): Promise<Buffer | null> {
    this.stats.files++;
    this.step();
    const real = await local(this.io, path);
    let bytes: Buffer;
    try { bytes = await readBoundedFile(real, this.io, MAX_LOCATION_FILE, { local: target => !nonLocalPath(target) }); }
    catch (error) {
      if (error instanceof BoundedFileError) {
        if (error.message === 'protected file') throw new GitHistoryError(PROTECTED);
        if (error.message === 'not a local file') throw new GitHistoryError(NOT_LOCAL);
        if (error.message === 'not a regular file') return null;
        throw new GitHistoryError(UNREADABLE);
      }
      // Absent or inaccessible: git would not read it either.
      if ([...ABSENT, 'ELOOP'].includes(errorCode(error))) return null;
      throw new GitHistoryError(UNREADABLE);
    }
    this.stats.bytes += bytes.length;
    this.step();
    return bytes;
  }
  /** Adds a followed edge and the child's expansion to `into`, failing once it exceeds a budget. */
  follow(into: Expansion, child: Expansion): void {
    into.height = Math.max(into.height, 1 + child.height);
    into.edges += 1 + child.edges;
    into.bytes += child.bytes;
    if (into.edges > this.limits.edges || into.bytes > this.limits.bytes) throw new GitHistoryError(UNREADABLE);
  }
  /** Adds a root location's expansion to the totals for the whole repository. */
  root(expansion: Expansion): void {
    this.stats.expandedEdges += expansion.edges;
    this.stats.expandedBytes += expansion.bytes;
    this.step();
  }
  /**
   * Validates `location` at `depth` at most once. A location validated earlier is accepted
   * when its deepest chain still fits under `max` from this depth; one on the chain being
   * walked is a cycle, which git would follow until its own depth limit, so it is refused.
   */
  async visit(location: string, depth: number, max: number, walk: () => Promise<Expansion>): Promise<Expansion> {
    const key = this.key(location);
    const known = this.done.get(key);
    if (known !== undefined) {
      if (depth + known.height > max) throw new GitHistoryError(UNREADABLE);
      return known;
    }
    if (this.walking.has(key)) throw new GitHistoryError(UNREADABLE);
    this.walking.add(key);
    try {
      const expansion = await walk();
      if (depth + expansion.height > max) throw new GitHistoryError(UNREADABLE);
      this.done.set(key, expansion);
      return expansion;
    } finally { this.walking.delete(key); }
  }
}

const NOTHING: Expansion = { height: 0, edges: 0, bytes: 0 };

/** Unquotes a C-style quoted alternates line as git writes them. */
function unquoteAlternate(line: string): string {
  if (!line.startsWith('"') || !line.endsWith('"') || line.length < 2) return line;
  return line.slice(1, -1).replace(/\\(["\\abfnrtv]|[0-7]{3})/g, (_m, escape: string) => {
    const named: Record<string, string> = { a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v' };
    if (/^[0-7]{3}$/.test(escape)) return String.fromCharCode(parseInt(escape, 8));
    return named[escape] ?? escape;
  });
}

/** Alternates chains of at most MAX_ALTERNATE_DEPTH levels; each objects directory is read once. */
function checkAlternates(run: Preflight, objects: string, depth: number): Promise<Expansion> {
  const file = join(objects, 'info', 'alternates');
  return run.visit(file, depth, MAX_ALTERNATE_DEPTH, async () => {
    const bytes = await run.small(file);
    if (bytes === null) return NOTHING;
    if (depth >= MAX_ALTERNATE_DEPTH) throw new GitHistoryError(UNREADABLE);
    const own: Expansion = { height: 0, edges: 0, bytes: bytes.length };
    for (const raw of bytes.toString('utf8').split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      run.edge();
      run.follow(own, await checkAlternates(run, await local(run.io, absoluteLocation(objects, unquoteAlternate(line), run.workTree)), depth + 1));
    }
    return own;
  });
}

// git's sane_ctype classes, which config parsing uses: ASCII only, space is \t \n \r and ' '.
const isSpace = (c: number) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
const isAlpha = (c: number) => (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
const isKeyChar = (c: number) => isAlpha(c) || (c >= 0x30 && c <= 0x39) || c === 0x2d;
const lower = (c: number) => (c >= 0x41 && c <= 0x5a ? c + 0x20 : c);
const UTF8_BOM = [0xef, 0xbb, 0xbf];

/**
 * The values of `include.path` and `includeIf.<condition>.path` in one config file, in file
 * order, parsed exactly as git's config parser (config.c: get_next_char, get_base_var,
 * get_extended_base_var, get_value, parse_value) reads them: quotes open and close anywhere
 * in a value, `#` and `;` start a comment anywhere outside quotes, `\` escapes and line
 * continuations, CR LF, a UTF-8 byte order mark, and the deprecated [section.sub] header.
 * Every includeIf condition is treated as true. A line git would reject (it then fails)
 * fails closed, and so does an include value that is not valid UTF-8 or has no value.
 */
export function configIncludePaths(bytes: Buffer): string[] {
  const fail = () => new GitHistoryError(UNREADABLE);
  let at = 0;
  let eof = false;
  const next = (): number => {
    if (at >= bytes.length) { eof = true; return 0x0a; }
    const c = bytes[at++];
    if (c === 0x0d && at < bytes.length && bytes[at] === 0x0a) { at++; return 0x0a; }
    return c;
  };
  const text = (codes: number[]) => Buffer.from(codes).toString('latin1');
  const extendedBaseVar = (name: string, first: number): string | null => {
    let c = first;
    do {
      if (c === 0x0a) return null;
      c = next();
    } while (isSpace(c));
    if (c !== 0x22) return null;
    const sub: number[] = [];
    for (;;) {
      let d = next();
      if (d === 0x0a) return null;
      if (d === 0x22) break;
      if (d === 0x5c) {
        d = next();
        if (d === 0x0a) return null;
      }
      sub.push(d);
    }
    if (next() !== 0x5d) return null;
    return `${name}.${Buffer.from(sub).toString('latin1')}`;
  };
  const baseVar = (): string | null => {
    const name: number[] = [];
    for (;;) {
      const c = next();
      if (eof) return null;
      if (c === 0x5d) return text(name);
      if (isSpace(c)) return extendedBaseVar(text(name), c);
      if (!isKeyChar(c) && c !== 0x2e) return null;
      name.push(lower(c));
    }
  };
  const parseValue = (): number[] | null => {
    let quote = false;
    let comment = false;
    let trim = 0;
    const value: number[] = [];
    for (;;) {
      let c = next();
      if (c === 0x0a) {
        if (quote) return null;
        if (trim) value.length = trim;
        return value;
      }
      if (comment) continue;
      if (isSpace(c) && !quote) {
        if (!trim) trim = value.length;
        if (value.length) value.push(c);
        continue;
      }
      if (!quote && (c === 0x3b || c === 0x23)) { comment = true; continue; }
      if (trim) trim = 0;
      if (c === 0x5c) {
        c = next();
        if (c === 0x0a) continue;
        if (c === 0x74) c = 0x09;
        else if (c === 0x62) c = 0x08;
        else if (c === 0x6e) c = 0x0a;
        else if (c !== 0x5c && c !== 0x22) return null;
        value.push(c);
        continue;
      }
      if (c === 0x22) { quote = !quote; continue; }
      value.push(c);
    }
  };
  const paths: string[] = [];
  let section = '';
  let comment = false;
  let bom = 0;
  for (;;) {
    let c = next();
    if (bom >= 0 && bom < UTF8_BOM.length) {
      if (c === UTF8_BOM[bom]) { bom++; continue; }
      if (bom !== 0) throw fail();
      bom = -1;
    }
    if (c === 0x0a) {
      if (eof) return paths;
      comment = false;
      continue;
    }
    if (comment) continue;
    if (isSpace(c)) continue;
    if (c === 0x23 || c === 0x3b) { comment = true; continue; }
    if (c === 0x5b) {
      const base = baseVar();
      if (base === null || base.length < 1) throw fail();
      section = `${base}.`;
      continue;
    }
    if (!isAlpha(c)) throw fail();
    const key = [lower(c)];
    for (;;) {
      c = next();
      if (eof || !isKeyChar(c)) break;
      key.push(lower(c));
    }
    while (c === 0x20 || c === 0x09) c = next();
    let value: number[] | null = null;
    if (c !== 0x0a) {
      if (c !== 0x3d) throw fail();
      value = parseValue();
      if (value === null) throw fail();
    }
    const name = section + text(key);
    // parse_config_key: includeIf needs a subsection, which runs to the last '.'.
    const include = name === 'include.path'
      || (name.startsWith('includeif.') && name.endsWith('.path') && name.lastIndexOf('.') > 'includeif'.length);
    if (!include) continue;
    if (value === null) throw fail();
    // git uses the value as a C string: it ends at the first NUL byte.
    const end = value.indexOf(0);
    const raw = Buffer.from(end === -1 ? value : value.slice(0, end));
    const decoded = raw.toString('utf8');
    if (!Buffer.from(decoded, 'utf8').equals(raw)) throw fail();
    if (decoded) paths.push(decoded);
  }
}

/**
 * The path git opens for an include value named in `file` (as git formed that file's path):
 * `~/` from HOME (which git is given as this same home directory), %(prefix)/ is the git
 * installation (null: not repository input), an absolute path as written, a Windows rooted
 * path (\x) on the work tree's drive, and anything else relative to the including file's own
 * directory as git writes it, not its resolved target. `~user/` and a Windows drive-relative
 * path (C:x) are refused rather than guessed.
 */
function includeLocation(file: string, value: string, workTree: string): string | null {
  if (value.startsWith('%(prefix)/')) return null;
  let named = value;
  if (named === '~' || named.startsWith('~/')) named = homedir() + named.slice(1);
  else if (named.startsWith('~')) throw new GitHistoryError(UNREADABLE);
  if (windows) {
    if (/^[A-Za-z]:(?![\\/])/.test(named)) throw new GitHistoryError(UNREADABLE);
    if (/^[\\/](?![\\/])/.test(named)) return win32.resolve(win32.parse(workTree).root, named);
    return win32.resolve(dirname(file), named);
  }
  return named.startsWith('/') ? named : `${dirname(file)}/${named}`;
}

/**
 * Include chains of at most MAX_INCLUDE_DEPTH levels. `file` is the path as git forms it;
 * each (resolved file, path as written) pair is read once, because nested includes resolve
 * from the written path's directory.
 */
async function checkIncludes(run: Preflight, file: string, depth: number): Promise<Expansion> {
  const real = await local(run.io, file);
  return run.visit(`${real}\0${file}`, depth, MAX_INCLUDE_DEPTH, async () => {
    const bytes = await run.small(real);
    if (bytes === null) return NOTHING;
    const own: Expansion = { height: 0, edges: 0, bytes: bytes.length };
    for (const value of configIncludePaths(bytes)) {
      if (depth >= MAX_INCLUDE_DEPTH) throw new GitHistoryError(UNREADABLE);
      run.edge();
      const named = includeLocation(file, value, run.workTree);
      if (named === null) { run.follow(own, NOTHING); continue; }
      run.follow(own, await checkIncludes(run, named, depth + 1));
    }
    return own;
  });
}

/** Top-level git directory entries the commands macwarden runs never read. */
const UNREAD_GIT_DIR_ENTRIES = new Set(['hooks', 'lfs']);

/**
 * git reads refs, packed-refs, HEAD, reflogs, packs and other files inside the git directory
 * through whatever symlinks or junctions are there. Lists the git and common directories
 * (lstat-only directory entries, never following an unchecked link) and resolves every link
 * found like any other location: a network, device or protected target is refused, and a
 * local directory target is listed in turn. git reads every regular file under refs/, logs/
 * and objects/pack/ by name, so inside a directory reached through a link (and its
 * subdirectories) a protected file or directory name (SAFE-02) is refused as well: the link's
 * own path and target passed the per-location check, and this is the only check the files
 * below it get. git's own, unlinked directory is exempt: a branch named `seed` or
 * `password` there is a ref, not a credential. Loose-object fan-out directories
 * (objects/xx) are not listed. At most MAX_GIT_DIR_ENTRIES entries are examined.
 */
async function checkGitDirectoryLinks(run: Preflight, roots: string[]): Promise<void> {
  const seen = new Set<string>();
  const queue = roots.map(directory => ({ directory, top: true, linked: false }));
  let examined = 0;
  while (queue.length) {
    const { directory, top, linked } = queue.pop()!;
    const key = run.key(directory);
    if (seen.has(key)) continue;
    seen.add(key);
    checkCancellation();
    let entries: Dirent[];
    try { entries = await run.io.readdir(directory, { withFileTypes: true }); }
    catch (error) {
      if (ABSENT.includes(errorCode(error))) continue;
      throw new GitHistoryError(UNREADABLE);
    }
    const objects = basename(directory).toLowerCase() === 'objects';
    for (const entry of entries) {
      if (++examined > MAX_GIT_DIR_ENTRIES) throw new GitHistoryError(UNREADABLE);
      if ((examined & 1023) === 0) checkCancellation();
      if (top && UNREAD_GIT_DIR_ENTRIES.has(entry.name.toLowerCase())) continue;
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        const real = await local(run.io, path);
        const stat = await run.io.lstat(real).catch(() => null);
        if (stat?.isDirectory()) queue.push({ directory: real, top: false, linked: true });
        continue;
      }
      if (linked && isProtectedPath(entry.name)) throw new GitHistoryError(PROTECTED);
      if (entry.isDirectory() && !(objects && /^[0-9a-f]{2}$/i.test(entry.name))) queue.push({ directory: path, top: false, linked });
    }
  }
}

/** GIT_CEILING_DIRECTORIES as git reads it: discovery never moves up into one of these. */
function ceilings(): Set<string> {
  const key = (path: string) => windows ? path.toLowerCase() : path;
  return new Set((process.env.GIT_CEILING_DIRECTORIES ?? '').split(delimiter)
    .filter(path => path && isAbsolute(path)).map(path => key(resolve(path))));
}

/**
 * The target of a gitfile as git's read_gitfile reads it: the content (up to a NUL byte) must
 * start with "gitdir: ", and the rest, less trailing CR and LF, is the path.
 */
function gitfileTarget(bytes: Buffer): string | null {
  let text = bytes.toString('utf8');
  const nul = text.indexOf('\0');
  if (nul !== -1) text = text.slice(0, nul);
  if (!text.startsWith('gitdir: ')) return null;
  return text.slice('gitdir: '.length).replace(/[\r\n]+$/, '') || null;
}

/**
 * Finds the repository containing `directory` the way git discovery would (a .git
 * directory or gitfile in it or a parent) and validates every location git would read.
 */
export async function locateRepository(directory: string,
  options: { limits?: Partial<PreflightLimits>; stats?: Partial<PreflightStats>; io?: LocationIO } = {}): Promise<Repository> {
  const io = options.io ?? fs;
  const run = new Preflight(io, options.limits, options.stats);
  if (nonLocalPath(resolve(directory))) throw new GitHistoryError(NOT_LOCAL);
  // Every link on the way is checked before realpath follows it.
  const checked = await local(io, resolve(directory));
  let current = await io.realpath(checked).catch(() => { throw new GitHistoryError(NOT_WORK_TREE); });
  if (nonLocalPath(current)) throw new GitHistoryError(NOT_LOCAL);
  const ceiling = ceilings();
  const key = (path: string) => windows ? path.toLowerCase() : path;
  for (;;) {
    const candidate = join(current, '.git');
    const stat = await io.lstat(candidate).catch(() => null);
    if (stat) {
      run.workTree = current;
      // The entry is resolved link by link first (a non-local or protected target is refused
      // before it is touched) and classified by what is there: a .git that is a symlink to a
      // gitfile or to a directory is followed like the gitfile itself, as git does, and a
      // relative gitdir: resolves against the directory holding .git, not the link target's.
      const resolved = await local(io, candidate);
      const kind = await io.lstat(resolved).catch(() => null);
      let gitDir: string;
      if (kind?.isFile()) {
        const bytes = await run.small(candidate);
        const target = bytes === null ? null : gitfileTarget(bytes);
        if (!target) throw new GitHistoryError(NOT_WORK_TREE);
        gitDir = await local(io, absoluteLocation(current, target, current));
      } else gitDir = resolved;
      // gitDir is resolved and checked, so stat follows no unchecked link.
      const gitStat = await io.stat(gitDir).catch(() => null);
      if (!gitStat?.isDirectory()) throw new GitHistoryError(NOT_WORK_TREE);
      const common = await run.small(join(gitDir, 'commondir'));
      const commonDir = common === null ? gitDir : await local(io, absoluteLocation(gitDir, common.toString('utf8').trim(), current));
      await checkGitDirectoryLinks(run, run.key(commonDir) === run.key(gitDir) ? [gitDir] : [gitDir, commonDir]);
      run.root(await checkAlternates(run, join(commonDir, 'objects'), 0));
      run.root(await checkIncludes(run, join(commonDir, 'config'), 0));
      run.root(await checkIncludes(run, join(gitDir, 'config.worktree'), 0));
      return { gitDir, workTree: current };
    }
    const parent = dirname(current);
    if (parent === current || ceiling.has(key(parent))) throw new GitHistoryError(NOT_WORK_TREE);
    current = parent;
  }
}

/**
 * The absolute, local entries of a PATH value. A relative entry (`.`, `bin`, empty) would be
 * searched from git's working directory, which is the scanned tree, and a network entry would
 * make a lookup open a connection; both are dropped.
 */
function absolutePathEntries(value: string | undefined): string[] {
  return (value ?? '').split(delimiter)
    .map(entry => windows ? entry.replace(/^"(.*)"$/, '$1') : entry)
    .filter(entry => windows ? /^[A-Za-z]:[\\/]/.test(entry) : entry.startsWith('/'));
}

/**
 * Finds git once as an absolute path, searching only absolute, local PATH entries in order,
 * so a `git` (or git.exe) inside the scanned directory is never what runs.
 */
export async function resolveGit(path: string | undefined = process.env.PATH): Promise<string> {
  const name = windows ? 'git.exe' : 'git';
  for (const entry of absolutePathEntries(path)) {
    const candidate = join(entry, name);
    try {
      const stat = await fs.stat(candidate);
      if (!stat.isFile()) continue;
      if (!windows) await fs.access(candidate, constants.X_OK);
      return candidate;
    } catch { /* not here: keep looking */ }
  }
  throw new GitHistoryError(UNAVAILABLE);
}

/** The complete environment git runs with: an allowlist plus pinned hardening variables. */
export function gitEnvironment(repository: Repository): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    GIT_DIR: repository.gitDir,
    GIT_WORK_TREE: repository.workTree,
    GIT_CEILING_DIRECTORIES: dirname(repository.workTree),
    GIT_CONFIG_NOSYSTEM: '1',
    // Git for Windows maps /dev/null itself and rejects the Windows device path from node:os.
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_NO_LAZY_FETCH: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_GRAFT_FILE: NO_PROGRAM,
    GIT_LITERAL_PATHSPECS: '1',
    GIT_PAGER: 'cat',
    LC_ALL: 'C',
  };
  for (const name of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'HOME', 'USERPROFILE', 'TMPDIR', 'TEMP', 'TMP'])
    if (process.env[name] !== undefined) env[name] = process.env[name];
  // git searches PATH for its own helpers from the scanned directory: absolute entries only.
  for (const name of ['PATH', 'Path']) if (env[name] !== undefined) env[name] = absolutePathEntries(env[name]).join(delimiter);
  // git expands `~/` in include paths from HOME; the location check expanded them from this.
  env.HOME = homedir();
  return env;
}

/**
 * Runs git and streams its stdout to `onData`. `input` is written to stdin in order,
 * respecting backpressure, so a long request list is never held as one string. An
 * interrupt (the invocation's cancellation signal) kills git and rejects with Cancelled.
 */
function runGit(git: string, cwd: string, repository: Repository, args: string[], input: Iterable<string>,
  onData: (chunk: Buffer) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let child: ReturnType<typeof spawn> | undefined;
    let idle: ReturnType<typeof setTimeout> | undefined;
    let closed = false;
    const abort = cancellationSignal();
    const onAbort = () => finish(new Cancelled());
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      if (idle) clearTimeout(idle);
      abort?.removeEventListener('abort', onAbort);
      if (!error) { resolve(); return; }
      // Never leave git running behind a failed scan: kill it and report once it has exited.
      if (child && !closed) {
        const running = child;
        const done = () => { clearTimeout(grace); reject(error); };
        const grace = setTimeout(done, 5_000);
        running.once('close', done);
        running.kill();
        return;
      }
      reject(error);
    };
    if (abort?.aborted) { finish(new Cancelled()); return; }
    abort?.addEventListener('abort', onAbort, { once: true });
    const arm = () => {
      if (idle) clearTimeout(idle);
      idle = setTimeout(() => finish(new GitHistoryError('git history timed out')), GIT_IDLE_TIMEOUT_MS);
    };
    try {
      child = spawn(git, ['--no-pager', '--no-optional-locks', ...PINNED_CONFIG, ...args],
        { cwd, env: gitEnvironment(repository), shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
    } catch {
      finish(new GitHistoryError(UNAVAILABLE)); return;
    }
    arm();
    const started = child;
    child.on('error', error => {
      if (started.pid === undefined) closed = true;
      finish(new GitHistoryError((error as NodeJS.ErrnoException).code === 'ENOENT' ? UNAVAILABLE : UNREADABLE));
    });
    child.stdout!.on('data', (chunk: Buffer) => {
      if (settled) return;
      arm();
      try { onData(chunk); }
      catch (error) { finish(error instanceof GitHistoryError || error instanceof Cancelled ? error : new GitHistoryError(UNREADABLE)); }
    });
    child.on('close', code => {
      closed = true;
      finish(code === 0 ? undefined : new GitHistoryError(
        args[0] === 'rev-parse' ? 'path is not inside a git work tree' : UNREADABLE));
    });
    const stdin = child.stdin!;
    stdin.on('error', () => undefined);
    const lines = input[Symbol.iterator]();
    const pump = () => {
      for (;;) {
        if (settled) return;
        const next = lines.next();
        if (next.done) { stdin.end(); return; }
        if (!stdin.write(next.value)) { stdin.once('drain', pump); return; }
      }
    };
    pump();
  });
}

/** Request lines for cat-file (or revisions for log --stdin), in batches of about 64 KiB. */
function* requestLines(values: readonly string[], suffix = ''): Generator<string> {
  let batch = '';
  for (const value of values) {
    batch += `${value}${suffix}\n`;
    if (batch.length >= 65_536) { yield batch; batch = ''; }
  }
  if (batch) yield batch;
}

/**
 * Splits a byte stream on `separator` without re-copying earlier data. A token longer than
 * `max` bytes fails with `tooLong()` as soon as the bytes held for it pass `max`.
 */
function splitter(separator: number, onToken: (token: Buffer) => void, max = Infinity,
  tooLong: () => Error = () => new GitHistoryError(UNREADABLE)): { push(chunk: Buffer): void; end(): void } {
  let pending: Buffer[] = [];
  let held = 0;
  return {
    push(chunk) {
      let start = 0;
      for (let end = chunk.indexOf(separator); end !== -1; end = chunk.indexOf(separator, start)) {
        if (held + end - start > max) throw tooLong();
        pending.push(chunk.subarray(start, end));
        onToken(pending.length === 1 ? pending[0] : Buffer.concat(pending));
        pending = [];
        held = 0;
        start = end + 1;
      }
      if (start < chunk.length) {
        held += chunk.length - start;
        if (held > max) throw tooLong();
        pending.push(Buffer.from(chunk.subarray(start)));
      }
    },
    end() { if (pending.length) { onToken(Buffer.concat(pending)); pending = []; held = 0; } },
  };
}

/** Confirms that `cwd` is inside a git work tree. */
export async function assertWorkTree(git: string, cwd: string, repository: Repository): Promise<void> {
  let output = '';
  await runGit(git, cwd, repository, ['rev-parse', '--is-inside-work-tree'], [], chunk => {
    output += chunk.toString('utf8');
    if (output.length > 64) throw new GitHistoryError('path is not inside a git work tree');
  });
  if (output.trim() !== 'true') throw new GitHistoryError('path is not inside a git work tree');
}

/** True when the repository is a shallow clone, whose history is incomplete. */
export async function isShallowRepository(git: string, cwd: string, repository: Repository): Promise<boolean> {
  let output = '';
  await runGit(git, cwd, repository, ['rev-parse', '--is-shallow-repository'], [], chunk => {
    output += chunk.toString('utf8');
    if (output.length > 64) throw new GitHistoryError(UNREADABLE);
  });
  const answer = output.trim();
  if (answer !== 'true' && answer !== 'false') throw new GitHistoryError(UNREADABLE);
  return answer === 'true';
}

const RAW = /^\n?:([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40,64}) ([0-9a-f]{40,64}) ([A-Z])[0-9]*$/;
/** A `--format=%x01%H` commit marker, optionally after the newline git emits between commits. */
function commitMarker(value: string): string | null {
  const text = value.startsWith('\n') ? value.slice(1) : value;
  return text.startsWith('\u0001') && /^[0-9a-f]{40,64}$/.test(text.slice(1)) ? text.slice(1) : null;
}

/** Column storage that grows by doubling up to MAX_HISTORY_ENTRIES. */
function emptyTable(): HistoryTable & { capacity: number } {
  const capacity = 1024;
  return { length: 0, capacity, commits: [], paths: [], blobs: [], commit: new Uint32Array(capacity),
    path: new Uint32Array(capacity), blob: new Uint32Array(capacity), mode: new Uint8Array(capacity) };
}

function grow(table: HistoryTable & { capacity: number }): void {
  const capacity = Math.min(table.capacity * 2, MAX_HISTORY_ENTRIES);
  const widen = <T extends Uint32Array | Uint8Array>(old: T, next: T): T => { next.set(old); return next; };
  table.commit = widen(table.commit, new Uint32Array(capacity));
  table.path = widen(table.path, new Uint32Array(capacity));
  table.blob = widen(table.blob, new Uint32Array(capacity));
  table.mode = widen(table.mode, new Uint8Array(capacity));
  table.capacity = capacity;
}

/** Bounds on one history listing besides MAX_HISTORY_ENTRIES; exceeding one fails closed. */
export type HistoryLimits = { pathBytes: number; tokenBytes: number; trees: number };
export const HISTORY_LIMITS: HistoryLimits = {
  // Each distinct path is held once, as a string: 256 MiB of path bytes keeps the listing's
  // memory near that figure however long the paths a history names (MAX_HISTORY_ENTRIES alone
  // allowed a million paths of any length).
  pathBytes: 256 * 1024 * 1024,
  // One path or listing line. File systems keep paths far shorter (PATH_MAX is 4,096 bytes),
  // so a longer one cannot be checked out and is not held while git streams it.
  tokenBytes: 64 * 1024,
  // Distinct trees named directly by a ref or tag; each is listed by its own git process.
  trees: 1024,
};

const tooLarge = (what: string) => new GitHistoryError(`git history is too large to scan (${what})`);
const REF_LINE = /^(commit|tree|blob|tag) ([0-9a-f]{40,64}) (\S.*)$/;
const PEELED = /^([0-9a-f]{40,64}) (commit|tree|blob|tag)$/;
const TREE_ENTRY = /^([0-7]{6}) (?:blob|tree|commit) ([0-9a-f]{40,64})$/;

/** Runs git and returns its stdout split into lines (or NUL-terminated tokens), each bounded. */
async function gitTokens(git: string, cwd: string, repository: Repository, args: string[], input: Iterable<string>,
  separator: number, max: number, onToken: (token: Buffer) => void): Promise<void> {
  const tokens = splitter(separator, onToken, max, () => tooLarge(`a path or line longer than ${max} bytes`));
  await runGit(git, cwd, repository, args, input, chunk => tokens.push(chunk));
  tokens.end();
}

/**
 * Lists every blob added or modified on any ref, oldest commit first, with paths
 * relative to `cwd`. Deletions are omitted: the deleted content was added earlier.
 * Root commits are compared with the empty tree and merges with each parent. Older stash
 * entries (the refs/stash reflog) are walked like refs, and so is everything a tag or ref
 * names directly when it is a tree (its files) or a blob (reported at the ref's name, only
 * when the whole work tree is scanned).
 */
export async function historyEntries(git: string, cwd: string, repository: Repository, pathspec: string[],
  limits: Partial<HistoryLimits> = {}): Promise<HistoryTable> {
  const bound = { ...HISTORY_LIMITS, ...limits };
  const table = emptyTable();
  const pathIndex = new Map<string, number>();
  const blobIndex = new Map<string, number>();
  let pathBytes = 0;
  const internBlob = (value: string): number => {
    let at = blobIndex.get(value);
    if (at === undefined) { at = table.blobs.length; table.blobs.push(value); blobIndex.set(value, at); }
    return at;
  };
  const internPath = (bytes: Buffer): number => {
    const text = bytes.toString('utf8');
    // Keyed by the raw bytes: paths that are not UTF-8 must not merge because they decode alike.
    const key = text.includes('�') && !Buffer.from(text, 'utf8').equals(bytes) ? `\0${bytes.toString('latin1')}` : text;
    let at = pathIndex.get(key);
    if (at === undefined) {
      pathBytes += bytes.length;
      if (pathBytes > bound.pathBytes) throw tooLarge(`more than ${bound.pathBytes} bytes of paths`);
      at = table.paths.length; table.paths.push(text); pathIndex.set(key, at);
    }
    return at;
  };
  // The commit (or ref object) entries are being listed for; recorded only once it adds one.
  let label: string | null = null;
  let labelIndex = -1;
  const start = (value: string) => { label = value; labelIndex = -1; };
  const add = (mode: string, blob: string, path: Buffer) => {
    if (table.length >= MAX_HISTORY_ENTRIES)
      throw tooLarge(`more than ${MAX_HISTORY_ENTRIES} added blobs`);
    if (labelIndex < 0) { labelIndex = table.commits.length; table.commits.push(label!); }
    if (table.length === table.capacity) grow(table);
    const at = table.length++;
    table.commit[at] = labelIndex;
    table.path[at] = internPath(path);
    table.blob[at] = internBlob(blob);
    table.mode[at] = mode === '100644' || mode === '100755' ? MODE_REGULAR : mode === '120000' ? MODE_SYMLINK : MODE_OTHER;
  };

  // Refs: the stash (whose older entries live only in its reflog) and refs naming a tag, a
  // tree or a blob rather than a commit (git log --all walks commits only).
  let stash = false;
  const named: { type: string; object: string; ref: string }[] = [];
  await gitTokens(git, cwd, repository, ['for-each-ref', '--format=%(objecttype) %(objectname) %(refname)'], [],
    0x0a, bound.tokenBytes, bytes => {
      const line = bytes.toString('utf8');
      if (line === '') return;
      const match = REF_LINE.exec(line);
      if (!match) throw new GitHistoryError(UNREADABLE);
      if (match[3] === 'refs/stash') stash = true;
      if (match[1] === 'commit') return;
      if (named.length >= MAX_HISTORY_ENTRIES) throw tooLarge(`more than ${MAX_HISTORY_ENTRIES} refs`);
      named.push({ type: match[1], object: match[2], ref: match[3] });
    });
  const stashes: string[] = [];
  if (stash) {
    await gitTokens(git, cwd, repository, ['log', '--walk-reflogs', '--no-show-signature', '--format=%H', 'refs/stash', '--'], [],
      0x0a, bound.tokenBytes, bytes => {
        const line = bytes.toString('utf8');
        if (line === '') return;
        if (!/^[0-9a-f]{40,64}$/.test(line)) throw new GitHistoryError(UNREADABLE);
        if (stashes.length >= MAX_HISTORY_ENTRIES) throw tooLarge(`more than ${MAX_HISTORY_ENTRIES} stash entries`);
        stashes.push(line);
      });
  }

  let pending: RegExpExecArray | null = null;
  await gitTokens(git, cwd, repository, ['log', '--all', '--stdin', '--reverse', '--root', '--diff-merges=separate',
    '--no-renames', '--no-show-signature', '--raw', '--no-abbrev', '-z', '--relative', '--no-color', '--no-ext-diff',
    '--no-textconv', '--format=%x01%H', '--', ...pathspec], requestLines(stashes), 0, bound.tokenBytes, bytes => {
    if (pending) {
      const [, , mode, , blob, status] = pending;
      pending = null;
      if (status !== 'D' && label !== null && !/^0+$/.test(blob)) add(mode, blob, bytes);
      return;
    }
    const value = bytes.toString('latin1');
    const marker = commitMarker(value);
    if (marker) { start(marker); return; }
    const raw = RAW.exec(value);
    if (raw) { pending = raw; return; }
    if (value.trim() !== '') throw new GitHistoryError(UNREADABLE);
  });
  if (pending) throw new GitHistoryError(UNREADABLE);
  if (!named.length) return table;

  // Peel tags fully (a tag may name a tag); commits are already listed.
  const peeled: string[] = [];
  await gitTokens(git, cwd, repository, ['cat-file', '--batch-check=%(objectname) %(objecttype)'],
    requestLines(named.map(item => item.object), '^{}'), 0x0a, bound.tokenBytes, bytes => {
      const line = bytes.toString('utf8');
      if (line === '') return;
      const match = PEELED.exec(line);
      if (!match || peeled.length >= named.length) throw new GitHistoryError(UNREADABLE);
      peeled.push(`${match[2]} ${match[1]}`);
    });
  if (peeled.length !== named.length) throw new GitHistoryError(UNREADABLE);
  // A blob has no path of its own: it is reported at its ref's name, and only when the scan
  // covers the whole work tree (no file argument, the work tree root as the directory).
  const sameDirectory = (left: string, right: string) => windows ? left.toLowerCase() === right.toLowerCase() : left === right;
  const wholeTree = pathspec.length === 0
    && sameDirectory(await fs.realpath(cwd).catch(() => resolve(cwd)), repository.workTree);
  const trees = new Map<string, string>();
  for (let i = 0; i < named.length; i++) {
    const [type, object] = peeled[i].split(' ');
    if (type === 'tree' && !trees.has(object)) {
      if (trees.size >= bound.trees) throw tooLarge(`more than ${bound.trees} refs naming a tree`);
      trees.set(object, named[i].object);
    } else if (type === 'blob' && wholeTree) {
      start(named[i].object);
      add('100644', object, Buffer.from(named[i].ref, 'utf8'));
    }
  }
  for (const [tree, ref] of trees) {
    checkCancellation();
    start(ref);
    // ls-tree lists paths relative to cwd and only below it, like log --relative.
    let header: RegExpExecArray | null = null;
    await gitTokens(git, cwd, repository, ['ls-tree', '-r', '-z', tree, '--', ...pathspec], [], 0, bound.tokenBytes, bytes => {
      if (bytes.length === 0) return;
      const tab = bytes.indexOf(0x09);
      header = tab === -1 ? null : TREE_ENTRY.exec(bytes.subarray(0, tab).toString('latin1'));
      if (!header) throw new GitHistoryError(UNREADABLE);
      add(header[1], header[2], bytes.subarray(tab + 1));
    });
  }
  return table;
}

/**
 * Returns the size of each requested blob, aligned with `blobs`, without reading content.
 * git answers in request order; a missing object or any other reply fails closed.
 */
export async function blobSizes(git: string, cwd: string, repository: Repository, blobs: readonly string[]): Promise<Float64Array> {
  const sizes = new Float64Array(blobs.length);
  let next = 0;
  const lines = splitter(0x0a, bytes => {
    const line = bytes.toString('utf8');
    if (line === '') return;
    const match = /^([0-9a-f]{40,64}) ([0-9]+)$/.exec(line);
    if (!match || next >= blobs.length || match[1] !== blobs[next]) throw new GitHistoryError(UNREADABLE);
    sizes[next++] = Number(match[2]);
  });
  await runGit(git, cwd, repository, ['cat-file', '--batch-check=%(objectname) %(objectsize)'], requestLines(blobs),
    chunk => lines.push(chunk));
  lines.end();
  if (next !== blobs.length) throw new GitHistoryError(UNREADABLE);
  return sizes;
}

/**
 * Streams each requested blob to `onBlob(index, bytes)`, in request order. At most
 * `keep(index)` bytes of a blob are retained; the rest is read and discarded. A missing
 * object fails.
 */
export async function readBlobs(git: string, cwd: string, repository: Repository, blobs: readonly string[], keep: (index: number) => number,
  onBlob: (index: number, bytes: Buffer) => void): Promise<void> {
  type Current = { index: number; remaining: number; room: number; kept: Buffer[] };
  let header: Buffer[] = [];
  let current: Current | null = null;
  let trailer = false;
  let next = 0;
  await runGit(git, cwd, repository, ['cat-file', '--batch'], requestLines(blobs), chunk => {
    let at = 0;
    while (at < chunk.length) {
      if (trailer) {
        if (chunk[at] !== 0x0a || !current) throw new GitHistoryError(UNREADABLE);
        trailer = false; at++;
        const done: Current = current;
        current = null;
        onBlob(done.index, done.kept.length === 1 ? done.kept[0] : Buffer.concat(done.kept));
        continue;
      }
      if (!current) {
        const end = chunk.indexOf(0x0a, at);
        if (end === -1) { header.push(Buffer.from(chunk.subarray(at))); return; }
        header.push(chunk.subarray(at, end));
        const line = Buffer.concat(header).toString('utf8');
        header = [];
        at = end + 1;
        // `<sha> missing` and every other non-blob reply fail closed.
        const match = /^([0-9a-f]{40,64}) blob ([0-9]+)$/.exec(line);
        if (!match || next >= blobs.length || match[1] !== blobs[next]) throw new GitHistoryError(UNREADABLE);
        const index = next++;
        const started: Current = { index, remaining: Number(match[2]), room: keep(index), kept: [] };
        current = started;
        if (started.remaining === 0) trailer = true;
        continue;
      }
      const blob: Current = current;
      const take = Math.min(blob.remaining, chunk.length - at);
      if (blob.room > 0) {
        const kept = Math.min(blob.room, take);
        blob.kept.push(Buffer.from(chunk.subarray(at, at + kept)));
        blob.room -= kept;
      }
      blob.remaining -= take;
      at += take;
      if (blob.remaining === 0) trailer = true;
    }
  });
  if (current || trailer || header.length || next !== blobs.length) throw new GitHistoryError(UNREADABLE);
}
