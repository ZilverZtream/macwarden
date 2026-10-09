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
// Repository location: git would follow a .git gitfile, commondir, objects/info/alternates
// and include/includeIf paths anywhere, including UNC and device paths, so a tree could
// make an offline scan open SMB connections. locateRepository() resolves all of them in
// JavaScript first, refuses any that are not on a local file system before touching them,
// and the git processes then run with GIT_DIR and GIT_WORK_TREE pinned to the result.
// Every location is also checked against the protected names (SAFE-02) on its supplied path
// and resolved target before it is opened, because git would read the same files.
import { spawn } from 'node:child_process';
import * as fs from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, dirname, isAbsolute, join, resolve, win32 } from 'node:path';
import { BoundedFileError, readBoundedFile } from '../bounded-file.js';
import { Cancelled, cancellationSignal, checkCancellation } from '../cancellation.js';
import { isProtectedPath } from '../protected-path.js';

export class GitHistoryError extends Error {
  constructor(message: string) { super(message); this.name = 'GitHistoryError'; }
}

/**
 * Every blob added or modified on any ref, oldest commit first, stored column-wise so a
 * large history costs a few bytes per entry: commit, path and blob are indexes into
 * de-duplicated string tables, and mode is a small code (MODE_*).
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

function absolute(base: string, value: string): string {
  return isAbsolute(value) || (process.platform === 'win32' && win32.isAbsolute(value)) ? resolve(value) : resolve(base, value);
}

/** The file system calls repository location uses; tests inject a recording wrapper. */
export type LocationIO = Pick<typeof fs, 'realpath' | 'stat' | 'lstat' | 'open'>;

/**
 * Resolves a path named inside the repository. Refuses non-local ones before any I/O, and
 * (SAFE-02) one whose supplied path or resolved target has a protected file or directory
 * component before anything there is opened.
 */
async function local(io: LocationIO, base: string, value: string): Promise<string> {
  const path = absolute(base, value);
  if (nonLocalPath(path)) throw new GitHistoryError(NOT_LOCAL);
  if (isProtectedPath(path)) throw new GitHistoryError(PROTECTED);
  const real = await io.realpath(path).catch(() => null);
  if (real !== null && nonLocalPath(real)) throw new GitHistoryError(NOT_LOCAL);
  if (real !== null && isProtectedPath(real)) throw new GitHistoryError(PROTECTED);
  return real ?? path;
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
  /** Canonical location → its expansion, once validated. Each location is read at most once. */
  readonly done = new Map<string, Expansion>();
  readonly walking = new Set<string>();
  constructor(readonly io: LocationIO, limits: Partial<PreflightLimits> = {}, stats?: Partial<PreflightStats>) {
    this.limits = { ...PREFLIGHT_LIMITS, ...limits };
    this.stats = Object.assign(stats ?? {}, { files: 0, bytes: 0, edges: 0, expandedEdges: 0, expandedBytes: 0 });
  }
  key(path: string): string { return process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path); }
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
   * Reads one location file, or null when it is absent or not a regular file. A protected
   * path or resolved target (SAFE-02) is refused before it is opened; the content is read
   * through one descriptor checked to be the regular file that was resolved, and at most
   * MAX_LOCATION_FILE + 1 bytes are ever read.
   */
  async small(path: string): Promise<string | null> {
    this.stats.files++;
    this.step();
    if (isProtectedPath(path)) throw new GitHistoryError(PROTECTED);
    let bytes: Buffer;
    try { bytes = await readBoundedFile(path, this.io, MAX_LOCATION_FILE); }
    catch (error) {
      if (error instanceof BoundedFileError) {
        if (error.message === 'protected file') throw new GitHistoryError(PROTECTED);
        if (error.message === 'not a regular file') return null;
        throw new GitHistoryError(UNREADABLE);
      }
      // Absent or inaccessible: git would not read it either.
      if (['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM', 'ELOOP'].includes((error as NodeJS.ErrnoException).code ?? '')) return null;
      throw new GitHistoryError(UNREADABLE);
    }
    this.stats.bytes += bytes.length;
    this.step();
    return bytes.toString('utf8');
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
    const text = await run.small(file);
    if (text === null) return NOTHING;
    if (depth >= MAX_ALTERNATE_DEPTH) throw new GitHistoryError(UNREADABLE);
    const own: Expansion = { height: 0, edges: 0, bytes: Buffer.byteLength(text) };
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      run.edge();
      run.follow(own, await checkAlternates(run, await local(run.io, objects, unquoteAlternate(line)), depth + 1));
    }
    return own;
  });
}

/** Include paths named by [include] and [includeIf "..."] sections of one config file. */
function includePaths(text: string): string[] {
  const paths: string[] = [];
  let including = false;
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.trim();
    const header = /^\[([^\]]*)\](.*)$/.exec(line);
    if (header) {
      including = /^\s*include(?:if\b.*)?\s*$/i.test(header[1].replace(/\s+"[^"]*"\s*$/, ''))
        || /^\s*includeif\s+"/i.test(header[1]);
      line = header[2].trim();
      if (!line) continue;
    }
    if (!including || line.startsWith('#') || line.startsWith(';')) continue;
    const entry = /^path\s*=\s*(.*)$/i.exec(line);
    if (!entry) continue;
    let value = entry[1].replace(/\s+[#;].*$/, '').trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1).replace(/\\(["\\])/g, '$1');
    if (value) paths.push(value);
  }
  return paths;
}

/** Include chains of at most MAX_INCLUDE_DEPTH levels; each config file is read once. */
function checkIncludes(run: Preflight, file: string, depth: number): Promise<Expansion> {
  return run.visit(file, depth, MAX_INCLUDE_DEPTH, async () => {
    const text = await run.small(file);
    if (text === null) return NOTHING;
    const own: Expansion = { height: 0, edges: 0, bytes: Buffer.byteLength(text) };
    for (const value of includePaths(text)) {
      if (depth >= MAX_INCLUDE_DEPTH) throw new GitHistoryError(UNREADABLE);
      run.edge();
      const named = value.startsWith('~/') || value.startsWith('~\\') ? join(homedir(), value.slice(2)) : value;
      // %(prefix)/ names the git installation, which is not repository input.
      if (named.startsWith('%(prefix)/')) { run.follow(own, NOTHING); continue; }
      run.follow(own, await checkIncludes(run, await local(run.io, dirname(file), named), depth + 1));
    }
    return own;
  });
}

/** GIT_CEILING_DIRECTORIES as git reads it: discovery never moves up into one of these. */
function ceilings(): Set<string> {
  const key = (path: string) => process.platform === 'win32' ? path.toLowerCase() : path;
  return new Set((process.env.GIT_CEILING_DIRECTORIES ?? '').split(delimiter)
    .filter(path => path && isAbsolute(path)).map(path => key(resolve(path))));
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
  let current = await io.realpath(directory).catch(() => { throw new GitHistoryError(NOT_WORK_TREE); });
  if (nonLocalPath(current)) throw new GitHistoryError(NOT_LOCAL);
  const ceiling = ceilings();
  const key = (path: string) => process.platform === 'win32' ? path.toLowerCase() : path;
  for (;;) {
    const candidate = join(current, '.git');
    const stat = await io.lstat(candidate).catch(() => null);
    if (stat) {
      let gitDir: string;
      if (stat.isFile()) {
        const text = await run.small(candidate);
        const target = text === null ? null : /^gitdir:\s*(.+?)\s*$/m.exec(text)?.[1];
        if (!target) throw new GitHistoryError(NOT_WORK_TREE);
        gitDir = await local(io, current, target);
      } else gitDir = await local(io, current, candidate);
      const gitStat = await io.stat(gitDir).catch(() => null);
      if (!gitStat?.isDirectory()) throw new GitHistoryError(NOT_WORK_TREE);
      const common = await run.small(join(gitDir, 'commondir'));
      const commonDir = common === null ? gitDir : await local(io, gitDir, common.trim());
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

/** Request lines for cat-file, in batches of about 64 KiB. */
function* requestLines(blobs: readonly string[]): Generator<string> {
  let batch = '';
  for (const blob of blobs) {
    batch += `${blob}\n`;
    if (batch.length >= 65_536) { yield batch; batch = ''; }
  }
  if (batch) yield batch;
}

/** Splits a byte stream on `separator` without re-copying earlier data. */
function splitter(separator: number, onToken: (token: Buffer) => void): { push(chunk: Buffer): void; end(): void } {
  let pending: Buffer[] = [];
  return {
    push(chunk) {
      let start = 0;
      for (let end = chunk.indexOf(separator); end !== -1; end = chunk.indexOf(separator, start)) {
        pending.push(chunk.subarray(start, end));
        onToken(pending.length === 1 ? pending[0] : Buffer.concat(pending));
        pending = [];
        start = end + 1;
      }
      if (start < chunk.length) pending.push(Buffer.from(chunk.subarray(start)));
    },
    end() { if (pending.length) { onToken(Buffer.concat(pending)); pending = []; } },
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

/**
 * Lists every blob added or modified on any ref, oldest commit first, with paths
 * relative to `cwd`. Deletions are omitted: the deleted content was added earlier.
 * Root commits are compared with the empty tree and merges with each parent.
 */
export async function historyEntries(git: string, cwd: string, repository: Repository, pathspec: string[]): Promise<HistoryTable> {
  const table = emptyTable();
  const pathIndex = new Map<string, number>();
  const blobIndex = new Map<string, number>();
  const intern = (index: Map<string, number>, values: string[], value: string): number => {
    let at = index.get(value);
    if (at === undefined) { at = values.length; values.push(value); index.set(value, at); }
    return at;
  };
  let commit = -1;
  let pending: RegExpExecArray | null = null;
  const token = (value: string) => {
    if (pending) {
      const [, , mode, , blob, status] = pending;
      pending = null;
      if (status !== 'D' && commit >= 0 && !/^0+$/.test(blob)) {
        if (table.length >= MAX_HISTORY_ENTRIES)
          throw new GitHistoryError(`git history is too large to scan (more than ${MAX_HISTORY_ENTRIES} added blobs)`);
        if (table.length === table.capacity) grow(table);
        const at = table.length++;
        table.commit[at] = commit;
        table.path[at] = intern(pathIndex, table.paths, value);
        table.blob[at] = intern(blobIndex, table.blobs, blob);
        table.mode[at] = mode === '100644' || mode === '100755' ? MODE_REGULAR : mode === '120000' ? MODE_SYMLINK : MODE_OTHER;
      }
      return;
    }
    const marker = commitMarker(value);
    if (marker) { commit = table.commits.length; table.commits.push(marker); return; }
    const raw = RAW.exec(value);
    if (raw) { pending = raw; return; }
    if (value.trim() !== '') throw new GitHistoryError(UNREADABLE);
  };
  const tokens = splitter(0, bytes => token(bytes.toString('utf8')));
  await runGit(git, cwd, repository, ['log', '--all', '--reverse', '--root', '--diff-merges=separate', '--no-renames',
    '--no-show-signature', '--raw', '--no-abbrev', '-z', '--relative', '--no-color', '--no-ext-diff', '--no-textconv',
    '--format=%x01%H', '--', ...pathspec], [], chunk => tokens.push(chunk));
  tokens.end();
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
