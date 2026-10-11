/** `glob`: the glob as written, null for a fingerprint-only entry; `tokens`: its matcher's length. */
export type IgnoreEntry = { fingerprint: string; glob: string | null; tokens: number; matches: (path: string) => boolean };
export class IgnoreFileError extends Error {
  constructor() { super('invalid ignore file'); }
}

/** At most this many entries (lines) in one ignore file. */
const IGNORE_ENTRIES_LIMIT = 1024;

type GlobToken = { kind: 'literal'; char: string } | { kind: 'star' | 'globstar' | 'directories' | 'question' };

function globMatcher(glob: string): { tokens: number; matches: (path: string) => boolean } {
  if (glob.length > 1024) throw new IgnoreFileError();
  const tokens: GlobToken[] = [];
  for (let i = 0; i < glob.length; i++) {
    const char = glob[i];
    if (char === '*' && glob[i + 1] === '*') {
      if (glob[i + 2] === '/') {
        tokens.push({ kind: 'directories' });
        i += 2;
      } else {
        tokens.push({ kind: 'globstar' });
        i++;
      }
    } else if (char === '*') tokens.push({ kind: 'star' });
    else if (char === '?') tokens.push({ kind: 'question' });
    else tokens.push({ kind: 'literal', char });
  }
  if (tokens.length > 256) throw new IgnoreFileError();
  return { tokens: tokens.length, matches: path => {
    // Two buffers, swapped per token, instead of an allocation per token.
    let reachable = new Uint8Array(path.length + 1);
    let next = new Uint8Array(path.length + 1);
    reachable[0] = 1;
    for (const token of tokens) {
      next.fill(0);
      if (token.kind === 'directories') {
        // Zero or more nonempty path segments, each followed by '/'.
        next.set(reachable);
        let insideSegment = false;
        for (let i = 0; i < path.length; i++) {
          if (path[i] === '/') {
            if (insideSegment) next[i + 1] = 1;
            insideSegment = false;
          } else {
            insideSegment = insideSegment || next[i] !== 0;
          }
        }
      } else if (token.kind === 'star' || token.kind === 'globstar') {
        next.set(reachable);
        for (let i = 0; i < path.length; i++) {
          if (next[i] && (token.kind === 'globstar' || path[i] !== '/')) next[i + 1] = 1;
        }
      } else {
        for (let i = 0; i < path.length; i++) {
          if (reachable[i] && (token.kind === 'literal' ? path[i] === token.char : path[i] !== '/'))
            next[i + 1] = 1;
        }
      }
      [reachable, next] = [next, reachable];
    }
    return reachable[path.length] !== 0;
  } };
}

export function parseIgnoreFile(content: string): IgnoreEntry[] {
  if (content.length > 5_242_880) throw new IgnoreFileError();
  const entries: IgnoreEntry[] = [];
  // The same fingerprint and glob written twice is one entry; every line counts toward the limit.
  const seen = new Set<string>();
  let lines = 0;
  for (const source of content.split(/\r\n|\n|\r/)) {
    const line = source.split('#', 1)[0].trim();
    if (!line) continue;
    const match = /^(fp:[0-9a-fA-F]{16})(?:\s+(\S+))?$/.exec(line);
    if (!match) throw new IgnoreFileError();
    const glob = match[2];
    let matches: (path: string) => boolean;
    let tokens = 0;
    if (glob === undefined) matches = () => true;
    else if (glob.startsWith('/')) {
      // As in .gitignore, a leading '/' anchors the glob at the ignore file's directory. Globs
      // already match whole relative paths, so the '/' is dropped for them; an absolute
      // reported path (--ignore-file) is matched against the glob as written.
      const anchored = globMatcher(glob.slice(1));
      const absolute = globMatcher(glob);
      tokens = absolute.tokens;
      matches = path => path.startsWith('/') ? absolute.matches(path) : anchored.matches(path);
    } else ({ tokens, matches } = globMatcher(glob));
    if (++lines > IGNORE_ENTRIES_LIMIT) throw new IgnoreFileError();
    const fingerprint = match[1].toLowerCase();
    const key = `${fingerprint}\0${glob ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push({ fingerprint, glob: glob ?? null, tokens, matches });
  }
  return entries;
}

/**
 * Bound on glob matching work for one scan, in matcher steps (a glob's tokens + 1 times the
 * path's length + 1, per match): about a second of matching. An ignore file in a scanned tree
 * is written by whoever controls the tree, and without a bound many long failing globs against
 * many finding paths cost minutes. Once the budget is spent no further glob is evaluated and
 * the finding is kept (fail closed: a credential is never hidden because matching stopped).
 */
export const IGNORE_MATCH_WORK_LIMIT = 1_000_000_000;

/**
 * Whether a finding with this fingerprint at this path is ignored, charging `budget` (shared by
 * every path argument of a scan) for each glob matched. Fingerprint-only entries cost nothing.
 */
export function ignoreDecider(entries: IgnoreEntry[], budget: { remaining: number }): (fingerprint: string, path: string) => boolean {
  const byFingerprint = new Map<string, IgnoreEntry[]>();
  const everywhere = new Set<string>();
  for (const entry of entries) {
    if (entry.glob === null) everywhere.add(entry.fingerprint);
    const list = byFingerprint.get(entry.fingerprint);
    if (list) list.push(entry); else byFingerprint.set(entry.fingerprint, [entry]);
  }
  return (fingerprint, path) => {
    if (everywhere.has(fingerprint)) return true;
    for (const entry of byFingerprint.get(fingerprint) ?? []) {
      const cost = (entry.tokens + 1) * (path.length + 1);
      if (budget.remaining < cost) { budget.remaining = 0; return false; }
      budget.remaining -= cost;
      if (entry.matches(path)) return true;
    }
    return false;
  };
}
