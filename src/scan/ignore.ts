export type IgnoreEntry = { fingerprint: string; matches: (path: string) => boolean };
export class IgnoreFileError extends Error {
  constructor() { super('invalid ignore file'); }
}

type GlobToken = { kind: 'literal'; char: string } | { kind: 'star' | 'globstar' | 'directories' | 'question' };

function globMatcher(glob: string): (path: string) => boolean {
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
  return path => {
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
  };
}

export function parseIgnoreFile(content: string): IgnoreEntry[] {
  if (content.length > 5_242_880) throw new IgnoreFileError();
  const entries: IgnoreEntry[] = [];
  for (const source of content.split(/\r\n|\n|\r/)) {
    const line = source.split('#', 1)[0].trim();
    if (!line) continue;
    const match = /^(fp:[0-9a-fA-F]{16})(?:\s+(\S+))?$/.exec(line);
    if (!match) throw new IgnoreFileError();
    const glob = match[2];
    let matches: (path: string) => boolean;
    if (glob === undefined) matches = () => true;
    else if (glob.startsWith('/')) {
      // As in .gitignore, a leading '/' anchors the glob at the ignore file's directory. Globs
      // already match whole relative paths, so the '/' is dropped for them; an absolute
      // reported path (--ignore-file) is matched against the glob as written.
      const anchored = globMatcher(glob.slice(1));
      const absolute = globMatcher(glob);
      matches = path => path.startsWith('/') ? absolute(path) : anchored(path);
    } else matches = globMatcher(glob);
    if (entries.length >= 1024) throw new IgnoreFileError();
    entries.push({ fingerprint: match[1].toLowerCase(), matches });
  }
  return entries;
}
