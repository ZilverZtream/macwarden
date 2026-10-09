// Locates string values that sit inside an MCP server entry of a JSON (or JSONC)
// configuration file: `mcpServers.<name>...`, `mcp_servers.<name>...`,
// `context_servers.<name>...`, or `servers.<name>...` under `mcp` or in a file named
// mcp.json. A credential found there is configured for an AI agent, which scan reports
// as `context: "mcp-config"`. Positions use the scanner's convention: 1-based lines split
// on CRLF, LF or CR, and 1-based columns in Unicode code points.

export type Position = { line: number; column: number };
export type Span = { start: Position; end: Position };

const CONTAINERS = new Set(['mcpServers', 'mcp_servers', 'context_servers']);
/** Tagging gives up (returns []) beyond this nesting depth; real configuration files stay far below. */
export const MAX_DEPTH = 1000;

// A string value is inside a server entry when some key on its path, other than the last,
// is a server container: mcpServers, mcp_servers, context_servers, or servers in an MCP
// file or directly under mcp. The path is summarised incrementally, so each value costs O(1)
// however deep it is nested: `inside` holds whether an element before the last qualifies,
// `last` and `lastQualifies` describe the last element.
type PathSummary = { inside: boolean; last: string | null; lastQualifies: boolean };
const EMPTY_PATH: PathSummary = { inside: false, last: null, lastQualifies: false };

function append(path: PathSummary, element: string, mcpFile: boolean): PathSummary {
  return { inside: path.inside || path.lastQualifies, last: element,
    lastQualifies: CONTAINERS.has(element) || (element === 'servers' && (mcpFile || path.last === 'mcp')) };
}

/**
 * Spans of every string value inside a server entry. Returns [] for text that is not
 * well-formed JSON with optional comments and trailing commas, or that nests deeper than
 * MAX_DEPTH: tagging is best effort and never changes what is detected. Work is linear in
 * the text length.
 */
export function mcpServerStringSpans(text: string, mcpFile: boolean): Span[] {
  const chars = Array.from(text.startsWith('﻿') ? text.slice(1) : text);
  const spans: Span[] = [];
  let i = 0, line = 1, column = 1;
  const advance = () => {
    const c = chars[i++];
    if (c === '\r') { if (chars[i] === '\n') i++; line++; column = 1; }
    else if (c === '\n') { line++; column = 1; }
    else column++;
  };
  // Each frame keeps the summary of the path its parents form; its own element (its current
  // key, or [] for an array) is appended when a value or a child frame needs it.
  type Frame = ({ kind: 'object'; key: string | null; expectKey: boolean } | { kind: 'array' }) & { parents: PathSummary };
  const stack: Frame[] = [];
  const pathOf = (frame: Frame | undefined): PathSummary => {
    if (!frame) return EMPTY_PATH;
    if (frame.kind === 'array') return append(frame.parents, '[]', mcpFile);
    return frame.key === null ? frame.parents : append(frame.parents, frame.key, mcpFile);
  };
  const readString = (): { value: string; start: Position; end: Position } | null => {
    const start = { line, column };
    advance();
    let value = '';
    while (i < chars.length) {
      const c = chars[i];
      if (c === '"') { const end = { line, column }; advance(); return { value, start, end }; }
      if (c === '\\') { advance(); if (i >= chars.length) return null; value += chars[i]; advance(); continue; }
      if (c === '\n' || c === '\r') return null;
      value += c; advance();
    }
    return null;
  };
  const afterValue = () => {
    const top = stack.at(-1);
    if (top?.kind === 'object') { top.key = null; top.expectKey = false; }
  };
  try {
    while (i < chars.length) {
      const c = chars[i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { advance(); continue; }
      if (c === '/' && chars[i + 1] === '/') { while (i < chars.length && chars[i] !== '\n' && chars[i] !== '\r') advance(); continue; }
      if (c === '/' && chars[i + 1] === '*') {
        advance(); advance();
        while (i < chars.length && !(chars[i] === '*' && chars[i + 1] === '/')) advance();
        if (i >= chars.length) return [];
        advance(); advance(); continue;
      }
      const top = stack.at(-1);
      if (c === '{' || c === '[') {
        if (stack.length >= MAX_DEPTH) return [];
        const parents = pathOf(top);
        advance();
        stack.push(c === '{' ? { kind: 'object', key: null, expectKey: true, parents } : { kind: 'array', parents });
        continue;
      }
      if (c === '}' || c === ']') {
        const frame = stack.pop();
        if (!frame || (c === '}') !== (frame.kind === 'object')) return [];
        advance(); afterValue(); continue;
      }
      if (c === ',') { if (top?.kind === 'object') { top.key = null; top.expectKey = true; } advance(); continue; }
      if (c === ':') { if (top?.kind !== 'object' || top.key === null) return []; top.expectKey = false; advance(); continue; }
      if (c === '"') {
        const token = readString();
        if (!token) return [];
        if (top?.kind === 'object' && top.expectKey && top.key === null) { top.key = token.value; continue; }
        if (pathOf(top).inside) spans.push({ start: token.start, end: token.end });
        afterValue(); continue;
      }
      // Numbers and the literals true, false and null.
      if (/[-0-9a-z]/i.test(c)) { while (i < chars.length && /[-+.0-9a-z]/i.test(chars[i])) advance(); afterValue(); continue; }
      return [];
    }
  } catch {
    return [];
  }
  return stack.length === 0 ? spans : [];
}

const before = (a: Position, b: Position) => a.line < b.line || (a.line === b.line && a.column <= b.column);

/**
 * True when the position falls within one of the spans (inclusive of the quotes). Spans come
 * in document order and never overlap (string values cannot nest), so a binary search finds
 * the only candidate: each finding costs O(log spans), not O(spans).
 */
export function withinSpans(position: Position, spans: readonly Span[]): boolean {
  let low = 0, high = spans.length - 1, candidate = -1;
  while (low <= high) {
    const middle = (low + high) >>> 1;
    if (before(spans[middle].start, position)) { candidate = middle; low = middle + 1; }
    else high = middle - 1;
  }
  return candidate >= 0 && before(position, spans[candidate].end);
}
