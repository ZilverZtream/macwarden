// Parser review 2026-10-08, HIGH-1: MCP-context tagging rebuilt the whole key path for
// every string value, so one committed .json file with deep nesting and many strings held
// `scan` for hours (O(depth x strings)). Tagging must be linear and give up past a depth cap.
import * as fs from 'node:fs/promises';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { run } from '../src/commands/scan.js';
import type { ScanResult } from '../src/scan/index.js';
import { MAX_DEPTH, mcpServerStringSpans, withinSpans } from '../src/scan/mcp-context.js';

const repo = resolve();
const scratch = mkdtempSync(join(resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp')), 'parsers-h1-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
// An undecodable candidate is enough to make scan tag the file.
const CANDIDATE = `0201036c6e6402${'ab'.repeat(30)}`;
const elapsed = <T>(work: () => T): [T, number] => { const start = performance.now(); const value = work(); return [value, performance.now() - start]; };

/** The review's repro shape: half the file is nesting, half is string values. */
function attack(bytes: number, depth = Math.floor(bytes / 2 / 5)): string {
  const strings = Math.floor(bytes / 2 / 3);
  return `{"note":"${CANDIDATE}","x":${'{"a":'.repeat(depth)}[${'"",'.repeat(strings)}""]${'}'.repeat(depth)}}`;
}

async function scanOne(name: string, text: string): Promise<[ScanResult, number]> {
  const dir = mkdtempSync(join(scratch, 'scan-'));
  writeFileSync(join(dir, name), text);
  const start = performance.now();
  const output = await run([dir, '--json'], { fs });
  const ms = performance.now() - start;
  expect(output.ok).toBe(true);
  return [output.result as ScanResult, ms];
}

it('PARSERS-H1/the review repro (176 KB, 19.3 s before) scans in under 3 s with one finding', async () => {
  // Before the fix this file took 19.3 s end to end.
  const [result, ms] = await scanOne('settings.json', attack(176 * 1024));
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0].kind).toBe('undecodable-candidate');
  expect(ms).toBeLessThan(3_000);
});

it('PARSERS-H1/a 5 MB file at the text limit is tagged in linear time and scanned in seconds', async () => {
  // About 4 to 5 hours of CPU before the fix (extrapolated from the measured quadratic growth).
  const text = `{"note":"${CANDIDATE}","x":${'{"a":'.repeat(400_000)}[${'"",'.repeat(900_000)}""]${'}'.repeat(400_000)}}`;
  expect(text.length).toBeGreaterThan(4_900_000);
  expect(text.length).toBeLessThanOrEqual(5_242_880);
  const [spans, ms] = elapsed(() => mcpServerStringSpans(text, true));
  expect(spans).toEqual([]);
  expect(ms).toBeLessThan(2_000);
  const [result, scanMs] = await scanOne('mcp.json', text);
  expect(result.findings).toHaveLength(1);
  expect(scanMs).toBeLessThan(10_000);
});

it('PARSERS-H1/many strings just under the depth cap are tagged at O(1) each', () => {
  const depth = MAX_DEPTH - 3;
  const strings = 1_000_000;
  const text = `{"mcpServers":{"a":${'{"k":'.repeat(depth)}[${'"",'.repeat(strings - 1)}""]${'}'.repeat(depth)}}}`;
  const [spans, ms] = elapsed(() => mcpServerStringSpans(text, false));
  expect(spans).toHaveLength(strings);
  const last = spans.at(-1)!;
  expect([last.start.line, last.end.column - last.start.column]).toEqual([1, 1]);
  expect(ms).toBeLessThan(3_000);
  // At the cap tagging gives up, as it does for any text it cannot read.
  expect(MAX_DEPTH).toBe(1000);
  expect(mcpServerStringSpans(`{"mcpServers":${'['.repeat(MAX_DEPTH - 1)}"v"${']'.repeat(MAX_DEPTH - 1)}}`, false)).toHaveLength(1);
  expect(mcpServerStringSpans(`{"mcpServers":${'['.repeat(MAX_DEPTH)}"v"${']'.repeat(MAX_DEPTH)}}`, false)).toEqual([]);
});

// The previous definition, kept as the reference: rebuild the key path for each string.
function referenceSpans(text: string, mcpFile: boolean): number {
  const containers = new Set(['mcpServers', 'mcp_servers', 'context_servers']);
  const inside = (path: string[]) => path.some((key, i) => i < path.length - 1
    && (containers.has(key) || (key === 'servers' && (mcpFile || (i > 0 && path[i - 1] === 'mcp')))));
  type Frame = { kind: 'object'; key: string | null; expectKey: boolean } | { kind: 'array' };
  const stack: Frame[] = [];
  let count = 0;
  const tokens = text.match(/"(?:[^"\\]|\\.)*"|[{}[\],:]|[-0-9a-z]+/gi) ?? [];
  for (const token of tokens) {
    const top = stack.at(-1);
    const after = () => { const frame = stack.at(-1); if (frame?.kind === 'object') { frame.key = null; frame.expectKey = false; } };
    if (token === '{') stack.push({ kind: 'object', key: null, expectKey: true });
    else if (token === '[') stack.push({ kind: 'array' });
    else if (token === '}' || token === ']') { stack.pop(); after(); }
    else if (token === ',') { if (top?.kind === 'object') { top.key = null; top.expectKey = true; } }
    else if (token === ':') { if (top?.kind === 'object') top.expectKey = false; }
    else if (token.startsWith('"')) {
      const value = JSON.parse(token) as string;
      if (top?.kind === 'object' && top.expectKey && top.key === null) { top.key = value; continue; }
      if (inside(stack.flatMap(frame => frame.kind === 'object' ? (frame.key === null ? [] : [frame.key]) : ['[]']))) count++;
      after();
    } else after();
  }
  return count;
}

it('PARSERS-H1/tagging matches the previous key-path definition on random configurations', () => {
  let seed = 12345;
  const random = (n: number) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return (seed >>> 16) % n; };
  const keys = ['mcpServers', 'mcp_servers', 'context_servers', 'servers', 'mcp', 'env', 'a', 'args'];
  const value = (depth: number): unknown => {
    const pick = random(depth > 4 ? 3 : 6);
    if (pick === 0) return 'v';
    if (pick === 1) return random(2) ? 1 : null;
    if (pick === 2) return '';
    if (pick === 3) return Array.from({ length: random(3) }, () => value(depth + 1));
    return Object.fromEntries(Array.from({ length: random(4) }, () => [keys[random(keys.length)], value(depth + 1)]));
  };
  let tagged = 0;
  for (let i = 0; i < 3000; i++) {
    const text = JSON.stringify(value(0), null, random(2) ? 1 : undefined);
    for (const mcpFile of [false, true]) {
      const expected = referenceSpans(text, mcpFile);
      expect(mcpServerStringSpans(text, mcpFile), text).toHaveLength(expected);
      tagged += expected;
    }
  }
  expect(tagged).toBeGreaterThan(500);
});

it('PARSERS-H1/many findings among many tagged strings cost O(log spans) each', async () => {
  // Before: 5,000 candidates among 205,000 tagged strings took 48 s (findings x spans).
  const candidates = 5000;
  const text = `{"mcpServers":{"a":[${Array(200_000).fill('""').join(',')},${Array(candidates).fill(`"${CANDIDATE}"`).join(',\n')}]}}`;
  const [result, ms] = await scanOne('mcp.json', text);
  expect(result.findings).toHaveLength(candidates);
  expect(result.findings.every(finding => finding.context === 'mcp-config')).toBe(true);
  expect(ms).toBeLessThan(10_000);
});

it('PARSERS-H1/span lookup agrees with a linear search', () => {
  const text = '{"mcpServers": {"a": {"env": {"K": "v1", "L": "value two"}, "args": ["x",\n"yy", "",\r\n"zzz"]}}, "other": "no"}';
  const spans = mcpServerStringSpans(text, false);
  expect(spans).toHaveLength(6);
  const before = (a: { line: number; column: number }, b: { line: number; column: number }) =>
    a.line < b.line || (a.line === b.line && a.column <= b.column);
  for (let line = 0; line <= 4; line++) for (let column = 0; column <= 80; column++) {
    const position = { line, column };
    expect(withinSpans(position, spans), `${line}:${column}`)
      .toBe(spans.some(span => before(span.start, position) && before(position, span.end)));
  }
  expect(withinSpans({ line: 1, column: 1 }, [])).toBe(false);
});
