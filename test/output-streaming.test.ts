import { EventEmitter } from 'node:events';
import { expect, it } from 'vitest';
import { writeChunks } from '../src/cli.js';
import { render, renderChunks, type OutputResult } from '../src/output/index.js';

// A scan result shaped like real output, large enough that the old renderer built
// one multi-megabyte string. Expectations come from JSON.stringify of the same
// document, computed independently of the renderer.
function scanResult(count: number): OutputResult {
  const findings = Array.from({ length: count }, (_, index) => ({
    path: `/repo/dir-${index % 97}/file-${index}.env`, line: index + 1, column: 3, kind: 'macaroon-hex',
    fingerprint: `fp:${index.toString(16).padStart(16, '0')}`, grade: 'READ', rootKeyId: String(index),
    location: 'lnd', permissions: ['info:read', 'offchain:read'], caveats: [], warnings: [],
    ...(index % 3 === 0 ? { commit: 'a'.repeat(40) } : {}),
  }));
  return { command: 'scan', ok: true, warnings: [], error: null, result: {
    findings, skipped: [{ path: '/repo/big.bin', reason: 'size' }],
    summary: { findings: count, distinct: count, filesScanned: count, filesSkipped: 1, ignored: 0 },
    failOn: null } } as unknown as OutputResult;
}

it('OUTPUT/streaming JSON chunks concatenate to exactly the single-document serialization', () => {
  const result = scanResult(5000);
  const chunks = [...renderChunks(result, 'json')];
  const { display: _d, exitCode: _e, ...document } = result as OutputResult & { display?: unknown; exitCode?: unknown };
  void _d; void _e;
  expect(chunks.join('')).toBe(`${JSON.stringify({ schema: 1, ...document })}\n`);
  expect(chunks.join('')).toBe(render(result, 'json'));
});

it('OUTPUT/streaming large JSON and text results are emitted in bounded chunks', () => {
  const result = scanResult(8_000);
  for (const mode of ['json', 'text'] as const) {
    const chunks = [...renderChunks(result, mode)];
    const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    expect(total).toBeGreaterThan(600_000);
    expect(chunks.length).toBeGreaterThan(8);
    // A chunk is the 64 KiB batch plus at most one finding.
    expect(Math.max(...chunks.map(chunk => chunk.length))).toBeLessThan(70_000);
  }
});

it('OUTPUT/streaming text chunks keep one line per finding and the summary last', () => {
  const text = [...renderChunks(scanResult(3), 'text')].join('');
  expect(text.split('\n')).toEqual([
    expect.stringMatching(/^aaaaaaa:\/repo\/dir-0\/file-0\.env:1:3 {2}macaroon-hex {2}fp:0{16} READ root key 0$/),
    expect.stringMatching(/^\/repo\/dir-1\/file-1\.env:2:3 /),
    expect.stringMatching(/^\/repo\/dir-2\/file-2\.env:3:3 /),
    '3 findings (3 distinct) in 3 files; 1 skipped; 0 ignored',
    '',
  ]);
});

it('OUTPUT/streaming a rejected value fails before any chunk is produced', () => {
  const bad = { command: 'scan', ok: true, warnings: [], error: null, result: new Map() } as unknown as OutputResult;
  const chunks = renderChunks(bad, 'json');
  expect(() => chunks.next()).toThrow('internal output value');
});

it('OUTPUT/streaming the writer waits for drain before writing the next chunk', async () => {
  const written: string[] = [];
  let full = true;
  const stream = Object.assign(new EventEmitter(), {
    write(chunk: string) { written.push(chunk); return !full; },
  });
  const done = writeChunks(stream as unknown as NodeJS.WriteStream, ['a', 'b', 'c']);
  await new Promise(resolve => setImmediate(resolve));
  expect(written).toEqual(['a']);
  full = false;
  stream.emit('drain');
  await done;
  expect(written).toEqual(['a', 'b', 'c']);
});
