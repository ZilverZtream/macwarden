import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it } from 'vitest';

type Finding = { line: number | null; column: number | null; kind: string };
type Scan = { findings: Finding[]; skipped: unknown[];
  summary: { findings: number; distinct: number; filesScanned: number }; failOn: unknown };

const tempRoot = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');

const scanner = () => import('../src/scan/index.js') as Promise<{
  scan: (paths: string[], options: object) => Promise<Scan> }>;

it('CP-037/A11-linear-columns long UTF-8 and UTF-16 lines use linear position work', async () => {
  const { scan } = await scanner();
  mkdirSync(tempRoot, { recursive: true });
  const dir = mkdtempSync(join(tempRoot, 'cp037-columns-'));
  // This is deliberately undecodable, so the test cannot treat product facts as its oracle.
  const candidate = '0201036c6e6402' + 'a'.repeat(40);
  const count = 20_000;
  const line = '😀' + `${candidate} `.repeat(count);
  const sourcePoints = 1 + (candidate.length + 1) * count;
  const originalFrom = Array.from;
  const originalSlice = String.prototype.slice;
  let observed = 0;
  let overflow: boolean;
  const budget = sourcePoints * 24;
  try {
    for (const encoding of ['utf8', 'utf16le', 'utf16be']) {
      const path = join(dir, `${encoding}.txt`);
      if (encoding === 'utf8') writeFileSync(path, line, 'utf8');
      else {
        const le = Buffer.from(line, 'utf16le');
        writeFileSync(path, encoding === 'utf16le'
          ? Buffer.concat([Buffer.from([0xff, 0xfe]), le])
          : Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(le).swap16()]));
      }
      observed = 0;
      overflow = false;
      Array.from = ((value: Iterable<unknown> | ArrayLike<unknown>, ...args: unknown[]) => {
        if (typeof value === 'string') observed += value.length;
        if (observed > budget) {
          overflow = true;
          throw new Error('position work exceeded linear budget');
        }
        return Reflect.apply(originalFrom, Array, [value, ...args]);
      }) as typeof Array.from;
      String.prototype.slice = function(start?: number, end?: number) {
        const value = Reflect.apply(originalSlice, this, [start, end]) as string;
        if (value.length > 1_000) observed += value.length;
        if (observed > budget) {
          overflow = true;
          throw new Error('position work exceeded linear budget');
        }
        return value;
      };
      let result: Scan;
      try { result = await scan([path], {}); }
      catch (error) {
        if (overflow) throw new Error('position work exceeded linear budget', { cause: error });
        throw error;
      }
      finally { Array.from = originalFrom; String.prototype.slice = originalSlice; }
      expect(result.findings).toHaveLength(count);
      expect(result.summary.findings).toBe(count);
      for (let index = 0; index < count; index++) {
        const finding = result.findings[index];
        expect([finding.line, finding.column, finding.kind], `finding ${index}`)
          .toEqual([1, 2 + (candidate.length + 1) * index, 'undecodable-candidate']);
      }
      expect(observed).toBeLessThanOrEqual(budget);
    }
  } finally {
    Array.from = originalFrom;
    String.prototype.slice = originalSlice;
    rmSync(dir, { recursive: true, force: true });
  }
}, 120_000);
