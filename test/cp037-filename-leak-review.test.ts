import { childEnvironment } from './helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

const repo = resolve();
const sentinel = readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
const sentinelList = join(repo, 'test/sentinels.json');
const testTmp = process.env.MACWARDEN_TEST_TMP;
if (!testTmp) throw new Error('MACWARDEN_TEST_TMP is required for CP-037 filename controls');

function bytePairs(bytes: Buffer): string[] {
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0'));
}

function groupedHex(bytes: Buffer): string {
  const pairs = bytePairs(bytes);
  const groups: string[] = [];
  for (let index = 0, group = 0; index < pairs.length; group++) {
    const width = group % 2 === 0 ? 2 : 4;
    groups.push(pairs.slice(index, index + width).join(''));
    index += width;
  }
  return groups.join(' ');
}

function percentBytes(bytes: Buffer): string {
  return bytePairs(bytes).map(pair => `%${pair}`).join('');
}

function checkFilename(fileName: string): {
  status: number | null;
  started: boolean;
  disclosedName: boolean;
  namedEncoding: boolean;
} {
  mkdirSync(testTmp!, { recursive: true });
  const root = mkdtempSync(join(testTmp!, 'cp037-filename-'));
  try {
    const candidates = join(root, 'candidates');
    const registered = join(root, 'registered');
    mkdirSync(candidates);
    mkdirSync(registered);
    writeFileSync(join(candidates, fileName), 'ordinary text\n');
    const run = spawnSync(process.execPath,
      [join(repo, 'scripts/leak-check.mjs'), '--sentinels', sentinelList, candidates],
      { cwd: repo, encoding: 'utf8', timeout: 15_000,
        env: childEnvironment({MACWARDEN_TEST_TMP: root, MACWARDEN_SENTINEL_DIR: registered}) });
    const diagnostic = `${run.stdout ?? ''}${run.stderr ?? ''}`;
    return { status: run.status, started: run.error === undefined,
      disclosedName: diagnostic.includes(fileName),
      namedEncoding: /(?:hex|percent)/i.test(diagnostic) };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const changed = Buffer.from(sentinel);
changed[changed.length - 1] ^= 1;

it('CP-037/A9-leak-variants detects contiguous hex in a filename through the public CLI', () => {
  const result = checkFilename(`${sentinel.toString('hex')}.txt`);
  expect(result.started).toBe(true);
  expect(result.status).toBe(1);
});

it('CP-037/A9-leak-variants detects space-separated hex in a filename through the public CLI', () => {
  const result = checkFilename(`${bytePairs(sentinel).join(' ')}.txt`);
  expect(result.started).toBe(true);
  expect(result.status).toBe(1);
  expect(result.namedEncoding).toBe(true);
  expect(result.disclosedName).toBe(false);
});

it('CP-037/A9-leak-variants detects grouped hex in a filename through the public CLI', () => {
  const result = checkFilename(`${groupedHex(sentinel)}.txt`);
  expect(result.started).toBe(true);
  expect(result.status).toBe(1);
  expect(result.namedEncoding).toBe(true);
  expect(result.disclosedName).toBe(false);
});

it('CP-037/A9-leak-variants detects percent-encoded bytes in a filename through the public CLI', () => {
  const result = checkFilename(`${percentBytes(sentinel)}.txt`);
  expect(result.started).toBe(true);
  expect(result.status).toBe(1);
  expect(result.namedEncoding).toBe(true);
  expect(result.disclosedName).toBe(false);
});

it('CP-037/A9-leak-variants ignores changed bytes in a space-separated hex filename', () => {
  const result = checkFilename(`${bytePairs(changed).join(' ')}.txt`);
  expect(result.started).toBe(true);
  expect(result.status).toBe(0);
});

it('CP-037/A9-leak-variants ignores truncated bytes in a grouped hex filename', () => {
  const result = checkFilename(`${groupedHex(sentinel.subarray(0, -1))}.txt`);
  expect(result.started).toBe(true);
  expect(result.status).toBe(0);
});
