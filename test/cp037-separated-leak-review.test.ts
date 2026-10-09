import { childEnvironment } from './helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

const repo = resolve();
const sentinel = readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
const sentinelList = join(repo, 'test/sentinels.json');
const testTmp = process.env.MACWARDEN_TEST_TMP;
if (!testTmp) throw new Error('MACWARDEN_TEST_TMP is required for CP-037 leak controls');

function runLeakCheck(data: string, fileName = 'capture.txt'): { status: number | null; location: boolean; encoding: boolean } {
  mkdirSync(testTmp!, { recursive: true });
  const dir = mkdtempSync(join(testTmp!, 'cp037-separated-leak-'));
  try {
    const capture = join(dir, fileName);
    const sentinelDir = join(dir, 'sentinels');
    mkdirSync(sentinelDir);
    writeFileSync(capture, data);
    const run = spawnSync(process.execPath,
      [join(repo, 'scripts/leak-check.mjs'), '--sentinels', sentinelList, capture],
      { cwd: repo, env: childEnvironment({MACWARDEN_TEST_TMP: dir, MACWARDEN_SENTINEL_DIR: sentinelDir}), encoding: 'utf8', timeout: 15_000 });
    return {
      status: run.status,
      location: run.stderr.includes(fileName),
      encoding: /hex/i.test(run.stderr),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function pairs(bytes: Buffer): string[] {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0'));
}

function mixedCase(pairList: string[]): string[] {
  let letter = 0;
  return pairList.map(pair => pair.replace(/[a-f]/g, char =>
    letter++ % 2 === 0 ? char.toUpperCase() : char));
}

function groupedHex(bytes: Buffer, groupWidths: readonly number[], separator: string): string {
  const bytePairs = pairs(bytes);
  const groups: string[] = [];
  for (let index = 0, group = 0; index < bytePairs.length; group++) {
    const width = groupWidths[group % groupWidths.length];
    groups.push(bytePairs.slice(index, index + width).join(''));
    index += width;
  }
  return groups.join(separator);
}

const changed = Buffer.from(sentinel);
changed[0] ^= 1;
changed[changed.length - 1] ^= 1;

const forms: Array<{ name: string; encode: (bytes: Buffer) => string }> = [
  { name: 'single-space hex', encode: bytes => pairs(bytes).join(' ') },
  { name: 'double-space hex', encode: bytes => pairs(bytes).join('  ') },
  { name: 'tab-separated hex', encode: bytes => pairs(bytes).join('\t') },
  { name: 'CR-separated hex', encode: bytes => pairs(bytes).join('\r') },
  { name: 'LF-separated hex', encode: bytes => pairs(bytes).join('\n') },
  { name: 'CRLF-separated hex', encode: bytes => pairs(bytes).join('\r\n') },
  { name: 'colon-separated hex', encode: bytes => pairs(bytes).join(':') },
  { name: 'uppercase colon-separated hex', encode: bytes => pairs(bytes).map(pair => pair.toUpperCase()).join(':') },
  { name: 'mixed-case double-space hex', encode: bytes => mixedCase(pairs(bytes)).join('  ') },
  { name: 'JSON-escaped tabs', encode: bytes => JSON.stringify(pairs(bytes).join('\t')) },
  { name: 'JSON-escaped CRLF', encode: bytes => JSON.stringify(pairs(bytes).join('\r\n')) },
];

for (const { name, encode } of forms) {
  it(`CP-037/A9-leak-variants detects ${name} through the public CLI`, () => {
    const result = runLeakCheck(encode(sentinel));
    expect(result.status, name).toBe(1);
    expect(result.location, name).toBe(true);
    expect(result.encoding, name).toBe(true);
  });

  it(`CP-037/A9-leak-variants ignores mutated bytes in ${name}`, () => {
    expect(runLeakCheck(encode(changed)).status, name).toBe(0);
  });
}

it('CP-037/A9-leak-variants ignores long credential-free separated text', () => {
  const benign = 'ordinary cafe text: 01  02\t03\r\n04:05 and {"value":"06\\t07"}\n';
  expect(runLeakCheck(benign.repeat(1_024)).status).toBe(0);
});

const groupedForms: Array<{ name: string; fileName: string; encode: (bytes: Buffer) => string }> = [
  { name: 'two-byte colon groups in command output', fileName: 'command-output.txt',
    encode: bytes => groupedHex(bytes, [2], ':') },
  { name: 'four-byte colon groups in temporary output', fileName: 'temporary-output.txt',
    encode: bytes => groupedHex(bytes, [4], ':') },
  { name: 'alternating two- and four-byte colon groups in evidence', fileName: 'evidence.txt',
    encode: bytes => groupedHex(bytes, [2, 4], ':') },
  { name: 'two-byte whitespace groups in temporary output', fileName: 'temporary-output.txt',
    encode: bytes => groupedHex(bytes, [2], '  ') },
  { name: 'four-byte JSON-escaped tab groups in command output', fileName: 'command-output.txt',
    encode: bytes => JSON.stringify(groupedHex(bytes, [4], '\t')) },
  { name: 'alternating two- and four-byte JSON-escaped CRLF groups in evidence', fileName: 'evidence.txt',
    encode: bytes => JSON.stringify(groupedHex(bytes, [2, 4], '\r\n')) },
];

for (const { name, fileName, encode } of groupedForms) {
  it(`CP-037/A9-leak-variants detects ${name} through the public CLI`, () => {
    const result = runLeakCheck(encode(sentinel), fileName);
    expect(result.status, name).toBe(1);
    expect(result.location, name).toBe(true);
    expect(result.encoding, name).toBe(true);
  });

  it(`CP-037/A9-leak-variants ignores mutated bytes in ${name}`, () => {
    expect(runLeakCheck(encode(changed), fileName).status, name).toBe(0);
  });
}
