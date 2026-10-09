import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

const repo = resolve();
const sentinelPath = join(repo, 'test/sentinels/sentinel.macaroon');
const sentinelList = join(repo, 'test/sentinels.json');
const base = process.env.MACWARDEN_TEST_TMP;
if (!base) throw new Error('MACWARDEN_TEST_TMP is required for CP-037 leak controls');

function check(data: string | Buffer): { status: number | null; stderr: string } {
  mkdirSync(base!, { recursive: true });
  const dir = mkdtempSync(join(base!, 'cp037-leak-'));
  try {
    const path = join(dir, 'capture.txt');
    writeFileSync(path, data);
    const run = spawnSync(process.execPath,
      [join(repo, 'scripts/leak-check.mjs'), '--sentinels', sentinelList, path],
      { cwd: repo, env: childEnvironment({ MACWARDEN_TEST_TMP: dir  }),
        input: undefined, encoding: 'utf8', timeout: 15_000 });
    return { status: run.status, stderr: run.stderr };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const bytes = readFileSync(sentinelPath);
  const percentEncodedBytes = (value: Buffer) => [...value]
    .map(byte => `%${byte.toString(16).padStart(2, '0')}`).join('');
  const hex = bytes.toString('hex');
  const base64 = bytes.toString('base64');
  const variants: [string, string | Buffer][] = [
    ['decimal byte array', JSON.stringify([...bytes])],
    ['mixed-case hex', [...hex].map((ch, i) => i % 2 ? ch.toUpperCase() : ch).join('')],
    ['space-separated hex', hex.match(/.{2}/g)!.join(' ')],
    ['percent-encoded hex', [...hex].map(ch => `%${ch.charCodeAt(0).toString(16)}`).join('')],
    ['percent-encoded base64', [...base64].map(ch => `%${ch.charCodeAt(0).toString(16)}`).join('')],
    ['percent-encoded raw bytes', percentEncodedBytes(bytes)],
    ['wrapped hex', hex.match(/.{1,64}/g)!.join('\n')],
    ['wrapped base64', base64.match(/.{1,64}/g)!.join('\n')],
    ['offset base64', Buffer.concat([Buffer.from([0x51]), bytes]).toString('base64')],
    ['backslash-x bytes', [...bytes].map(byte => `\\x${byte.toString(16).padStart(2, '0')}`).join('')],
    ['UTF-16LE', Buffer.from(bytes.toString('latin1'), 'utf16le')],
    ['UTF-16BE', Buffer.from(bytes.toString('latin1'), 'utf16le').swap16()],
  ];
for (const [name, data] of variants) {
  it(`CP-037/A9-leak-variants detects ${name} in a temporary file`, () => {
    const run = check(data);
    expect(run.status, name).toBe(1);
    expect(run.stderr, name).toMatch(/capture\.txt.*(array|hex|percent|base64|escaped|utf-16)/i);
    expect(run.stderr, name).not.toContain(hex);
    expect(run.stderr, name).not.toContain(base64);
  });
}

it('CP-037/A9-leak-variants permits percent-encoded raw bytes after one byte changes', () => {
  const changed = Buffer.from(bytes);
  changed[changed.length - 1] ^= 1;
  expect(check(percentEncodedBytes(changed)).status).toBe(0);
});

it('CP-037/leak-check benign neighboring data passes and output API detects the same forms', async () => {
  const bytes = readFileSync(sentinelPath);
  const { findLeaks } = await import("../helpers/leak-check.js");
  const changed = Buffer.from(bytes);
  changed[changed.length - 1] ^= 1;
  expect(check('ordinary café 1234').status).toBe(0);
  expect(check(changed.toString('hex')).status).toBe(0);
  const percent = [...bytes.toString('base64')].map(ch => `%${ch.charCodeAt(0).toString(16)}`).join('');
  const hit = findLeaks({ sentinels: sentinelList, commandOutput: `safeA${percent}Bsafe`, root: repo });
  expect(hit?.path).toBe('command output');
  expect(hit?.encoding).toMatch(/percent/i);
  expect(findLeaks({ sentinels: sentinelList, commandOutput: 'ordinary café 1234', root: repo })).toBeNull();
});
