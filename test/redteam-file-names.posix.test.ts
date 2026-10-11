import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { run as scanCommand } from '../src/commands/scan.js';
import { render } from '../src/output/index.js';

// POSIX variant (scripts/platform-variants.mjs) of RED-TEAM/forging in test/redteam-files.test.ts:
// real scanned files whose names start a GitHub workflow command or carry a bidi override.
// Windows file names cannot contain ':' or these controls; the renderer check runs everywhere.
function varint(n: number): Buffer { const b: number[] = []; do { let d = n % 128; n = Math.floor(n / 128); if (n) d |= 0x80; b.push(d); } while (n); return Buffer.from(b); }
const packet = (kind: number, value: Buffer) => Buffer.concat([Buffer.from([kind]), varint(value.length), value]);
const field = (number: number, value: Buffer) => Buffer.concat([varint(number << 3 | 2), varint(value.length), value]);
const operation = (entity: string, actions: string[]) =>
  field(3, Buffer.concat([field(1, Buffer.from(entity)), ...actions.map(action => field(2, Buffer.from(action)))]));
// Structurally valid LND-style macaroon v2 bytes with a random signature: synthetic, never a real credential.
function macaroon(operations: Buffer[]): Buffer {
  const identifier = Buffer.concat([Buffer.from([3]), field(1, randomBytes(16)), field(2, Buffer.from('0')), ...operations]);
  return Buffer.concat([Buffer.from([2]), packet(1, Buffer.from('lnd')), packet(2, identifier), Buffer.from([0]), Buffer.from([0]),
    packet(6, randomBytes(32))]);
}

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

it('RED-TEAM/forging-posix a file name cannot start a text line with a GitHub workflow command or reorder the terminal', async () => {
  const dir = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP!, 'mw-redteam-names-'));
  dirs.push(dir);
  const admin = macaroon([operation('info', ['read'])]).toString('hex');
  writeFileSync(join(dir, '::stop-commands::x'), `${admin}\n`);
  writeFileSync(join(dir, 'safe‮gnp.txt'), `${admin}\n`);
  const result = await scanCommand([dir]);
  const text = render(result, 'text');
  for (const line of text.split('\n')) expect(line.startsWith('::')).toBe(false);
  expect(text).not.toContain('‮');
  expect(text).toContain('\\u202e');
});
