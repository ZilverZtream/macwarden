// attenuate refuses an input whose caveats, with the requested ones, pass the decoder's reported
// caveat bound (pre-1.4 audit): exit 3 before anything is written, never exit 8 "internal".
import { createHmac } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it } from 'vitest';
import { run as attenuate } from '../src/commands/attenuate.js';
import { expectSchemaValid } from './helpers/output-schema.js';

const tmp = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');
const deps = () => ({ stdin: Object.assign(Readable.from([]), { isTTY: true }), fs, env: {},
  clock: () => new Date('2026-10-05T09:00:00.000Z') });

async function scratch<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(tmp, { recursive: true });
  const dir = mkdtempSync(join(tmp, 'mutate-audit-attenuate-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

// Synthetic macaroon v2 (go-macaroon layout) with `count` first-party caveats, from a synthetic root key.
const varint = (value: number) => {
  const bytes: number[] = [];
  do { bytes.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value);
  return Buffer.from(bytes);
};
const field = (kind: number, bytes: Buffer) => Buffer.concat([varint(kind), varint(bytes.length), bytes]);
const proto = (kind: number, bytes: Buffer) => field(kind * 8 + 2, bytes);
const hmac = (key: Buffer, data: Buffer) => createHmac('sha256', key).update(data).digest();
function synthetic(count: number): Buffer {
  const op = proto(3, Buffer.concat([proto(1, Buffer.from('info')), proto(2, Buffer.from('read'))]));
  const identifier = Buffer.concat([Buffer.from([3]), proto(1, Buffer.alloc(16, 7)), proto(2, Buffer.from('4242')), op]);
  let signature = hmac(hmac(Buffer.from('macaroons-key-generator'), Buffer.alloc(32, 0x5a)), identifier);
  const caveats: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    const condition = Buffer.from('ipaddr 127.0.0.1');
    caveats.push(field(2, condition), Buffer.from([0]));
    signature = hmac(signature, condition);
  }
  return Buffer.concat([Buffer.from([2]), field(1, Buffer.from('lnd')), field(2, identifier), Buffer.from([0]),
    ...caveats, Buffer.from([0]), field(6, signature)]);
}

const refused: Array<[number, string[]]> = [
  [4096, ['--expires', '1d']],
  [4095, ['--expires', '1d', '--ip', '127.0.0.1']],
  [5000, ['--expires', '1d']],
  [4096, ['--expires', '1d', '--dry-run']],
];
for (const [count, flags] of refused) {
  it(`attenuate refuses with exit 3 an input with ${count} caveats plus ${flags.filter(flag => flag.startsWith('--') && flag !== '--dry-run').length} requested${flags.includes('--dry-run') ? ' (dry run)' : ''}`,
    async () => scratch(async dir => {
      const input = join(dir, 'in.macaroon'), out = join(dir, 'out.macaroon');
      writeFileSync(input, synthetic(count));
      const result = await attenuate([input, '--out', out, ...flags], deps());
      expectSchemaValid(result);
      expect(result).toMatchObject({ ok: false, result: null, error: { code: 3, step: 'A4' } });
      expect(result.error!.message).toContain('too many caveats');
      expect(existsSync(out)).toBe(false);
    }));
}

it('attenuate still accepts an input whose result reaches exactly the caveat bound', async () => scratch(async dir => {
  const input = join(dir, 'in.macaroon'), out = join(dir, 'out.macaroon');
  writeFileSync(input, synthetic(4095));
  const result = await attenuate([input, '--out', out, '--expires', '1d'], deps());
  expectSchemaValid(result);
  expect(result.error).toBeNull();
  expect(existsSync(out)).toBe(true);
}));
