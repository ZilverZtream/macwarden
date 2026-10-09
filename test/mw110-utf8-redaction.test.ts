// MW110-08: SAFE-01 covers a credential's raw bytes rendered as UTF-8. Buffer.toString('utf8')
// replaces every ill-formed sequence with U+FFFD, so the rendering of a binary credential is
// lossy; output filtering must still recognise it, in linear time.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { redactEncodedCredentials } from '../src/credential-recognition.js';
import { addFirstPartyCaveat } from '../src/decode/index.js';
import { Secret } from '../src/secret.js';
import { captureMain } from './support/capture.js';
import { revealSecret } from './helpers/secret-bytes.js';

const repo = resolve();
const vectors = join(repo, 'test/vectors');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as { vectors: { name: string; file: string }[] };
const committed = manifest.vectors.map(entry => ({ name: entry.name, bytes: readFileSync(join(vectors, entry.file)) }));
const admin = readFileSync(join(vectors, 'default-admin.macaroon'));

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'mw110-08-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

it('MW110-08 the committed vectors are binary: their UTF-8 rendering is lossy', () => {
  expect(committed.length).toBeGreaterThan(3);
  for (const { name, bytes } of committed)
    expect(Buffer.from(bytes.toString('utf8'), 'utf8').equals(bytes), name).toBe(false);
});

it('MW110-08 inspect --json redacts a caveat embedding the lossy UTF-8 rendering of a committed vector', async () => temp(async dir => {
  const lossy = admin.toString('utf8');
  expect(lossy).toContain('�');
  const child = revealSecret(addFirstPartyCaveat(new Secret(admin), `note ${lossy} end`));
  const path = join(dir, 'child.macaroon');
  writeFileSync(path, child);
  const run = await captureMain(main, ['inspect', path, '--json']);
  expect(run.code).toBe(0);
  const output = JSON.parse(run.stdout) as { result: { caveats: { value: string }[] } };
  const values = output.result.caveats.map(caveat => caveat.value);
  expect(values.some(value => value.includes(lossy))).toBe(false);
  expect(values.some(value => value.startsWith('note [redacted]') && value.endsWith(' end'))).toBe(true);
  // The text rendering too.
  const text = await captureMain(main, ['inspect', path]);
  expect(text.code).toBe(0);
  expect(text.stdout).toContain('note [redacted]');
}));

it('MW110-08 recognises the lossy UTF-8 rendering of every committed vector, keeping the text around it', () => {
  for (const { name, bytes } of committed) {
    const lossy = bytes.toString('utf8');
    const prefix = 'before: ';
    const suffix = ` :after${'.'.repeat(64)}`;
    const output = redactEncodedCredentials(prefix + lossy + suffix);
    expect(output.includes(lossy), name).toBe(false);
    expect(output.startsWith(`${prefix}[redacted]`), name).toBe(true);
    // At most the 32 characters a lossy signature can stand for are consumed after it.
    expect(output.endsWith('.'.repeat(32)), name).toBe(true);
    // Also alone, after JSON escaping, and inside the rendering of other bytes.
    expect(redactEncodedCredentials(lossy).startsWith('[redacted]'), name).toBe(true);
    expect(redactEncodedCredentials(JSON.stringify(lossy)).includes(lossy), name).toBe(false);
    const embedded = Buffer.concat([Buffer.from([0xe2, 0x82]), bytes, Buffer.from([0xac, 0xff])]).toString('utf8');
    const redacted = redactEncodedCredentials(embedded);
    expect(redacted, name).toContain('[redacted]');
    expect(redacted.replace('[redacted]', '').length, name).toBeLessThanOrEqual(4);
  }
});

it('MW110-08 recognises a lossless UTF-8 rendering with multi-byte characters', () => {
  // The decoder does not verify the signature: a signature of valid UTF-8 renders losslessly.
  const signature = Buffer.from(`${'€'.repeat(10)}ab`, 'utf8');
  expect(signature).toHaveLength(32);
  const bytes = Buffer.concat([admin.subarray(0, admin.length - 32), signature]);
  const header = admin.subarray(0, admin.length - 32);
  // Only the identifier's nonce is binary; the signature's characters are above U+00FF.
  const rendered = Buffer.concat([header, signature]).toString('utf8');
  expect(rendered.endsWith('€'.repeat(10) + 'ab')).toBe(true);
  expect(redactEncodedCredentials(`x ${rendered} y`)).toBe('x [redacted] y');
  expect(bytes).toHaveLength(admin.length);
});

it('MW110-08 ordinary text with replacement characters is left alone', () => {
  for (const text of ['caf� au lait', '�'.repeat(100), `\u0002\u0002 no signature ${'�'.repeat(40)}`,
    `\u0000\u0006 ${'�'.repeat(40)} before any start`, 'ordinary € text \u0002\u0001x\u0000\u0006 short'])
    expect(redactEncodedCredentials(text)).toBe(text);
});

it('MW110-08 recognition of lossy renderings stays linear', () => {
  const lossy = admin.toString('utf8');
  const unit = `\u0002\u0002�\u0000\u0006 ${'�'.repeat(10)}é`;
  const timings: number[] = [];
  for (const size of [250_000, 1_000_000]) {
    const text = (unit.repeat(Math.ceil(size / unit.length)) + lossy).slice(-size - lossy.length);
    const started = performance.now();
    const output = redactEncodedCredentials(text);
    timings.push(performance.now() - started);
    expect(output.includes(lossy)).toBe(false);
  }
  console.log(`MW110-08 recognition ms [250 K, 1 M chars]: ${timings.map(Math.round).join(', ')}`);
  expect(timings[1]).toBeLessThan(10_000);
  expect(timings[1]).toBeLessThan(8 * Math.max(timings[0], 25));
}, 60_000);
