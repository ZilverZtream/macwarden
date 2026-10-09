import { childEnvironment } from './helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';

const repo = resolve();
const sentinel = readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
const testTmp = process.env.MACWARDEN_TEST_TMP;
if (!testTmp) throw new Error('MACWARDEN_TEST_TMP is required');

function leakStatus(contents: string): number | null {
  mkdirSync(testTmp!, { recursive: true });
  const dir = mkdtempSync(join(testTmp!, 'cp037-round11-leak-'));
  try {
    const capture = join(dir, 'capture.txt');
    writeFileSync(capture, contents);
    const run = spawnSync(process.execPath, [join(repo, 'scripts/leak-check.mjs'),
      '--sentinels', join(repo, 'test/sentinels.json'), capture], {
      cwd: repo, encoding: 'utf8', timeout: 15_000,
      env: childEnvironment({MACWARDEN_TEST_TMP: dir, MACWARDEN_SENTINEL_DIR: join(dir, 'registered')}),
    });
    expect(run.error).toBeUndefined();
    return run.status;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

function grouped(bytes: Buffer, widths: readonly number[], separator: string): string {
  const pairs = [...bytes].map(byte => byte.toString(16).padStart(2, '0'));
  const groups: string[] = [];
  for (let at = 0, group = 0; at < pairs.length; group++) {
    const width = widths[group % widths.length];
    groups.push(pairs.slice(at, at + width).join(''));
    at += width;
  }
  return groups.join(separator);
}

const separated = [
  { name: 'colon two-byte groups', widths: [2], separator: ':' },
  { name: 'colon four-byte groups', widths: [4], separator: ':' },
  { name: 'colon variable groups', widths: [2, 4], separator: ':' },
  { name: 'space variable groups', widths: [2, 4], separator: '  ' },
  { name: 'tab four-byte groups', widths: [4], separator: '\t' },
  { name: 'escaped tab variable groups', widths: [2, 4], separator: '\\t' },
  { name: 'escaped CRLF four-byte groups', widths: [4], separator: '\\r\\n' },
] as const;

for (const form of separated) for (const alignment of ['a', 'ab'] as const) {
  it(`CP-037/A9-leak-variants detects ${form.name} with ${alignment.length}-nibble neighbors`, () => {
    const encoded = grouped(sentinel, form.widths, form.separator);
    expect(leakStatus(encoded), 'unprefixed positive control').toBe(1);
    expect(leakStatus(`${alignment}${encoded}`), 'prefix positive control').toBe(1);
    expect(leakStatus(`${encoded}${alignment}`), 'suffix positive control').toBe(1);
    expect(leakStatus(`${alignment}${encoded}${alignment}`), 'prefix and suffix positive control').toBe(1);
  });
}

it('CP-037/A9-leak-variants ignores changed and truncated grouped bytes', () => {
  const changed = Buffer.from(sentinel);
  changed[0] ^= 1;
  changed[changed.length - 1] ^= 1;
  for (const form of separated) {
    expect(leakStatus(`a${grouped(changed, form.widths, form.separator)}b`), form.name).toBe(0);
    expect(leakStatus(`a${grouped(sentinel.subarray(0, -1), form.widths, form.separator)}b`),
      form.name).toBe(0);
  }
});

const envelope = (message: string) => ({ schema: 1 as const, command: 'inspect', ok: true,
  warnings: [], result: { message }, error: null });

function varint(value: number): Buffer {
  const digits: number[] = [];
  do {
    digits.push((value & 127) | (value >= 128 ? 128 : 0));
    value = Math.floor(value / 128);
  } while (value);
  return Buffer.from(digits);
}

function packet(kind: number, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([kind]), varint(data.length), data]);
}

function nestedInvalid(count: number): Buffer {
  const signature = Buffer.concat([Buffer.from([0, 0, 6, 32]), Buffer.alloc(32)]);
  let bytes = Buffer.concat([Buffer.from([2, 2, 3, 3, 34, 0]), signature]);
  for (let index = 0; index < count; index++) {
    const id = Buffer.concat([Buffer.from([3, 34]), varint(bytes.length), bytes]);
    bytes = Buffer.concat([Buffer.from([2]), packet(2, id), signature]);
  }
  return bytes;
}

it('CP-037/A10-bounded-adversarial bounds renderer copying on nested invalid identifiers', async () => {
  const { render } = await import('./helpers/render-adversarial.js');
  const marker = 'ordinary-round11-marker';
  const template = render(envelope(marker), 'text');
  expect(template.split(marker)).toHaveLength(2);
  for (const count of [40, 80, 160, 320]) {
    const ordinary = `safe-left ${nestedInvalid(count).toString('hex')} safe-right`;
    let copied = 0;
    const original = Buffer.concat;
    const spy = vi.spyOn(Buffer, 'concat').mockImplementation(((parts: readonly Uint8Array[], length?: number) => {
      copied += parts.reduce((sum, part) => sum + part.byteLength, 0);
      return Reflect.apply(original, Buffer, [parts, length]);
    }) as typeof Buffer.concat);
    let json: string, text: string;
    try {
      json = render(envelope(ordinary), 'json');
      text = render(envelope(ordinary), 'text');
    } finally { spy.mockRestore(); }
    expect((JSON.parse(json) as ReturnType<typeof envelope>).result?.message).toBe(ordinary);
    expect(text).toBe(template.replace(marker, ordinary));
    expect(copied, `linear copy budget for count ${count}`).toBeLessThanOrEqual(ordinary.length * 24);
  }
});

it('CP-037/A10-bounded-adversarial still protects a later committed credential', async () => {
  const { render } = await import('./helpers/render-adversarial.js');
  const ordinary = nestedInvalid(160).toString('hex');
  const credential = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon')).toString('hex');
  for (const mode of ['text', 'json'] as const) {
    const separate = render(envelope(`safe-left ${ordinary} ${credential} safe-right`), mode);
    const expected = `safe-left ${ordinary} [redacted] safe-right`;
    if (mode === 'json') expect((JSON.parse(separate) as ReturnType<typeof envelope>).result?.message).toBe(expected);
    else expect(separate).toBe(render(envelope(expected), 'text'));
    const adjacent = render(envelope(`safe-left ${ordinary}${credential} safe-right`), mode);
    expect(adjacent.includes(credential)).toBe(false);
    expect(adjacent.includes(credential.slice(-24))).toBe(false);
    expect(adjacent).toContain('[redacted]');
  }
});

const symbolFixture = vi.hoisted(() => {
  let getterCalls = 0;
  const hidden = Symbol('hidden');
  const value = { [hidden]: Buffer.from([1, 2, 3]), message: 'safe' };
  const getter = Object.defineProperty({ message: 'safe' }, 'secret', {
    enumerable: true, get() { getterCalls++; return Buffer.from([1, 2, 3]); },
  });
  return { value, getter, get calls() { return getterCalls; }, reset() { getterCalls = 0; } };
});

vi.mock('../src/commands/handlers.js', () => ({ handlers: {
  symbolpoison: async () => ({ code: 0, warnings: [], result: { nested: symbolFixture.value } }),
} }));

import { main } from '../src/cli.js';

for (const mode of ['text', 'json'] as const) {
  it(`CP-037/A9-nonplain-output rejects nested symbol values in ${mode}`, async () => {
    const { render } = await import('./helpers/render-adversarial.js');
    const doc = (value: unknown) => ({ schema: 1 as const, command: 'symbolpoison', ok: true,
      warnings: [], result: { nested: value }, error: null });
    expect(() => render(doc(symbolFixture.value), mode)).toThrow();
    const plain = doc({ message: 'safe' });
    if (mode === 'json') expect(JSON.parse(render(plain, mode))).toEqual(plain);
    else expect(render(plain, mode)).toContain('safe');
  });

  it(`CP-037/A9-nonplain-output rejects an accessor without calling it in ${mode}`, async () => {
    const { render } = await import('./helpers/render-adversarial.js');
    symbolFixture.reset();
    const doc = { schema: 1 as const, command: 'symbolpoison', ok: true, warnings: [],
      result: { nested: symbolFixture.getter }, error: null };
    let rejected = false;
    try { render(doc, mode); }
    catch { rejected = true; }
    expect(symbolFixture.calls).toBe(0);
    expect(rejected).toBe(true);
  });

  it(`CP-037/A9-nonplain-output maps hidden symbol bytes to exit 8 in ${mode}`, async () => {
    const observed = await captureMain(main, ['symbolpoison', ...(mode === 'json' ? ['--json'] : [])]);
    expect(observed.code).toBe(8);
    expect(observed.exitCalls).toBe(0);
    if (mode === 'json') {
      expect(observed.stderr).toBe('');
      expect(JSON.parse(observed.stdout)).toEqual({ schema: 1, command: 'symbolpoison', ok: false,
        warnings: [], result: null,
        error: { code: 8, step: 'internal', message: expect.any(String) } });
      expect(observed.stdout).not.toContain('1,2,3');
    } else {
      expect(observed.stdout).toBe('');
      expect(observed.stderr).toMatch(/^error: internal[^\r\n]*\r?\n$/);
      expect(observed.stderr).not.toContain('1,2,3');
    }
  });
}
