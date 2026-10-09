import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';

const repo = resolve();
const vector = (name: string) => readFileSync(join(repo, 'test/vectors', name));
const sentinel = () => readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
const envelope = (message: string) => ({ schema: 1 as const, command: 'inspect', ok: true,
  warnings: [], result: { message }, error: null });

function assertEncodedSpan(encoded: string, bytes: Buffer): void {
  expect(Buffer.from(encoded, 'base64').equals(bytes),
    'base64 source span independently decodes to both complete fixtures').toBe(true);
}

function assertSafeRender(actual: string, expectedMessage: string, mode: 'text' | 'json',
  representation: string): void {
  const tail = representation.slice(-24);
  expect(actual.includes(representation), 'full encoded source span is absent').toBe(false);
  expect(actual.includes(tail), 'final encoded signature suffix is absent').toBe(false);
  if (mode === 'json') {
    const parsed = JSON.parse(actual) as ReturnType<typeof envelope>;
    expect(parsed.result?.message === expectedMessage, 'exact JSON safe context').toBe(true);
  } else {
    // Comparing booleans keeps credential-bearing output out of assertion diffs.
    expect(actual === expectedMessage, 'exact text safe context').toBe(true);
  }
}

for (const order of ['forward', 'reverse', 'offset'] as const) {
  for (const mode of ['text', 'json'] as const) {
    it(`CP-037/A10-wrapped-backstop redacts adjacent base64 source spans ${order} in ${mode}`, async () => {
      const noLocation = vector('no-location.macaroon');
      const readonly = vector('default-readonly.macaroon');
      const joined = order === 'reverse'
        ? Buffer.concat([readonly, noLocation])
        : Buffer.concat([...(order === 'offset' ? [Buffer.from([0x51])] : []), noLocation, readonly]);
      const representation = joined.toString('base64');
      assertEncodedSpan(representation, joined);
      expect(joined.includes(noLocation) && joined.includes(readonly),
        'both committed credentials occupy the same source span').toBe(true);

      const { render } = await import('./helpers/render-adversarial.js');
      const safeMessage = 'safe-left [redacted] safe-right';
      const actual = render(envelope(`safe-left ${representation} safe-right`), mode);
      const expectedText = mode === 'text' ? render(envelope(safeMessage), mode) : safeMessage;
      assertSafeRender(actual, expectedText, mode, representation);
    });
  }
}

function packet(kind: number, data: Buffer): Buffer {
  const length: number[] = [];
  let remaining = data.length;
  do {
    length.push((remaining & 127) | (remaining >= 128 ? 128 : 0));
    remaining = Math.floor(remaining / 128);
  } while (remaining);
  return Buffer.concat([Buffer.from([kind, ...length]), data]);
}

function withLocation(location: string): Buffer {
  const base = vector('default-readonly.macaroon');
  if (base[0] !== 2 || base[1] !== 1) throw new Error('unexpected committed vector layout');
  let at = 2, size = 0, scale = 1, digit: number;
  do { digit = base[at++]; size += (digit & 127) * scale; scale *= 128; } while (digit & 128);
  if (at + size >= base.length || base[at + size] !== 2)
    throw new Error('unexpected committed location packet');
  return Buffer.concat([base.subarray(0, 1), packet(1, Buffer.from(location, 'utf8')),
    base.subarray(at + size)]);
}

function inspect(input: Buffer, mode: 'text' | 'json') {
  const run = spawnSync(process.execPath,
    [join(repo, 'dist/bin.js'), 'inspect', '-', ...(mode === 'json' ? ['--json'] : [])],
    { cwd: repo, input, encoding: 'utf8', timeout: 15_000, maxBuffer: 2_000_000 });
  return { status: run.status, stdout: run.stdout || '', stderr: run.stderr || '',
    error: run.error };
}

function assertSeparatedHex(representation: string, separator: string, bytes: Buffer): void {
  expect(representation.split(separator).join('') === bytes.toString('hex'),
    'separated source reconstructs the complete registered sentinel').toBe(true);
  expect(Buffer.from(representation.split(separator).join(''), 'hex').equals(bytes),
    'independent hex decoding recovers the complete registered sentinel').toBe(true);
}

for (const [name, separator] of [
  ['single spaces', ' '], ['multiple spaces', '  '], ['tabs', '\t'],
  ['CR/LF', '\r\n'], ['colons', ':'],
] as const) {
  for (const mode of ['text', 'json'] as const) {
    it(`CP-037/A10-wrapped-backstop inspect redacts sentinel hex separated by ${name} in ${mode}`, () => {
      const bytes = sentinel();
      const representation = bytes.toString('hex').match(/.{2}/g)!.join(separator);
      assertSeparatedHex(representation, separator, bytes);
      const run = inspect(withLocation(`safe-left ${representation} safe-right`), mode);
      expect(run.error === undefined, 'inspect completes within 15 seconds').toBe(true);
      expect(run.status === 0, 'synthetic inspect succeeds').toBe(true);
      expect(run.stderr === '', 'inspect stderr remains empty').toBe(true);
      expect(run.stdout.includes(representation), 'complete separated credential is absent').toBe(false);
      expect(run.stdout.includes(representation.slice(-24)),
        'separated signature suffix is absent').toBe(false);
      expect(run.stdout.includes(bytes.toString('hex').slice(-24)),
        'contiguous signature suffix is absent').toBe(false);
      if (mode === 'json') {
        const doc = JSON.parse(run.stdout) as { ok: boolean; result?: { location?: string } };
        expect(doc.ok === true, 'one JSON success document').toBe(true);
        expect(doc.result?.location === 'safe-left [redacted] safe-right',
          'exact JSON safe neighbors').toBe(true);
      } else {
        expect(run.stdout.includes('safe-left [redacted] safe-right'),
          'text keeps safe neighbors').toBe(true);
      }
    }, 20_000);
  }
}

it('CP-037/A10-wrapped-backstop inspect preserves ordinary separated text controls', () => {
  for (const ordinary of ['safe-left 02 01 03 safe-right',
    'safe-left 02\t01\t03 safe-right', 'safe-left 02:01:03 safe-right',
    'safe-left 02\r\n01 safe-right']) {
    for (const mode of ['text', 'json'] as const) {
      const run = inspect(withLocation(ordinary), mode);
      expect(run.error === undefined && run.status === 0, 'ordinary inspect succeeds').toBe(true);
      expect(run.stderr === '', 'ordinary inspect stderr').toBe(true);
      if (mode === 'json') {
        const doc = JSON.parse(run.stdout) as { ok: boolean; result?: { location?: string } };
        expect(doc.ok === true && doc.result?.location === ordinary,
          'exact ordinary JSON location').toBe(true);
      } else {
        const escaped = ordinary.replace(/\r/g, '\\x0d').replace(/\n/g, '\\x0a')
          .replace(/\t/g, '\\x09');
        expect(run.stdout.includes(escaped), 'ordinary text and escapes remain intact').toBe(true);
      }
    }
  }
}, 35_000);

it('CP-037/A10-bounded-adversarial limits separated near-match decode work and inspect time', async () => {
  const { render } = await import('./helpers/render-adversarial.js');
  for (const size of [8192, 16384, 32768]) {
    const ordinary = '02:01:00:ff:'.repeat(Math.floor(size / 12));
    let decodedCharacters = 0;
    const original = Buffer.from;
    const spy = vi.spyOn(Buffer, 'from').mockImplementation(((value: unknown, ...args: unknown[]) => {
      if (typeof value === 'string') decodedCharacters += value.length;
      return Reflect.apply(original, Buffer, [value, ...args]);
    }) as typeof Buffer.from);
    let actual: string;
    try { actual = render(envelope(ordinary), 'json'); }
    finally { spy.mockRestore(); }
    const parsed = JSON.parse(actual) as ReturnType<typeof envelope>;
    expect(parsed.result?.message === ordinary, 'near-match ordinary text is unchanged').toBe(true);
    expect(decodedCharacters <= ordinary.length * 12,
      'separated recognition uses a linear decode budget').toBe(true);
  }

  const bytes = sentinel();
  const representation = bytes.toString('hex').match(/.{2}/g)!.join('\t');
  assertSeparatedHex(representation, '\t', bytes);
  const input = withLocation(`${'02:01:00:ff:'.repeat(2730)}safe-left ${representation} safe-right`);
  for (const mode of ['text', 'json'] as const) {
    const started = performance.now();
    const run = inspect(input, mode);
    expect(run.error === undefined && performance.now() - started < 15_000,
      '32 KiB offline inspect bound').toBe(true);
    expect(run.status === 0, 'adversarial inspect succeeds').toBe(true);
    expect(run.stdout.includes(representation.slice(-24)),
      'adversarial inspect hides the signature suffix').toBe(false);
  }
}, 35_000);
