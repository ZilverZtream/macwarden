import { spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';

const repo = resolve();
const vectorPath = join(repo, 'test/vectors/no-location.macaroon');
const sentinelPath = join(repo, 'test/sentinels/sentinel.macaroon');
const noLocationFingerprint = 'fp:034ad6d9996d9ff5';
const envelope = (message: string) => ({ schema: 1 as const, command: 'inspect', ok: true,
  warnings: [], result: { message }, error: null });

function registeredCredential(path: string): Buffer {
  const bytes = readFileSync(path);
  if (path === vectorPath) {
    const actual = `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
    expect(actual === noLocationFingerprint, 'committed no-location reference fingerprint').toBe(true);
  }
  return bytes;
}

function noCredential(output: string, bytes: Buffer, representation: string): void {
  const hex = bytes.toString('hex');
  const base64 = bytes.toString('base64');
  for (const encoded of [hex, base64, representation]) {
    expect(output.includes(encoded), 'complete credential representation must be absent').toBe(false);
  }
  // A wrapped representation may leave a signature tail even when its first line is hidden.
  const lastLine = representation.split(/\r?\n/).at(-1) ?? '';
  const signatureTail = lastLine.slice(-Math.min(24, lastLine.length));
  expect(output.includes(signatureTail), 'signature tail must be absent').toBe(false);
}

async function assertExactRedaction(bytes: Buffer, representation: string, prefix: string,
  mode: 'text' | 'json'): Promise<void> {
  const { render } = await import('./helpers/render-adversarial.js');
  const suffix = ' right Ω';
  const message = `café left ${prefix}${representation}${suffix}`;
  const expected = `café left ${prefix}[redacted]${suffix}`;
  const label = `${representation.includes('\n') ? 'wrapped' : representation.includes('%') ? 'percent' : 'contiguous'} prefix=${prefix.length}`;
  const actual = render(envelope(message), mode);
  noCredential(actual, bytes, representation);
  if (mode === 'json') {
    const parsed = JSON.parse(actual) as ReturnType<typeof envelope>;
    expect(parsed.result?.message === expected, `${label} exact JSON safe context`).toBe(true);
  } else {
    expect(actual === render(envelope(expected), mode), `${label} exact text safe context`).toBe(true);
  }
}

it('CP-037/A10-wrapped-backstop keeps zero/two-character hex alignment and benign neighbors', async () => {
  const bytes = registeredCredential(vectorPath);
  const hex = bytes.toString('hex');
  for (const representation of [hex, hex.match(/.{1,64}/g)!.join('\n')]) {
    for (const prefix of ['', 'ab']) for (const mode of ['text', 'json'] as const) {
      await assertExactRedaction(bytes, representation, prefix, mode);
    }
  }
});

for (const mode of ['text', 'json'] as const) {
  for (const form of ['contiguous', 'wrapped'] as const) {
    it(`CP-037/A10-wrapped-backstop redacts no-location ${form} hex at odd alignment in ${mode}`, async () => {
      const bytes = registeredCredential(vectorPath);
      const hex = bytes.toString('hex');
      const representation = form === 'wrapped' ? hex.match(/.{1,64}/g)!.join('\n') : hex;
      await assertExactRedaction(bytes, representation, 'a', mode);
    });
  }
  it(`CP-037/A10-wrapped-backstop redacts registered sentinel wrapped hex after one benign hex character in ${mode}`, async () => {
    const bytes = registeredCredential(sentinelPath);
    const wrapped = bytes.toString('hex').match(/.{1,64}/g)!.join('\n');
    await assertExactRedaction(bytes, wrapped, 'a', mode);
  });
  it(`CP-037/A10-wrapped-backstop redacts direct percent-escaped credential bytes in ${mode}`, async () => {
    const bytes = registeredCredential(sentinelPath);
    const escaped = [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join('');
    await assertExactRedaction(bytes, escaped, 'note:', mode);
  });
}

function packet(kind: number, data: Buffer): Buffer {
  const digits: number[] = [];
  let length = data.length;
  do { digits.push((length & 127) | (length >= 128 ? 128 : 0)); length = Math.floor(length / 128); }
  while (length);
  return Buffer.concat([Buffer.from([kind, ...digits]), data]);
}

function addCaveat(base: Buffer, condition: string): Buffer {
  if (base[0] !== 2 || base[1] !== 1) throw new Error('unexpected committed reference layout');
  let offset = 1;
  for (const expectedKind of [1, 2]) {
    const kind = base[offset++];
    let length = 0, scale = 1, digit: number;
    do { digit = base[offset++]; length += (digit & 127) * scale; scale *= 128; } while (digit & 128);
    if (kind !== expectedKind) throw new Error('unexpected committed reference packet');
    offset += length;
  }
  if (base[offset] !== 0 || base[offset + 1] !== 0 || base[offset + 2] !== 6 ||
      base[offset + 3] !== 32 || offset + 36 !== base.length)
    throw new Error('unexpected committed reference signature');
  const caveat = Buffer.from(condition, 'utf8');
  const signature = createHmac('sha256', base.subarray(offset + 4)).update(caveat).digest();
  return Buffer.concat([base.subarray(0, offset + 1), packet(2, caveat), Buffer.from([0, 0]),
    packet(6, signature)]);
}

function inspect(input: Buffer, json: boolean): { status: number | null; stdout: string; stderr: string;
  error?: Error } {
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', '-', ...(json ? ['--json'] : [])],
    { cwd: repo, input, encoding: 'utf8', timeout: 15_000, maxBuffer: 1_000_000 });
  return { status: run.status, stdout: run.stdout || '', stderr: run.stderr || '',
    error: run.error };
}

for (const json of [false, true]) it(`CP-037/A10-wrapped-backstop inspect hides direct percent-escaped bytes in ${json ? 'JSON' : 'text'} caveats`, () => {
  const base = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));
  const bytes = registeredCredential(sentinelPath);
  const escaped = [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join('');
  const input = addCaveat(base, `opaque safe-left ${escaped} safe-right`);
  const run = inspect(input, json);
  expect(run.error === undefined, 'inspect must finish within 15 seconds').toBe(true);
  expect(run.status === 0, 'inspect exit code').toBe(true);
  expect(run.stderr === '', 'inspect stderr').toBe(true);
  noCredential(run.stdout + run.stderr, bytes, escaped);
  if (json) {
    const doc = JSON.parse(run.stdout) as { ok: boolean; result: { caveats: { value: string }[] } };
    expect(doc.ok, 'inspect JSON success').toBe(true);
    expect(doc.result.caveats.some(c => c.value === 'opaque safe-left [redacted] safe-right'),
      'exact JSON caveat').toBe(true);
  } else {
    expect(run.stdout.includes('safe-left [redacted] safe-right'), 'exact text caveat').toBe(true);
  }
}, 35_000);

it('CP-037/A10-bounded-adversarial preserves repeated malformed-header text with linear decode work', async () => {
  const { render } = await import('./helpers/render-adversarial.js');
  for (const size of [4096, 8192, 16384]) {
    const ordinary = '02010002'.repeat(size / 8);
    let decodedCharacters = 0;
    const original = Buffer.from;
    const spy = vi.spyOn(Buffer, 'from').mockImplementation(((value: unknown, ...args: unknown[]) => {
      if (typeof value === 'string') decodedCharacters += value.length;
      return Reflect.apply(original, Buffer, [value, ...args]);
    }) as typeof Buffer.from);
    let json: string, text: string;
    try {
      json = render(envelope(ordinary), 'json');
      text = render(envelope(ordinary), 'text');
    } finally { spy.mockRestore(); }
    const parsed = JSON.parse(json) as ReturnType<typeof envelope>;
    expect(parsed.result?.message === ordinary, `${size} JSON ordinary text`).toBe(true);
    const marker = 'ordinary-marker';
    const textPattern = render(envelope(marker), 'text');
    expect(textPattern.split(marker).length === 2, 'text control marker occurs once').toBe(true);
    expect(text === textPattern.replace(marker, ordinary), `${size} text ordinary output`).toBe(true);
    expect(decodedCharacters <= ordinary.length * 12, `${size} linear string-decode budget`).toBe(true);
  }
});

it('CP-037/A10-bounded-adversarial inspects a 32 KiB malformed-header caveat within 15 seconds', () => {
  const base = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));
  const ordinary = '02010002'.repeat(4096);
  const input = addCaveat(base, `opaque ${ordinary}`);
  for (const json of [false, true]) {
    const started = performance.now();
    const run = inspect(input, json);
    const elapsed = performance.now() - started;
    expect(run.error === undefined, 'inspect must finish within 15 seconds').toBe(true);
    expect(elapsed < 15_000, 'conservative inspect time bound').toBe(true);
    expect(run.status === 0, 'inspect exit code').toBe(true);
    expect(run.stderr === '', 'inspect stderr').toBe(true);
    if (json) {
      const doc = JSON.parse(run.stdout) as { ok: boolean; result: { caveats: { value: string }[] } };
      expect(doc.ok, 'inspect JSON success').toBe(true);
      expect(doc.result.caveats.some(c => c.value === `opaque ${ordinary}`), 'whole JSON caveat').toBe(true);
    } else {
      expect(run.stdout.includes(ordinary), 'whole text caveat').toBe(true);
    }
  }
}, 35_000);
