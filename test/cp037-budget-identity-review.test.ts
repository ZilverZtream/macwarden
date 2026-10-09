import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { render } from './helpers/render-adversarial.js';

const repo = resolve();
const vector = (name: string): Buffer => readFileSync(join(repo, 'test/vectors', name));
const envelope = (message: string) => ({ schema: 1 as const, command: 'inspect', ok: true,
  warnings: [], result: { message }, error: null });
const malformed = Buffer.concat([
  Buffer.from('0202010300'.repeat(30), 'hex'), Buffer.from([0, 6, 32]), Buffer.alloc(32),
]);
const malformedHex = malformed.toString('hex');

function packet(kind: number, data: Buffer): Buffer {
  const digits: number[] = [];
  let length = data.length;
  do {
    digits.push((length & 127) | (length >= 128 ? 128 : 0));
    length = Math.floor(length / 128);
  } while (length);
  return Buffer.concat([Buffer.from([kind, ...digits]), data]);
}

function withLocation(location: string): Buffer {
  const base = vector('default-readonly.macaroon');
  if (base[0] !== 2 || base[1] !== 1) throw new Error('unexpected reference layout');
  let at = 2, size = 0, scale = 1, digit: number;
  do { digit = base[at++]; size += (digit & 127) * scale; scale *= 128; } while (digit & 128);
  if (at + size >= base.length || base[at + size] !== 2)
    throw new Error('unexpected reference location packet');
  return Buffer.concat([base.subarray(0, 1), packet(1, Buffer.from(location, 'utf8')),
    base.subarray(at + size)]);
}

function inspect(location: string, mode: 'text' | 'json') {
  const run = spawnSync(process.execPath,
    [join(repo, 'dist/bin.js'), 'inspect', '-', ...(mode === 'json' ? ['--json'] : [])],
    { cwd: repo, input: withLocation(location), encoding: 'utf8', timeout: 15_000,
      maxBuffer: 2_000_000 });
  return { status: run.status, stdout: run.stdout || '', stderr: run.stderr || '',
    error: run.error };
}

function assertExactRender(message: string): void {
  const parsed = JSON.parse(render(envelope(message), 'json')) as ReturnType<typeof envelope>;
  expect(parsed.result?.message === message, 'whole JSON field is byte-identical').toBe(true);
  const marker = 'ordinary-location-marker';
  const template = render(envelope(marker), 'text');
  expect(template.split(marker).length === 2, 'text control marker occurs exactly once').toBe(true);
  expect(render(envelope(message), 'text') === template.replace(marker, message),
    'whole text document is byte-identical').toBe(true);
}

function assertExactInspect(location: string, mode: 'text' | 'json'): void {
  const run = inspect(location, mode);
  expect(run.error === undefined, 'offline inspect finishes within 15 seconds').toBe(true);
  expect(run.status === 0, 'offline inspect exits successfully').toBe(true);
  expect(run.stderr === '', 'offline inspect has no stderr').toBe(true);
  if (mode === 'json') {
    const doc = JSON.parse(run.stdout) as { ok: boolean; result?: { location?: string } };
    expect(doc.ok === true && doc.result?.location === location,
      'whole public JSON location is byte-identical').toBe(true);
  } else {
    const lines = run.stdout.split(/\r?\n/).filter(line => /^location\s+/.test(line));
    expect(lines.length === 1, 'one public text location field').toBe(true);
    expect(lines[0].replace(/^location\s+/, '') === location,
      'whole public text location is byte-identical').toBe(true);
  }
}

it('CP-037/C-ordinary-text-identity proves repeated packet text has no valid credential', () => {
  expect(malformed.length === 185 && malformedHex.length === 370,
    'synthetic sequence has the specified safe length').toBe(true);
  expect(malformed[0] === 2 && malformed[1] === 2,
    'v2 begins with a one-byte identifier packet and no location').toBe(true);
  expect(malformed.subarray(0, 5).equals(Buffer.from([2, 2, 1, 3, 0])),
    'identifier contains only version 3, with no required protobuf fields').toBe(true);
  expect(malformed.subarray(-36, -32).equals(Buffer.from([0, 0, 6, 32])),
    'signature-shaped suffix cannot repair the invalid header order').toBe(true);
  const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/negative/manifest.json'), 'utf8')) as {
    vectors: { name: string; stage: string }[] };
  expect(manifest.vectors.some(item => item.name === 'truncated-protobuf' && item.stage === 'identifier-proto'),
    'committed negative rule rejects incomplete version-3 identifiers').toBe(true);
});

for (const mode of ['text', 'json'] as const) {
  it(`CP-037/C-ordinary-text-identity preserves repeated malformed packets in public ${mode} inspect`, () => {
    const location = `safe-left ${malformedHex} safe-right`;
    expect(location.length === 391, 'entire synthetic location has the expected length').toBe(true);
    assertExactInspect(location, mode);
    assertExactRender(location);
  });
}

it('CP-037/C-ordinary-text-identity preserves the whole direct text and JSON documents', () => {
  assertExactRender(`safe-left ${malformedHex} safe-right`);
});

it('CP-037/C-ordinary-text-identity preserves invalid packet and identifier families', () => {
  const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/negative/manifest.json'), 'utf8')) as {
    vectors: { name: string; stage: string }[] };
  for (const [name, stage] of [
    ['fields-out-of-order', 'packet'],
    ['header-without-identifier', 'packet'],
    ['identifier-version-02', 'identifier-version'],
    ['storage-nondigits', 'identifier-root-key-id'],
  ] as const) {
    expect(manifest.vectors.some(item => item.name === name && item.stage === stage),
      `${name} independently classified by the negative-vector manifest`).toBe(true);
    const bytes = vector(`negative/${name}.macaroon`);
    const ordinary = `safe-left ${Array.from({ length: 16 }, () => bytes.toString('hex')).join(' | ')} safe-right`;
    assertExactRender(ordinary);
  }
});

it('CP-037/A10-wrapped-backstop retains both committed credentials around malformed text', () => {
  const credential = vector('default-readonly.macaroon').toString('hex');
  const message = `safe-left ${credential} ${malformedHex} ${credential} safe-right`;
  const expected = `safe-left [redacted] ${malformedHex} [redacted] safe-right`;
  for (const mode of ['text', 'json'] as const) {
    const actual = render(envelope(message), mode);
    expect(actual.includes(credential), 'complete credential absent after rendering').toBe(false);
    expect(actual.includes(credential.slice(-24)), 'signature suffix absent after rendering').toBe(false);
    if (mode === 'json') {
      const parsed = JSON.parse(actual) as ReturnType<typeof envelope>;
      expect(parsed.result?.message === expected, 'exact JSON safe context and both redactions').toBe(true);
    } else {
      expect(actual === render(envelope(expected), 'text'),
        'exact text safe context and both redactions').toBe(true);
    }
  }
});

it('CP-037/A10-wrapped-backstop protects credentials in one encoded run across malformed bytes', () => {
  const credential = vector('default-readonly.macaroon');
  const joined = Buffer.concat([credential, malformed, credential]);
  const encoded = joined.toString('base64');
  expect(Buffer.from(encoded, 'base64').equals(joined), 'encoded run contains both real credentials').toBe(true);
  for (const mode of ['text', 'json'] as const) {
    const actual = render(envelope(`safe-left ${encoded} safe-right`), mode);
    expect(actual.includes(encoded), 'whole encoded run absent').toBe(false);
    expect(actual.includes(encoded.slice(-24)), 'final signature suffix absent').toBe(false);
    if (mode === 'json') {
      const parsed = JSON.parse(actual) as ReturnType<typeof envelope>;
      expect(parsed.result?.message.startsWith('safe-left ') === true &&
        parsed.result.message.endsWith(' safe-right') && parsed.result.message.includes('[redacted]'),
      'JSON retains safe context and marks redaction').toBe(true);
    } else {
      expect(actual.includes('safe-left ') && actual.includes(' safe-right') && actual.includes('[redacted]'),
        'text retains safe context and marks redaction').toBe(true);
    }
  }
});

it('CP-037/A10-bounded-adversarial preserves a larger repeated malformed location within the bound', () => {
  const location = `safe-left ${malformedHex.repeat(90)} safe-right`;
  expect(location.length > 32 * 1024, 'location exceeds 32 KiB').toBe(true);
  for (const mode of ['text', 'json'] as const) assertExactInspect(location, mode);
}, 35_000);

it('CP-037/A10-bounded-adversarial uses linear string decoding on repeated malformed packets', () => {
  for (const count of [21, 42, 84]) {
    const message = `safe-left ${malformedHex.repeat(count)} safe-right`;
    let decodedCharacters = 0;
    const original = Buffer.from;
    const spy = vi.spyOn(Buffer, 'from').mockImplementation(((value: unknown, ...args: unknown[]) => {
      if (typeof value === 'string') decodedCharacters += value.length;
      return Reflect.apply(original, Buffer, [value, ...args]);
    }) as typeof Buffer.from);
    let actual: string;
    try { actual = render(envelope(message), 'json'); }
    finally { spy.mockRestore(); }
    const parsed = JSON.parse(actual) as ReturnType<typeof envelope>;
    expect(parsed.result?.message === message, 'whole ordinary JSON field is preserved').toBe(true);
    expect(decodedCharacters <= message.length * 12,
      'observable decoded characters stay within a linear budget').toBe(true);
  }
});
