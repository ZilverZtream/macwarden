import { render } from './helpers/render-adversarial.js';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';

const repo = resolve();
const sentinel = () => readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
const envelope = (message: string) => ({ schema: 1 as const, command: 'inspect', ok: true,
  warnings: [], result: { message }, error: null });

function packet(kind: number, data: Buffer): Buffer {
  const varint: number[] = [];
  let n = data.length;
  do { varint.push((n & 127) | (n >= 128 ? 128 : 0)); n = Math.floor(n / 128); } while (n);
  return Buffer.concat([Buffer.from([kind, ...varint]), data]);
}

function controlledCaveat(base: Buffer, condition: string): Buffer {
  // The committed default-readonly vector has a location and identifier, then
  // the two 0 end markers and a 32-byte signature packet.
  if (base[0] !== 2 || base[1] !== 1) throw new Error('unexpected reference vector layout');
  let at = 1;
  for (let i = 0; i < 2; i++) {
    const kind = base[at++];
    let length = 0; let scale = 1; let byte: number;
    do { byte = base[at++]; length += (byte & 127) * scale; scale *= 128; } while (byte & 128);
    if (kind !== i + 1) throw new Error('unexpected reference packet');
    at += length;
  }
  if (base[at] !== 0 || base[at + 1] !== 0 || base[at + 2] !== 6 || base[at + 3] !== 32)
    throw new Error('reference vector has unexpected caveats or signature');
  const caveat = Buffer.from(condition, 'utf8');
  const signature = createHmac('sha256', base.subarray(at + 4)).update(caveat).digest();
  return Buffer.concat([base.subarray(0, at + 1), packet(2, caveat), Buffer.from([0, 0]), packet(6, signature)]);
}

const credentialBytes = sentinel();
const hex = credentialBytes.toString('hex');
const base64 = credentialBytes.toString('base64');
const cases: [string, string][] = [
    ['contiguous hex', hex],
    ['contiguous base64', base64],
    ['wrapped hex', hex.match(/.{1,64}/g)!.join('\n')],
    ['wrapped base64', base64.match(/.{1,64}/g)!.join('\n')],
    ['percent-encoded hex', [...hex].map(ch => `%${ch.charCodeAt(0).toString(16)}`).join('')],
    ['percent-encoded base64', [...base64].map(ch => `%${ch.charCodeAt(0).toString(16)}`).join('')],
];
for (const [name, credential] of cases) {
  it(`CP-037/A10-wrapped-backstop redacts ${name} with exact safe context`, async () => {
  await import('../src/output/index.js');
  const safe = 'café left [redacted] right Ω';
    const message = `café left ${credential} right Ω`;
    const json = render(envelope(message), 'json');
    expect(JSON.parse(json), `${name} JSON`).toEqual(envelope(safe));
    expect(render(envelope(message), 'text'), `${name} text`)
      .toBe(render(envelope(safe), 'text'));
    expect(json.includes(hex), name).toBe(false);
    expect(json.includes(base64), name).toBe(false);
  });
}

it('CP-037/C-ordinary-text-identity retains every safe character and escapes controls exactly', async () => {
  const output = await import('../src/output/index.js');
  const message = 'préfixe Ω\x1b\x07\x7f\x9b suffix';
  const expected = 'préfixe Ω\\x1b\\x07\\x7f\\x9b suffix';
  const text = render(envelope(message), 'text');
  const safeText = render(envelope(expected), 'text');
  expect(text).toBe(safeText);
  expect(JSON.parse(render(envelope(message), 'json'))).toEqual(envelope(message));
  expect(output.error('input-form', message)).toBe(output.error('input-form', expected));
});

it('CP-037/A10-bounded-adversarial renders large near-matches within a conservative offline bound', async () => {
  await import('../src/output/index.js');
  const bytes = sentinel();
  const candidate = bytes.toString('base64').slice(0, -8);
  const nearMatches = (`A${candidate.slice(0, 12)}!`).repeat(8192);
  const message = `${'x'.repeat(32 * 1024)}${nearMatches} safe-end ${bytes.toString('hex')}`;
  let decodedInput = 0;
  const originalFrom = Buffer.from;
  const from = vi.spyOn(Buffer, 'from').mockImplementation(((value: unknown, ...args: unknown[]) => {
    if (typeof value === 'string') decodedInput += value.length;
    return Reflect.apply(originalFrom, Buffer, [value, ...args]);
  }) as typeof Buffer.from);
  const started = performance.now();
  let json: string;
  try { json = render(envelope(message), 'json'); }
  finally { from.mockRestore(); }
  const elapsed = performance.now() - started;
  expect(elapsed).toBeLessThan(10_000);
  expect(decodedInput).toBeLessThanOrEqual(message.length * 6);
  const rendered = JSON.parse(json) as ReturnType<typeof envelope>;
  expect(rendered.result?.message.endsWith(' safe-end [redacted]')).toBe(true);
  expect(json.includes(bytes.toString('hex'))).toBe(false);
});

it('CP-037/A10-bounded-adversarial decodes ordinary hex-like text with linear work', async () => {
  await import('../src/output/index.js');
  const message = '02'.repeat(4096);
  let decodedInput = 0;
  const originalFrom = Buffer.from;
  const from = vi.spyOn(Buffer, 'from').mockImplementation(((value: unknown, ...args: unknown[]) => {
    if (typeof value === 'string') decodedInput += value.length;
    return Reflect.apply(originalFrom, Buffer, [value, ...args]);
  }) as typeof Buffer.from);
  let json: string;
  try { json = render(envelope(message), 'json'); }
  finally { from.mockRestore(); }
  expect(JSON.parse(json)).toEqual(envelope(message));
  // A linear recognizer may decode a few complete candidates. Repeated suffix
  // decoding of this 8 KiB input instead processes millions of characters.
  expect(decodedInput).toBeLessThanOrEqual(message.length * 6);
});

it('CP-037/A10-bounded-adversarial inspects a 32 KiB caveat end to end within 15 seconds', () => {
  const base = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));
  const bytes = sentinel();
  const wrapped = bytes.toString('hex').match(/.{1,64}/g)!.join('\n');
  const caveat = `${'02'.repeat(16 * 1024)}${'AgEDbG5kA!'.repeat(256)}safeA${wrapped}Bsafe`;
  const input = controlledCaveat(base, `opaque ${caveat}`);
  const started = performance.now();
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', '-', '--json'],
    { cwd: repo, input, encoding: 'utf8', timeout: 15_000, maxBuffer: 2_000_000 });
  const elapsed = performance.now() - started;
  expect(run.error).toBeUndefined();
  expect(elapsed).toBeLessThan(15_000);
  const stage = (() => { try { return JSON.parse(run.stdout)?.error?.step; } catch { return 'not-json'; } })();
  expect(run.status, `inspect stage ${String(stage)}`).toBe(0);
  const doc = JSON.parse(run.stdout) as { ok: boolean; result: { caveats: { value: string }[] } };
  expect(doc.ok).toBe(true);
  expect(doc.result.caveats[0].value.endsWith('safeA[redacted]Bsafe')).toBe(true);
  expect(run.stdout.includes(bytes.toString('hex'))).toBe(false);
}, 20_000);
import { spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
