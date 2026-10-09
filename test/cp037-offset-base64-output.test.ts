import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';

const repo = resolve();
const sentinelList = join(repo, 'test/sentinels.json');
const sentinel = readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
const base = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));

function packet(kind: number, value: Buffer): Buffer {
  const length: number[] = [];
  let remaining = value.length;
  do {
    length.push((remaining & 127) | (remaining >= 128 ? 128 : 0));
    remaining = Math.floor(remaining / 128);
  } while (remaining);
  return Buffer.concat([Buffer.from([kind, ...length]), value]);
}

function withLocation(location: string): Buffer {
  if (base[0] !== 2 || base[1] !== 1) throw new Error('unexpected committed vector layout');
  let at = 2;
  let size = 0;
  let scale = 1;
  let digit: number;
  do {
    digit = base[at++];
    size += (digit & 127) * scale;
    scale *= 128;
  } while (digit & 128);
  if (at + size >= base.length || base[at + size] !== 2)
    throw new Error('unexpected committed location packet');
  return Buffer.concat([base.subarray(0, 1), packet(1, Buffer.from(location, 'utf8')),
    base.subarray(at + size)]);
}

function inspect(input: Buffer, mode: 'text' | 'json') {
  const run = spawnSync(process.execPath,
    [join(repo, 'dist/bin.js'), 'inspect', '-', ...(mode === 'json' ? ['--json'] : [])],
    { cwd: repo, input, encoding: 'utf8', timeout: 15_000, maxBuffer: 1_000_000 });
  return { status: run.status, stdout: run.stdout || '', stderr: run.stderr || '',
    error: run.error };
}

function parseJsonSafely(output: string): { ok?: boolean; result?: { location?: string } } {
  try { return JSON.parse(output) as { ok?: boolean; result?: { location?: string } }; }
  catch { throw new Error('inspect did not return one JSON document'); }
}

for (const offset of [1, 2]) {
  for (const encoding of ['base64', 'base64url'] as const) {
    for (const mode of ['text', 'json'] as const) {
      it(`CP-037/A10-wrapped-backstop inspect redacts ${encoding} after ${offset} preceding byte(s) in ${mode}`, async () => {
        const { findLeaks } = await import("./helpers/leak-check.js");
        const representation = Buffer.concat([Buffer.alloc(offset, 0x51), sentinel])
          .toString(encoding);
        const location = `safe-left ${representation} safe-right`;
        const run = inspect(withLocation(location), mode);

        expect(run.error === undefined, 'inspect must finish within 15 seconds').toBe(true);
        expect(run.status === 0, 'synthetic inspect must succeed').toBe(true);
        expect(run.stderr === '', 'inspect stderr must be empty').toBe(true);
        const actual = run.stdout + run.stderr;
        expect(findLeaks({ sentinels: sentinelList, commandOutput: actual, root: repo }) === null,
          'standing leak check must find no credential in inspect output').toBe(true);
        expect(actual.includes(representation), 'complete offset encoding must be absent').toBe(false);
        expect(actual.includes(representation.slice(-24)), 'signature suffix must be absent').toBe(false);
        if (mode === 'json') {
          const document = parseJsonSafely(run.stdout);
          expect(document.ok === true, 'JSON inspect success').toBe(true);
          expect(document.result?.location === 'safe-left [redacted] safe-right',
            'JSON location keeps exact safe neighbors').toBe(true);
        } else {
          expect(run.stdout.includes('safe-left [redacted] safe-right'),
            'text location keeps exact safe neighbors').toBe(true);
        }
      }, 20_000);
    }
  }
}

it('CP-037/A10-wrapped-backstop standing leak check recognizes both offset base64 forms', async () => {
  const { findLeaks } = await import("./helpers/leak-check.js");
  for (const offset of [1, 2]) for (const encoding of ['base64', 'base64url'] as const) {
    const representation = Buffer.concat([Buffer.alloc(offset, 0x51), sentinel])
      .toString(encoding);
    const hit = findLeaks({ sentinels: sentinelList,
      commandOutput: `safe-left ${representation} safe-right`, root: repo });
    expect(hit !== null, `${encoding} offset ${offset} positive control`).toBe(true);
    expect(hit?.path === 'command output', 'leak location').toBe(true);
  }
  expect(findLeaks({ sentinels: sentinelList,
    commandOutput: 'safe-left ordinary-cafe-1234 safe-right', root: repo }) === null,
  'ordinary text negative control').toBe(true);
});

it('CP-037/A10-wrapped-backstop inspect preserves an ordinary location in text and JSON', async () => {
  const ordinary = 'safe-left ordinary-cafe-1234 safe-right';
  for (const mode of ['text', 'json'] as const) {
    const run = inspect(withLocation(ordinary), mode);
    expect(run.error === undefined, 'ordinary inspect must finish').toBe(true);
    expect(run.status === 0, 'ordinary inspect must succeed').toBe(true);
    expect(run.stderr === '', 'ordinary inspect stderr').toBe(true);
    if (mode === 'json') {
      const document = parseJsonSafely(run.stdout);
      expect(document.ok === true, 'ordinary JSON success').toBe(true);
      expect(document.result?.location === ordinary, 'exact ordinary JSON location').toBe(true);
    } else {
      expect(run.stdout.includes(ordinary), 'ordinary text location').toBe(true);
    }
  }
}, 35_000);

it('CP-037/A10-bounded-adversarial keeps long base64-alphabet text with linear decode work', async () => {
  const { render } = await import('./helpers/render-adversarial.js');
  const envelope = (message: string) => ({ schema: 1 as const, command: 'inspect',
    ok: true, warnings: [], result: { message }, error: null });
  for (const size of [8192, 16384, 32768]) {
    const ordinary = `AgEDbG5kA${'A'.repeat(size - 9)}`;
    let decodedCharacters = 0;
    const original = Buffer.from;
    const spy = vi.spyOn(Buffer, 'from').mockImplementation(((value: unknown, ...args: unknown[]) => {
      if (typeof value === 'string') decodedCharacters += value.length;
      return Reflect.apply(original, Buffer, [value, ...args]);
    }) as typeof Buffer.from);
    let json: string;
    try { json = render(envelope(ordinary), 'json'); }
    finally { spy.mockRestore(); }
    const parsed = parseJsonSafely(json) as { result?: { message?: string } };
    expect(parsed.result?.message === ordinary, `${size} ordinary text identity`).toBe(true);
    expect(decodedCharacters <= ordinary.length * 12, `${size} linear decode budget`).toBe(true);
  }
});
