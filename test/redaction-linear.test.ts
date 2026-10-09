import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { captureMain } from './support/capture.js';

// Grouped base64 recognition used X+(?:SX+)+ regular expressions, which backtrack from
// every start over a long unseparated run: a 200 KB caveat took about 52 s to inspect.
// The linear matchers must return exactly the regular expressions' matches.
const shapes = {
  dash: /[A-Za-z0-9+/_]+(?:-[A-Za-z0-9+/_]+)+={0,2}/g,
  underscore: /[A-Za-z0-9+/]+(?:_[A-Za-z0-9+/]+)+={0,2}/g,
  other: /[A-Za-z0-9+/_-]+(?:[^A-Za-z0-9+/_=\s\\-][A-Za-z0-9+/_-]+)+={0,2}/g,
} as const;
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');

function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => { state = (state * 1664525 + 1013904223) >>> 0; return state / 2 ** 32; };
}

it('LINEAR/grouped-runs both matchers equal the regular expressions on random text', async () => {
  const { groupedBase64 } = await import('../src/grouped-runs.js');
  const { groupedBase64Runs } = await import('../scripts/leak-check.mjs') as {
    groupedBase64Runs: (text: string, shape: keyof typeof shapes) => string[] };
  const alphabet = ['A', 'b', '0', '9', '+', '/', '_', '-', '=', '=', '.', ':', ' ', '\t', '\n', '\\', '~', 'é', ' ', '\ud83d', '#'];
  const next = random(20261008);
  for (let iteration = 0; iteration < 4000; iteration++) {
    const length = Math.floor(next() * 48);
    const text = Array.from({ length }, () => alphabet[Math.floor(next() * alphabet.length)]).join('');
    for (const shape of Object.keys(shapes) as (keyof typeof shapes)[]) {
      const expected = [...text.matchAll(shapes[shape])].map(match => ({ index: match.index, value: match[0] }));
      expect(groupedBase64[shape](text), `${shape} ${JSON.stringify(text)}`).toEqual(expected);
      expect(groupedBase64Runs(text, shape), `leak-check ${shape} ${JSON.stringify(text)}`).toEqual(expected.map(match => match.value));
    }
  }
});

it.each(['A', '7', 'Ab0+', 'A-', 'A_', 'A.'])('LINEAR/redaction a 1 MB run of %j is redacted in linear time', async filler => {
  const { redactEncodedCredentials } = await import('../src/credential-recognition.js');
  const text = filler.repeat(Math.ceil(1_000_000 / filler.length));
  const started = performance.now();
  expect(redactEncodedCredentials(text)).toBe(text);
  expect(performance.now() - started).toBeLessThan(2_000);
});

async function bigCaveat(value: string): Promise<{ file: string; dir: string }> {
  const { addFirstPartyCaveat } = await import('../src/decode/index.js');
  const { Secret } = await import('../src/secret.js');
  const { revealSecret } = await import('../src/secret-capability.js');
  const parent = new Secret(readFileSync(resolve('test/vectors/default-readonly.macaroon')));
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'linear-'));
  const file = join(dir, 'big.macaroon');
  writeFileSync(file, Buffer.from(revealSecret(addFirstPartyCaveat(parent, `lnd-custom ${value}`))));
  return { file, dir };
}

it('LINEAR/display a 200 KB caveat inspects quickly and is shown whole (CP-037/A10)', async () => {
  const value = `x ${'A'.repeat(200_000)}`;
  const { file, dir } = await bigCaveat(value);
  try {
    const { main } = await import('../src/cli.js');
    const started = performance.now();
    const json = await captureMain(main, ['inspect', file, '--json']);
    const text = await captureMain(main, ['inspect', file]);
    // About 52 s with the backtracking expressions; linear recognition takes well under a second.
    expect(performance.now() - started).toBeLessThan(4_000);
    const caveats = (JSON.parse(json.stdout) as { result: { caveats: { type: string; value: string }[] } }).result.caveats;
    expect(caveats.at(-1)).toEqual({ type: 'lnd-custom', value });
    expect(text.stdout).toContain(`caveats      lnd-custom ${value}
`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('LINEAR/display a 1 MB caveat across many grouped shapes is inspected in linear time', async () => {
  const value = `z ${'Ab0+-'.repeat(100_000)}${'A_'.repeat(100_000)}${'A.'.repeat(100_000)}`;
  const { file, dir } = await bigCaveat(value);
  try {
    const { main } = await import('../src/cli.js');
    const started = performance.now();
    const run = await captureMain(main, ['inspect', file, '--json']);
    expect(run.code).toBe(0);
    expect(performance.now() - started).toBeLessThan(6_000);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
