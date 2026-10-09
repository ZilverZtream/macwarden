import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { compare, growth } from './helpers/growth.js';
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

// Cost is measured as growth, not against a fixed limit: four times the run must take well
// under the sixteen times that quadratic backtracking needs (a 200 KB run took about 52 s).
it.each(['A', '7', 'Ab0+', 'A-', 'A_', 'A.'])('LINEAR/redaction a run of %j four times longer costs about four times as much', async filler => {
  const { redactEncodedCredentials } = await import('../src/credential-recognition.js');
  const run = (size: number) => {
    const text = filler.repeat(Math.ceil(size / filler.length));
    return () => expect(redactEncodedCredentials(text)).toBe(text);
  };
  const timing = await growth(run, 64_000, 4);
  console.log(`LINEAR/redaction ${JSON.stringify(filler)} 64 KB and 256 KB: ${timing.summary}`);
  expect(timing.ratio, timing.summary).toBeLessThan(8);
}, 60_000);

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

it('LINEAR/display a 200 KB caveat is shown whole, at about four times the cost of a 50 KB one (CP-037/A10)', async () => {
  // About 52 s at 200 KB with the backtracking expressions, which grow with the square of the caveat.
  const value = (size: number) => `x ${'A'.repeat(size)}`;
  const small = await bigCaveat(value(50_000));
  const large = await bigCaveat(value(200_000));
  try {
    const { main } = await import('../src/cli.js');
    let json = { stdout: '' }, text = { stdout: '' };
    const inspect = (file: string) => async () => {
      json = await captureMain(main, ['inspect', file, '--json']);
      text = await captureMain(main, ['inspect', file]);
    };
    const timing = await compare(inspect(small.file), inspect(large.file));
    console.log(`LINEAR/display 50 KB and 200 KB caveats: ${timing.summary}`);
    expect(timing.ratio, timing.summary).toBeLessThan(8);
    // The last timed run inspected the 200 KB caveat.
    const caveats = (JSON.parse(json.stdout) as { result: { caveats: { type: string; value: string }[] } }).result.caveats;
    expect(caveats.at(-1)).toEqual({ type: 'lnd-custom', value: value(200_000) });
    expect(text.stdout).toContain(`caveats      lnd-custom ${value(200_000)}
`);
  } finally { for (const { dir } of [small, large]) rmSync(dir, { recursive: true, force: true }); }
}, 60_000);

it('LINEAR/display a 1 MB caveat across many grouped shapes costs about four times a 250 KB one', async () => {
  const value = (repeats: number) => `z ${'Ab0+-'.repeat(repeats)}${'A_'.repeat(repeats)}${'A.'.repeat(repeats)}`;
  const small = await bigCaveat(value(25_000));
  const large = await bigCaveat(value(100_000));
  try {
    const { main } = await import('../src/cli.js');
    const inspect = (file: string) => async () => expect((await captureMain(main, ['inspect', file, '--json'])).code).toBe(0);
    const timing = await compare(inspect(small.file), inspect(large.file));
    console.log(`LINEAR/display 250 KB and 1 MB grouped caveats: ${timing.summary}`);
    expect(timing.ratio, timing.summary).toBeLessThan(8);
  } finally { for (const { dir } of [small, large]) rmSync(dir, { recursive: true, force: true }); }
}, 60_000);
