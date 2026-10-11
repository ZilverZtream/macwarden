import { mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks, internals, leakScans } from '../../scripts/leak-check.mjs';
import { collectedNameDuplicates } from '../../scripts/validation-support.mjs';

// The leak prefilter, the redactor fast path and the parallel scan are checked against
// their reference definitions: the literal-alternation regexes the prefilter replaced
// (copied below from the former scripts/leak-check.mjs), the unconditional redaction
// pass, and the sequential findLeaks. All sources here are random synthetic bytes.
type State = { source: Buffer; variants: Array<{ bytes: Buffer }>; utf16le: Buffer; utf16be: Buffer;
  percentBytes: string; escapedBytes: string };
type Input = { data: Buffer; recovered: Buffer[]; lower: Buffer; compact: Buffer; compactLower: Buffer;
  percent: Buffer; percentLower: Buffer; splitViews: Buffer[]; base64Runs: Buffer[];
  hexStreams(): Array<{ bytes: Buffer }>; decimalStream(): Array<{ bytes: Buffer }> };

function referencePrefilter(states: State[]): (input: Input) => boolean {
  const matcher = (values: Buffer[]) => {
    const literals = [...new Set(values.map(bytes => bytes.toString('latin1')))];
    const pattern = new RegExp(literals.map(value => value.replace(/[|\\{}()[\]^$+*?.]/g, '\\$&')).join('|'));
    return (bytes: Buffer) => pattern.test(bytes.toString('latin1'));
  };
  const raw = matcher(states.map(state => state.source));
  const encoded = matcher(states.flatMap(state => [
    ...state.variants.map(variant => variant.bytes), state.utf16le, state.utf16be,
    Buffer.from(state.percentBytes), Buffer.from(state.escapedBytes),
  ]));
  return input => {
    if (raw(input.data) || encoded(input.data)) return true;
    if ([...input.recovered, input.lower, input.compact, input.compactLower,
      input.percent, input.percentLower, ...input.splitViews].some(encoded)) return true;
    if (input.hexStreams().some(stream => raw(stream.bytes) || encoded(stream.bytes)) ||
        input.decimalStream().some(stream => raw(stream.bytes))) return true;
    return input.base64Runs.some(run => raw(run) || encoded(run));
  };
}

// Deterministic, so a disagreement is reproducible.
function random(seed: number) {
  let state = seed >>> 0;
  const next = () => { state = (state + 0x6d2b79f5) >>> 0; let t = state; t = Math.imul(t ^ t >>> 15, t | 1);
    t ^= t + Math.imul(t ^ t >>> 7, t | 61); return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  const int = (limit: number) => Math.floor(next() * limit);
  const bytes = (length: number, kind = int(6)) => Buffer.from(Array.from({ length }, (_, at) =>
    kind === 0 ? int(256) : kind === 1 ? 32 + int(95) : kind === 2 ? (int(4) ? 0 : int(256))
      : kind === 3 ? 128 + int(128) : kind === 4 ? (at % 7 ? 0x41 : int(256)) : 'ab0'.charCodeAt(int(3))));
  return { int, bytes };
}

const chunks = (text: string, size: number) => text.match(new RegExp(`[^]{1,${size}}`, 'g')) ?? [];
// Every literal form, plus the derived shapes each prefilter view exists for.
const encodings: Array<(source: Buffer, pick: ReturnType<typeof random>) => Buffer> = [
  source => source,
  ...internals.variants(Buffer.from([1])).map((_, index) => (source: Buffer) =>
    Buffer.from(internals.variants(source)[index]?.[1] ?? '', 'utf8')),
  source => Buffer.from(source.toString('latin1'), 'utf16le'),
  source => Buffer.from(Buffer.from(source.toString('latin1'), 'utf16le')).swap16(),
  source => Buffer.from(source.toString('hex').replace(/../g, byte => `%${byte}`)),
  source => Buffer.from(source.toString('hex').replace(/../g, byte => `\\x${byte}`)),
  source => Buffer.from(source.toString('hex').match(/../g)!.join(':')),
  source => Buffer.from([...source].join(', ')),
  source => Buffer.from(Buffer.from(source.toString('hex')).toString('base64')),
  source => Buffer.from(Buffer.from(source.toString('base64')).toString('hex').match(/../g)!.join(' ')),
  source => Buffer.from(encodeURIComponent(source.toString('base64'))),
  source => Buffer.from(chunks(source.toString('base64'), 13).join('\n')),
  source => Buffer.from(chunks(source.toString('base64'), 9).map(piece => `"${piece}"`).join(' + ')),
  source => Buffer.from(JSON.stringify(source.toString('latin1'))),
  source => Buffer.from([...source.toString('latin1')].map(c => `&#${c.charCodeAt(0)};`).join('')),
  (source, pick) => Buffer.from([...source.toString('hex')].map(c => pick.int(2) ? c.toUpperCase() : c).join('')),
  (source, pick) => Buffer.from(`C:\\work\\1${[...source.toString('hex')].map(c => pick.int(2) ? c.toUpperCase() : c).join('')}\\x`),
  source => Buffer.from(source.toString('base64').replace(/=+$/, '').toLowerCase()),
  source => Buffer.from(chunks(source.toString('base64'), 4).join('-')),
  // Near misses: a truncated or changed form must agree too.
  source => Buffer.from(source.toString('hex').slice(1)),
  source => { const changed = Buffer.from(source); changed[changed.length - 1]! ^= 1; return Buffer.from(changed.toString('base64')); },
];

function noise(pick: ReturnType<typeof random>, length: number) {
  const kind = pick.int(4);
  if (kind === 0) return pick.bytes(length, 0);
  if (kind === 1) return Buffer.from(pick.bytes(length, 1).toString('latin1').replace(/[^ -~]/g, ' '));
  if (kind === 2) return Buffer.from(pick.bytes(Math.ceil(length * 0.75), 0).toString('base64'));
  return pick.bytes(length, 3);
}

function sources(pick: ReturnType<typeof random>, count: number, lengths: () => number) {
  const shared = Buffer.concat([Buffer.from([2, 1, 3]), Buffer.from('lnd'), pick.bytes(40, 0)]);
  return Array.from({ length: count }, (_, at) => at % 5 === 0
    ? Buffer.concat([shared, pick.bytes(lengths(), 0)]) : pick.bytes(lengths()));
}

// Six runs of 50 source lengths each (1 to 300 in all): one run takes a few seconds, so a
// loaded machine stays inside the default test timeout.
it.each([1, 51, 101, 151, 201, 251].map(first => ({ first, last: first + 49 })))('PERF-01 the prefilter agrees with the literal-alternation reference on every encoding of sources of $first to $last bytes', ({ first, last }) => {
  const pick = random(20261011 + first);
  const tally = { cases: 0, positive: 0, negative: 0, disagreements: [] as string[] };
  for (let length = first; length <= last; length++) {
    const population = sources(pick, 6, () => 1 + pick.int(300));
    population[0] = pick.bytes(length);
    const states = population.map(source => internals.preparedCredential(source));
    const reference = referencePrefilter(states);
    const { possibleLeak } = internals.preparedFilter(states);
    encodings.forEach((encode, form) => {
      const planted = encode(population[pick.int(population.length)]!, pick);
      const before = noise(pick, pick.int(400)), after = noise(pick, pick.int(400));
      for (const data of [Buffer.concat([before, planted, after]), Buffer.concat([before, after]), planted]) {
        const input = internals.preparedData(data);
        const expected = reference(input), actual = possibleLeak(input);
        tally.cases++; if (expected) tally.positive++; else tally.negative++;
        // Lengths and indices only: never the bytes.
        if (expected !== actual) tally.disagreements.push(`length ${length} form ${form} expected ${expected}`);
      }
    });
  }
  expect(tally.disagreements).toEqual([]);
  expect(tally.positive, JSON.stringify({ ...tally, disagreements: undefined })).toBeGreaterThan(tally.cases / 4);
  expect(tally.negative).toBeGreaterThan(tally.cases / 10);
});

const corpusFiles = (directory: string): string[] => readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
  const path = join(directory, entry.name);
  if (entry.isDirectory()) return ['.tmp', '.sentinels', 'node_modules'].includes(entry.name) ? [] : corpusFiles(path);
  return entry.isFile() && statSync(path).size <= 2_000_000 ? [path] : [];
});

// The corpus comparison runs in eight slices (every eighth file each), so one test stays well
// inside the default timeout on a slow CI runner; a final test checks the slices together.
const corpus = (() => {
  let built: { reference: (input: Input) => boolean; possibleLeak: (input: Input) => boolean; files: string[] } | undefined;
  return () => {
    if (built) return built;
    const pick = random(7);
    const registered = readdirSync(resolve('test/sentinels')).map(name => readFileSync(join(resolve('test/sentinels'), name)));
    const population = [...registered, ...sources(pick, 20, () => 1 + pick.int(300))];
    const states = population.map(source => internals.preparedCredential(source));
    const { possibleLeak } = internals.preparedFilter(states);
    built = { reference: referencePrefilter(states), possibleLeak, files: [...corpusFiles(resolve('test')), ...corpusFiles(resolve('src'))] };
    return built;
  };
})();
const corpusSlices = 8;
const corpusTally = { slices: 0, files: 0, positive: 0 };

it.each(Array.from({ length: corpusSlices }, (_, slice) => ({ slice, part: slice + 1 })))('PERF-02 the prefilter agrees with the reference on the repository test corpora and their names (part $part of 8)', ({ slice }) => {
  const { reference, possibleLeak, files } = corpus();
  const disagreements: string[] = [];
  const mine = files.filter((_, index) => index % corpusSlices === slice);
  for (const path of mine) {
    for (const data of [readFileSync(path), Buffer.from(relative(resolve(), path))]) {
      const input = internals.preparedData(data);
      const expected = reference(input);
      if (expected) corpusTally.positive++;
      if (expected !== possibleLeak(input)) disagreements.push(relative(resolve(), path));
    }
  }
  corpusTally.slices++;
  corpusTally.files += mine.length;
  expect(disagreements).toEqual([]);
});

it('PERF-02 the corpus slices together covered every file, and the corpora hold registered encodings', () => {
  expect(corpusTally.slices).toBe(corpusSlices);
  expect(corpusTally.files).toBe(corpus().files.length);
  expect(corpusTally.files).toBeGreaterThan(200);
  expect(corpusTally.positive, 'the corpora hold registered encodings').toBeGreaterThan(0);
});

it('PERF-03 the redactor fast path returns exactly what the full redaction pass returns', () => {
  const pick = random(99);
  const population = sources(pick, 12, () => 1 + pick.int(120));
  const state = internals.preparedRedactor(population);
  const strings: string[] = [];
  for (const source of population) {
    for (const encode of encodings) {
      const planted = encode(source, pick).toString('utf8');
      strings.push(planted, `prefix ${planted} suffix`, `C:\\scratch\\run\\${planted}`, `/tmp/x/${planted}/report.json`);
    }
  }
  for (let at = 0; at < 300; at++) strings.push(noise(pick, pick.int(200)).toString('utf8'));
  strings.push('command output', '', 'CP-950/B1 an ordinary test title', 'C:\\Users\\x\\AppData\\Local\\Temp\\0abcdef\\file.txt');
  const disagreements = strings.flatMap((text, index) =>
    internals.safePath(text, population, state) === internals.fullSafePath(text, state) ? [] : [index]);
  expect(disagreements).toEqual([]);
  const redacted = strings.filter(text => internals.fullSafePath(text, state) !== text).length;
  expect(redacted, 'most planted strings are redacted').toBeGreaterThan(strings.length / 2);
});

it('PERF-04 the parallel leak scan returns what the sequential scan returns or throws', async () => {
  if (!process.env.MACWARDEN_TEST_TMP) throw new Error('Private test scratch is required');
  const pick = random(4242);
  const root = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP, 'leak-parallel-'));
  mkdirSync(join(root, 'test/sentinels'), { recursive: true });
  writeFileSync(join(root, 'test/sentinels.json'), JSON.stringify(['test/sentinels/*.bin']));
  const registered = sources(pick, 3, () => 32 + pick.int(200));
  registered.forEach((source, at) => writeFileSync(join(root, `test/sentinels/${at}.bin`), source));
  const runtime = join(root, 'runtime');
  mkdirSync(runtime);
  const late = pick.bytes(64, 0);
  writeFileSync(join(runtime, 'late.bin'), late);
  const tree = (name: string, plants: Array<[number, Buffer]>) => {
    const directory = join(root, name);
    for (let at = 0; at < 40; at++) {
      mkdirSync(join(directory, `d${at % 4}`), { recursive: true });
      const plant = plants.find(([index]) => index === at)?.[1];
      writeFileSync(join(directory, `d${at % 4}`, `f${at}.log`), Buffer.concat([noise(pick, 2000), plant ?? Buffer.alloc(0), noise(pick, 500)]));
    }
    return directory;
  };
  const base = { root, sentinels: join(root, 'test/sentinels.json'), sentinelDir: runtime };
  const sets = [
    { ...base, paths: [tree('clean', [])] },
    { ...base, paths: [tree('two', [[7, Buffer.from(registered[1]!.toString('base64'))], [31, Buffer.from(late.toString('hex'))]])] },
    { ...base, paths: [tree('many', [[3, registered[0]!], [12, Buffer.from(registered[2]!.toString('hex').match(/../g)!.join(':'))],
      [25, Buffer.from(late.toString('base64url'))]])] },
    { ...base, commandOutput: `log ${registered[2]!.toString('base64')}`, paths: [tree('output', [[1, registered[0]!]])] },
    { ...base, paths: [join(root, 'absent')] },
  ];
  const outcome = (options: Parameters<typeof findLeaks>[0]) => {
    try { return { hit: findLeaks(options) }; }
    catch (error) { return { error: (error as Error).message }; }
  };
  const expected = sets.map(outcome);
  const actual = (await leakScans(sets, 3)).map(result => 'error' in result ? { error: result.error.message } : { hit: result.hit });
  expect(actual).toEqual(expected);
  expect(expected.map(result => 'hit' in result && result.hit !== null)).toEqual([false, true, true, true, false]);
  expect(expected[4]).toHaveProperty('error');
});

it('PERF-05 the early name check finds the duplicates the report check rejects, before any test runs', () => {
  if (!process.env.MACWARDEN_TEST_TMP) throw new Error('Private test scratch is required');
  const root = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP, 'early-names-'));
  const api = JSON.stringify(resolve('node_modules/vitest/dist/index.js').replaceAll('\\', '/'));
  writeFileSync(join(root, 'vitest.config.mjs'), "export default { test: { include: ['t/**/*.test.mjs'] } };\n");
  mkdirSync(join(root, 't'));
  // The reporter joins suite and test titles with one space: these two collide only there.
  writeFileSync(join(root, 't/a.test.mjs'), `import { describe, it } from ${api};\ndescribe('one two', () => it('three', () => {}));\nit('same', () => {});\n`);
  writeFileSync(join(root, 't/b.test.mjs'), `import { describe, it } from ${api};\ndescribe('one', () => it('two three', () => {}));\nit('same', () => {});\nit('unique', () => {});\n`);
  const scratch = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP, 'early-names-out-'));
  const found = collectedNameDuplicates(root, process.env, scratch, 120_000);
  expect({ collected: found.collected, count: found.count, duplicates: [...found.duplicates].sort() })
    .toEqual({ collected: true, count: 5, duplicates: ['one two three', 'same'] });
  writeFileSync(join(root, 't/b.test.mjs'), `import { it } from ${api};\nit('other', () => {});\n`);
  expect(collectedNameDuplicates(root, process.env, scratch, 120_000).duplicates).toEqual([]);
});
