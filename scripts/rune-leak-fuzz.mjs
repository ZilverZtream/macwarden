// Leak fuzz for Core Lightning runes: fuzz-generated runes (valid, mutated, nested in each other's
// restriction values) go through every output path (inspect text and JSON, inspect refusals and
// decoding errors, scan text, JSON, SARIF and GitHub annotations, scanned file names, the output
// redaction), and the output is checked with the repository's leak checker
// (scripts/leak-check.mjs, every encoding it knows) against each rune's decoded bytes, its
// authenticator and its text, registered as sentinels for that batch only.
//
//   npm run build && node scripts/rune-leak-fuzz.mjs [--cases 20000] [--batch 25] [--seed <n>]
//
// test/rune-leak.test.ts runs a short profile on every test run.
import { randomInt } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import * as fsPromises from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { findLeaks } from './leak-check.mjs';
import { caseSeed, encodeRune, mutate, prng, randomAst, referenceDecode } from './rune-fuzz-core.mjs';

// The first four and last four are key contexts (every value is redacted); the two in the middle are
// command contexts, where only a rune a node issued is a credential (see checkable).
const COMMAND_CONTEXTS = new Set([4, 5]);
const CONTEXTS = [
  value => `RUNE=${value}`, value => `  "rune": "${value}",`, value => `Rune: ${value}`, value => `curl -H 'rune:${value}' https://node`,
  value => `lightning-cli checkrune ${value}`, value => `lightning-cli commando 02${'ab'.repeat(32)} getinfo '{}' ${value}`,
  value => `myapp --rune ${value}`, value => `<rune>${value}</rune>`, value => `CLN_RUNE="${value}`, value => `clnRune := "${value}"`,
];

/** Whether a node could have issued this text (reference decoder, unique ID as createrune writes it, at most 2^63-1). */
function checkable(text) {
  const decoded = referenceDecode(text);
  return decoded.ok && decoded.uniqueId !== null && /^(?:0|[1-9][0-9]{0,18})$/.test(decoded.uniqueId) && BigInt(decoded.uniqueId) < 2n ** 63n;
}

function encodings(text, r) {
  return r.pick([text, text.replace(/=+$/, ''), Buffer.from(text).toString('base64'), Buffer.from(text).toString('hex'),
    encodeURIComponent(text), text.replace(/=/g, '%3D')]);
}

/** One case: a rune text, the bytes it stands for and its authenticator (null when it does not decode). */
function makeCase(seed, index, previous) {
  const r = prng(caseSeed(seed, index));
  const ast = randomAst(r, { methods: ['pay', 'getinfo', 'listfunds', 'invoice'] });
  if (ast.uniqueId === null || r.chance(0.5)) { ast.uniqueId = String(r.int(0, 99999)); ast.version = null; }
  // Some runes carry another case's rune in a restriction value, in one of its encodings.
  if (previous && r.chance(0.3)) ast.restrictions.push([{ field: r.pick(['pnamenote', 'method', 'id']), condition: '=', value: encodings(previous, r) }]);
  const authenticator = r.bytes(32);
  // The leak checker builds one pattern per sentinel; runes of up to about 1,000 characters keep them bounded.
  while (ast.restrictions.length && encodeRune(ast, authenticator).text.length > 1000) ast.restrictions.splice(0, 1);
  const { text, bytes } = encodeRune(ast, authenticator);
  const mutated = r.chance(0.25) ? mutate(r, text, bytes) : text;
  return { text: mutated, bytes, authenticator, r };
}

/**
 * Runs `cases` cases in batches; `api` = { scan, renderChunks, inspectRun, redactRuneContexts }.
 * Returns counts and the leaks found (seed, batch, where, encoding; never the value).
 * @param {Record<string, any>} api
 * @param {{ seed: number, cases: number, batch?: number, scratchRoot?: string, onProgress?: (report: any) => void }} options
 */
export async function leakCampaign(api, { seed, cases, batch = 25, scratchRoot = tmpdir(), onProgress }) {
  const report = { seed, cases: 0, batches: 0, outputBytes: 0, checkSeconds: 0, leaks: /** @type {object[]} */ ([]) };
  const root = mkdtempSync(join(scratchRoot, 'rune-leak-'));
  try {
    for (let first = 0; first < cases; first += batch) {
      const dir = join(root, `batch-${first}`);
      const sentinels = join(dir, 'sentinels');
      const files = join(dir, 'files');
      mkdirSync(sentinels, { recursive: true });
      mkdirSync(files, { recursive: true });
      const outputs = [];
      const lines = [];
      let previous = null;
      const count = Math.min(batch, cases - first);
      for (let index = first; index < first + count; index++) {
        const item = makeCase(seed, index, previous);
        previous = item.text;
        writeFileSync(join(sentinels, `${index}-bytes`), item.bytes);
        writeFileSync(join(sentinels, `${index}-authenticator`), item.authenticator);
        // The text itself is a credential when it decodes as a rune (a mutation can leave one, or make a different one).
        if (referenceDecode(item.text).ok) writeFileSync(join(sentinels, `${index}-text`), Buffer.from(item.text, 'utf8'));
        const context = item.r.int(0, CONTEXTS.length - 1);
        lines.push(CONTEXTS[context](item.text));
        // inspect: stdin, a refused literal, a literal with --unsafe-arg, text and JSON.
        const deps = input => ({ stdin: Object.assign(Readable.from([Buffer.from(input)]), { isTTY: false }), fs: fsPromises,
          clock: () => new Date('2026-10-09T00:00:00Z') });
        for (const args of [['-'], ['-', '--json'], [item.text], [item.text, '--unsafe-arg', '--json']]) {
          const result = await api.inspectRun(args, deps(args[0] === '-' ? item.text : ''));
          outputs.push({ where: `inspect ${args.length > 1 ? args.slice(1).join(' ') : args[0] === '-' ? 'stdin' : 'literal'} (case ${index})`,
            text: api.render(result, args.includes('--json') ? 'json' : 'text') });
        }
        // The output redaction must remove every key-context value that is a rune, and every command-context value a node
        // could have issued. A mutation that breaks the text (a blank or other character inside it) leaves no rune to remove.
        if (referenceDecode(item.text).ok && (!COMMAND_CONTEXTS.has(context) || checkable(item.text)))
          outputs.push({ where: `redaction (case ${index})`, text: api.redactRuneContexts(lines.at(-1)) });
        report.cases++;
      }
      // A file whose name holds a short rune, and the batch's lines in LF, CRLF and UTF-16 files.
      const short = lines.find(line => line.length < 150 && /^RUNE=/.test(line));
      if (short) writeFileSync(join(files, `cfg-rune=${short.slice(5).replace(/=+$/, '')}.env`), 'x\n');
      writeFileSync(join(files, 'a.env'), `${lines.join('\n')}\n`);
      writeFileSync(join(files, 'b.txt'), `${lines.join('\r\n')}\r\n`);
      writeFileSync(join(files, 'c.txt'), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(lines.join('\n'), 'utf16le')]));
      const scanned = await api.scan([files], { clock: () => new Date('2026-10-09T00:00:00Z') });
      for (const format of ['text', 'json', 'sarif', 'github']) {
        const result = { command: 'scan', ok: true, warnings: [], result: scanned, error: null,
          ...(format === 'sarif' || format === 'github' ? { display: { format, scanRoot: files } } : {}) };
        outputs.push({ where: `scan ${format}`, text: [...api.renderChunks(result, format === 'json' ? 'json' : 'text')].join('') });
      }
      const check = commandOutput => findLeaks({ sentinels: join(dir, 'none.json'), sentinelDir: sentinels, root: dir, commandOutput });
      const timer = performance.now();
      const commandOutput = outputs.map(item => item.text).join('\n');
      report.outputBytes += commandOutput.length;
      if (check(commandOutput)) {
        // Name each output that leaks (where, and the encoding found), never the value.
        for (const item of outputs) {
          const leak = check(item.text);
          if (leak && report.leaks.length < 50) report.leaks.push({ seed, batch: first, where: item.where, encoding: leak.encoding });
        }
      }
      report.checkSeconds += (performance.now() - timer) / 1000;
      report.batches++;
      rmSync(dir, { recursive: true, force: true });
      if (onProgress) onProgress(report);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  return report;
}

/** The built package's output paths. */
export async function builtLeakApi(distRoot = resolve('dist')) {
  const load = path => import(pathToFileURL(join(distRoot, path)).href);
  const [scan, output, inspect, context] = await Promise.all([load('scan/index.js'), load('output/index.js'), load('commands/inspect.js'),
    load('scan/rune-context.js')]);
  return { scan: scan.scan, renderChunks: output.renderChunks, render: output.render, inspectRun: inspect.run,
    redactRuneContexts: context.redactRuneContexts };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const args = process.argv.slice(2);
  const option = (name, fallback) => { const at = args.indexOf(name); return at < 0 ? fallback : Number(args[at + 1]); };
  const seed = option('--seed', randomInt(2 ** 31));
  const cases = option('--cases', 20_000);
  process.stdout.write(`rune leak fuzz: seed ${seed}, ${cases} cases\n`);
  const began = performance.now();
  const report = await leakCampaign(await builtLeakApi(), { seed, cases, batch: option('--batch', 25),
    onProgress: partial => { if (partial.batches % 80 === 0) process.stdout.write(`  ${partial.cases} cases, ${partial.leaks.length} leaks, ${((performance.now() - began) / 1000).toFixed(0)} s\n`); } });
  process.stdout.write(`${JSON.stringify({ ...report, seconds: Number(((performance.now() - began) / 1000).toFixed(1)) }, null, 2)}\n`);
  process.exitCode = report.leaks.length ? 1 : 0;
}
