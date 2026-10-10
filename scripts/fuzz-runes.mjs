// Long-running property fuzz of macwarden's Core Lightning rune support on the built package.
// Run after `npm run build`:
//
//   npm run fuzz:runes                       200,000 cases from a fresh seed
//   RUNE_FUZZ_CASES=1000000 RUNE_FUZZ_SEED=123 npm run fuzz:runes
//
// The seed is printed first; a failure is reproduced by its seed and case index (RUNE_FUZZ_START
// runs from that index). The properties are those of test/rune-fuzz.test.ts, which runs a short
// profile on every test run (scripts/rune-fuzz-core.mjs). Exits 1 when any case fails.
import { randomInt } from 'node:crypto';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { runCampaign } from './rune-fuzz-core.mjs';

export async function builtApi(distRoot = resolve('dist')) {
  const load = path => import(pathToFileURL(join(distRoot, path)).href);
  const [decode, grade, methods, report, scan] = await Promise.all([load('decode/rune.js'), load('grade/rune.js'),
    load('grade/cln-methods.js'), load('rune-report.js'), load('scan/runes.js')]);
  return { decodeRuneText: decode.decodeRuneText, RUNE_TEXT_LIMIT: decode.RUNE_TEXT_LIMIT, RUNE_RESTRICTION_LIMIT: decode.RUNE_RESTRICTION_LIMIT,
    RUNE_ALTERNATIVE_LIMIT: decode.RUNE_ALTERNATIVE_LIMIT, assessRune: grade.assessRune, methodMayPass: grade.methodMayPass,
    CLN_METHODS: methods.CLN_METHODS, runeReport: report.runeReport, runeFindings: scan.runeFindings };
}

function positive(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  if (!/^[0-9]+$/.test(value)) throw new Error(`${name} must be a non-negative integer`);
  return Number(value);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const cases = positive('RUNE_FUZZ_CASES', 200_000);
  const seed = positive('RUNE_FUZZ_SEED', randomInt(2 ** 31));
  const start = positive('RUNE_FUZZ_START', 0);
  process.stdout.write(`rune fuzz: seed ${seed}, cases ${cases}, from index ${start}\n`);
  const api = await builtApi();
  const began = performance.now();
  const { stats, failures } = runCampaign(api, { seed, cases, start, maxFailures: 50,
    onProgress: (done, partial, found) => process.stdout.write(`  ${done} cases, ${found.length} failures, ${((performance.now() - began) / 1000).toFixed(1)} s\n`) });
  const seconds = (performance.now() - began) / 1000;
  process.stdout.write(`${JSON.stringify({ seed, cases, start, seconds: Number(seconds.toFixed(1)), stats }, null, 2)}\n`);
  for (const failure of failures) process.stdout.write(`FAIL seed=${failure.seed} index=${failure.index} ${failure.kind}: ${failure.message}\n`);
  process.exitCode = failures.length ? 1 : 0;
}
