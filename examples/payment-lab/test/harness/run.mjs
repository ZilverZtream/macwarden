// The payment lab's state-machine harness from the command line (see harness.ts and the lab's README,
// "State-machine harness"). The lab is TypeScript run through Node's type stripping, as `node src/cli.ts` is;
// this file only parses arguments and imports harness.ts.
//
//   node examples/payment-lab/test/harness/run.mjs                          500 cases, a random seed
//   node examples/payment-lab/test/harness/run.mjs --seed 7 --cases 2000 --steps 80 --replay-out runtime/replays
//   node examples/payment-lab/test/harness/run.mjs --replay examples/payment-lab/test/harness/replays
//   node examples/payment-lab/test/harness/run.mjs --replay <dir> --lab-src <old>/examples/payment-lab/src --expect-violation
//   node examples/payment-lab/test/harness/run.mjs --replay <file> --mutant examples/payment-lab/test/harness/mutants/<predicate>.cjs --expect-violation
//
// Campaign: prints the seed first, then one JSON summary (cases, events, seconds, violations, event coverage)
// and exits 1 on any violation; each predicate's first violation is shrunk and written as a replay file to
// --replay-out (default: a new directory under the system temp directory, printed).
// Replay: runs each file's events against --lab-src (default: the lab's src/) and exits 0 when none violates
// a predicate; with --expect-violation, 0 when every file violates the predicate it records (a replay recorded on a
// mutant is skipped there unless --mutant is given). A file that is not a valid replay (an unknown event, a field out
// of range, a malformed configuration) is refused with its name and step before anything of it runs; the other files
// still run, and the exit code is 2.
// --mutant <file.cjs>: applies the mutant's edits to a copy of --lab-src (default: the lab's src/) and runs against it.
import { randomInt } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';

const show = path => relative(process.cwd(), path) || path;

// node:sqlite (and type stripping on older Node releases) announce themselves as experimental; the lab uses them on purpose.
process.removeAllListeners('warning');
process.on('warning', warning => { if (warning.name !== 'ExperimentalWarning') process.stderr.write(`${warning.name}: ${warning.message}\n`); });

const args = process.argv.slice(2);
const option = name => { const at = args.indexOf(name); return at < 0 ? undefined : args[at + 1]; };
const number = (name, fallback) => {
  const value = option(name);
  if (value === undefined) return fallback;
  if (!/^[0-9]{1,9}$/.test(value)) { process.stderr.write(`${name} must be a non-negative integer\n`); process.exit(2); }
  return Number(value);
};
const known = new Set(['--seed', '--cases', '--start', '--steps', '--lab-src', '--replay-out', '--replay', '--shrink-budget', '--mutant']);
const flags = new Set(['--no-shrink', '--expect-violation', '--collect']);
for (let index = 0; index < args.length; index += 1) {
  if (flags.has(args[index])) continue;
  if (known.has(args[index]) && index + 1 < args.length) { index += 1; continue; }
  process.stderr.write(`unknown or incomplete argument ${args[index]}\n`);
  process.exit(2);
}

const harness = await import('./harness.ts');
const mutant = option('--mutant');
let labSrc = option('--lab-src');
if (mutant !== undefined) {
  try {
    const dir = mkdtempSync(join(tmpdir(), 'macwarden-lab-mutant-'));
    // The mutated copy goes when the process ends (a directory Windows still holds is left in the temp directory).
    process.on('exit', () => { try { rmSync(dir, { recursive: true, force: true }); } catch { /* left behind */ } });
    labSrc = harness.buildMutant(mutant, dir, labSrc);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(2);
  }
  process.stdout.write(`mutant ${show(mutant)}: ${harness.readMutant(mutant).description}\n`);
}

if (option('--replay') !== undefined) {
  const expectViolation = args.includes('--expect-violation');
  const outcomes = await harness.replay({ path: option('--replay'), labSrc });
  let bad = 0;
  let skipped = 0;
  let invalid = 0;
  for (const outcome of outcomes) {
    if (outcome.invalid !== undefined) {
      invalid += 1;
      process.stdout.write(`BAD  ${show(outcome.file)}: refused, nothing of it ran: ${outcome.invalid.startsWith(outcome.file) ? outcome.invalid.slice(outcome.file.length + 2) : outcome.invalid}\n`);
      continue;
    }
    if (expectViolation && outcome.mutant !== undefined && mutant === undefined) {
      skipped += 1;
      process.stdout.write(`skip ${show(outcome.file)}: recorded on mutants/${outcome.mutant}; run it with --mutant\n`);
      continue;
    }
    if (expectViolation && !outcome.recorded && mutant === undefined) {
      skipped += 1;
      process.stdout.write(`skip ${show(outcome.file)}: a hand-written scenario, it records no violation${outcome.violations.length === 0 ? ''
        : ` (violates ${outcome.violations.map(item => item.predicate).join(', ')})`}\n`);
      continue;
    }
    const expected = outcome.violations.find(item => item.predicate === outcome.predicate);
    const ok = expectViolation ? expected !== undefined : outcome.violations.length === 0;
    if (!ok) bad += 1;
    const shown = expected ?? outcome.violations[0];
    process.stdout.write(`${ok ? 'ok  ' : 'FAIL'} ${show(outcome.file)}: ${shown === undefined ? 'no violation'
      : `violates ${outcome.violations.map(item => item.predicate).join(', ')}; ${shown.predicate} at step ${shown.step}: ${shown.message}`}`
      + `${expectViolation ? ` (expected ${outcome.predicate})` : ''}\n`);
  }
  process.stdout.write(`${outcomes.length} replay(s), ${bad} unexpected${skipped === 0 ? '' : `, ${skipped} skipped`}${invalid === 0 ? '' : `, ${invalid} refused`}`
    + `, lab source ${labSrc ?? 'examples/payment-lab/src'}\n`);
  process.exitCode = invalid > 0 ? 2 : bad === 0 ? 0 : 1;
} else {
  const seed = number('--seed', randomInt(2 ** 31));
  const cases = number('--cases', 500);
  const replayOut = option('--replay-out') ?? mkdtempSync(join(tmpdir(), 'macwarden-lab-replays-'));
  process.stdout.write(`payment lab harness: seed ${seed}, ${cases} cases\n`);
  let last = 0;
  const result = await harness.campaign({ seed, cases, start: number('--start', 0), steps: number('--steps', 60), labSrc, replayOut,
    shrink: !args.includes('--no-shrink'), shrinkBudget: number('--shrink-budget', 300), collect: args.includes('--collect'),
    onProgress: done => { if (done - last >= 100) { last = done; process.stdout.write(`  ${done}/${cases} cases\n`); } } });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  for (const violation of result.violations) {
    process.stdout.write(`VIOLATION case ${violation.case} ${violation.predicate}: ${violation.replayMessage ?? violation.message}\n`);
    if (violation.replay !== undefined) {
      process.stdout.write(`  replay (${violation.shrunkSteps} events): node ${show(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))} --replay ${violation.replay}\n`);
    }
  }
  if (result.violations.length === 0) process.stdout.write('no violations\n');
  process.exitCode = result.violations.length === 0 ? 0 : 1;
}
