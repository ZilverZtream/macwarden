// The full differential campaign against the regtest Core Lightning fixture (see
// scripts/cln-rune-differential.mjs). Run after `npm run build` and `npm run fixture:cln:up`:
//
//   node scripts/cln-rune-campaign.mjs [--runes 2500] [--pairs 2] [--mutations 2] [--seed <n>] [--json]
//
// Prints the seed first and the counts at the end; exits 1 when any comparison fails. Bring the
// fixture down afterwards with `npm run fixture:cln:down`.
import { randomInt } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { session, status, CLN_VERSION } from '../test/fixture/cln-fixture.mjs';
import { runDifferential } from './cln-rune-differential.mjs';
import { builtApi } from './fuzz-runes.mjs';

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const args = process.argv.slice(2);
  // A flag needs a whole number of at least its minimum: a typo or a missing value is an error,
  // never NaN (zero cases, a null seed) or a batch of 0 (no progress).
  const option = (name, fallback, minimum = 0) => {
    const at = args.indexOf(name);
    if (at < 0) return fallback;
    const value = args[at + 1];
    if (value === undefined || !/^[0-9]+$/.test(value) || Number(value) < minimum || !Number.isSafeInteger(Number(value)))
      throw new Error(`${name} must be an integer of at least ${minimum}`);
    return Number(value);
  };
  const seed = option('--seed', randomInt(2 ** 31));
  const runes = option('--runes', 2500, 1);
  process.stdout.write(`cln rune campaign: seed ${seed}, ${runes} runes\n`);
  const identity = status();
  if (!identity || identity.version !== CLN_VERSION || identity.network !== 'regtest')
    throw new Error('the Core Lightning fixture is not running: npm run fixture:cln:up');
  const rpc = session();
  const began = performance.now();
  try {
    const report = await runDifferential(rpc, await builtApi(), { seed, runes, pairsPerRune: option('--pairs', 2),
      mutationsPerRune: option('--mutations', 2),
      onProgress: (done, partial) => process.stdout.write(`  ${done} runes, ${partial.pairs} pairs, ${partial.failures.length} failures, ${((performance.now() - began) / 1000).toFixed(0)} s\n`) });
    const seconds = Number(((performance.now() - began) / 1000).toFixed(1));
    if (args.includes('--json')) process.stdout.write(`${JSON.stringify({ ...report, seconds }, null, 2)}\n`);
    else {
      const { failures, modelDisagreements, ...counts } = report;
      process.stdout.write(`${JSON.stringify({ ...counts, seconds }, null, 2)}\n`);
      for (const item of modelDisagreements) process.stdout.write(`MODEL ${JSON.stringify(item)}\n`);
      for (const failure of failures) process.stdout.write(`FAIL seed=${failure.seed} index=${failure.index} ${failure.kind}: ${failure.message}\n`);
    }
    process.exitCode = report.failures.length ? 1 : 0;
  } finally {
    await rpc.close();
  }
}
