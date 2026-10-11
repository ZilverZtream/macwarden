import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Measured seconds per LND oracle file. Full validation balances its shards with it; a
// missing or unreadable map only costs balance, never coverage (every file is still assigned).
export const durationMapPath = 'test/fixture/oracle-shards.json';

/** Reads the map, or an empty one when the file is absent or malformed (a synthetic project). */
export function readDurations(root) {
  try {
    const data = JSON.parse(readFileSync(resolve(root, durationMapPath), 'utf8'));
    const files = data && typeof data.files === 'object' && !Array.isArray(data.files) ? data.files : {};
    const valid = Object.entries(files).filter(([, seconds]) => Number.isFinite(seconds) && seconds >= 0);
    const defaultSeconds = Number.isFinite(data?.defaultSeconds) && data.defaultSeconds > 0 ? data.defaultSeconds : 30;
    return { defaultSeconds, files: Object.fromEntries(valid) };
  } catch {
    return { defaultSeconds: 30, files: {} };
  }
}

/**
 * Greedy longest-first assignment of files (root-relative, forward slashes) into at most `count`
 * shards. Each file lands in exactly one shard; a file the map does not know weighs
 * `defaultSeconds` and so goes to whichever shard is least loaded when its turn comes. Ties
 * break by name and shard index, so the same inputs always give the same shards. Empty shards
 * are dropped: Vitest refuses a run with no files.
 */
export function assignShards(files, durations, count) {
  if (!Number.isInteger(count) || count < 1) throw new Error('invalid shard count');
  if (new Set(files).size !== files.length) throw new Error('duplicate oracle file');
  const weight = file => Object.hasOwn(durations.files, file) ? durations.files[file] : durations.defaultSeconds;
  const ordered = [...files].sort((a, b) => weight(b) - weight(a) || (a < b ? -1 : a > b ? 1 : 0));
  const shards = Array.from({ length: count }, () => ({ files: [], seconds: 0 }));
  for (const file of ordered) {
    const target = shards.reduce((best, shard) => shard.seconds < best.seconds ? shard : best);
    target.files.push(file);
    target.seconds += weight(file);
  }
  return shards.filter(shard => shard.files.length);
}

// Regenerates the map from Vitest JSON reports (per-file startTime/endTime):
//   node scripts/oracle-shards.mjs <report.json>...
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const files = {};
  for (const path of process.argv.slice(2)) {
    for (const suite of JSON.parse(readFileSync(path, 'utf8')).testResults ?? []) {
      // Reports may come from another checkout: keep the path from test/oracle/ on.
      const file = /(?:^|\/)(test\/oracle\/[^:]+)$/.exec(String(suite.name).replaceAll('\\', '/'))?.[1];
      if (!file || !(suite.endTime >= suite.startTime)) continue;
      files[file] = Math.round((suite.endTime - suite.startTime) / 100) / 10;
    }
  }
  const seconds = Object.values(files);
  if (!seconds.length) { process.stderr.write('no oracle files in the given reports\n'); process.exit(1); }
  const sorted = Object.fromEntries(Object.entries(files).sort(([a], [b]) => (a < b ? -1 : 1)));
  const defaultSeconds = Math.round(seconds.reduce((sum, value) => sum + value, 0) / seconds.length);
  writeFileSync(resolve(root, durationMapPath), `${JSON.stringify({ defaultSeconds, files: sorted }, null, 2)}\n`);
  process.stdout.write(`${seconds.length} files, ${Math.round(seconds.reduce((a, b) => a + b, 0))} s in total\n`);
}
