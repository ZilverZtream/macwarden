// Robustness review RR-04 smoke helper (Linux): keeps a regular file at <target> most of the
// time and briefly swaps a FIFO in by rename, the race between the scan's lstat and open.
// Usage: node rr111-fifo-swapper.mjs <side directory> <target> <FIFO pool size>
// Prints "ready" once the FIFO pool exists, then swaps until killed.
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';

const [side, target, poolText] = process.argv.slice(2);
const pool = Number(poolText);
execFileSync('mkfifo', Array.from({ length: pool }, (_, i) => `${side}/p${i}`));
const spin = ms => { const end = performance.now() + ms; while (performance.now() < end); };
process.stdout.write('ready\n');
for (let n = 0; ; n = (n + 1) % pool) {
  fs.writeFileSync(`${side}/r`, 'hello\n');
  fs.renameSync(`${side}/r`, target);
  spin(Math.random() * 2);
  fs.linkSync(`${side}/p${n}`, `${side}/q`);
  fs.renameSync(`${side}/q`, target);
  spin(0.5);
}
