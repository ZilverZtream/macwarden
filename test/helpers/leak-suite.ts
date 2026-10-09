import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { afterAll } from 'vitest';

// Keep artifacts until the suite's standing leak check; workers never scan peers.
export function isolateLeakSuite(name: string): void {
  const variables = ['MACWARDEN_TEST_TMP', 'MACWARDEN_SENTINEL_DIR'] as const;
  const parents = variables.map(variable => {
    const value = process.env[variable];
    if (!value || !isAbsolute(value)) throw new Error(`${variable} must be absolute`);
    const parent = resolve(value);
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    return parent;
  });
  const roots = parents.map(parent => mkdtempSync(join(parent, `${name}-suite-`)));
  variables.forEach((variable, index) => { process.env[variable] = roots[index]; });
  afterAll(() => {
    const declared = join(roots[0], 'declared-out.txt');
    if (existsSync(declared))
      appendFileSync(join(parents[0], 'declared-out.txt'), readFileSync(declared));
    const inside = relative(parents[0], roots[0]);
    if (!inside || isAbsolute(inside) || inside === '..' || inside.startsWith(`..${sep}`))
      throw new Error('Unsafe suite scratch cleanup');
    try { rmSync(roots[0], { recursive: true, force: true }); }
    finally { variables.forEach((variable, index) => { process.env[variable] = parents[index]; }); }
    // Registered sentinels remain available for the gate's whole-run scan.
  });
}
