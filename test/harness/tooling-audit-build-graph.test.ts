import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';
import { repo, scratch } from '../support/cp041-controls.js';

// Payloads that type-check against the production tsconfig yet reach the
// credential capability through the compiled module loader or through a
// value an approved consumer returns. The actual build graph must reject each.
const loaderPayloads = {
  'declared require': ['ambient production declaration', `import type { Secret } from '../secret.js';
declare const require: (id: string) => { revealSecret(secret: Secret): Buffer };
export function leak(secret: Secret): string { return require('../secret-capability.js').revealSecret(secret).toString('hex'); }`],
  '@types/node require': ['module loader identifier', `import type { Secret } from '../secret.js';
type Capability = { revealSecret(secret: Secret): Buffer };
export function leak(secret: Secret): string { return (require('../secret-capability.js') as Capability).revealSecret(secret).toString('hex'); }`],
  'module.require': ['module loader identifier', `import type { Secret } from '../secret.js';
type Capability = { revealSecret(secret: Secret): Buffer };
export function leak(secret: Secret): string { return (module.require('../secret-capability.js') as Capability).revealSecret(secret).toString('hex'); }`],
  'declared runtime loader': ['ambient production declaration', `import type { Secret } from '../secret.js';
declare function load(id: string): { revealSecret(secret: Secret): Buffer };
export function leak(secret: Secret): string { return load('secret-capability.js').revealSecret(secret).toString('hex'); }`],
  'import equals require': ['module loader import', `import type { Secret } from '../secret.js';
import capability = require('../secret-capability.js');
export function leak(secret: Secret): string { return capability.revealSecret(secret).toString('hex'); }`],
  // Direct eval and Function read the digest-named loader from the stack or runtime.js.
  'direct eval': ['dynamic code', `import type { Secret } from '../secret.js';
const name = (new Error().stack ?? '').match(/__mw[0-9a-f]{24}_load/)?.[0] ?? 'none';
export function leak(secret: Secret): string {
  const load = eval(name) as (id: string) => { revealSecret(s: Secret): Buffer };
  return load('secret-capability.js').revealSecret(secret).toString('hex');
}`],
  'Function constructor': ['dynamic code', `import type { Secret } from '../secret.js';
const name = (new Error().stack ?? '').match(/__mw[0-9a-f]{24}_load/)?.[0] ?? 'none';
export function leak(secret: Secret): string {
  const load = new Function('return ' + name)() as (id: string) => { revealSecret(s: Secret): Buffer };
  return load('secret-capability.js').revealSecret(secret).toString('hex');
}`],
};
// Lint directives that would switch the boundary rules off (lint itself obeys them).
const directivePayloads = {
  'named disable': '// eslint-disable-next-line no-eval, macwarden/capability-boundary\nexport const value = 1;\n',
  'blanket disable': '/* eslint-disable */\nexport const value = 1;\n',
  'inline configuration': '/* eslint no-new-func: "off" */\nexport const value = 1;\n',
  'global declaration': '/* global require */\nexport const value = 1;\n',
};
const body = '  return nwcPrefixLength(revealSecret(secret)) > 0;';
const namespace = `import * as capability from '../secret-capability.js';\n`;
const returnPayloads: Record<string, [string, string]> = {
  wrapped: ['', '  return Buffer.from(revealSecret(secret)) as unknown as boolean;'],
  closure: ['', '  return { open: (s: Secret) => revealSecret(s) } as unknown as boolean;'],
  namespace: [namespace, '  return capability.revealSecret(secret) as unknown as boolean;'],
  'namespace object': [namespace, '  return capability as unknown as boolean;'],
  getter: ['', '  return { get open() { return revealSecret(secret); } } as unknown as boolean;'],
  method: ['', '  return { open(s: Secret) { return revealSecret(s); } } as unknown as boolean;'],
  'class static': ['', '  return class { static open = revealSecret; } as unknown as boolean;'],
  template: ['', "  return `${revealSecret(secret).toString('hex')}` as unknown as boolean;"],
  'Array.from': ['', '  return Array.from(revealSecret(secret)) as unknown as boolean;'],
  // Audit verification: flows the return analysis alone did not follow.
  'map callback': ['', '  return [secret].map(revealSecret)[0] as unknown as boolean;'],
  'Array.from callback': ['', '  return Array.from([secret], revealSecret)[0] as unknown as boolean;'],
  'late assignment': ['', '  let out: unknown = null; out = revealSecret(secret); return out as boolean;'],
  'array destructuring': ['', '  const [r] = [revealSecret]; return r as unknown as boolean;'],
  'catch variable': ['', '  try { throw revealSecret(secret); } catch (e) { return e as boolean; }'],
  'argument mutation': ['', '  (secret as unknown as { x: unknown }).x = revealSecret(secret); return false;'],
  'thrown to the caller': ['', '  if (secret) throw revealSecret(secret); return false;'],
  'Reflect.apply': ['', '  return Reflect.apply(revealSecret, undefined, [secret]) as unknown as boolean;'],
  'Map.set': ['', "  const m = new Map<string, unknown>(); m.set('k', revealSecret(secret)); return m as unknown as boolean;"],
  'defineProperty': ['', "  const o = {}; Object.defineProperty(o, 'v', { value: revealSecret(secret) }); return o as unknown as boolean;"],
};
// Each consumer rule on its own: payloads that need no assertion, some with a changed signature.
const signature = 'export function isNwcContainer(secret: Secret): boolean {';
const rulePayloads: Record<string, [string, string, string]> = {
  'value use': [signature, '  return [secret].map(revealSecret).length > 0;', 'revealSecret used as a value'],
  'assertion to unknown': [signature, '  return nwcPrefixLength(revealSecret(secret)) as unknown as boolean;', 'assertion to any, unknown or never'],
  'any annotation': [signature, '  const value: any = nwcPrefixLength(revealSecret(secret)) > 0; return value;', 'any type'],
  'raw value thrown': [signature, '  if (secret) throw revealSecret(secret); return false;', 'credential value thrown'],
  'non-Error thrown': [signature, '  if (secret) throw nwcPrefixLength(revealSecret(secret)); return false;', 'non-Error thrown'],
  'bytes in the signature': ['export function isNwcContainer(secret: Secret): Buffer {',
    '  return Buffer.alloc(nwcPrefixLength(revealSecret(secret)));', 'credential consumer export can carry raw data'],
  'late assignment returned': ['export function isNwcContainer(secret: Secret): string {',
    "  let out = ''; out = revealSecret(secret).toString('hex'); return out;", 'credential authority returned by public consumer'],
};

it('TOOLING-01/02/09 the build graph rejects loader access and wrapped credential returns; a failed build emits nothing', async () => { await scratch(dir => {
  const copy = join(dir, 'build-control');
  mkdirSync(copy, { mode: 0o700 });
  for (const name of ['src', 'scripts']) cpSync(join(repo, name), join(copy, name), { recursive: true });
  for (const name of ['package.json', 'tsconfig.json']) cpSync(join(repo, name), join(copy, name));
  symlinkSync(join(repo, 'node_modules'), join(copy, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
  const run = (args: string[]) => spawnSync(process.execPath, args, { cwd: copy, env: childEnvironment(), encoding: 'utf8', timeout: 120_000 });
  const tsc = () => run([join(copy, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json']);
  const graph = () => run([join(copy, 'scripts/build.mjs'), '--copy-permissions']);
  const compiled = tsc();
  expect(compiled.error, 'private source copy compiles').toBeUndefined();
  expect(compiled.status, 'private source copy compiles with pinned TypeScript').toBe(0);
  const baseline = graph();
  expect(baseline.error, 'positive control completes').toBeUndefined();
  expect(baseline.status, `unchanged sources pass the build graph: ${baseline.stderr}`).toBe(0);
  const runtime = readFileSync(join(copy, 'dist/runtime.js'), 'utf8');
  expect(runtime, 'factories no longer take guessable loader parameters').not.toContain('(module, exports, require) =>');
  expect(runtime, 'factory loader parameters carry the source digest')
    .toMatch(/: \((__mw[0-9a-f]{24}_)module, \1exports, \1require\) =>/);
  expect(runtime, 'runtime loader carries the source digest').toMatch(/function __mw[0-9a-f]{24}_load\(/);
  expect(runtime, 'no unprefixed runtime loader').not.toMatch(/function load\(/);

  // One compiler run shows every payload type-checks, so only the graph can stop it.
  const probes = Object.values(loaderPayloads).map((_, index) => join(copy, `src/output/zzprobe${index}.ts`));
  Object.values(loaderPayloads).forEach(([, source], index) => writeFileSync(probes[index], source));
  const checked = tsc();
  expect(checked.status, `payloads type-check: ${checked.stdout}`).toBe(0);
  probes.forEach(path => rmSync(path));
  const probe = join(copy, 'src/output/zzprobe.ts');
  for (const [name, [reason, source]] of Object.entries(loaderPayloads)) {
    writeFileSync(probe, source);
    const rejected = graph();
    expect.soft(rejected.status, `${name} payload fails the build graph`).toBe(1);
    expect.soft(rejected.stderr, `${name} rejection reason`).toContain(reason);
    const lint = spawnSync(process.execPath, [join(repo, 'test/helpers/cp044-lint.mjs'), 'src/output/zzprobe.ts',
      Buffer.from(source).toString('base64')], { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 120_000 });
    expect.soft(lint.status, `${name} lint probe runs`).toBe(0);
    expect.soft(JSON.parse(lint.stdout || '{}').rejected, `${name} payload fails lint`).toBe(true);
  }
  rmSync(probe);

  const decode = join(copy, 'src/decode/index.ts');
  const original = readFileSync(decode, 'utf8');
  expect(original, 'payload site is present').toContain(body);
  for (const [name, [header, replacement]] of Object.entries(returnPayloads)) {
    writeFileSync(decode, header + original.replace(body, replacement));
    const rejected = graph();
    expect.soft(rejected.status, `${name} return fails the build graph`).toBe(1);
    expect.soft(rejected.stderr, `${name} rejection reason`)
      .toMatch(/credential (?:authority returned by public consumer|consumer rule \(.+\)|consumer export can carry raw data): decode\/index\.js/);
  }
  expect(original, 'signature site is present').toContain(`${signature}\n${body}`);
  for (const [name, [declaration, replacement, reason]] of Object.entries(rulePayloads)) {
    writeFileSync(decode, original.replace(`${signature}\n${body}`, `${declaration}\n${replacement}`));
    const rejected = graph();
    expect.soft(rejected.status, `${name} fails the build graph`).toBe(1);
    expect.soft(rejected.stderr, `${name} rejection reason`).toContain(reason);
  }
  writeFileSync(decode, original);
  for (const [name, source] of Object.entries(directivePayloads)) {
    writeFileSync(probe, source);
    const rejected = graph();
    expect.soft(rejected.status, `${name} fails the build graph`).toBe(1);
    expect.soft(rejected.stderr, `${name} rejection reason`).toContain('lint directive weakening the capability boundary');
  }
  rmSync(probe);

  // TOOLING-09: a type error fails the build without leaving tsc's per-file output, whose
  // dist/secret-capability.js would export revealSecret (postbuild never runs to seal it).
  writeFileSync(join(copy, 'src/output/zztype.ts'), 'export const broken: number = "not a number";\n');
  expect(run([join(copy, 'scripts/build.mjs')]).status, 'prebuild clears dist').toBe(0);
  const failed = tsc();
  expect(failed.status, 'the type error fails the compiler').not.toBe(0);
  expect(existsSync(join(copy, 'dist/secret-capability.js')), 'no unsealed capability module is emitted').toBe(false);
}); }, 600_000);
