import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';
import { repo, scratch, sentinelPath } from './cp041-controls.js';
const probes = [
  { name: 'concatenated property', get: `const Execute = (() => {})['con'.concat('structor')];` },
  { name: 'character-code property', get: `const Execute = (() => {})[String.fromCharCode(99,111,110,115,116,114,117,99,116,111,114)];` },
  { name: 'destructured constructor', get: `const {constructor: Execute} = (() => {});` },
  { name: 'Object alias', get: `const O = Object; const Execute = O.getPrototypeOf(() => {}).constructor;` },
  { name: 'property-name scan', get: `const proto = Object.getPrototypeOf(() => {}); const key = Object.getOwnPropertyNames(proto).find(k => k.startsWith('con')); const Execute = proto[key];` },
  { name: 'helper constructor', get: `const helper = value => value['con'.concat('structor')]; const Execute = helper(() => {});` },
];
export async function capabilityProbeControls() { await scratch(dir => {
  const cap = pathToFileURL(join(repo, 'dist/secret-capability.js')).href;
  for (const probe of probes) {
    const positive = join(dir, 'positive.mjs');
    writeFileSync(positive, `${probe.get} process.stdout.write(String(Execute('return 73')() === 73));`);
    const good = spawnSync(process.execPath, [positive], { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 10000 });
    expect(good.status === 0 && good.stdout === 'true', `${probe.name} executable positive control`).toBe(true);
    const source = `${probe.get} await Execute(${JSON.stringify(`return import(${JSON.stringify(cap)})`)})();`;
    const lint = spawnSync(process.execPath, [join(repo, 'test/helpers/cp044-lint.mjs'), 'src/output/cp044-probe.ts',
      Buffer.from(source).toString('base64')], { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 20000 });
    expect(lint.status, 'lint boundary control executes').toBe(0);
    const runtime = join(dir, 'attack.mjs');
    writeFileSync(runtime, `import {readFileSync} from 'node:fs';
      import {Secret} from ${JSON.stringify(pathToFileURL(join(repo, 'dist/secret.js')).href)};
      const bytes = readFileSync(${JSON.stringify(sentinelPath)}); const secret = new Secret(bytes);
      ${probe.get} try { const cap = await Execute(${JSON.stringify(`return import(${JSON.stringify(cap)})`)})();
      process.stdout.write(String(Buffer.from(cap.revealSecret(secret)).equals(bytes))); } catch { process.stdout.write('false'); }`);
    const attack = spawnSync(process.execPath, [runtime], { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 10000 });
    expect(attack.status, 'attack produces only a capture boolean').toBe(0);
    expect.soft(JSON.parse(lint.stdout).rejected || attack.stdout === 'false', `${probe.name} cannot bypass runtime and build authority`).toBe(true);
  }
  const reexport = 'import { revealSecret } from "../secret-capability.js"; const access = revealSecret; export const helper = access;';
  const sourceCopy = join(dir, 'build-control');
  mkdirSync(sourceCopy, { mode: 0o700 });
  for (const name of ['src', 'scripts']) {
    cpSync(join(repo, name), join(sourceCopy, name), { recursive: true });
  }
  for (const name of ['package.json', 'tsconfig.json', 'tsconfig.test.json']) {
    cpSync(join(repo, name), join(sourceCopy, name));
  }
  symlinkSync(join(repo, 'node_modules'), join(sourceCopy, 'node_modules'),
    process.platform === 'win32' ? 'junction' : 'dir');
  const compiled = spawnSync(process.execPath, [join(sourceCopy, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json'],
    { cwd: sourceCopy, env: childEnvironment(), encoding: 'utf8', timeout: 20000 });
  expect(compiled.error === undefined, 'private source copy compilation completes').toBe(true);
  expect(compiled.status, 'private source copy compiles with pinned TypeScript').toBe(0);
  const buildGraph = () => spawnSync(process.execPath, [join(sourceCopy, 'scripts/build.mjs'), '--copy-permissions'],
    { cwd: sourceCopy, env: childEnvironment(), encoding: 'utf8', timeout: 20000 });
  const baseline = buildGraph();
  expect(baseline.error === undefined, 'actual prebuild positive control completes').toBe(true);
  expect(baseline.status, 'unchanged private source copy passes actual build graph enforcement').toBe(0);
  writeFileSync(join(sourceCopy, 'src/decode/index.ts'), reexport);
  const rejectedBuild = buildGraph();
  expect(rejectedBuild.error === undefined, 'actual prebuild re-export control completes').toBe(true);
  expect(rejectedBuild.signal, 'build graph rejection is a normal process exit').toBeNull();
  expect(rejectedBuild.status, 'build graph rejection has an exit status').not.toBeNull();
  expect(rejectedBuild.status, 'actual build graph rejects unchanged allowlisted value re-export payload').not.toBe(0);
  const lint = spawnSync(process.execPath, [join(repo, 'test/helpers/cp044-lint.mjs'), 'src/decode/index.ts',
    Buffer.from(reexport).toString('base64')], { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 20000 });
  expect(lint.status, 'allowlisted value re-export probe executes').toBe(0);
  const laundering = join(dir, 'launder.mjs'), attackPath = join(dir, 'value-attack.mjs');
  writeFileSync(laundering, `import {revealSecret} from ${JSON.stringify(cap)}; const access = revealSecret; export const helper = access;`);
  writeFileSync(attackPath, `import {readFileSync} from 'node:fs'; import {Secret} from ${JSON.stringify(pathToFileURL(join(repo, 'dist/secret.js')).href)};
    const bytes = readFileSync(${JSON.stringify(sentinelPath)});
    try { const {helper} = await import(${JSON.stringify(pathToFileURL(laundering).href)});
      process.stdout.write(String(Buffer.from(helper(new Secret(bytes))).equals(bytes))); } catch { process.stdout.write('false'); }`);
  const attack = spawnSync(process.execPath, [attackPath], { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 10000 });
  expect(attack.status, 'value re-export attack yields capture boolean').toBe(0);
  expect.soft(JSON.parse(lint.stdout).rejected || attack.stdout === 'false', 'allowed-module value re-export cannot provide authority').toBe(true);
}); }

export async function weakMapInterceptionControl() { await scratch(async dir => {
  const preload = join(dir, 'intercept.mjs'), report = join(dir, 'capture.json');
  writeFileSync(preload, `import { readFileSync, writeFileSync } from 'node:fs';
    const bytes = readFileSync(${JSON.stringify(sentinelPath)});
    let captured = false;
    const set = WeakMap.prototype.set;
    WeakMap.prototype.set = function(key, value) {
      if (value instanceof Uint8Array && Buffer.from(value).equals(bytes)) captured = true;
      return set.call(this, key, value);
    };
    new WeakMap().set({}, bytes);
    const active = captured; captured = false;
    process.on('exit', () => writeFileSync(${JSON.stringify(report)}, JSON.stringify({active,captured})));
  `);
  const run = spawnSync(process.execPath, ['--import', pathToFileURL(preload).href, join(repo, 'dist/bin.js'),
    'inspect', sentinelPath, '--json'], { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 15000 });
  expect(run.status, 'legitimate built inspect remains functional').toBe(0);
  const result = JSON.parse(readFileSync(report, 'utf8')) as { active: boolean; captured: boolean };
  expect(result.active, 'interceptor positive control captures actual sentinel bytes').toBe(true);
  expect(result.captured, 'no credential crosses intercepted WeakMap.set').toBe(false);
  expect(JSON.parse(run.stdout).ok).toBe(true);
}); }
