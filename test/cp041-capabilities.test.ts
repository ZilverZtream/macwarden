import { fork, spawnSync, type ChildProcess } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Linter } from 'eslint';
import ts from 'typescript';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { childEnvironment } from './helpers/environment.js';
import { noEcho, repo, scratch, vector } from './support/cp041-controls.js';

let child: ChildProcess;
function reply(): Promise<{ ready?: boolean; messages?: Linter.LintMessage[]; error?: string }> {
  return new Promise((done, fail) => {
    const cleanup = () => { child.off('message', message); child.off('error', error); child.off('exit', error); };
    const message = (value: { ready?: boolean; messages?: Linter.LintMessage[] }) => { cleanup(); done(value); };
    const error = () => { cleanup(); fail(new Error('Boundary probe failed before diagnostics')); };
    child.once('message', message); child.once('error', error); child.once('exit', error);
  });
}
beforeAll(async () => {
  child = fork(join(repo, 'test/support/cp039-lint.mjs'), [], { cwd: repo, execArgv: [],
    windowsHide: true, env: childEnvironment(), stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  expect((await reply()).ready).toBe(true);
});
afterAll(async () => {
  if (child?.exitCode === null && child.signalCode === null) {
    const stopped = new Promise<void>(done => child.once('exit', () => done())); child.kill(); await stopped;
  }
});
async function rejects(code: string, site: string) {
  const pending = reply(); child.send({ code, site }); const result = await pending;
  if (result.error || !result.messages) throw new Error('Boundary diagnostics unavailable');
  return result.messages.some(m => m.severity === 2 && m.ruleId !== null &&
    !['@typescript-eslint/no-unused-vars', '@typescript-eslint/no-explicit-any'].includes(m.ruleId));
}
const capability = pathToFileURL(join(repo, 'dist/secret-capability.js')).href;
const dynamic = `return import(${JSON.stringify(capability)})`;
const probes = [
  { name: 'assertion-wrapped function constructor', code: `const fn = (() => {}) as () => void; let key = 'con'; key += 'structor'; const Execute = fn[key as keyof typeof fn] as unknown as (source: string) => () => Promise<unknown>; await Execute(${JSON.stringify(dynamic)})();`,
    runtime: `const fn = (() => {}); let key = 'con'; key += 'structor'; const Execute = fn[key]; const cap = await Execute(${JSON.stringify(dynamic)})();` },
  { name: 'mutable-function constructor', code: `let fn = () => {}; fn(); fn = () => {}; let key = 'con'; key += 'structor'; const Execute = fn[key] as (source: string) => () => Promise<unknown>; await Execute(${JSON.stringify(dynamic)})();`,
    runtime: `let fn = () => {}; fn(); fn = () => {}; let key = 'con'; key += 'structor'; const Execute = fn[key]; const cap = await Execute(${JSON.stringify(dynamic)})();` },
  { name: 'direct import', code: 'import { revealSecret } from "../secret-capability.js"; void revealSecret;', runtime: `const cap = await import(${JSON.stringify(capability)});` },
  { name: 'fragment constructor', code: `const key = ['con','structor'].join(''); const Execute = (() => {})[key]; await Execute(${JSON.stringify(dynamic)})();`,
    runtime: `const key = ['con','structor'].join(''); const Execute = (() => {})[key]; const cap = await Execute(${JSON.stringify(dynamic)})();` },
  { name: 'named-variable constructor', code: `const fn = () => {}; const parts = ['con','structor']; const key = parts.join(''); const Execute = fn[key]; await Execute(${JSON.stringify(dynamic)})();`,
    runtime: `const fn = () => {}; const parts = ['con','structor']; const key = parts.join(''); const Execute = fn[key]; const cap = await Execute(${JSON.stringify(dynamic)})();` },
  { name: 'empty-template-separator named-variable constructor', code: `const fn = () => {}; const parts = ['con','structor']; const separator = \`\`; const key = parts.join(separator); const Execute = fn[key]; await Execute(${JSON.stringify(dynamic)})();`,
    runtime: `const fn = () => {}; const parts = ['con','structor']; const separator = \`\`; const key = parts.join(separator); const Execute = fn[key]; const cap = await Execute(${JSON.stringify(dynamic)})();` },
  { name: 'reflected constructor', code: `const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(() => {}), 'constructor'); await descriptor.value(${JSON.stringify(dynamic)})();`,
    runtime: `const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(() => {}), 'constructor'); const cap = await descriptor.value(${JSON.stringify(dynamic)})();` },
] as const;
async function publicDecodeControl(dir: string, publicSource?: string) {
  const reference = vector();
  const publicModule = join(dir, 'public-secret.mjs');
  const secretUrl = pathToFileURL(join(repo, 'dist/secret.js')).href;
  if (publicSource) writeFileSync(publicModule, ts.transpileModule(publicSource.replace('../secret.js', secretUrl), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText);
  const control = join(dir, 'public-decode.mjs');
  writeFileSync(control, `import { readFileSync } from 'node:fs';
    import ${publicSource ? 'Secret' : '{ Secret }'} from ${JSON.stringify(publicSource ? pathToFileURL(publicModule).href : secretUrl)};
    import { decodeMacaroon } from ${JSON.stringify(pathToFileURL(join(repo, 'dist/decode/index.js')).href)};
    const facts = decodeMacaroon(new Secret(readFileSync(${JSON.stringify(join(repo, 'test/vectors', reference.file))})));
    process.stdout.write(JSON.stringify({ fingerprint: facts.fingerprint, rootKeyId: String(facts.rootKeyId), permissions: facts.permissions }));`);
  const run = spawnSync(process.execPath, [control], { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 10_000 });
  noEcho(run.stdout + run.stderr, reference.bytes);
  expect(run.status, 'public decode executes successfully').toBe(0);
  expect(run.stderr, 'public decode emits no diagnostics').toBe('');
  expect(JSON.parse(run.stdout)).toEqual({ fingerprint: reference.fingerprint,
    rootKeyId: reference.printed.root_key_id, permissions: reference.printed.permissions });
}
for (const probe of probes) it(`CP-041/B1-capability-escapes rejects ${probe.name} with a public decode control`, async () => scratch(async dir => {
  await publicDecodeControl(dir);
  expect(await rejects(probe.code, 'src/output/cp041-probe.ts'), 'enforced boundary rejects credential access').toBe(true);
}));
for (const site of ['src/decode/cp041-probe.ts', 'src/lnd/cp041-probe.ts', 'src/commands/bake/write-out.ts']) {
  for (const kind of ['star', 'named'] as const) it(`CP-041/B1-capability-escapes rejects ${kind} laundering at ${site}`, async () => scratch(async dir => {
    const specifier = site.includes('/commands/') ? '../../secret-capability.js' : '../secret-capability.js';
    const source = kind === 'star' ? `export * from '${specifier}';` : `export { revealSecret as helper } from '${specifier}';`;
    await publicDecodeControl(dir);
    expect(await rejects(source, site), 'allowed consumers cannot launder the capability').toBe(true);
  }));
}
it('CP-041/B1-capability-escapes preserves allowed consumption and ordinary JSON access', async () => {
  await scratch(dir => publicDecodeControl(dir));
  expect(await rejects('const data = JSON.parse("{}"); const key = "result"; void data[key];', 'src/output/cp041-probe.ts')).toBe(false);
});
it('CP-041/B1-capability-escapes rejects assertion-wrapped default capability export with executable public Secret decode controls', async () => scratch(async dir => {
  const source = 'import { revealSecret } from "../secret-capability.js"; export default (revealSecret as unknown);';
  const publicSource = 'import { Secret } from "../secret.js"; export default (Secret as unknown);';
  await publicDecodeControl(dir, publicSource);
  expect(await rejects(publicSource, 'src/decode/cp041-probe.ts'), 'ordinary public Secret default export remains allowed').toBe(false);
  expect(await rejects(source, 'src/decode/cp041-probe.ts'), 'assertion wrapper cannot launder the capability').toBe(true);
}));
it('CP-041/B1-capability-escapes rejects budget-exhausting wrapped default capability export with executable public Secret decode controls', async () => scratch(async dir => {
  const source = 'import { revealSecret } from "../secret-capability.js"; export default (revealSecret' + ' as unknown'.repeat(17) + ');';
  const publicSource = 'import { Secret } from "../secret.js"; export default (Secret as unknown);';
  await publicDecodeControl(dir, publicSource);
  expect(await rejects(publicSource, 'src/decode/cp041-probe.ts'), 'ordinary public Secret default export remains allowed').toBe(false);
  expect(await rejects(source, 'src/decode/cp041-probe.ts'), 'exhausted assertion traversal cannot launder the capability').toBe(true);
}));
