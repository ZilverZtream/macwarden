import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import Ajv2020 from 'ajv/dist/2020.js';
import { afterAll, expect, it } from 'vitest';
import { run as attenuate } from '../src/commands/attenuate.js';
import { render } from '../src/output/index.js';
import { expectSchemaValid } from './helpers/output-schema.js';
import { childEnvironment } from './helpers/environment.js';

const repo = resolve();
const schemaFile = (name: string) => JSON.parse(readFileSync(join(repo, 'schemas/output', `${name}.schema.json`), 'utf8'));
const commands = ['inventory', 'bake', 'revoke', 'rotate', 'attenuate', 'verify', 'watch', 'recommend', 'reconcile'];
const tmp = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP ?? tmpdir(), 'output-schemas-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

it('UX/output-schemas every command publishes a draft 2020-12 schema with a stable $id', () => {
  for (const name of commands) {
    const schema = schemaFile(name);
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema.$id).toBe(`https://github.com/ZilverZtream/macwarden/blob/main/schemas/output/${name}.schema.json`);
    expect(schema.properties.command).toEqual({ const: name });
    expect(schema.additionalProperties).toBe(false);
  }
});

it('UX/output-schemas the generated files are current and reuse the hand-written definitions', () => {
  const check = spawnSync(process.execPath, [join(repo, 'scripts/output-schemas.mjs'), '--check'], { encoding: 'utf8' });
  expect(check.status, check.stderr).toBe(0);
  const entry = schemaFile('registry-entry');
  for (const name of ['bake', 'revoke', 'rotate'])
    expect(schemaFile(name).$defs.registryEntry.properties).toEqual(entry.properties);
  const inspect = schemaFile('inspect');
  expect(schemaFile('attenuate').$defs.caveat).toEqual(inspect.$defs.caveat);
  expect(schemaFile('attenuate').$defs.result.required).toEqual(expect.arrayContaining(inspect.$defs.result.required));
  expect(schemaFile('verify').$defs.caveat).toEqual(inspect.$defs.caveat);
  expect(schemaFile('verify').$defs.result.required).toEqual(expect.arrayContaining(inspect.$defs.result.required));
});

it('UX/output-schemas the schemas reject documents that break the contract', () => {
  const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false });
  const validate = ajv.compile(schemaFile('revoke'));
  const plan = { schema: 1, command: 'revoke', ok: true, warnings: [], error: null,
    result: { dryRun: true, rootKeyId: '4294967296', label: 'App', grade: 'READ', proof: 'by-id-only' } };
  expect(validate(plan)).toBe(true);
  const broken = [
    { ...plan, result: { ...plan.result, extra: 1 } },
    { ...plan, result: { ...plan.result, rootKeyId: 4294967296 } },
    { ...plan, result: { ...plan.result, proof: 'trust-me' } },
    { ...plan, ok: true, error: { code: 2, step: null, message: 'x' } },
    { ...plan, ok: false, result: null, error: { code: 9, step: null, message: 'x' } },
    { ...plan, ok: false, result: null, error: { code: 2, step: '', message: 'x' } },
    { ...plan, command: 'bake' },
  ];
  for (const document of broken) expect(validate(document), JSON.stringify(document)).toBe(false);
});

it('UX/output-schemas attenuate results validate for a dry run, a written copy and a refusal', async () => {
  const deps = { stdin: Object.assign(Readable.from([]), { isTTY: true }), fs, env: {}, clock: () => new Date('2026-10-04T00:00:00Z') };
  mkdirSync(tmp, { recursive: true });
  const input = join(repo, 'test/vectors/default-readonly.macaroon');
  const results = [
    await attenuate([input, '--out', join(tmp, 'dry.macaroon'), '--expires', '1h', '--dry-run'], deps),
    await attenuate([input, '--out', join(tmp, 'copy.macaroon'), '--expires', '1h', '--ip', '127.0.0.1'], deps),
    await attenuate([input, '--out', join(tmp, 'none.macaroon')], deps),
  ];
  expect(results.map(result => result.ok)).toEqual([true, true, false]);
  for (const result of results) expectSchemaValid(result);
  expect(JSON.parse(render(results[1], 'json')).result.added).toHaveLength(2);
});

it('UX/output-schemas watch event lines have their own schema, apart from the final document', () => {
  const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false });
  const schema = schemaFile('watch-event');
  expect(schema.$id).toBe('https://github.com/ZilverZtream/macwarden/blob/main/schemas/output/watch-event.schema.json');
  const validate = ajv.compile(schema);
  const time = '2026-10-08T12:00:00.000Z';
  const call = { schema: 1, event: 'call', time, method: '/lnrpc.Lightning/GetInfo', rootKeyId: '4294967341', credential: 'id:0123456789abcdef', label: 'app' };
  const good = [call, { ...call, event: 'error' }, { ...call, rootKeyId: 'none', credential: 'id:none', label: null },
    { ...call, event: 'canary', denied: true }, { ...call, event: 'canary', denied: true, repeats: 4 },
    { schema: 1, event: 'status', time, status: 'registered', canaries: 1, readOnly: true },
    { schema: 1, event: 'status', time, status: 'reconnecting', canaries: 0, readOnly: true },
    { schema: 1, event: 'status', time, status: 'output-dropped', dropped: 5 },
    { schema: 1, event: 'status', time, status: 'alert-failed', rootKeyId: '4294967342', label: 'decoy' }];
  for (const document of good) expect(validate(document), JSON.stringify(document)).toBe(true);
  const bad = [{ ...call, event: 'canary' }, { ...call, event: 'canary', denied: false }, { ...call, extra: 1 }, { ...call, credential: 'fp:0123456789abcdef' },
    { ...call, rootKeyId: 42 }, { ...call, schema: 2 }, { ...call, event: 'other' }, { ...call, time: 'yesterday' },
    { schema: 1, event: 'status', time, status: 'output-dropped', dropped: 0 },
    { schema: 1, event: 'status', time, status: 'stopped', canaries: 0, readOnly: true },
    { schema: 1, command: 'watch', ok: true, warnings: [], result: null, error: null }];
  for (const document of bad) expect(validate(document), JSON.stringify(document)).toBe(false);
  // The final document is never mistaken for an event line, and an event line is not a final document.
  expect(ajv.compile(schemaFile('watch'))(call)).toBe(false);
});

it('UX/output-schemas the built CLI\'s watch and recommend refusals validate against the shipped schemas', () => {
  const cli = (...args: string[]) => spawnSync(process.execPath, [join(repo, 'dist/bin.js'), ...args],
    { cwd: tmp, env: childEnvironment(), encoding: 'utf8', timeout: 30_000, windowsHide: true });
  const cases: [string[], string, number][] = [
    [['watch', '--json', '--until', '0s'], 'watch', 2], [['watch', '--json'], 'watch', 2],
    [['recommend', '--json'], 'recommend', 2], [['recommend', 'app1', '--json'], 'recommend', 2]];
  for (const [args, command, status] of cases) {
    const run = cli(...args);
    expect(run.status, run.stderr).toBe(status);
    // One document, the last (only) line.
    const lines = run.stdout.trimEnd().split('\n');
    expect(lines).toHaveLength(1);
    const document = JSON.parse(lines[0]);
    expect(document).toMatchObject({ command, ok: false });
    const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(schemaFile(command));
    expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
  }
});

it('UX/output-schemas MW110-10 every command schema accepts its own --help --json document and nothing looser', () => {
  const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false });
  for (const name of [...commands, 'inspect', 'scan', 'respond']) {
    const validate = ajv.compile(schemaFile(name));
    const help = { schema: 1, command: name, ok: true, warnings: [], result: { usage: [`macwarden ${name} --json`] }, error: null };
    expect(validate(help), name).toBe(true);
    for (const broken of [
      { ...help, result: { usage: ['macwarden other --json'] } },
      { ...help, result: { usage: [] } },
      { ...help, result: { usage: [`macwarden ${name} --json`], extra: 1 } },
      { ...help, ok: false, error: { code: 2, step: null, message: 'x' } },
    ]) expect(validate(broken), `${name} ${JSON.stringify(broken)}`).toBe(false);
  }
});

it('UX/output-schemas MW110-10 the top-level schema covers command: null documents only', () => {
  const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false });
  const validate = ajv.compile(schemaFile('macwarden'));
  const help = { schema: 1, command: null, ok: true, warnings: [], error: null,
    result: { usage: ['macwarden --help | --version'], commands: [{ name: 'verify', summary: 'x' }] } };
  const usageError = { schema: 1, command: null, ok: false, warnings: [], result: null, error: { code: 2, step: null, message: 'unknown command' } };
  expect(validate(help)).toBe(true);
  expect(validate(usageError)).toBe(true);
  for (const broken of [{ ...help, command: 'verify' }, { ...help, result: { usage: help.result.usage } },
    { ...help, result: { ...help.result, extra: 1 } }, { ...help, ok: false }])
    expect(validate(broken), JSON.stringify(broken)).toBe(false);
});
